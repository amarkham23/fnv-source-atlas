"""Read-only review queues and reproducible reviewer-labelled snapshots.

This module is deliberately downstream of the atlas evidence model.  It never
writes review decisions, scores evidence, chooses among alternatives, expands a
fold bundle into independent claims, or infers consensus between reviewers.

Queue pages are bounded and standalone. Their keyset cursors are tied to a
content hash of the complete triage ordering, so a bucket-changing database
update invalidates an older cursor instead of silently drifting. A
review-release snapshot is a separate immutable, normalized label set suitable
for measuring producer coverage against one explicitly named reviewer.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any


REVIEW_QUEUE_FORMAT = "fnv-source-atlas-review-queue/v1"
REVIEW_SNAPSHOT_FORMAT = "fnv-source-atlas-review-release-snapshot/v1"
PRODUCER_EVALUATION_FORMAT = "fnv-source-atlas-producer-evaluation/v1"

TRIAGE_BUCKETS = (
    "contradicted",
    "incomplete",
    "ambiguous",
    "fold",
    "unresolved",
    "exact",
)
DECISION_STATES = ("accepted", "rejected", "deferred", "open")

_TRIAGE_RANK = {name: rank for rank, name in enumerate(TRIAGE_BUCKETS)}
_REQUIRED_RELATIONS = {
    "address_groups",
    "claim_evidence",
    "current_review_decisions",
    "fold_group_members",
    "fold_groups",
    "function_names",
    "functions",
    "match_claims",
    "match_hypothesis_alternative_evidence",
    "match_hypothesis_alternatives",
    "match_hypothesis_evidence",
    "match_hypothesis_sets",
    "programs",
    "provenance",
    "review_releases",
    "reviewers",
    "unresolved_targets",
}


class ReviewQueueError(RuntimeError):
    """Persisted atlas rows cannot be represented without guessing."""


def canonical_json(value: Mapping[str, Any]) -> str:
    """Serialize a mapping deterministically and reject non-finite numbers."""

    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ReviewQueuePage:
    """One bounded, standalone page from a deterministic queue ordering."""

    _payload_json: str
    page_sha256: str

    def to_dict(self) -> dict[str, Any]:
        result = json.loads(self._payload_json)
        result["page_sha256"] = self.page_sha256
        return result

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class ReviewReleaseSnapshot:
    """Immutable candidate universe plus one reviewer's release-bound labels."""

    _payload_json: str
    snapshot_sha256: str

    def to_dict(self) -> dict[str, Any]:
        result = json.loads(self._payload_json)
        result["snapshot_sha256"] = self.snapshot_sha256
        return result

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class ProducerEvaluation:
    """Count-only comparison against one immutable reviewer snapshot."""

    _payload_json: str
    evaluation_sha256: str

    def to_dict(self) -> dict[str, Any]:
        result = json.loads(self._payload_json)
        result["evaluation_sha256"] = self.evaluation_sha256
        return result

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def _encode_cursor(value: Mapping[str, Any]) -> str:
    raw = canonical_json(value).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(value: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        raise ValueError("review queue cursor must be a non-empty string")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid review queue cursor") from exc
    if not isinstance(decoded, dict):
        raise ValueError("invalid review queue cursor payload")
    return decoded


def _decode_object(value: Any, *, field: str) -> dict[str, Any]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError) as exc:
        raise ReviewQueueError(f"{field} is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ReviewQueueError(f"{field} must contain a JSON object")
    return decoded


def _fetch_dicts(
    connection: sqlite3.Connection,
    sql: str,
    parameters: Sequence[Any] = (),
) -> list[dict[str, Any]]:
    cursor = connection.execute(sql, tuple(parameters))
    names = [str(column[0]) for column in cursor.description or ()]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def _fetch_one(
    connection: sqlite3.Connection,
    sql: str,
    parameters: Sequence[Any],
    *,
    description: str,
) -> dict[str, Any]:
    rows = _fetch_dicts(connection, sql, parameters)
    if len(rows) != 1:
        raise ReviewQueueError(
            f"expected exactly one {description}; database returned {len(rows)}"
        )
    return rows[0]


def _fetch_for_ids(
    connection: sqlite3.Connection,
    sql_prefix: str,
    *,
    id_expression: str,
    identifiers: Sequence[str] | None,
    order_by: str,
) -> list[dict[str, Any]]:
    """Run one bounded family of SELECTs without exceeding variable limits."""

    if identifiers is None:
        return _fetch_dicts(connection, f"{sql_prefix} ORDER BY {order_by}")
    unique = sorted(set(identifiers))
    if not unique:
        return []
    result: list[dict[str, Any]] = []
    for start in range(0, len(unique), 800):
        batch = unique[start : start + 800]
        placeholders = ",".join("?" for _ in batch)
        result.extend(
            _fetch_dicts(
                connection,
                f"{sql_prefix} WHERE {id_expression} IN ({placeholders}) "
                f"ORDER BY {order_by}",
                batch,
            )
        )
    return result


@contextmanager
def _connect_read_only(
    database: str | Path | sqlite3.Connection,
) -> Iterator[sqlite3.Connection]:
    if isinstance(database, sqlite3.Connection):
        yield database
        return
    path = Path(database).resolve()
    if not path.is_file():
        raise ReviewQueueError(f"atlas database does not exist: {path}")
    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro",
        uri=True,
        isolation_level=None,
    )
    try:
        yield connection
    finally:
        connection.close()


def _ensure_shape(connection: sqlite3.Connection) -> None:
    rows = _fetch_dicts(
        connection,
        "SELECT name FROM sqlite_schema WHERE type IN ('table', 'view')",
    )
    present = {str(row["name"]) for row in rows}
    missing = sorted(_REQUIRED_RELATIONS - present)
    if missing:
        raise ReviewQueueError(
            "database lacks required atlas relations: " + ", ".join(missing)
        )


def _context(
    connection: sqlite3.Connection,
    reviewer_id: str,
    review_release_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    reviewer = _fetch_one(
        connection,
        """
        SELECT reviewer_id, identity_kind, identity_key, display_name,
               affiliation, details_json
        FROM reviewers WHERE reviewer_id = ?
        """,
        (reviewer_id,),
        description=f"reviewer {reviewer_id!r}",
    )
    reviewer["details"] = _decode_object(
        reviewer.pop("details_json"), field="reviewers.details_json"
    )
    release = _fetch_one(
        connection,
        """
        SELECT review_release_id, release_key, label, version, source_revision,
               manifest_id, provenance_id, details_json
        FROM review_releases WHERE review_release_id = ?
        """,
        (review_release_id,),
        description=f"review release {review_release_id!r}",
    )
    release["details"] = _decode_object(
        release.pop("details_json"), field="review_releases.details_json"
    )
    return reviewer, release


def _load_provenance(connection: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in _fetch_dicts(
        connection,
        """
        SELECT provenance_id, kind, producer, producer_version, method,
               manifest_id, parameters_json, notes, created_at
        FROM provenance ORDER BY provenance_id
        """,
    ):
        row["parameters"] = _decode_object(
            row.pop("parameters_json"), field="provenance.parameters_json"
        )
        result[str(row["provenance_id"])] = row
    return result


def _with_provenance(
    provenance: Mapping[str, Mapping[str, Any]], provenance_id: Any
) -> dict[str, Any]:
    key = str(provenance_id)
    if key not in provenance:
        raise ReviewQueueError(f"missing provenance row {key!r}")
    return dict(provenance[key])


def _load_functions(
    connection: sqlite3.Connection,
    function_ids: Sequence[str] | None,
) -> dict[str, dict[str, Any]]:
    functions: dict[str, dict[str, Any]] = {}
    for row in _fetch_for_ids(
        connection,
        """
        SELECT f.function_id, f.program_id, p.platform, f.address_group_id,
               a.address_space, a.address, f.identity_key, f.kind, f.type_index,
               f.module_id, f.symbol_record_kind, f.details_json
        FROM functions f
        JOIN programs p USING (program_id)
        JOIN address_groups a
          ON a.address_group_id = f.address_group_id
         AND a.program_id = f.program_id
        """,
        id_expression="f.function_id",
        identifiers=function_ids,
        order_by="f.function_id",
    ):
        row["details"] = _decode_object(
            row.pop("details_json"), field="functions.details_json"
        )
        row["endpoint_kind"] = "function"
        row["names"] = []
        functions[str(row["function_id"])] = row
    for row in _fetch_for_ids(
        connection,
        """
        SELECT name_id, function_id, name, name_kind, is_primary,
               provenance_id, details_json
        FROM function_names
        """,
        id_expression="function_id",
        identifiers=function_ids,
        order_by="function_id, name_kind, name, name_id",
    ):
        function_id = str(row["function_id"])
        if function_id not in functions:
            raise ReviewQueueError(f"name refers to missing function {function_id!r}")
        row["is_primary"] = bool(row["is_primary"])
        row["details"] = _decode_object(
            row.pop("details_json"), field="function_names.details_json"
        )
        functions[function_id]["names"].append(row)
    return functions


def _load_targets(
    connection: sqlite3.Connection,
    target_ids: Sequence[str] | None,
) -> dict[str, dict[str, Any]]:
    targets: dict[str, dict[str, Any]] = {}
    for row in _fetch_for_ids(
        connection,
        """
        SELECT t.target_id, t.program_id, p.platform, t.address_group_id,
               a.address_space, a.address, t.target_kind, t.name_hint,
               t.reason, t.status, t.resolved_function_id, t.provenance_id,
               t.details_json
        FROM unresolved_targets t
        JOIN programs p USING (program_id)
        LEFT JOIN address_groups a
          ON a.address_group_id = t.address_group_id
         AND a.program_id = t.program_id
        """,
        id_expression="t.target_id",
        identifiers=target_ids,
        order_by="t.target_id",
    ):
        row["details"] = _decode_object(
            row.pop("details_json"), field="unresolved_targets.details_json"
        )
        row["endpoint_kind"] = "unresolved_target"
        targets[str(row["target_id"])] = row
    return targets


def _endpoint(
    *,
    function_id: Any,
    target_id: Any,
    functions: Mapping[str, Mapping[str, Any]],
    targets: Mapping[str, Mapping[str, Any]],
    description: str,
) -> dict[str, Any]:
    if (function_id is None) == (target_id is None):
        raise ReviewQueueError(f"{description} must select exactly one endpoint")
    if function_id is not None:
        key = str(function_id)
        if key not in functions:
            raise ReviewQueueError(f"{description} references missing function {key!r}")
        return json.loads(json.dumps(functions[key]))
    key = str(target_id)
    if key not in targets:
        raise ReviewQueueError(f"{description} references missing target {key!r}")
    return json.loads(json.dumps(targets[key]))


def _load_evidence(
    connection: sqlite3.Connection,
    provenance: Mapping[str, Mapping[str, Any]],
    *,
    set_ids: Sequence[str] | None,
    alternative_ids: Sequence[str] | None,
    claim_ids: Sequence[str] | None,
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    specifications = (
        ("match_hypothesis_evidence", "hypothesis_set_id", "set", set_ids),
        (
            "match_hypothesis_alternative_evidence",
            "alternative_id",
            "alternative",
            alternative_ids,
        ),
        ("claim_evidence", "claim_id", "claim", claim_ids),
    )
    loaded: list[dict[str, list[dict[str, Any]]]] = []
    for table, target_column, scope, identifiers in specifications:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        sql = f"""
            SELECT evidence_id, {target_column} AS target_id, effect,
                   evidence_kind, independence_group, provenance_id,
                   asserted_strength, details_json, created_at
            FROM {table}
        """
        for row in _fetch_for_ids(
            connection,
            sql,
            id_expression=target_column,
            identifiers=identifiers,
            order_by=f"{target_column}, evidence_id",
        ):
            row["scope"] = scope
            row["details"] = _decode_object(
                row.pop("details_json"), field=f"{table}.details_json"
            )
            row["provenance"] = _with_provenance(
                provenance, row["provenance_id"]
            )
            grouped[str(row.pop("target_id"))].append(row)
        loaded.append(grouped)
    return loaded[0], loaded[1], loaded[2]


def _load_review_leaves(
    connection: sqlite3.Connection,
    target_keys: set[tuple[str, str]] | None,
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    seen: set[tuple[str, str, str]] = set()
    identifiers = (
        None
        if target_keys is None
        else sorted({target_id for _, target_id in target_keys})
    )
    rows = _fetch_for_ids(
        connection,
        """
        SELECT d.target_kind, d.target_id, d.decision_id, d.reviewer_id,
               r.identity_kind, r.identity_key, r.display_name, r.affiliation,
               d.action, d.derived_status, d.decided_at, d.rationale,
               d.provenance_id, d.review_release_id, rr.release_key,
               rr.label AS release_label, rr.version AS release_version,
               rr.source_revision, d.previous_decision_id, d.details_json
        FROM current_review_decisions d
        JOIN reviewers r USING (reviewer_id)
        JOIN review_releases rr USING (review_release_id)
        """,
        id_expression="d.target_id",
        identifiers=identifiers,
        order_by="d.target_kind, d.target_id, d.reviewer_id, d.decision_id",
    )
    for row in rows:
        key = (str(row["target_kind"]), str(row["target_id"]))
        if target_keys is not None and key not in target_keys:
            continue
        reviewer_key = key + (str(row["reviewer_id"]),)
        if reviewer_key in seen:
            raise ReviewQueueError(
                "multiple current review leaves for one reviewer and target: "
                + repr(reviewer_key)
            )
        seen.add(reviewer_key)
        row["details"] = _decode_object(
            row.pop("details_json"), field="review_decisions.details_json"
        )
        grouped[key].append(row)
    return grouped


def _selected_review(
    leaves: Sequence[Mapping[str, Any]],
    *,
    reviewer_id: str,
    review_release_id: str,
) -> dict[str, Any]:
    selected = [leaf for leaf in leaves if leaf["reviewer_id"] == reviewer_id]
    if len(selected) > 1:
        raise ReviewQueueError("selected reviewer has multiple current leaves")
    leaf = None if not selected else dict(selected[0])
    if leaf is None:
        state, basis = "open", "no_current_decision"
    elif leaf["review_release_id"] != review_release_id:
        state, basis = "open", "current_leaf_from_another_release"
    elif leaf["action"] == "accept":
        state, basis = "accepted", "current_accept_in_selected_release"
    elif leaf["action"] == "reject":
        state, basis = "rejected", "current_reject_in_selected_release"
    elif leaf["action"] == "defer":
        state, basis = "deferred", "current_defer_in_selected_release"
    elif leaf["action"] in {"reopen", "supersede"}:
        state, basis = "open", f"current_{leaf['action']}_in_selected_release"
    else:
        raise ReviewQueueError(f"unsupported review action {leaf['action']!r}")
    return {
        "state": state,
        "basis": basis,
        "current_leaf": leaf,
    }


def _review_block(
    leaves: Sequence[Mapping[str, Any]],
    *,
    reviewer_id: str,
    review_release_id: str,
) -> dict[str, Any]:
    copied = [dict(leaf) for leaf in leaves]
    actions = sorted({str(leaf["action"]) for leaf in copied})
    return {
        "selected_reviewer": _selected_review(
            copied,
            reviewer_id=reviewer_id,
            review_release_id=review_release_id,
        ),
        "all_current_reviewer_leaves": copied,
        "literal_leaf_summary": {
            "reviewer_count": len(copied),
            "distinct_actions": actions,
            "has_action_disagreement": len(actions) > 1,
            "consensus_inferred": False,
        },
    }


@dataclass(slots=True)
class _LoadedReviewData:
    reviewer: dict[str, Any]
    release: dict[str, Any]
    provenance: dict[str, dict[str, Any]]
    functions: dict[str, dict[str, Any]]
    targets: dict[str, dict[str, Any]]
    claims: dict[str, dict[str, Any]]
    sets: dict[str, dict[str, Any]]
    alternatives: dict[str, dict[str, Any]]
    alternatives_by_set: dict[str, list[str]]
    folds: dict[str, dict[str, Any]]
    set_evidence: dict[str, list[dict[str, Any]]]
    alternative_evidence: dict[str, list[dict[str, Any]]]
    claim_evidence: dict[str, list[dict[str, Any]]]
    review_leaves: dict[tuple[str, str], list[dict[str, Any]]]


def _load_data(
    connection: sqlite3.Connection,
    *,
    reviewer_id: str,
    review_release_id: str,
    fold_sample_limit: int,
    hypothesis_set_ids: Sequence[str] | None,
    include_all_claims: bool,
) -> _LoadedReviewData:
    reviewer, release = _context(connection, reviewer_id, review_release_id)
    provenance = _load_provenance(connection)

    raw_sets = _fetch_for_ids(
        connection,
        """
        SELECT hypothesis_set_id, pc_function_id, pc_target_id, status,
               provenance_id, identity_key, rationale, details_json,
               created_at, updated_at
        FROM match_hypothesis_sets
        """,
        id_expression="hypothesis_set_id",
        identifiers=hypothesis_set_ids,
        order_by="hypothesis_set_id",
    )
    loaded_set_ids = [str(row["hypothesis_set_id"]) for row in raw_sets]
    raw_alternatives = _fetch_for_ids(
        connection,
        """
        SELECT alternative_id, hypothesis_set_id, claim_id,
               xbox_fold_group_id, details_json, created_at
        FROM match_hypothesis_alternatives
        """,
        id_expression="hypothesis_set_id",
        identifiers=(None if hypothesis_set_ids is None else loaded_set_ids),
        order_by="hypothesis_set_id, alternative_id",
    )
    referenced_claim_ids = sorted(
        {
            str(row["claim_id"])
            for row in raw_alternatives
            if row["claim_id"] is not None
        }
    )
    raw_claims = _fetch_for_ids(
        connection,
        """
        SELECT claim_id, pc_function_id, pc_target_id, xbox_function_id,
               xbox_target_id, status, confidence_label, confidence_value,
               provenance_id, rationale, details_json, created_at, updated_at
        FROM match_claims
        """,
        id_expression="claim_id",
        identifiers=None if include_all_claims else referenced_claim_ids,
        order_by="claim_id",
    )

    referenced_folds = sorted(
        {
            str(row["xbox_fold_group_id"])
            for row in raw_alternatives
            if row["xbox_fold_group_id"] is not None
        }
    )
    raw_folds: dict[str, tuple[dict[str, Any], list[dict[str, Any]], int]] = {}
    fold_sample_function_ids: set[str] = set()
    for fold_id in referenced_folds:
        fold_row = _fetch_one(
            connection,
            """
            SELECT fg.fold_group_id, fg.program_id, p.platform, fg.kind,
                   fg.provenance_id, fg.details_json
            FROM fold_groups fg JOIN programs p USING (program_id)
            WHERE fg.fold_group_id = ?
            """,
            (fold_id,),
            description=f"fold group {fold_id!r}",
        )
        count_row = _fetch_one(
            connection,
            """
            SELECT COUNT(*) AS member_count
            FROM fold_group_members WHERE fold_group_id = ?
            """,
            (fold_id,),
            description=f"member count for fold group {fold_id!r}",
        )
        sample_rows = _fetch_dicts(
            connection,
            """
            SELECT function_id, member_role
            FROM fold_group_members
            WHERE fold_group_id = ?
            ORDER BY function_id LIMIT ?
            """,
            (fold_id, fold_sample_limit),
        )
        fold_sample_function_ids.update(str(row["function_id"]) for row in sample_rows)
        raw_folds[fold_id] = (fold_row, sample_rows, int(count_row["member_count"]))

    function_ids = set(fold_sample_function_ids)
    target_ids: set[str] = set()
    for row in (*raw_sets, *raw_claims):
        for column in ("pc_function_id", "xbox_function_id"):
            if column in row and row[column] is not None:
                function_ids.add(str(row[column]))
        for column in ("pc_target_id", "xbox_target_id"):
            if column in row and row[column] is not None:
                target_ids.add(str(row[column]))
    functions = _load_functions(connection, sorted(function_ids))
    targets = _load_targets(connection, sorted(target_ids))

    claims: dict[str, dict[str, Any]] = {}
    for row in raw_claims:
        claim_id = str(row["claim_id"])
        row["details"] = _decode_object(
            row.pop("details_json"), field="match_claims.details_json"
        )
        row["producer"] = _with_provenance(provenance, row["provenance_id"])
        row["pc_endpoint"] = _endpoint(
            function_id=row.pop("pc_function_id"),
            target_id=row.pop("pc_target_id"),
            functions=functions,
            targets=targets,
            description=f"claim {claim_id} PC endpoint",
        )
        row["xbox_endpoint"] = _endpoint(
            function_id=row.pop("xbox_function_id"),
            target_id=row.pop("xbox_target_id"),
            functions=functions,
            targets=targets,
            description=f"claim {claim_id} Xbox endpoint",
        )
        claims[claim_id] = row

    sets: dict[str, dict[str, Any]] = {}
    for row in raw_sets:
        set_id = str(row["hypothesis_set_id"])
        row["details"] = _decode_object(
            row.pop("details_json"), field="match_hypothesis_sets.details_json"
        )
        row["producer"] = _with_provenance(provenance, row["provenance_id"])
        row["pc_subject"] = _endpoint(
            function_id=row.pop("pc_function_id"),
            target_id=row.pop("pc_target_id"),
            functions=functions,
            targets=targets,
            description=f"hypothesis set {set_id} PC subject",
        )
        sets[set_id] = row

    alternatives: dict[str, dict[str, Any]] = {}
    alternatives_by_set: dict[str, list[str]] = defaultdict(list)
    for row in raw_alternatives:
        alternative_id = str(row["alternative_id"])
        set_id = str(row["hypothesis_set_id"])
        if set_id not in sets:
            raise ReviewQueueError(
                f"alternative {alternative_id!r} references missing set {set_id!r}"
            )
        row["details"] = _decode_object(
            row.pop("details_json"),
            field="match_hypothesis_alternatives.details_json",
        )
        claim_id = row["claim_id"]
        fold_id = row["xbox_fold_group_id"]
        if (claim_id is None) == (fold_id is None):
            raise ReviewQueueError(
                f"alternative {alternative_id!r} must select claim xor fold"
            )
        if claim_id is not None and str(claim_id) not in claims:
            raise ReviewQueueError(
                f"alternative {alternative_id!r} references missing claim {claim_id!r}"
            )
        alternatives[alternative_id] = row
        alternatives_by_set[set_id].append(alternative_id)

    folds: dict[str, dict[str, Any]] = {}
    for fold_id in referenced_folds:
        row, sample_rows, member_count = raw_folds[fold_id]
        row["details"] = _decode_object(
            row.pop("details_json"), field="fold_groups.details_json"
        )
        row["producer"] = (
            None
            if row["provenance_id"] is None
            else _with_provenance(provenance, row["provenance_id"])
        )
        sample: list[dict[str, Any]] = []
        for sample_row in sample_rows:
            function_id = str(sample_row["function_id"])
            if function_id not in functions:
                raise ReviewQueueError(
                    f"fold group {fold_id!r} references missing function "
                    f"{function_id!r}"
                )
            sample.append(
                {
                    "member_role": sample_row["member_role"],
                    "function": json.loads(json.dumps(functions[function_id])),
                }
            )
        row["member_count"] = member_count
        row["member_sample_limit"] = fold_sample_limit
        row["member_sample"] = sample
        row["member_sample_truncated"] = member_count > len(sample)
        folds[fold_id] = row

    set_evidence, alternative_evidence, claim_evidence = _load_evidence(
        connection,
        provenance,
        set_ids=loaded_set_ids,
        alternative_ids=sorted(alternatives),
        claim_ids=sorted(claims),
    )
    review_target_keys = {
        *(("hypothesis_set", target_id) for target_id in sets),
        *(("alternative", target_id) for target_id in alternatives),
        *(("claim", target_id) for target_id in claims),
    }
    return _LoadedReviewData(
        reviewer=reviewer,
        release=release,
        provenance=provenance,
        functions=functions,
        targets=targets,
        claims=claims,
        sets=sets,
        alternatives=alternatives,
        alternatives_by_set=alternatives_by_set,
        folds=folds,
        set_evidence=set_evidence,
        alternative_evidence=alternative_evidence,
        claim_evidence=claim_evidence,
        review_leaves=_load_review_leaves(connection, review_target_keys),
    )


def _independence_summary(
    evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in evidence:
        groups[str(item["independence_group"])].append(item)
    result = []
    for group in sorted(groups):
        rows = groups[group]
        result.append(
            {
                "independence_group": group,
                "evidence_count": len(rows),
                "evidence_references": sorted(
                    f"{row['scope']}:{row['evidence_id']}" for row in rows
                ),
                "literal_effects": sorted({str(row["effect"]) for row in rows}),
            }
        )
    return result


def _claim_document(data: _LoadedReviewData, claim_id: str) -> dict[str, Any]:
    claim = json.loads(json.dumps(data.claims[claim_id]))
    evidence = [dict(item) for item in data.claim_evidence.get(claim_id, ())]
    leaves = data.review_leaves.get(("claim", claim_id), ())
    claim["evidence"] = evidence
    claim["review"] = _review_block(
        leaves,
        reviewer_id=str(data.reviewer["reviewer_id"]),
        review_release_id=str(data.release["review_release_id"]),
    )
    return claim


def _alternative_document(
    data: _LoadedReviewData, alternative_id: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    row = json.loads(json.dumps(data.alternatives[alternative_id]))
    evidence = [
        dict(item) for item in data.alternative_evidence.get(alternative_id, ())
    ]
    claim_id = row.pop("claim_id")
    fold_id = row.pop("xbox_fold_group_id")
    if claim_id is not None:
        row["alternative_kind"] = "scalar_claim"
        row["claim"] = _claim_document(data, str(claim_id))
        nested_evidence = row["claim"]["evidence"]
    else:
        fold_key = str(fold_id)
        if fold_key not in data.folds:
            raise ReviewQueueError(
                f"alternative {alternative_id!r} references unloaded fold {fold_key!r}"
            )
        row["alternative_kind"] = "fold_bundle"
        row["fold_bundle"] = json.loads(json.dumps(data.folds[fold_key]))
        nested_evidence = []
    row["evidence"] = evidence
    row["review"] = _review_block(
        data.review_leaves.get(("alternative", alternative_id), ()),
        reviewer_id=str(data.reviewer["reviewer_id"]),
        review_release_id=str(data.release["review_release_id"]),
    )
    return row, evidence + nested_evidence


def _triage(
    *,
    item: Mapping[str, Any],
    all_evidence: Sequence[Mapping[str, Any]],
) -> tuple[str, dict[str, Any]]:
    alternatives = item["alternatives"]
    has_fold = any(alt["alternative_kind"] == "fold_bundle" for alt in alternatives)
    has_empty_fold = any(
        alt["alternative_kind"] == "fold_bundle"
        and alt["fold_bundle"]["member_count"] == 0
        for alt in alternatives
    )
    has_unresolved = item["pc_subject"]["endpoint_kind"] == "unresolved_target"
    for alternative in alternatives:
        if alternative["alternative_kind"] == "scalar_claim":
            claim = alternative["claim"]
            has_unresolved = has_unresolved or any(
                endpoint["endpoint_kind"] == "unresolved_target"
                for endpoint in (claim["pc_endpoint"], claim["xbox_endpoint"])
            )
    contradictory_count = sum(
        evidence["effect"] == "contradicts" for evidence in all_evidence
    )
    directional_count = sum(
        evidence["effect"] in {"supports", "contradicts"}
        for evidence in all_evidence
    )
    incomplete = not alternatives or directional_count == 0 or has_empty_fold
    ambiguous = len(alternatives) > 1
    exact_topology = (
        len(alternatives) == 1
        and alternatives[0]["alternative_kind"] == "scalar_claim"
        and not has_unresolved
    )
    if contradictory_count:
        bucket = "contradicted"
    elif incomplete:
        bucket = "incomplete"
    elif ambiguous:
        bucket = "ambiguous"
    elif has_fold:
        bucket = "fold"
    elif has_unresolved:
        bucket = "unresolved"
    else:
        bucket = "exact"
    flags = {
        "has_contradicting_evidence": bool(contradictory_count),
        "has_directional_evidence": bool(directional_count),
        "has_multiple_alternatives": ambiguous,
        "has_fold_bundle": has_fold,
        "has_empty_fold_bundle": has_empty_fold,
        "has_unresolved_endpoint": has_unresolved,
        "has_exact_scalar_topology": exact_topology,
        "alternative_count": len(alternatives),
        "evidence_count": len(all_evidence),
        "directional_evidence_count": directional_count,
        "contradicting_evidence_count": contradictory_count,
    }
    return bucket, flags


def _queue_items(data: _LoadedReviewData) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for set_id in sorted(data.sets):
        row = json.loads(json.dumps(data.sets[set_id]))
        set_evidence = [dict(item) for item in data.set_evidence.get(set_id, ())]
        alternatives: list[dict[str, Any]] = []
        all_evidence = list(set_evidence)
        for alternative_id in data.alternatives_by_set.get(set_id, ()):
            alternative, nested_evidence = _alternative_document(data, alternative_id)
            alternatives.append(alternative)
            all_evidence.extend(nested_evidence)
        row["evidence"] = set_evidence
        row["alternatives"] = alternatives
        row["independence_groups"] = _independence_summary(all_evidence)
        row["review"] = _review_block(
            data.review_leaves.get(("hypothesis_set", set_id), ()),
            reviewer_id=str(data.reviewer["reviewer_id"]),
            review_release_id=str(data.release["review_release_id"]),
        )
        bucket, flags = _triage(item=row, all_evidence=all_evidence)
        row["triage_bucket"] = bucket
        row["triage_flags"] = flags
        row["queue_key"] = [_TRIAGE_RANK[bucket], set_id]
        result.append(row)
    result.sort(key=lambda row: (row["queue_key"][0], row["queue_key"][1]))
    return result


_QUEUE_INDEX_SQL = """
WITH alternative_stats AS (
    SELECT h.hypothesis_set_id,
           COUNT(a.alternative_id) AS alternative_count,
           COALESCE(MAX(a.xbox_fold_group_id IS NOT NULL), 0) AS has_fold,
           COALESCE(MAX(
               CASE
                   WHEN a.xbox_fold_group_id IS NOT NULL AND NOT EXISTS (
                       SELECT 1 FROM fold_group_members member
                       WHERE member.fold_group_id = a.xbox_fold_group_id
                   ) THEN 1
                   ELSE 0
               END
           ), 0) AS has_empty_fold,
           MAX(
               h.pc_target_id IS NOT NULL OR
               c.pc_target_id IS NOT NULL OR
               c.xbox_target_id IS NOT NULL
           ) AS has_unresolved
    FROM match_hypothesis_sets h
    LEFT JOIN match_hypothesis_alternatives a USING (hypothesis_set_id)
    LEFT JOIN match_claims c USING (claim_id)
    GROUP BY h.hypothesis_set_id
), all_evidence AS (
    SELECT hypothesis_set_id, effect FROM match_hypothesis_evidence
    UNION ALL
    SELECT a.hypothesis_set_id, evidence.effect
    FROM match_hypothesis_alternative_evidence evidence
    JOIN match_hypothesis_alternatives a USING (alternative_id)
    UNION ALL
    SELECT a.hypothesis_set_id, evidence.effect
    FROM claim_evidence evidence
    JOIN match_hypothesis_alternatives a USING (claim_id)
), evidence_stats AS (
    SELECT hypothesis_set_id,
           COUNT(*) AS evidence_count,
           SUM(effect IN ('supports', 'contradicts')) AS directional_count,
           SUM(effect = 'contradicts') AS contradicting_count
    FROM all_evidence GROUP BY hypothesis_set_id
), classified AS (
    SELECT alternatives.hypothesis_set_id,
           alternatives.alternative_count,
           alternatives.has_fold,
           alternatives.has_empty_fold,
           alternatives.has_unresolved,
           COALESCE(evidence.evidence_count, 0) AS evidence_count,
           COALESCE(evidence.directional_count, 0) AS directional_count,
           COALESCE(evidence.contradicting_count, 0) AS contradicting_count,
           CASE
               WHEN COALESCE(evidence.contradicting_count, 0) > 0 THEN 0
               WHEN alternatives.alternative_count = 0
                 OR COALESCE(evidence.directional_count, 0) = 0
                 OR alternatives.has_empty_fold = 1 THEN 1
               WHEN alternatives.alternative_count > 1 THEN 2
               WHEN alternatives.has_fold = 1 THEN 3
               WHEN alternatives.has_unresolved = 1 THEN 4
               ELSE 5
           END AS triage_rank
    FROM alternative_stats alternatives
    LEFT JOIN evidence_stats evidence USING (hypothesis_set_id)
)
SELECT hypothesis_set_id, triage_rank, alternative_count, has_fold,
       has_empty_fold, has_unresolved, evidence_count, directional_count,
       contradicting_count
FROM classified ORDER BY triage_rank, hypothesis_set_id
"""


def _queue_index(
    connection: sqlite3.Connection,
    *,
    context: Mapping[str, Any],
    limit: int,
    after: str | None,
) -> tuple[list[list[Any]], dict[str, int], int, str, bool]:
    after_key: list[Any] | None = None
    after_queue_sha256: str | None = None
    if after is not None:
        cursor = _decode_cursor(after)
        after_queue_sha256 = cursor.get("queue_order_sha256")
        key = cursor.get("queue_key")
        if (
            not isinstance(after_queue_sha256, str)
            or not isinstance(key, list)
            or len(key) != 2
            or isinstance(key[0], bool)
            or not isinstance(key[0], int)
            or not isinstance(key[1], str)
            or key[0] not in range(len(TRIAGE_BUCKETS))
        ):
            raise ValueError("invalid review queue cursor payload")
        after_key = key

    digest = hashlib.sha256(canonical_json(context).encode("utf-8"))
    bucket_counts = {bucket: 0 for bucket in TRIAGE_BUCKETS}
    selected: list[list[Any]] = []
    total_count = 0
    matched_after = after_key is None
    has_more = False
    for row in connection.execute(_QUEUE_INDEX_SQL):
        set_id, rank = str(row[0]), int(row[1])
        key = [rank, set_id]
        digest.update(f"\0{rank}\0{set_id}".encode("utf-8"))
        total_count += 1
        bucket_counts[TRIAGE_BUCKETS[rank]] += 1
        if after_key is not None and key == after_key:
            matched_after = True
            continue
        if not matched_after:
            continue
        if len(selected) < limit:
            selected.append(key)
        else:
            has_more = True
    if not matched_after:
        raise ValueError("review queue cursor key is absent from current ordering")
    queue_order_sha256 = digest.hexdigest()
    if (
        after_queue_sha256 is not None
        and after_queue_sha256 != queue_order_sha256
    ):
        raise ValueError("review queue changed after this cursor was issued")
    return selected, bucket_counts, total_count, queue_order_sha256, has_more


def build_review_queue_page(
    database: str | Path | sqlite3.Connection,
    *,
    reviewer_id: str,
    review_release_id: str,
    limit: int = 100,
    after: str | None = None,
    fold_sample_limit: int = 8,
) -> ReviewQueuePage:
    """Load one bounded, standalone page from the SELECT-only review queue.

    ``exact`` describes an exact scalar endpoint shape, not truth or
    confidence.  The selected release changes only the explicit review-state
    projection; it never changes producer evidence or candidate status.
    """

    if not reviewer_id or not review_release_id:
        raise ValueError("reviewer_id and review_release_id are required")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= 1000
    ):
        raise ValueError("limit must be an integer from 1 through 1000")
    if (
        isinstance(fold_sample_limit, bool)
        or not isinstance(fold_sample_limit, int)
        or not 0 <= fold_sample_limit <= 100
    ):
        raise ValueError("fold_sample_limit must be an integer from 0 through 100")
    with _connect_read_only(database) as connection:
        _ensure_shape(connection)
        reviewer, release = _context(connection, reviewer_id, review_release_id)
        index_context = {
            "format": REVIEW_QUEUE_FORMAT,
            "triage_policy": list(TRIAGE_BUCKETS),
            "reviewer_id": reviewer_id,
            "review_release": release,
            "fold_sample_limit": fold_sample_limit,
        }
        keys, bucket_counts, total_count, queue_order_sha256, has_more = (
            _queue_index(
                connection,
                context=index_context,
                limit=limit,
                after=after,
            )
        )
        data = _load_data(
            connection,
            reviewer_id=reviewer_id,
            review_release_id=review_release_id,
            fold_sample_limit=fold_sample_limit,
            hypothesis_set_ids=[str(key[1]) for key in keys],
            include_all_claims=False,
        )
        items = _queue_items(data)
        if [item["queue_key"] for item in items] != keys:
            raise ReviewQueueError(
                "queue triage changed between index and page materialization"
            )
        next_cursor = None
        if has_more and items:
            next_cursor = _encode_cursor(
                {
                    "queue_order_sha256": queue_order_sha256,
                    "queue_key": items[-1]["queue_key"],
                }
            )
        payload = {
            "format": REVIEW_QUEUE_FORMAT + "/page",
            "policy": {
                "database_access": "select_only",
                "paging": "bounded_keyset_over_explicit_triage_order",
                "decision_scope": "literal_current_leaf_per_reviewer",
                "selected_release_state": (
                    "selected_reviewer_current_leaf_from_exact_selected_release"
                ),
                "consensus_inferred": False,
                "confidence_inferred": False,
                "fold_members_expanded": False,
                "exact_means": "one resolved scalar function-to-function topology",
                "triage_precedence": list(TRIAGE_BUCKETS),
            },
            "reviewer": data.reviewer,
            "review_release": data.release,
            "fold_sample_limit": fold_sample_limit,
            "limit": limit,
            "returned_count": len(items),
            "total_count": total_count,
            "queue_order_sha256": queue_order_sha256,
            "next_cursor": next_cursor,
            "counts": {
                "hypothesis_sets": total_count,
                "by_triage_bucket": bucket_counts,
            },
            "items": items,
        }
    payload_json = canonical_json(payload)
    return ReviewQueuePage(
        payload_json, hashlib.sha256(payload_json.encode()).hexdigest()
    )


def _snapshot_target(
    *,
    target_kind: str,
    target_id: str,
    producer_provenance_id: str,
    candidate: Mapping[str, Any],
    leaves: Sequence[Mapping[str, Any]],
    reviewer_id: str,
    review_release_id: str,
) -> dict[str, Any]:
    return {
        "target_kind": target_kind,
        "target_id": target_id,
        "producer_provenance_id": producer_provenance_id,
        "candidate": json.loads(json.dumps(candidate)),
        "selected_review": _selected_review(
            leaves,
            reviewer_id=reviewer_id,
            review_release_id=review_release_id,
        ),
    }


def _endpoint_reference(endpoint: Mapping[str, Any]) -> str:
    kind = str(endpoint["endpoint_kind"])
    if kind == "function":
        identity = str(endpoint["function_id"])
    elif kind == "unresolved_target":
        identity = str(endpoint["target_id"])
    else:
        raise ReviewQueueError(f"unsupported snapshot endpoint kind {kind!r}")
    return f"{kind}:{identity}"


def _snapshot_catalogs(data: _LoadedReviewData) -> dict[str, Any]:
    endpoints: dict[str, dict[str, Any]] = {}
    for endpoint in (*data.functions.values(), *data.targets.values()):
        reference = _endpoint_reference(endpoint)
        if reference in endpoints:
            raise ReviewQueueError(f"duplicate snapshot endpoint {reference!r}")
        endpoints[reference] = json.loads(json.dumps(endpoint))
    folds: dict[str, dict[str, Any]] = {}
    for fold_id in sorted(data.folds):
        fold = json.loads(json.dumps(data.folds[fold_id]))
        fold.pop("producer", None)
        for member in fold["member_sample"]:
            member["function_ref"] = _endpoint_reference(member.pop("function"))
        folds[fold_id] = fold
    return {
        "provenance": {
            key: json.loads(json.dumps(data.provenance[key]))
            for key in sorted(data.provenance)
        },
        "endpoints": {key: endpoints[key] for key in sorted(endpoints)},
        "fold_bundles": folds,
    }


def build_review_release_snapshot(
    database: str | Path | sqlite3.Connection,
    *,
    reviewer_id: str,
    review_release_id: str,
    fold_sample_limit: int = 8,
) -> ReviewReleaseSnapshot:
    """Freeze the full review-target universe and one reviewer's labels.

    Every scalar claim, hypothesis set, and hypothesis alternative is a
    separate evaluation unit.  A set decision is never copied to an alternative
    and an alternative decision is never copied to its scalar claim.
    """

    if not reviewer_id or not review_release_id:
        raise ValueError("reviewer_id and review_release_id are required")
    if (
        isinstance(fold_sample_limit, bool)
        or not isinstance(fold_sample_limit, int)
        or not 0 <= fold_sample_limit <= 100
    ):
        raise ValueError("fold_sample_limit must be an integer from 0 through 100")
    with _connect_read_only(database) as connection:
        _ensure_shape(connection)
        data = _load_data(
            connection,
            reviewer_id=reviewer_id,
            review_release_id=review_release_id,
            fold_sample_limit=fold_sample_limit,
            hypothesis_set_ids=None,
            include_all_claims=True,
        )
        targets: list[dict[str, Any]] = []
        for claim_id in sorted(data.claims):
            claim = data.claims[claim_id]
            candidate = {
                key: value
                for key, value in claim.items()
                if key not in {"producer", "pc_endpoint", "xbox_endpoint"}
            }
            candidate["pc_endpoint_ref"] = _endpoint_reference(claim["pc_endpoint"])
            candidate["xbox_endpoint_ref"] = _endpoint_reference(
                claim["xbox_endpoint"]
            )
            targets.append(
                _snapshot_target(
                    target_kind="claim",
                    target_id=claim_id,
                    producer_provenance_id=str(claim["provenance_id"]),
                    candidate=candidate,
                    leaves=data.review_leaves.get(("claim", claim_id), ()),
                    reviewer_id=reviewer_id,
                    review_release_id=review_release_id,
                )
            )
        for set_id in sorted(data.sets):
            hypothesis = data.sets[set_id]
            candidate = {
                key: value
                for key, value in hypothesis.items()
                if key not in {"producer", "pc_subject"}
            }
            candidate["pc_subject_ref"] = _endpoint_reference(
                hypothesis["pc_subject"]
            )
            targets.append(
                _snapshot_target(
                    target_kind="hypothesis_set",
                    target_id=set_id,
                    producer_provenance_id=str(hypothesis["provenance_id"]),
                    candidate=candidate,
                    leaves=data.review_leaves.get(("hypothesis_set", set_id), ()),
                    reviewer_id=reviewer_id,
                    review_release_id=review_release_id,
                )
            )
        for alternative_id in sorted(data.alternatives):
            alternative = data.alternatives[alternative_id]
            set_id = str(alternative["hypothesis_set_id"])
            producer_provenance_id = str(data.sets[set_id]["provenance_id"])
            claim_id = alternative["claim_id"]
            fold_id = alternative["xbox_fold_group_id"]
            if claim_id is not None:
                destination = {
                    "alternative_kind": "scalar_claim",
                    "claim_id": claim_id,
                    "claim_pc_endpoint_ref": _endpoint_reference(
                        data.claims[str(claim_id)]["pc_endpoint"]
                    ),
                    "claim_xbox_endpoint_ref": _endpoint_reference(
                        data.claims[str(claim_id)]["xbox_endpoint"]
                    ),
                }
            else:
                destination = {
                    "alternative_kind": "fold_bundle",
                    "fold_group_id": str(fold_id),
                }
            candidate = {
                "hypothesis_set_id": set_id,
                "details": alternative["details"],
                "created_at": alternative["created_at"],
                **destination,
            }
            targets.append(
                _snapshot_target(
                    target_kind="alternative",
                    target_id=alternative_id,
                    producer_provenance_id=producer_provenance_id,
                    candidate=candidate,
                    leaves=data.review_leaves.get(("alternative", alternative_id), ()),
                    reviewer_id=reviewer_id,
                    review_release_id=review_release_id,
                )
            )

        target_kind_order = {"claim": 0, "hypothesis_set": 1, "alternative": 2}
        targets.sort(
            key=lambda target: (
                target_kind_order[target["target_kind"]], target["target_id"]
            )
        )
        counts = {state: 0 for state in DECISION_STATES}
        by_kind: dict[str, dict[str, int]] = {
            kind: {state: 0 for state in DECISION_STATES}
            for kind in target_kind_order
        }
        for target in targets:
            state = target["selected_review"]["state"]
            counts[state] += 1
            by_kind[target["target_kind"]][state] += 1
        payload = {
            "format": REVIEW_SNAPSHOT_FORMAT,
            "policy": {
                "candidate_universe": (
                    "all_claims_sets_and_alternatives_in_loaded_database"
                ),
                "decision_scope": (
                    "current_leaf_for_named_reviewer_and_exact_selected_release"
                ),
                "cross_target_propagation": False,
                "consensus_inferred": False,
                "confidence_inferred": False,
                "missing_or_other_release_leaf_state": "open",
                "reopen_or_supersede_leaf_state": "open",
                "evaluation_units_are_distinct": [
                    "claim",
                    "hypothesis_set",
                    "alternative",
                ],
            },
            "reviewer": data.reviewer,
            "review_release": data.release,
            "fold_sample_limit": fold_sample_limit,
            "catalogs": _snapshot_catalogs(data),
            "counts": {
                "all_targets": {**counts, "total": len(targets)},
                "by_target_kind": {
                    kind: {
                        **by_kind[kind],
                        "total": sum(by_kind[kind].values()),
                    }
                    for kind in target_kind_order
                },
            },
            "targets": targets,
        }
    payload_json = canonical_json(payload)
    return ReviewReleaseSnapshot(
        payload_json, hashlib.sha256(payload_json.encode()).hexdigest()
    )


def evaluate_producers(snapshot: ReviewReleaseSnapshot) -> ProducerEvaluation:
    """Count snapshot labels per producer without calculating quality rates."""

    if not isinstance(snapshot, ReviewReleaseSnapshot):
        raise TypeError("evaluate_producers requires a ReviewReleaseSnapshot")
    document = snapshot.to_dict()
    grouped: dict[str, dict[str, Any]] = {}
    target_kinds = ("claim", "hypothesis_set", "alternative")
    provenance_catalog = document["catalogs"]["provenance"]
    for target in document["targets"]:
        provenance_id = str(target["producer_provenance_id"])
        if provenance_id not in provenance_catalog:
            raise ReviewQueueError(
                f"snapshot target references missing provenance {provenance_id!r}"
            )
        provenance = provenance_catalog[provenance_id]
        producer_name = str(provenance["producer"])
        if producer_name not in grouped:
            grouped[producer_name] = {
                "producer": producer_name,
                "producer_versions": set(),
                "provenance_ids": set(),
                "counts": {state: 0 for state in DECISION_STATES},
                "by_target_kind": {
                    kind: {state: 0 for state in DECISION_STATES}
                    for kind in target_kinds
                },
            }
        group = grouped[producer_name]
        if provenance["producer_version"] is not None:
            group["producer_versions"].add(str(provenance["producer_version"]))
        group["provenance_ids"].add(str(provenance["provenance_id"]))
        state = str(target["selected_review"]["state"])
        kind = str(target["target_kind"])
        if state not in DECISION_STATES or kind not in target_kinds:
            raise ReviewQueueError("snapshot contains an unsupported evaluation unit")
        group["counts"][state] += 1
        group["by_target_kind"][kind][state] += 1

    producers: list[dict[str, Any]] = []
    for producer_name in sorted(grouped):
        group = grouped[producer_name]
        counts = group["counts"]
        producers.append(
            {
                "producer": producer_name,
                "producer_versions": sorted(group["producer_versions"]),
                "provenance_ids": sorted(group["provenance_ids"]),
                "counts": {**counts, "total": sum(counts.values())},
                "by_target_kind": {
                    kind: {
                        **group["by_target_kind"][kind],
                        "total": sum(group["by_target_kind"][kind].values()),
                    }
                    for kind in target_kinds
                },
            }
        )
    payload = {
        "format": PRODUCER_EVALUATION_FORMAT,
        "policy": {
            "reference": "one_named_reviewer_release_snapshot",
            "metrics": "counts_only",
            "precision_calculated": False,
            "accuracy_calculated": False,
            "consensus_inferred": False,
            "unreviewed_state": "open",
            "target_kinds_are_not_combined_as_independent_accuracy_trials": True,
        },
        "snapshot_sha256": snapshot.snapshot_sha256,
        "reviewer": document["reviewer"],
        "review_release": document["review_release"],
        "producer_count": len(producers),
        "producers": producers,
    }
    payload_json = canonical_json(payload)
    return ProducerEvaluation(
        payload_json, hashlib.sha256(payload_json.encode()).hexdigest()
    )


__all__ = [
    "DECISION_STATES",
    "PRODUCER_EVALUATION_FORMAT",
    "REVIEW_QUEUE_FORMAT",
    "REVIEW_SNAPSHOT_FORMAT",
    "TRIAGE_BUCKETS",
    "ProducerEvaluation",
    "ReviewQueuePage",
    "ReviewQueueError",
    "ReviewReleaseSnapshot",
    "build_review_queue_page",
    "build_review_release_snapshot",
    "canonical_json",
    "evaluate_producers",
]
