"""Conservative, read-only consumer exports for human-reviewed mappings.

This module deliberately sits downstream of the atlas evidence model.  It does
not score candidates, infer consensus, update review state, or create functions
in a reverse-engineering database.  An executable export plan contains only
current leaf decisions where one caller-selected reviewer explicitly accepted
one scalar PC-function/Xbox-function mapping in one caller-selected release.

Candidate reporting is a separate artifact type.  Ghidra and IDAPython
renderers accept :class:`ExportPlan` only, which prevents an unreviewed report
from accidentally becoming an executable rename script.
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
import re
import sqlite3
from typing import Any


EXPORT_PLAN_FORMAT = "fnv-source-atlas-consumer-export-plan/v1"
CANDIDATE_REPORT_FORMAT = "fnv-source-atlas-candidate-report/v1"
SUPPORTED_PC_ADDRESS_SPACES = frozenset({"ram", "va"})


class ConsumerExportError(RuntimeError):
    """The database cannot safely produce the requested consumer artifact."""


@dataclass(frozen=True, slots=True)
class ExportPlan:
    """Reviewed actions and explicit blockers for one reviewer/release pair."""

    reviewer: Mapping[str, Any]
    review_release: Mapping[str, Any]
    manifest: Mapping[str, Any]
    pc_executable: Mapping[str, Any]
    actions: tuple[Mapping[str, Any], ...]
    blocked: tuple[Mapping[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "format": EXPORT_PLAN_FORMAT,
            "policy": {
                "decision_scope": "current_leaf_for_exact_reviewer_and_release",
                "required_action": "accept",
                "required_pc_endpoint": "exact_scalar_function",
                "required_xbox_endpoint": "exact_scalar_function",
                "consensus_inferred": False,
                "functions_created_by_scripts": False,
            },
            "reviewer": dict(self.reviewer),
            "review_release": dict(self.review_release),
            "manifest": dict(self.manifest),
            "pc_executable": dict(self.pc_executable),
            "counts": {
                "actions": len(self.actions),
                "blocked": len(self.blocked),
            },
            "actions": [dict(item) for item in self.actions],
            "blocked": [dict(item) for item in self.blocked],
        }
        result["plan_sha256"] = _document_digest(result)
        return result


@dataclass(frozen=True, slots=True)
class CandidateReport:
    """Non-executable inventory of producer candidates and review state."""

    reviewer: Mapping[str, Any]
    review_release: Mapping[str, Any]
    records: tuple[Mapping[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "format": CANDIDATE_REPORT_FORMAT,
            "executable": False,
            "notice": (
                "Candidate and review-state inventory only; this artifact is not "
                "accepted mapping input and cannot be rendered as a tool script."
            ),
            "reviewer": dict(self.reviewer),
            "review_release": dict(self.review_release),
            "counts": {"records": len(self.records)},
            "records": [dict(item) for item in self.records],
        }
        result["report_sha256"] = _document_digest(result)
        return result


def canonical_json(value: Mapping[str, Any]) -> str:
    """Return stable, strict, UTF-8-safe JSON without a trailing newline."""

    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def export_plan_json(plan: ExportPlan) -> str:
    """Serialize an executable export plan deterministically."""

    if not isinstance(plan, ExportPlan):
        raise TypeError("export_plan_json requires an ExportPlan")
    return canonical_json(plan.to_dict())


def candidate_report_json(report: CandidateReport) -> str:
    """Serialize a non-executable candidate report deterministically."""

    if not isinstance(report, CandidateReport):
        raise TypeError("candidate_report_json requires a CandidateReport")
    return canonical_json(report.to_dict())


def _document_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _decode_object(value: Any, *, field: str) -> dict[str, Any]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError) as exc:
        raise ConsumerExportError(f"{field} is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ConsumerExportError(f"{field} must contain a JSON object")
    return decoded


def _fetch_dicts(
    connection: sqlite3.Connection,
    sql: str,
    parameters: Sequence[Any] = (),
) -> list[dict[str, Any]]:
    cursor = connection.execute(sql, tuple(parameters))
    names = [str(item[0]) for item in cursor.description or ()]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def _fetch_one(
    connection: sqlite3.Connection,
    sql: str,
    parameters: Sequence[Any] = (),
    *,
    description: str,
) -> dict[str, Any]:
    rows = _fetch_dicts(connection, sql, parameters)
    if len(rows) != 1:
        raise ConsumerExportError(
            f"expected exactly one {description}; database returned {len(rows)}"
        )
    return rows[0]


@contextmanager
def _connect_read_only(
    database: str | Path | sqlite3.Connection,
) -> Iterator[sqlite3.Connection]:
    if isinstance(database, sqlite3.Connection):
        yield database
        return
    path = Path(database).resolve()
    if not path.is_file():
        raise ConsumerExportError(f"atlas database does not exist: {path}")
    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro",
        uri=True,
        isolation_level=None,
    )
    try:
        yield connection
    finally:
        connection.close()


def _ensure_atlas_shape(connection: sqlite3.Connection) -> None:
    required = {
        "address_groups",
        "current_review_decisions",
        "function_assertions",
        "function_name_assertions",
        "function_names",
        "functions",
        "input_artifacts",
        "input_manifests",
        "manifest_entries",
        "match_claims",
        "match_hypothesis_alternatives",
        "match_hypothesis_sets",
        "programs",
        "provenance",
        "review_releases",
        "reviewers",
    }
    rows = _fetch_dicts(
        connection,
        "SELECT name FROM sqlite_schema WHERE type IN ('table', 'view')",
    )
    present = {str(row["name"]) for row in rows}
    missing = sorted(required - present)
    if missing:
        raise ConsumerExportError(
            "database lacks required atlas relations: " + ", ".join(missing)
        )


def _review_context(
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


def _verified_pc_executable(
    connection: sqlite3.Connection,
    release: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest_id = release.get("manifest_id")
    if not manifest_id:
        raise ConsumerExportError(
            "the selected review release has no input manifest; a PC executable "
            "digest cannot be verified"
        )
    manifest = _fetch_one(
        connection,
        """
        SELECT manifest_id, digest, canonical_json
        FROM input_manifests WHERE manifest_id = ?
        """,
        (manifest_id,),
        description=f"input manifest {manifest_id!r}",
    )
    canonical = str(manifest["canonical_json"])
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if manifest["manifest_id"] != f"sha256:{digest}" or manifest["digest"] != digest:
        raise ConsumerExportError("the review release input manifest failed its digest check")
    try:
        document = json.loads(canonical)
    except ValueError as exc:
        raise ConsumerExportError("the review release manifest is invalid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
        raise ConsumerExportError("the review release manifest has no entries array")
    entry_rows = _fetch_dicts(
        connection,
        """
        SELECT e.ordinal, e.content_id, e.role, e.logical_name, e.metadata_json,
               a.hash_algorithm, a.digest, a.size_bytes, a.media_type
        FROM manifest_entries e
        JOIN input_artifacts a USING (content_id)
        WHERE e.manifest_id = ? ORDER BY e.ordinal
        """,
        (manifest_id,),
    )
    normalized = [
        {
            "content_id": row["content_id"],
            "role": row["role"],
            "logical_name": row["logical_name"],
            "metadata": _decode_object(
                row["metadata_json"], field="manifest_entries.metadata_json"
            ),
        }
        for row in entry_rows
    ]
    if normalized != document["entries"]:
        raise ConsumerExportError(
            "normalized manifest entries do not match the content-addressed manifest"
        )
    pc_rows = [row for row in entry_rows if row["role"] == "pc_executable"]
    if len(pc_rows) != 1:
        raise ConsumerExportError(
            "the selected manifest must contain exactly one pc_executable entry"
        )
    pc = pc_rows[0]
    if pc["hash_algorithm"] != "sha256" or pc["content_id"] != "sha256:" + str(
        pc["digest"]
    ):
        raise ConsumerExportError("the PC executable artifact identity is inconsistent")
    manifest_summary = {
        "manifest_id": manifest["manifest_id"],
        "digest": manifest["digest"],
    }
    executable = {
        "content_id": pc["content_id"],
        "sha256": pc["digest"],
        "size_bytes": pc["size_bytes"],
        "media_type": pc["media_type"],
        "logical_name": pc["logical_name"],
        "manifest_role": pc["role"],
        "manifest_ordinal": pc["ordinal"],
        "metadata": _decode_object(
            pc["metadata_json"], field="manifest_entries.metadata_json"
        ),
    }
    return manifest_summary, executable


def _accepted_leaf_rows(
    connection: sqlite3.Connection,
    reviewer_id: str,
    review_release_id: str,
) -> list[dict[str, Any]]:
    rows = _fetch_dicts(
        connection,
        """
        SELECT
            d.decision_id, d.target_kind, d.target_id,
            d.hypothesis_set_id AS decision_hypothesis_set_id,
            d.alternative_id AS decision_alternative_id,
            d.claim_id AS decision_claim_id,
            d.action, d.decided_at, d.rationale AS decision_rationale,
            d.provenance_id AS decision_provenance_id,
            d.previous_decision_id, d.details_json AS decision_details_json,

            a.hypothesis_set_id AS alternative_hypothesis_set_id,
            a.claim_id AS alternative_claim_id,
            a.xbox_fold_group_id, a.details_json AS alternative_details_json,

            h.pc_function_id AS set_pc_function_id,
            h.pc_target_id AS set_pc_target_id,
            h.status AS set_status, h.provenance_id AS set_provenance_id,
            h.identity_key AS set_identity_key, h.rationale AS set_rationale,
            h.details_json AS set_details_json,

            c.claim_id, c.pc_function_id, c.pc_target_id,
            c.xbox_function_id, c.xbox_target_id,
            c.status AS claim_status, c.confidence_label, c.confidence_value,
            c.provenance_id AS claim_provenance_id,
            c.rationale AS claim_rationale, c.details_json AS claim_details_json
        FROM current_review_decisions d
        LEFT JOIN match_hypothesis_alternatives a
          ON a.alternative_id = d.alternative_id
        LEFT JOIN match_hypothesis_sets h
          ON h.hypothesis_set_id = COALESCE(
              d.hypothesis_set_id, a.hypothesis_set_id
          )
        LEFT JOIN match_claims c
          ON c.claim_id = COALESCE(d.claim_id, a.claim_id)
        WHERE d.reviewer_id = ?
          AND d.review_release_id = ?
          AND d.action = 'accept'
        ORDER BY d.target_kind, d.target_id, d.decision_id
        """,
        (reviewer_id, review_release_id),
    )
    for row in rows:
        for prefix in ("decision", "alternative", "set", "claim"):
            key = prefix + "_details_json"
            raw = row.pop(key)
            row[prefix + "_details"] = (
                None if raw is None else _decode_object(raw, field=key)
            )
    return rows


def _lineage(
    row: Mapping[str, Any],
    reviewer: Mapping[str, Any],
    release: Mapping[str, Any],
) -> dict[str, Any]:
    alternative = None
    if row["decision_alternative_id"] is not None:
        alternative = {
            "alternative_id": row["decision_alternative_id"],
            "hypothesis_set_id": row["alternative_hypothesis_set_id"],
            "claim_id": row["alternative_claim_id"],
            "xbox_fold_group_id": row["xbox_fold_group_id"],
            "details": row["alternative_details"],
        }
    hypothesis_set = None
    set_id = row["decision_hypothesis_set_id"] or row[
        "alternative_hypothesis_set_id"
    ]
    if set_id is not None:
        hypothesis_set = {
            "hypothesis_set_id": set_id,
            "pc_function_id": row["set_pc_function_id"],
            "pc_target_id": row["set_pc_target_id"],
            "status": row["set_status"],
            "provenance_id": row["set_provenance_id"],
            "identity_key": row["set_identity_key"],
            "rationale": row["set_rationale"],
            "details": row["set_details"],
        }
    claim = None
    if row["claim_id"] is not None:
        claim = {
            "claim_id": row["claim_id"],
            "pc_function_id": row["pc_function_id"],
            "pc_target_id": row["pc_target_id"],
            "xbox_function_id": row["xbox_function_id"],
            "xbox_target_id": row["xbox_target_id"],
            "status": row["claim_status"],
            "confidence_label": row["confidence_label"],
            "confidence_value": row["confidence_value"],
            "provenance_id": row["claim_provenance_id"],
            "rationale": row["claim_rationale"],
            "details": row["claim_details"],
        }
    return {
        "decision": {
            "decision_id": row["decision_id"],
            "target_kind": row["target_kind"],
            "target_id": row["target_id"],
            "action": row["action"],
            "decided_at": row["decided_at"],
            "rationale": row["decision_rationale"],
            "provenance_id": row["decision_provenance_id"],
            "previous_decision_id": row["previous_decision_id"],
            "details": row["decision_details"],
        },
        "reviewer": dict(reviewer),
        "review_release": dict(release),
        "hypothesis_set": hypothesis_set,
        "alternative": alternative,
        "claim": claim,
    }


def _endpoint(
    connection: sqlite3.Connection,
    function_id: str,
) -> dict[str, Any] | None:
    rows = _fetch_dicts(
        connection,
        """
        SELECT f.function_id, f.program_id, f.address_group_id, f.identity_key,
               f.kind, f.type_index, f.module_id, f.symbol_record_kind,
               f.details_json, p.platform, p.name AS program_name,
               a.address_space, a.address, a.kind AS address_kind
        FROM functions f
        JOIN programs p USING (program_id)
        JOIN address_groups a USING (address_group_id, program_id)
        WHERE f.function_id = ?
        """,
        (function_id,),
    )
    if not rows:
        return None
    if len(rows) != 1:
        raise ConsumerExportError(f"function identity is not scalar: {function_id}")
    endpoint = rows[0]
    endpoint["details"] = _decode_object(
        endpoint.pop("details_json"), field="functions.details_json"
    )
    return endpoint


def _primary_names(
    connection: sqlite3.Connection,
    function_id: str,
) -> list[dict[str, Any]]:
    rows = _fetch_dicts(
        connection,
        """
        SELECT name_id, name, name_kind, is_primary, provenance_id, details_json
        FROM function_names
        WHERE function_id = ? AND is_primary = 1
        ORDER BY name, name_kind, name_id
        """,
        (function_id,),
    )
    for row in rows:
        row["details"] = _decode_object(
            row.pop("details_json"), field="function_names.details_json"
        )
    return rows


def _direct_provenance_component(
    connection: sqlite3.Connection,
    *,
    component_kind: str,
    entity_id: Any,
    provenance_id: Any,
    required_manifest_id: str,
) -> dict[str, Any]:
    rows = []
    if provenance_id is not None:
        rows = _fetch_dicts(
            connection,
            """
            SELECT provenance_id, manifest_id
            FROM provenance WHERE provenance_id = ?
            """,
            (provenance_id,),
        )
    observations = [
        {
            "provenance_id": row["provenance_id"],
            "manifest_id": row["manifest_id"],
        }
        for row in rows
    ]
    return {
        "component_kind": component_kind,
        "entity_id": entity_id,
        "lineage_model": "direct_provenance",
        "compatible": any(
            row["manifest_id"] == required_manifest_id for row in observations
        ),
        "observations": observations,
    }


def _function_provenance_component(
    connection: sqlite3.Connection,
    *,
    component_kind: str,
    function_id: str | None,
    required_manifest_id: str,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    if function_id is not None:
        rows = _fetch_dicts(
            connection,
            """
            SELECT a.assertion_id, a.provenance_id, p.manifest_id
            FROM function_assertions a
            JOIN provenance p USING (provenance_id)
            WHERE a.function_id = ?
            ORDER BY a.assertion_id
            """,
            (function_id,),
        )
    observations = [
        {
            "assertion_id": row["assertion_id"],
            "provenance_id": row["provenance_id"],
            "manifest_id": row["manifest_id"],
        }
        for row in rows
    ]
    return {
        "component_kind": component_kind,
        "entity_id": function_id,
        "lineage_model": "function_assertion",
        "compatible": any(
            row["manifest_id"] == required_manifest_id for row in observations
        ),
        "observations": observations,
    }


def _primary_name_provenance_component(
    connection: sqlite3.Connection,
    *,
    primary_names: Sequence[Mapping[str, Any]],
    raw_name: str,
    required_manifest_id: str,
) -> dict[str, Any]:
    name_ids = sorted(
        {
            int(row["name_id"])
            for row in primary_names
            if str(row["name"]) == raw_name
        }
    )
    observations: list[dict[str, Any]] = []
    for name_id in name_ids:
        rows = _fetch_dicts(
            connection,
            """
            SELECT a.assertion_id, a.name_id, a.provenance_id, p.manifest_id
            FROM function_name_assertions a
            JOIN provenance p USING (provenance_id)
            WHERE a.name_id = ? AND a.is_primary = 1
            ORDER BY a.assertion_id
            """,
            (name_id,),
        )
        observations.extend(
            {
                "assertion_id": row["assertion_id"],
                "name_id": row["name_id"],
                "provenance_id": row["provenance_id"],
                "manifest_id": row["manifest_id"],
            }
            for row in rows
        )
    return {
        "component_kind": "xbox_primary_name",
        "entity_id": raw_name,
        "name_ids": name_ids,
        "lineage_model": "primary_function_name_assertion",
        "compatible": any(
            row["manifest_id"] == required_manifest_id for row in observations
        ),
        "observations": observations,
    }


def _target_provenance_components(
    connection: sqlite3.Connection,
    row: Mapping[str, Any],
    *,
    required_manifest_id: str,
) -> list[dict[str, Any]]:
    target_kind = str(row["target_kind"])
    if target_kind == "claim":
        return [
            _direct_provenance_component(
                connection,
                component_kind="match_claim",
                entity_id=row["claim_id"],
                provenance_id=row["claim_provenance_id"],
                required_manifest_id=required_manifest_id,
            )
        ]
    if target_kind == "hypothesis_set":
        return [
            _direct_provenance_component(
                connection,
                component_kind="match_hypothesis_set",
                entity_id=row["decision_hypothesis_set_id"],
                provenance_id=row["set_provenance_id"],
                required_manifest_id=required_manifest_id,
            )
        ]
    if target_kind != "alternative":
        return [
            {
                "component_kind": "accepted_target",
                "entity_id": row["target_id"],
                "lineage_model": "unsupported_target_kind",
                "compatible": False,
                "observations": [],
            }
        ]

    backing = [
        _direct_provenance_component(
            connection,
            component_kind="match_hypothesis_set",
            entity_id=row["alternative_hypothesis_set_id"],
            provenance_id=row["set_provenance_id"],
            required_manifest_id=required_manifest_id,
        )
    ]
    if row["alternative_claim_id"] is not None:
        backing.append(
            _direct_provenance_component(
                connection,
                component_kind="match_claim",
                entity_id=row["alternative_claim_id"],
                provenance_id=row["claim_provenance_id"],
                required_manifest_id=required_manifest_id,
            )
        )
    elif row["xbox_fold_group_id"] is not None:
        fold_rows = _fetch_dicts(
            connection,
            "SELECT provenance_id FROM fold_groups WHERE fold_group_id = ?",
            (row["xbox_fold_group_id"],),
        )
        fold_provenance = (
            fold_rows[0]["provenance_id"] if len(fold_rows) == 1 else None
        )
        backing.append(
            _direct_provenance_component(
                connection,
                component_kind="xbox_fold_group",
                entity_id=row["xbox_fold_group_id"],
                provenance_id=fold_provenance,
                required_manifest_id=required_manifest_id,
            )
        )
    alternative = {
        "component_kind": "match_hypothesis_alternative",
        "entity_id": row["decision_alternative_id"],
        "lineage_model": "parent_set_and_selected_member",
        "compatible": bool(backing) and all(
            bool(component["compatible"]) for component in backing
        ),
        "observations": [],
    }
    return [*backing, alternative]


def _attach_manifest_compatibility(
    lineage: dict[str, Any],
    *,
    required_manifest_id: str,
    components: Sequence[Mapping[str, Any]],
) -> bool:
    compatible = bool(components) and all(
        bool(component["compatible"]) for component in components
    )
    lineage["manifest_compatibility"] = {
        "required_manifest_id": required_manifest_id,
        "compatible": compatible,
        "components": [dict(component) for component in components],
    }
    return compatible


def _portable_label(raw_name: str, *, identity: str) -> str:
    readable = re.sub(r"[^A-Za-z0-9_]", "_", raw_name)
    readable = re.sub(r"_+", "_", readable).strip("_")
    if not readable:
        readable = "symbol"
    if readable[0].isdigit():
        readable = "n_" + readable
    readable = readable[:160].rstrip("_") or "symbol"
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    return f"FNVX360_{readable}__{suffix}"


def _blocked(
    reasons: Sequence[str],
    message: str,
    lineage: Mapping[str, Any],
    *,
    pc_endpoint: Mapping[str, Any] | None = None,
    xbox_endpoint: Mapping[str, Any] | None = None,
    xbox_primary_names: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    reason_list = sorted(set(reasons))
    seed = {
        "decision_id": lineage["decision"]["decision_id"],
        "reasons": reason_list,
    }
    return {
        "block_id": "consumer-block:sha256:" + _document_digest(seed),
        "reasons": reason_list,
        "message": message,
        "pc_endpoint": None if pc_endpoint is None else dict(pc_endpoint),
        "xbox_endpoint": None if xbox_endpoint is None else dict(xbox_endpoint),
        "xbox_primary_names": [dict(item) for item in xbox_primary_names],
        "lineage": dict(lineage),
    }


def build_export_plan(
    database: str | Path | sqlite3.Connection,
    *,
    reviewer_id: str,
    review_release_id: str,
) -> ExportPlan:
    """Build a deterministic accepted-only export plan using SELECT statements.

    The selected release must carry a verified content-addressed input manifest
    with exactly one ``pc_executable`` entry.  Only current leaf ``accept``
    decisions whose own release is exactly ``review_release_id`` are examined.
    Other reviewers' decisions have no effect on the result.
    """

    if not reviewer_id or not review_release_id:
        raise ValueError("reviewer_id and review_release_id are required")
    with _connect_read_only(database) as connection:
        _ensure_atlas_shape(connection)
        reviewer, release = _review_context(
            connection, reviewer_id, review_release_id
        )
        manifest, pc_executable = _verified_pc_executable(connection, release)
        accepted = _accepted_leaf_rows(connection, reviewer_id, review_release_id)
        provisional: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []

        for row in accepted:
            lineage = _lineage(row, reviewer, release)
            required_manifest_id = str(release["manifest_id"])
            manifest_components = _target_provenance_components(
                connection,
                row,
                required_manifest_id=required_manifest_id,
            )
            if row["target_kind"] == "hypothesis_set":
                reasons = ["hypothesis_set_only_acceptance"]
                pc_endpoint = (
                    _endpoint(connection, row["set_pc_function_id"])
                    if row["set_pc_function_id"] is not None
                    else None
                )
                if row["set_pc_function_id"] is None:
                    reasons.append("pc_unresolved_endpoint")
                elif pc_endpoint is None:
                    reasons.append("missing_pc_function")
                manifest_components.append(
                    _function_provenance_component(
                        connection,
                        component_kind="pc_endpoint_function",
                        function_id=row["set_pc_function_id"],
                        required_manifest_id=required_manifest_id,
                    )
                )
                if not _attach_manifest_compatibility(
                    lineage,
                    required_manifest_id=required_manifest_id,
                    components=manifest_components,
                ):
                    reasons.append("provenance_manifest_mismatch")
                blocked.append(
                    _blocked(
                        reasons,
                        "Acceptance of a hypothesis set does not select any alternative.",
                        lineage,
                        pc_endpoint=pc_endpoint,
                    )
                )
                continue
            if row["target_kind"] == "alternative" and row["xbox_fold_group_id"]:
                reasons = ["xbox_fold_bundle"]
                pc_endpoint = (
                    _endpoint(connection, row["set_pc_function_id"])
                    if row["set_pc_function_id"] is not None
                    else None
                )
                if row["set_pc_function_id"] is None:
                    reasons.append("pc_unresolved_endpoint")
                elif pc_endpoint is None:
                    reasons.append("missing_pc_function")
                elif pc_endpoint["platform"] != "pc":
                    reasons.append("pc_endpoint_wrong_platform")
                elif pc_endpoint["address_space"] not in SUPPORTED_PC_ADDRESS_SPACES:
                    reasons.append("pc_address_space_not_runtime")
                manifest_components.append(
                    _function_provenance_component(
                        connection,
                        component_kind="pc_endpoint_function",
                        function_id=row["set_pc_function_id"],
                        required_manifest_id=required_manifest_id,
                    )
                )
                if not _attach_manifest_compatibility(
                    lineage,
                    required_manifest_id=required_manifest_id,
                    components=manifest_components,
                ):
                    reasons.append("provenance_manifest_mismatch")
                blocked.append(
                    _blocked(
                        reasons,
                        "A folded Xbox bundle is not one exact destination function.",
                        lineage,
                        pc_endpoint=pc_endpoint,
                    )
                )
                continue
            if row["claim_id"] is None:
                reasons = ["missing_scalar_claim"]
                if not _attach_manifest_compatibility(
                    lineage,
                    required_manifest_id=required_manifest_id,
                    components=manifest_components,
                ):
                    reasons.append("provenance_manifest_mismatch")
                blocked.append(
                    _blocked(
                        reasons,
                        "The accepted target does not resolve to a scalar match claim.",
                        lineage,
                    )
                )
                continue

            endpoint_reasons: list[str] = []
            if row["pc_function_id"] is None:
                endpoint_reasons.append("pc_unresolved_endpoint")
            if row["xbox_function_id"] is None:
                endpoint_reasons.append("xbox_unresolved_endpoint")
            pc_endpoint = (
                _endpoint(connection, row["pc_function_id"])
                if row["pc_function_id"] is not None
                else None
            )
            xbox_endpoint = (
                _endpoint(connection, row["xbox_function_id"])
                if row["xbox_function_id"] is not None
                else None
            )
            if row["pc_function_id"] is not None and pc_endpoint is None:
                endpoint_reasons.append("missing_pc_function")
            if row["xbox_function_id"] is not None and xbox_endpoint is None:
                endpoint_reasons.append("missing_xbox_function")
            if pc_endpoint is not None:
                if pc_endpoint["platform"] != "pc":
                    endpoint_reasons.append("pc_endpoint_wrong_platform")
                if pc_endpoint["address_space"] not in SUPPORTED_PC_ADDRESS_SPACES:
                    endpoint_reasons.append("pc_address_space_not_runtime")
            if xbox_endpoint is not None and xbox_endpoint["platform"] != "xbox360":
                endpoint_reasons.append("xbox_endpoint_wrong_platform")
            if (
                row["target_kind"] == "alternative"
                and row["set_pc_function_id"] != row["pc_function_id"]
            ):
                endpoint_reasons.append("alternative_pc_subject_mismatch")
            manifest_components.extend(
                (
                    _function_provenance_component(
                        connection,
                        component_kind="pc_endpoint_function",
                        function_id=row["pc_function_id"],
                        required_manifest_id=required_manifest_id,
                    ),
                    _function_provenance_component(
                        connection,
                        component_kind="xbox_endpoint_function",
                        function_id=row["xbox_function_id"],
                        required_manifest_id=required_manifest_id,
                    ),
                )
            )
            if endpoint_reasons:
                if not _attach_manifest_compatibility(
                    lineage,
                    required_manifest_id=required_manifest_id,
                    components=manifest_components,
                ):
                    endpoint_reasons.append("provenance_manifest_mismatch")
                blocked.append(
                    _blocked(
                        endpoint_reasons,
                        "The accepted claim does not have exact, compatible scalar endpoints.",
                        lineage,
                        pc_endpoint=pc_endpoint,
                        xbox_endpoint=xbox_endpoint,
                    )
                )
                continue
            assert pc_endpoint is not None and xbox_endpoint is not None
            primary_names = _primary_names(connection, xbox_endpoint["function_id"])
            unique_names = sorted({str(item["name"]) for item in primary_names})
            if not unique_names:
                reasons = ["missing_xbox_name"]
                if not _attach_manifest_compatibility(
                    lineage,
                    required_manifest_id=required_manifest_id,
                    components=manifest_components,
                ):
                    reasons.append("provenance_manifest_mismatch")
                blocked.append(
                    _blocked(
                        reasons,
                        "The exact Xbox function has no explicit primary name.",
                        lineage,
                        pc_endpoint=pc_endpoint,
                        xbox_endpoint=xbox_endpoint,
                    )
                )
                continue
            if len(unique_names) != 1:
                reasons = ["ambiguous_xbox_names"]
                if not _attach_manifest_compatibility(
                    lineage,
                    required_manifest_id=required_manifest_id,
                    components=manifest_components,
                ):
                    reasons.append("provenance_manifest_mismatch")
                blocked.append(
                    _blocked(
                        reasons,
                        "The exact Xbox function has more than one distinct primary name.",
                        lineage,
                        pc_endpoint=pc_endpoint,
                        xbox_endpoint=xbox_endpoint,
                        xbox_primary_names=primary_names,
                    )
                )
                continue
            raw_name = unique_names[0]
            manifest_components.append(
                _primary_name_provenance_component(
                    connection,
                    primary_names=primary_names,
                    raw_name=raw_name,
                    required_manifest_id=required_manifest_id,
                )
            )
            if not _attach_manifest_compatibility(
                lineage,
                required_manifest_id=required_manifest_id,
                components=manifest_components,
            ):
                blocked.append(
                    _blocked(
                        ["provenance_manifest_mismatch"],
                        (
                            "The accepted mapping is not fully backed by provenance "
                            "from the selected release manifest."
                        ),
                        lineage,
                        pc_endpoint=pc_endpoint,
                        xbox_endpoint=xbox_endpoint,
                        xbox_primary_names=primary_names,
                    )
                )
                continue
            provisional.append(
                {
                    "pc_endpoint": pc_endpoint,
                    "xbox_endpoint": xbox_endpoint,
                    "xbox_primary_name": raw_name,
                    "xbox_primary_name_records": primary_names,
                    "lineage": lineage,
                }
            )

        by_pc_entry: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
        for item in provisional:
            pc = item["pc_endpoint"]
            by_pc_entry[(pc["program_id"], pc["address_space"], pc["address"])].append(
                item
            )

        actions: list[dict[str, Any]] = []
        for entry_key in sorted(by_pc_entry):
            items = by_pc_entry[entry_key]
            destination_ids = {item["xbox_endpoint"]["function_id"] for item in items}
            destination_names = {item["xbox_primary_name"] for item in items}
            if len(destination_ids) > 1 or len(destination_names) > 1:
                reasons = []
                if len(destination_ids) > 1:
                    reasons.append("conflicting_accepted_destination")
                if len(destination_names) > 1:
                    reasons.append("conflicting_accepted_name")
                for item in items:
                    blocked.append(
                        _blocked(
                            reasons,
                            "Accepted decisions disagree at one physical PC entry.",
                            item["lineage"],
                            pc_endpoint=item["pc_endpoint"],
                            xbox_endpoint=item["xbox_endpoint"],
                            xbox_primary_names=item["xbox_primary_name_records"],
                        )
                    )
                continue

            first = sorted(
                items, key=lambda item: item["lineage"]["decision"]["decision_id"]
            )[0]
            lineages = sorted(
                (item["lineage"] for item in items),
                key=lambda item: item["decision"]["decision_id"],
            )
            pc_function_ids = sorted(
                {item["pc_endpoint"]["function_id"] for item in items}
            )
            raw_name = first["xbox_primary_name"]
            identity = "\0".join(
                (
                    entry_key[0],
                    entry_key[1],
                    str(entry_key[2]),
                    first["xbox_endpoint"]["function_id"],
                    raw_name,
                )
            )
            label = _portable_label(raw_name, identity=identity)
            decision_ids = [item["decision"]["decision_id"] for item in lineages]
            comment = canonical_json(
                {
                    "atlas": "accepted-human-review",
                    "decision_ids": decision_ids,
                    "raw_xbox_name": raw_name,
                    "review_release_id": review_release_id,
                    "reviewer_id": reviewer_id,
                    "xbox_address": first["xbox_endpoint"]["address"],
                    "xbox_function_id": first["xbox_endpoint"]["function_id"],
                }
            )
            action_seed = {
                "pc_program_id": entry_key[0],
                "pc_address_space": entry_key[1],
                "pc_address": entry_key[2],
                "xbox_function_id": first["xbox_endpoint"]["function_id"],
                "raw_xbox_name": raw_name,
                "decision_ids": decision_ids,
            }
            actions.append(
                {
                    "action_id": "consumer-action:sha256:"
                    + _document_digest(action_seed),
                    "operation": "rename_and_comment_existing_pc_function",
                    "pc_program_id": entry_key[0],
                    "pc_address_space": entry_key[1],
                    "pc_address": entry_key[2],
                    "pc_address_hex": f"0x{entry_key[2]:X}",
                    "pc_function_ids": pc_function_ids,
                    "xbox_function_id": first["xbox_endpoint"]["function_id"],
                    "xbox_address": first["xbox_endpoint"]["address"],
                    "xbox_address_space": first["xbox_endpoint"]["address_space"],
                    "xbox_primary_name": raw_name,
                    "xbox_primary_name_records": first[
                        "xbox_primary_name_records"
                    ],
                    "tool_label": label,
                    "tool_comment": comment,
                    "lineages": lineages,
                }
            )

        actions.sort(key=lambda item: (item["pc_address"], item["action_id"]))
        blocked.sort(key=lambda item: item["block_id"])
        return ExportPlan(
            reviewer=reviewer,
            review_release=release,
            manifest=manifest,
            pc_executable=pc_executable,
            actions=tuple(actions),
            blocked=tuple(blocked),
        )


def _current_state_by_target(
    connection: sqlite3.Connection,
    reviewer_id: str,
) -> dict[tuple[str, str], dict[str, Any]]:
    rows = _fetch_dicts(
        connection,
        """
        SELECT target_kind, target_id, decision_id, action, derived_status,
               decided_at, rationale, provenance_id, review_release_id,
               previous_decision_id, details_json
        FROM current_review_decisions
        WHERE reviewer_id = ?
        ORDER BY target_kind, target_id, decision_id
        """,
        (reviewer_id,),
    )
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        row["details"] = _decode_object(
            row.pop("details_json"), field="review_decisions.details_json"
        )
        key = (str(row["target_kind"]), str(row["target_id"]))
        if key in result:
            raise ConsumerExportError(
                "one reviewer has multiple current leaves for target " + repr(key)
            )
        result[key] = row
    return result


def build_candidate_report(
    database: str | Path | sqlite3.Connection,
    *,
    reviewer_id: str,
    review_release_id: str,
) -> CandidateReport:
    """Build a deterministic, explicitly non-executable candidate inventory."""

    if not reviewer_id or not review_release_id:
        raise ValueError("reviewer_id and review_release_id are required")
    with _connect_read_only(database) as connection:
        _ensure_atlas_shape(connection)
        reviewer, release = _review_context(
            connection, reviewer_id, review_release_id
        )
        states = _current_state_by_target(connection, reviewer_id)
        records: list[dict[str, Any]] = []

        claim_rows = _fetch_dicts(
            connection,
            """
            SELECT claim_id, pc_function_id, pc_target_id, xbox_function_id,
                   xbox_target_id, status, confidence_label, confidence_value,
                   provenance_id, rationale, details_json
            FROM match_claims ORDER BY claim_id
            """,
        )
        for row in claim_rows:
            row["details"] = _decode_object(
                row.pop("details_json"), field="match_claims.details_json"
            )
            target_id = str(row["claim_id"])
            records.append(
                {
                    "record_kind": "claim",
                    "target_id": target_id,
                    "producer_candidate": row,
                    "reviewer_current_leaf": states.get(("claim", target_id)),
                }
            )

        set_rows = _fetch_dicts(
            connection,
            """
            SELECT hypothesis_set_id, pc_function_id, pc_target_id, status,
                   provenance_id, identity_key, rationale, details_json
            FROM match_hypothesis_sets ORDER BY hypothesis_set_id
            """,
        )
        for row in set_rows:
            row["details"] = _decode_object(
                row.pop("details_json"), field="match_hypothesis_sets.details_json"
            )
            target_id = str(row["hypothesis_set_id"])
            records.append(
                {
                    "record_kind": "hypothesis_set",
                    "target_id": target_id,
                    "producer_candidate": row,
                    "reviewer_current_leaf": states.get(("hypothesis_set", target_id)),
                }
            )

        alternative_rows = _fetch_dicts(
            connection,
            """
            SELECT alternative_id, hypothesis_set_id, claim_id,
                   xbox_fold_group_id, details_json
            FROM match_hypothesis_alternatives ORDER BY alternative_id
            """,
        )
        for row in alternative_rows:
            row["details"] = _decode_object(
                row.pop("details_json"),
                field="match_hypothesis_alternatives.details_json",
            )
            target_id = str(row["alternative_id"])
            records.append(
                {
                    "record_kind": "alternative",
                    "target_id": target_id,
                    "producer_candidate": row,
                    "reviewer_current_leaf": states.get(("alternative", target_id)),
                }
            )

        records.sort(key=lambda item: (item["record_kind"], item["target_id"]))
        return CandidateReport(
            reviewer=reviewer,
            review_release=release,
            records=tuple(records),
        )


def _script_payload(plan: ExportPlan) -> tuple[str, str, dict[str, Any]]:
    if not isinstance(plan, ExportPlan):
        raise TypeError("tool scripts can be rendered only from an ExportPlan")
    document = plan.to_dict()
    if document["format"] != EXPORT_PLAN_FORMAT:
        raise ConsumerExportError("unsupported export plan format")
    digest = str(document["plan_sha256"])
    payload = {
        "format": EXPORT_PLAN_FORMAT,
        "plan_sha256": digest,
        "pc_executable_sha256": document["pc_executable"]["sha256"],
        "reviewer_id": document["reviewer"]["reviewer_id"],
        "review_release_id": document["review_release"]["review_release_id"],
        "actions": [
            {
                key: action[key]
                for key in (
                    "action_id",
                    "pc_address",
                    "pc_address_hex",
                    "tool_label",
                    "tool_comment",
                )
            }
            for action in document["actions"]
        ],
    }
    payload_bytes = canonical_json(payload).encode("utf-8")
    payload_digest = hashlib.sha256(payload_bytes).hexdigest()
    encoded = base64.b64encode(payload_bytes).decode("ascii")
    return encoded, payload_digest, document


def render_ghidra_script(plan: ExportPlan) -> str:
    """Render an accepted-only Ghidra Python script.

    The script aborts before mutation if the imported executable's SHA-256 does
    not match the release manifest.  It requires ``getFunctionAt`` to return a
    function at the exact PC entry and never calls a function-creation API.
    """

    encoded, payload_digest, document = _script_payload(plan)
    return f'''# FNV Source Atlas accepted-only Ghidra consumer export
# Plan SHA-256: {document["plan_sha256"]}
# Reviewer: {document["reviewer"]["reviewer_id"]}
# Review release: {document["review_release"]["review_release_id"]}
# No consensus is inferred. This script never creates functions.

from ghidra.program.model.symbol import SourceType
import base64
import hashlib
import json

PAYLOAD_BYTES = base64.b64decode("{encoded}")
if hashlib.sha256(PAYLOAD_BYTES).hexdigest() != "{payload_digest}":
    raise RuntimeError("Atlas export: embedded action payload failed its digest check")
PAYLOAD = json.loads(PAYLOAD_BYTES.decode("utf-8"))

def _sha256_file(path):
    digest = hashlib.sha256()
    handle = open(path, "rb")
    try:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        handle.close()
    return digest.hexdigest()

input_path = currentProgram.getExecutablePath()
if not input_path:
    raise RuntimeError("Atlas export: Ghidra program has no executable path")
actual_digest = _sha256_file(input_path)
if actual_digest.lower() != PAYLOAD["pc_executable_sha256"].lower():
    raise RuntimeError("Atlas export: PC executable SHA-256 mismatch; no actions applied")

applied = 0
skipped = 0
for action in PAYLOAD["actions"]:
    try:
        address = toAddr(action["pc_address"])
        function = getFunctionAt(address)
        if function is None or function.getEntryPoint() != address:
            print("SKIP %s: no existing function exactly at %s" % (
                action["action_id"], action["pc_address_hex"]))
            skipped += 1
            continue
        function.setName(action["tool_label"], SourceType.USER_DEFINED)
        try:
            function.setComment(action["tool_comment"])
        except Exception as comment_error:
            print("WARN %s: label applied but function comment failed: %s" % (
                action["action_id"], comment_error))
        print("APPLY %s at %s as %s" % (
            action["action_id"], action["pc_address_hex"], action["tool_label"]))
        applied += 1
    except Exception as error:
        print("SKIP %s: %s" % (action["action_id"], error))
        skipped += 1

print("Atlas export complete: %d applied, %d skipped" % (applied, skipped))
'''


def render_idapython_script(plan: ExportPlan) -> str:
    """Render an accepted-only IDAPython script with exact-entry guards."""

    encoded, payload_digest, document = _script_payload(plan)
    return f'''# FNV Source Atlas accepted-only IDAPython consumer export
# Plan SHA-256: {document["plan_sha256"]}
# Reviewer: {document["reviewer"]["reviewer_id"]}
# Review release: {document["review_release"]["review_release_id"]}
# No consensus is inferred. This script never creates functions.

import base64
import hashlib
import json
import ida_funcs
import ida_name
import ida_nalt

PAYLOAD_BYTES = base64.b64decode("{encoded}")
if hashlib.sha256(PAYLOAD_BYTES).hexdigest() != "{payload_digest}":
    raise RuntimeError("Atlas export: embedded action payload failed its digest check")
PAYLOAD = json.loads(PAYLOAD_BYTES.decode("utf-8"))

def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()

input_path = ida_nalt.get_input_file_path()
if not input_path:
    raise RuntimeError("Atlas export: IDA database has no input file path")
actual_digest = _sha256_file(input_path)
if actual_digest.lower() != PAYLOAD["pc_executable_sha256"].lower():
    raise RuntimeError("Atlas export: PC executable SHA-256 mismatch; no actions applied")

applied = 0
skipped = 0
for action in PAYLOAD["actions"]:
    try:
        address = int(action["pc_address"])
        function = ida_funcs.get_func(address)
        if function is None or int(function.start_ea) != address:
            print("SKIP %s: no existing function exactly at %s" % (
                action["action_id"], action["pc_address_hex"]))
            skipped += 1
            continue
        if not ida_name.set_name(address, action["tool_label"], ida_name.SN_CHECK):
            print("SKIP %s: IDA rejected label %s" % (
                action["action_id"], action["tool_label"]))
            skipped += 1
            continue
        if not ida_funcs.set_func_cmt(function, action["tool_comment"], False):
            print("WARN %s: label applied but function comment was rejected" % (
                action["action_id"],))
        print("APPLY %s at %s as %s" % (
            action["action_id"], action["pc_address_hex"], action["tool_label"]))
        applied += 1
    except Exception as error:
        print("SKIP %s: %s" % (action["action_id"], error))
        skipped += 1

print("Atlas export complete: %d applied, %d skipped" % (applied, skipped))
'''
