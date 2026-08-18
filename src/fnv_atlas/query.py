"""Read-only, ambiguity-preserving queries for source-atlas researchers.

The database API intentionally focuses on safe writes and identity invariants.
This module is the complementary read side: it composes physical PDB records,
logical functions, fold bundles, vtables, and hypothesis evidence into stable
JSON-compatible documents suitable for mod authors and research tooling.

Every public method issues SELECT statements only.  Potentially plural results
carry paging metadata, and ambiguity is reported explicitly instead of choosing
the first name, function, address, fold member, or hypothesis alternative.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Iterable, Mapping, Sequence


DEFAULT_LIMIT = 50
MAX_LIMIT = 1000


class QueryError(ValueError):
    """A query argument is invalid or cannot be represented safely."""


def parse_query_address(value: int | str) -> int:
    """Parse a non-negative decimal integer or ``0x``-prefixed hex address."""

    if isinstance(value, bool):
        raise QueryError("an address cannot be boolean")
    if isinstance(value, int):
        address = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise QueryError("an address cannot be empty")
        try:
            if text.lower().startswith("0x"):
                address = int(text, 16)
            elif re.fullmatch(r"[0-9]+", text):
                address = int(text, 10)
            else:
                raise ValueError
        except ValueError as exc:
            raise QueryError(
                f"invalid address {value!r}; use decimal or 0x-prefixed hex"
            ) from exc
    else:
        raise QueryError(
            f"address must be an integer or string, got {type(value).__name__}"
        )
    if address < 0:
        raise QueryError("an address cannot be negative")
    return address


def _paging(limit: int, offset: int, total: int, returned: int) -> dict[str, Any]:
    return {
        "limit": limit,
        "offset": offset,
        "returned": returned,
        "total": total,
        "has_more": offset + returned < total,
        "next_offset": offset + returned if offset + returned < total else None,
    }


def _validate_page(limit: int, offset: int) -> tuple[int, int]:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise QueryError("limit must be an integer")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise QueryError("offset must be an integer")
    if not 1 <= limit <= MAX_LIMIT:
        raise QueryError(f"limit must be between 1 and {MAX_LIMIT}")
    if offset < 0:
        raise QueryError("offset cannot be negative")
    return limit, offset


def _decode_json(value: object) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        # A schema-valid atlas should never reach this branch.  Retaining the
        # raw value still makes a damaged research database inspectable.
        return {"_invalid_json": value}


def _hex(address: int | None) -> str | None:
    return None if address is None else f"0x{address:08X}"


def _ambiguity(*reasons: str) -> dict[str, Any]:
    normalized = sorted({reason for reason in reasons if reason})
    return {"is_ambiguous": bool(normalized), "reasons": normalized}


class AtlasQuery:
    """Compose stable read-only views over one validated atlas connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self._relations = frozenset(
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type IN ('table', 'view')"
            )
        )

    def _rows(
        self, sql: str, parameters: Sequence[object] = ()
    ) -> list[dict[str, Any]]:
        cursor = self.connection.execute(sql, tuple(parameters))
        columns = tuple(item[0] for item in cursor.description or ())
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def _one(
        self, sql: str, parameters: Sequence[object] = ()
    ) -> dict[str, Any] | None:
        rows = self._rows(sql, parameters)
        return rows[0] if rows else None

    def _scalar(
        self, sql: str, parameters: Sequence[object] = ()
    ) -> int:
        row = self.connection.execute(sql, tuple(parameters)).fetchone()
        return 0 if row is None else int(row[0])

    @staticmethod
    def _placeholders(values: Sequence[object]) -> str:
        if not values:
            raise QueryError("an internal query received an empty identity set")
        return ",".join("?" for _ in values)

    def _names(self, function_id: str) -> list[dict[str, Any]]:
        rows = self._rows(
            """
            SELECT name, name_kind, is_primary, provenance_id, details_json
            FROM function_names WHERE function_id = ?
            ORDER BY is_primary DESC, name_kind, name
            """,
            (function_id,),
        )
        for row in rows:
            row["is_primary"] = bool(row["is_primary"])
            row["details"] = _decode_json(row.pop("details_json"))
        return rows

    def _function_brief(self, function_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT f.function_id, f.program_id, p.platform, f.identity_key,
                   f.kind, f.type_index, f.symbol_record_kind, f.module_id,
                   m.name AS module_name, ag.address_group_id,
                   ag.address_space, ag.address, f.details_json
            FROM functions f
            JOIN programs p USING (program_id)
            JOIN address_groups ag USING (address_group_id, program_id)
            LEFT JOIN modules m USING (module_id, program_id)
            WHERE f.function_id = ?
            """,
            (function_id,),
        )
        if row is None:
            return None
        row["address_hex"] = _hex(int(row["address"]))
        row["details"] = _decode_json(row.pop("details_json"))
        row["names"] = self._names(function_id)
        return row

    def _signature(self, function_id: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT * FROM function_signatures WHERE function_id = ?",
            (function_id,),
        )
        if row is None:
            return None
        row["is_variadic"] = (
            None if row["is_variadic"] is None else bool(row["is_variadic"])
        )
        row["details"] = _decode_json(row.pop("details_json"))
        arguments = self._rows(
            """
            SELECT position, type_index, is_vararg_marker, rendered_type,
                   details_json
            FROM function_signature_arguments
            WHERE function_id = ? ORDER BY position
            """,
            (function_id,),
        )
        for argument in arguments:
            argument["is_vararg_marker"] = bool(argument["is_vararg_marker"])
            argument["details"] = _decode_json(argument.pop("details_json"))
        row["arguments"] = arguments
        return row

    def _sources(self, function_id: str) -> list[dict[str, Any]]:
        rows = self._rows(
            """
            SELECT r.source_file_id, s.normalized_path, s.language,
                   r.line_start, r.line_end, r.column_start, r.column_end,
                   r.is_primary, r.provenance_id, r.details_json
            FROM function_source_ranges r
            JOIN source_files s USING (source_file_id, program_id)
            WHERE r.function_id = ?
            ORDER BY r.is_primary DESC, s.normalized_path,
                     r.line_start, r.column_start
            """,
            (function_id,),
        )
        for row in rows:
            row["is_primary"] = bool(row["is_primary"])
            row["details"] = _decode_json(row.pop("details_json"))
        return rows

    def _fold_groups_for_function(
        self, function_id: str, *, member_limit: int = DEFAULT_LIMIT
    ) -> list[dict[str, Any]]:
        ids = [
            str(row["fold_group_id"])
            for row in self._rows(
                """
                SELECT fold_group_id FROM fold_group_members
                WHERE function_id = ? ORDER BY fold_group_id
                """,
                (function_id,),
            )
        ]
        return [self._fold_group(group_id, member_limit=member_limit) for group_id in ids]

    def _review_decisions(
        self, target_kind: str, target_id: str
    ) -> list[dict[str, Any]]:
        # Review history is additive in schema v5.  Keeping the pure query
        # object tolerant of a v4 connection is useful for read-only migration
        # audits; the CLI still validates the database's exact current schema.
        if "current_review_decisions" not in self._relations:
            return []
        rows = self._rows(
            """
            SELECT d.decision_id, d.target_kind, d.target_id, d.reviewer_id,
                   r.display_name AS reviewer_name, r.affiliation,
                   d.action, d.derived_status, d.decided_at, d.rationale,
                   d.review_release_id, rel.label AS release_label,
                   rel.version AS release_version, d.provenance_id,
                   d.previous_decision_id, d.details_json
            FROM current_review_decisions d
            JOIN reviewers r USING (reviewer_id)
            JOIN review_releases rel USING (review_release_id)
            WHERE d.target_kind = ? AND d.target_id = ?
            ORDER BY r.display_name, d.reviewer_id, d.decision_id
            """,
            (target_kind, target_id),
        )
        for row in rows:
            row["details"] = _decode_json(row.pop("details_json"))
        return rows

    def _function_record(
        self, function_id: str, *, member_limit: int = DEFAULT_LIMIT
    ) -> dict[str, Any] | None:
        result = self._function_brief(function_id)
        if result is None:
            return None
        result["sources"] = self._sources(function_id)
        result["signature"] = self._signature(function_id)
        result["fold_groups"] = self._fold_groups_for_function(
            function_id, member_limit=member_limit
        )
        return result

    def _target(self, target_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT u.target_id, u.program_id, p.platform, u.target_kind,
                   u.name_hint, u.reason, u.status, u.resolved_function_id,
                   u.provenance_id, u.address_group_id, ag.address_space,
                   ag.address, u.details_json
            FROM unresolved_targets u
            JOIN programs p USING (program_id)
            LEFT JOIN address_groups ag USING (address_group_id, program_id)
            WHERE u.target_id = ?
            """,
            (target_id,),
        )
        if row is None:
            return None
        row["address_hex"] = _hex(
            None if row["address"] is None else int(row["address"])
        )
        row["details"] = _decode_json(row.pop("details_json"))
        return row

    def _fold_group(
        self,
        fold_group_id: str,
        *,
        member_limit: int = DEFAULT_LIMIT,
        member_offset: int = 0,
    ) -> dict[str, Any]:
        member_limit, member_offset = _validate_page(member_limit, member_offset)
        group = self._one(
            """
            SELECT g.fold_group_id, g.program_id, p.platform, g.kind,
                   g.provenance_id, g.details_json
            FROM fold_groups g JOIN programs p USING (program_id)
            WHERE g.fold_group_id = ?
            """,
            (fold_group_id,),
        )
        if group is None:
            return {
                "fold_group_id": fold_group_id,
                "missing": True,
                "members": [],
                "members_page": _paging(member_limit, member_offset, 0, 0),
            }
        group["details"] = _decode_json(group.pop("details_json"))
        total = self._scalar(
            "SELECT COUNT(*) FROM fold_group_members WHERE fold_group_id = ?",
            (fold_group_id,),
        )
        member_rows = self._rows(
            """
            SELECT function_id, member_role FROM fold_group_members
            WHERE fold_group_id = ? ORDER BY function_id LIMIT ? OFFSET ?
            """,
            (fold_group_id, member_limit, member_offset),
        )
        members = []
        for member in member_rows:
            record = self._function_brief(str(member["function_id"]))
            if record is not None:
                record["member_role"] = member["member_role"]
                members.append(record)
        group["member_count"] = total
        group["members"] = members
        group["members_page"] = _paging(
            member_limit, member_offset, total, len(members)
        )
        group["ambiguity"] = _ambiguity(
            "multiple_logical_functions_share_one_address" if total > 1 else ""
        )
        return group

    def _claim(self, claim_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT c.*, p.producer, p.method
            FROM match_claims c JOIN provenance p USING (provenance_id)
            WHERE c.claim_id = ?
            """,
            (claim_id,),
        )
        if row is None:
            return None
        row["details"] = _decode_json(row.pop("details_json"))
        row["pc_endpoint"] = (
            self._function_brief(str(row["pc_function_id"]))
            if row["pc_function_id"] is not None
            else self._target(str(row["pc_target_id"]))
        )
        row["xbox_endpoint"] = (
            self._function_brief(str(row["xbox_function_id"]))
            if row["xbox_function_id"] is not None
            else self._target(str(row["xbox_target_id"]))
        )
        evidence = self._rows(
            """
            SELECT evidence_id, effect, evidence_kind, independence_group,
                   asserted_strength, provenance_id, details_json
            FROM claim_evidence WHERE claim_id = ?
            ORDER BY independence_group, evidence_kind, evidence_id
            """,
            (claim_id,),
        )
        for item in evidence:
            item["details"] = _decode_json(item.pop("details_json"))
        row["evidence"] = evidence
        row["current_review_decisions"] = self._review_decisions(
            "claim", claim_id
        )
        return row

    def _hypothesis_set(
        self, hypothesis_set_id: str, *, fold_member_limit: int = DEFAULT_LIMIT
    ) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT h.*, p.producer, p.method
            FROM match_hypothesis_sets h JOIN provenance p USING (provenance_id)
            WHERE h.hypothesis_set_id = ?
            """,
            (hypothesis_set_id,),
        )
        if row is None:
            return None
        row["details"] = _decode_json(row.pop("details_json"))
        row["pc_subject"] = (
            self._function_brief(str(row["pc_function_id"]))
            if row["pc_function_id"] is not None
            else self._target(str(row["pc_target_id"]))
        )
        alternatives = self._rows(
            """
            SELECT alternative_id, claim_id, xbox_fold_group_id, details_json
            FROM match_hypothesis_alternatives
            WHERE hypothesis_set_id = ? ORDER BY alternative_id
            """,
            (hypothesis_set_id,),
        )
        ambiguity_reasons: list[str] = []
        if len(alternatives) > 1:
            ambiguity_reasons.append("multiple_viable_alternatives")
        normalized_alternatives: list[dict[str, Any]] = []
        for alternative in alternatives:
            alternative["details"] = _decode_json(
                alternative.pop("details_json")
            )
            if alternative["claim_id"] is not None:
                alternative["alternative_kind"] = "scalar_claim"
                alternative["claim"] = self._claim(str(alternative["claim_id"]))
            else:
                alternative["alternative_kind"] = "fold_group_bundle"
                alternative["fold_group"] = self._fold_group(
                    str(alternative["xbox_fold_group_id"]),
                    member_limit=fold_member_limit,
                )
                ambiguity_reasons.append("xbox_fold_group_bundle")
            alternative["current_review_decisions"] = self._review_decisions(
                "alternative", str(alternative["alternative_id"])
            )
            normalized_alternatives.append(alternative)
        evidence = self._rows(
            """
            SELECT e.evidence_id, e.effect, e.evidence_kind,
                   e.independence_group, e.asserted_strength, e.provenance_id,
                   p.producer, e.details_json
            FROM match_hypothesis_evidence e
            JOIN provenance p USING (provenance_id)
            WHERE e.hypothesis_set_id = ?
            ORDER BY e.independence_group, e.evidence_kind, e.evidence_id
            """,
            (hypothesis_set_id,),
        )
        for item in evidence:
            item["details"] = _decode_json(item.pop("details_json"))
        row["alternative_count"] = len(normalized_alternatives)
        row["alternatives"] = normalized_alternatives
        row["evidence"] = evidence
        row["current_review_decisions"] = self._review_decisions(
            "hypothesis_set", hypothesis_set_id
        )
        if row["status"] == "conflicted":
            ambiguity_reasons.append("hypothesis_status_conflicted")
        row["ambiguity"] = _ambiguity(*ambiguity_reasons)
        return row

    def _hypothesis_page(
        self,
        ids_sql: str,
        parameters: Sequence[object],
        *,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        limit, offset = _validate_page(limit, offset)
        total = self._scalar(f"SELECT COUNT(*) FROM ({ids_sql})", parameters)
        id_rows = self._rows(
            f"SELECT hypothesis_set_id FROM ({ids_sql}) "
            "ORDER BY hypothesis_set_id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        )
        items = [
            item
            for item in (
                self._hypothesis_set(str(row["hypothesis_set_id"]), fold_member_limit=limit)
                for row in id_rows
            )
            if item is not None
        ]
        return {
            "items": items,
            "page": _paging(limit, offset, total, len(items)),
        }

    def _vtable_slots_targeting(
        self, group_ids: Sequence[str]
    ) -> list[dict[str, Any]]:
        if not group_ids:
            return []
        placeholders = self._placeholders(group_ids)
        rows = self._rows(
            f"""
            SELECT s.vtable_id, s.slot_index, v.address_space AS table_address_space,
                   v.address AS table_address, v.vfptr_role, v.subobject_offset,
                   v.class_id, p.platform, s.details_json
            FROM vtable_slots s
            JOIN vtables v USING (vtable_id, program_id)
            JOIN programs p USING (program_id)
            WHERE s.target_address_group_id IN ({placeholders})
            ORDER BY p.platform, v.vtable_id, s.slot_index
            """,
            tuple(group_ids),
        )
        for row in rows:
            row["table_address_hex"] = _hex(int(row["table_address"]))
            row["details"] = _decode_json(row.pop("details_json"))
            row["class_names"] = self._class_names(str(row["class_id"]))
        return rows

    def _class_names(self, class_id: str) -> list[dict[str, Any]]:
        rows = self._rows(
            """
            SELECT name, name_kind, is_primary FROM class_names
            WHERE class_id = ? ORDER BY is_primary DESC, name_kind, name
            """,
            (class_id,),
        )
        for row in rows:
            row["is_primary"] = bool(row["is_primary"])
        return rows

    def pc_address(
        self,
        address: int | str,
        *,
        address_space: str = "ram",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Describe all PC identities and mapping evidence at one address."""

        address = parse_query_address(address)
        limit, offset = _validate_page(limit, offset)
        groups = self._rows(
            """
            SELECT ag.address_group_id, ag.program_id, p.name AS program_name,
                   ag.address_space, ag.address, ag.kind, ag.details_json
            FROM address_groups ag JOIN programs p USING (program_id)
            WHERE p.platform = 'pc' AND ag.address_space = ? AND ag.address = ?
            ORDER BY ag.program_id, ag.address_group_id
            """,
            (address_space, address),
        )
        for group in groups:
            group["address_hex"] = _hex(int(group["address"]))
            group["details"] = _decode_json(group.pop("details_json"))
        group_ids = [str(group["address_group_id"]) for group in groups]

        functions: list[dict[str, Any]] = []
        function_ids: list[str] = []
        all_function_ids: list[str] = []
        total_functions = 0
        if group_ids:
            placeholders = self._placeholders(group_ids)
            total_functions = self._scalar(
                f"SELECT COUNT(*) FROM functions WHERE address_group_id IN ({placeholders})",
                group_ids,
            )
            rows = self._rows(
                f"""
                SELECT function_id FROM functions
                WHERE address_group_id IN ({placeholders})
                ORDER BY function_id LIMIT ? OFFSET ?
                """,
                (*group_ids, limit, offset),
            )
            function_ids = [str(row["function_id"]) for row in rows]
            all_function_ids = [
                str(row["function_id"])
                for row in self._rows(
                    f"""
                    SELECT function_id FROM functions
                    WHERE address_group_id IN ({placeholders})
                    ORDER BY function_id
                    """,
                    group_ids,
                )
            ]
            functions = [
                item
                for item in (
                    self._function_record(function_id, member_limit=limit)
                    for function_id in function_ids
                )
                if item is not None
            ]

        definitions = self._rows(
            """
            SELECT v.vtable_id, v.address_space, v.address, v.vfptr_role,
                   v.subobject_offset, v.declared_slot_count, v.class_id,
                   v.details_json
            FROM vtables v JOIN programs p USING (program_id)
            WHERE p.platform = 'pc' AND v.address_space = ? AND v.address = ?
            ORDER BY v.vtable_id
            """,
            (address_space, address),
        )
        for table in definitions:
            table["address_hex"] = _hex(int(table["address"]))
            table["details"] = _decode_json(table.pop("details_json"))
            table["class_names"] = self._class_names(str(table["class_id"]))

        hypothesis_page = {"items": [], "page": _paging(limit, offset, 0, 0)}
        standalone_claims: list[dict[str, Any]] = []
        unresolved_targets: list[dict[str, Any]] = []
        if group_ids:
            placeholders = self._placeholders(group_ids)
            unresolved_ids = self._rows(
                f"""
                SELECT target_id FROM unresolved_targets
                WHERE address_group_id IN ({placeholders}) ORDER BY target_id
                """,
                group_ids,
            )
            unresolved_target_ids = [
                str(row["target_id"]) for row in unresolved_ids
            ]
            hypothesis_parts: list[str] = []
            hypothesis_parameters: list[object] = []
            if all_function_ids:
                function_placeholders = self._placeholders(all_function_ids)
                hypothesis_parts.append(
                    "SELECT hypothesis_set_id FROM match_hypothesis_sets "
                    f"WHERE pc_function_id IN ({function_placeholders})"
                )
                hypothesis_parameters.extend(all_function_ids)
            if unresolved_target_ids:
                target_placeholders = self._placeholders(unresolved_target_ids)
                hypothesis_parts.append(
                    "SELECT hypothesis_set_id FROM match_hypothesis_sets "
                    "WHERE pc_function_id IS NULL AND "
                    f"pc_target_id IN ({target_placeholders})"
                )
                hypothesis_parameters.extend(unresolved_target_ids)
            if hypothesis_parts:
                hypothesis_page = self._hypothesis_page(
                    " UNION ".join(hypothesis_parts),
                    hypothesis_parameters,
                    limit=limit,
                    offset=offset,
                )
            unresolved_targets = [
                target
                for target in (
                    self._target(str(row["target_id"])) for row in unresolved_ids
                )
                if target is not None
            ]
            candidate_claim_ids: set[str] = set()
            if all_function_ids:
                function_placeholders = self._placeholders(all_function_ids)
                candidate_claim_ids.update(
                    str(row["claim_id"])
                    for row in self._rows(
                        f"""
                        SELECT claim_id FROM match_claims
                        WHERE pc_function_id IN ({function_placeholders})
                        """,
                        all_function_ids,
                    )
                )
            if unresolved_target_ids:
                target_placeholders = self._placeholders(unresolved_target_ids)
                candidate_claim_ids.update(
                    str(row["claim_id"])
                    for row in self._rows(
                        f"""
                        SELECT claim_id FROM match_claims
                        WHERE pc_function_id IS NULL
                          AND pc_target_id IN ({target_placeholders})
                        """,
                        unresolved_target_ids,
                    )
                )
            claim_ids = [
                claim_id
                for claim_id in sorted(candidate_claim_ids)
                if self._one(
                    """
                    SELECT 1 FROM match_hypothesis_alternatives
                    WHERE claim_id = ? LIMIT 1
                    """,
                    (claim_id,),
                )
                is None
            ][:limit]
            standalone_claims = [
                claim
                for claim in (
                    self._claim(claim_id) for claim_id in claim_ids
                )
                if claim is not None
            ]

        ambiguity_reasons: list[str] = []
        if len(groups) > 1:
            ambiguity_reasons.append("multiple_pc_program_address_groups")
        if total_functions == 0:
            ambiguity_reasons.append("no_canonical_function_at_address")
        elif total_functions > 1:
            ambiguity_reasons.append("multiple_logical_functions_at_address")
        return {
            "kind": "pc_address",
            "query": {
                "address": address,
                "address_hex": _hex(address),
                "address_space": address_space,
            },
            "found": bool(groups),
            "address_groups": groups,
            "functions": functions,
            "functions_page": _paging(
                limit, offset, total_functions, len(functions)
            ),
            "unresolved_targets": unresolved_targets,
            "vtable_definitions_at_address": definitions,
            "vtable_slots_targeting_address": self._vtable_slots_targeting(
                group_ids
            ),
            "mapping_hypotheses": hypothesis_page,
            "standalone_claims": standalone_claims,
            "ambiguity": _ambiguity(*ambiguity_reasons),
        }

    def _xbox_hypotheses(
        self,
        function_ids: Sequence[str],
        group_ids: Sequence[str],
        fold_group_ids: Sequence[str],
        target_ids: Sequence[str],
        *,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        clauses: list[str] = []
        parameters: list[object] = []
        if function_ids:
            placeholders = self._placeholders(function_ids)
            clauses.append(f"c.xbox_function_id IN ({placeholders})")
            parameters.extend(function_ids)
        if group_ids:
            placeholders = self._placeholders(group_ids)
            clauses.append(f"u.address_group_id IN ({placeholders})")
            parameters.extend(group_ids)
        if fold_group_ids:
            placeholders = self._placeholders(fold_group_ids)
            clauses.append(f"a.xbox_fold_group_id IN ({placeholders})")
            parameters.extend(fold_group_ids)
        if target_ids:
            placeholders = self._placeholders(target_ids)
            clauses.append(f"c.xbox_target_id IN ({placeholders})")
            parameters.extend(target_ids)
        if not clauses:
            return {"items": [], "page": _paging(limit, offset, 0, 0)}
        ids_sql = f"""
            SELECT DISTINCT a.hypothesis_set_id
            FROM match_hypothesis_alternatives a
            LEFT JOIN match_claims c ON c.claim_id = a.claim_id
            LEFT JOIN unresolved_targets u ON u.target_id = c.xbox_target_id
            WHERE {' OR '.join(clauses)}
        """
        return self._hypothesis_page(
            ids_sql, parameters, limit=limit, offset=offset
        )

    def xbox(
        self,
        query: int | str,
        *,
        name_mode: str = "exact",
        address_space: str = "xbox-va",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Find Xbox physical records by address or exact/substring symbol."""

        limit, offset = _validate_page(limit, offset)
        if name_mode not in {"exact", "contains"}:
            raise QueryError("name_mode must be 'exact' or 'contains'")
        is_address = isinstance(query, int)
        address: int | None = None
        if isinstance(query, str):
            stripped = query.strip()
            if stripped.lower().startswith("0x") or re.fullmatch(r"[0-9]+", stripped):
                try:
                    address = parse_query_address(stripped)
                    is_address = True
                except QueryError:
                    is_address = False
        if is_address:
            address = parse_query_address(query)
            base_sql = """
                SELECT DISTINCT f.function_id
                FROM functions f
                JOIN programs p USING (program_id)
                JOIN address_groups ag USING (address_group_id, program_id)
                WHERE p.platform = 'xbox360'
                  AND ag.address_space = ? AND ag.address = ?
            """
            parameters: tuple[object, ...] = (address_space, address)
            query_document = {
                "mode": "address",
                "address": address,
                "address_hex": _hex(address),
                "address_space": address_space,
            }
            address_groups = self._rows(
                """
                SELECT ag.address_group_id, ag.program_id, ag.address_space,
                       ag.address, ag.kind, ag.details_json
                FROM address_groups ag JOIN programs p USING (program_id)
                WHERE p.platform = 'xbox360'
                  AND ag.address_space = ? AND ag.address = ?
                ORDER BY ag.program_id, ag.address_group_id
                """,
                (address_space, address),
            )
            for group in address_groups:
                group["address_hex"] = _hex(int(group["address"]))
                group["details"] = _decode_json(group.pop("details_json"))
            initial_group_ids = [
                str(group["address_group_id"]) for group in address_groups
            ]
            if initial_group_ids:
                placeholders = self._placeholders(initial_group_ids)
                target_total = self._scalar(
                    f"""
                    SELECT COUNT(*) FROM unresolved_targets
                    WHERE address_group_id IN ({placeholders})
                    """,
                    initial_group_ids,
                )
                target_id_rows = self._rows(
                    f"""
                    SELECT target_id FROM unresolved_targets
                    WHERE address_group_id IN ({placeholders})
                    ORDER BY target_id LIMIT ? OFFSET ?
                    """,
                    (*initial_group_ids, limit, offset),
                )
            else:
                target_total = 0
                target_id_rows = []
        else:
            name = str(query)
            if name_mode == "exact":
                predicate = "n.name = ?"
            else:
                predicate = "instr(lower(n.name), lower(?)) > 0"
            base_sql = f"""
                SELECT DISTINCT f.function_id
                FROM function_names n
                JOIN functions f USING (function_id)
                JOIN programs p USING (program_id)
                WHERE p.platform = 'xbox360' AND {predicate}
            """
            parameters = (name,)
            query_document = {"mode": "name", "name": name, "name_mode": name_mode}
            address_groups = []
            target_predicate = (
                "u.name_hint = ?"
                if name_mode == "exact"
                else "instr(lower(u.name_hint), lower(?)) > 0"
            )
            target_total = self._scalar(
                f"""
                SELECT COUNT(*)
                FROM unresolved_targets u JOIN programs p USING (program_id)
                WHERE p.platform = 'xbox360' AND u.name_hint IS NOT NULL
                  AND {target_predicate}
                """,
                (name,),
            )
            target_id_rows = self._rows(
                f"""
                SELECT u.target_id
                FROM unresolved_targets u JOIN programs p USING (program_id)
                WHERE p.platform = 'xbox360' AND u.name_hint IS NOT NULL
                  AND {target_predicate}
                ORDER BY u.target_id LIMIT ? OFFSET ?
                """,
                (name, limit, offset),
            )

        total = self._scalar(f"SELECT COUNT(*) FROM ({base_sql})", parameters)
        id_rows = self._rows(
            f"SELECT function_id FROM ({base_sql}) "
            "ORDER BY function_id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        )
        function_ids = [str(row["function_id"]) for row in id_rows]
        records = [
            item
            for item in (
                self._function_record(function_id, member_limit=limit)
                for function_id in function_ids
            )
            if item is not None
        ]
        group_ids = sorted(
            {
                str(record["address_group_id"])
                for record in records
                if record.get("address_group_id") is not None
            }
            | {
                str(group["address_group_id"])
                for group in address_groups
            }
        )
        unresolved_targets = [
            target
            for target in (
                self._target(str(row["target_id"])) for row in target_id_rows
            )
            if target is not None
        ]
        target_ids = [str(target["target_id"]) for target in unresolved_targets]
        for target in unresolved_targets:
            if target.get("address_group_id") is not None:
                group_ids.append(str(target["address_group_id"]))
        group_ids = sorted(set(group_ids))
        fold_ids: list[str] = []
        if function_ids:
            placeholders = self._placeholders(function_ids)
            fold_ids = [
                str(row["fold_group_id"])
                for row in self._rows(
                    f"""
                    SELECT DISTINCT fold_group_id FROM fold_group_members
                    WHERE function_id IN ({placeholders}) ORDER BY fold_group_id
                    """,
                    function_ids,
                )
            ]
        folds = [
            self._fold_group(group_id, member_limit=limit) for group_id in fold_ids
        ]
        hypotheses = self._xbox_hypotheses(
            function_ids,
            group_ids,
            fold_ids,
            target_ids,
            limit=limit,
            offset=offset,
        )
        addresses = {
            (record["address_space"], int(record["address"])) for record in records
        }
        reasons: list[str] = []
        if total == 0 and not unresolved_targets:
            reasons.append("no_physical_pdb_record_match")
        elif total > 1:
            reasons.append("multiple_physical_pdb_records_match")
        if len(addresses) > 1:
            reasons.append("matching_name_occurs_at_multiple_addresses")
        if fold_ids:
            reasons.append("one_or_more_matches_are_fold_group_members")
        if unresolved_targets:
            reasons.append("unresolved_xbox_target_matches_query")
        return {
            "kind": "xbox_lookup",
            "query": query_document,
            "found": total > 0 or bool(unresolved_targets),
            "address_groups": address_groups,
            "physical_records": records,
            "physical_records_page": _paging(limit, offset, total, len(records)),
            "fold_groups": folds,
            "unresolved_targets": unresolved_targets,
            "unresolved_targets_page": _paging(
                limit, offset, target_total, len(unresolved_targets)
            ),
            "pc_mapping_hypotheses": hypotheses,
            "mapping_scope": "returned_physical_records",
            "ambiguity": _ambiguity(*reasons),
        }

    def _slot_record(
        self,
        vtable_id: str,
        slot_index: int,
        *,
        alignment_ids: Sequence[str] = (),
        target_function_limit: int = DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        row = self._one(
            """
            SELECT s.*, ag.address_space, ag.address
            FROM vtable_slots s
            LEFT JOIN address_groups ag
              ON ag.address_group_id = s.target_address_group_id
             AND ag.program_id = s.program_id
            WHERE s.vtable_id = ? AND s.slot_index = ?
            """,
            (vtable_id, slot_index),
        )
        if row is None:
            return {"vtable_id": vtable_id, "slot_index": slot_index, "missing": True}
        row["details"] = _decode_json(row.pop("details_json"))
        row["address_hex"] = _hex(
            None if row["address"] is None else int(row["address"])
        )
        functions: list[dict[str, Any]] = []
        function_count = 0
        if row["target_address_group_id"] is not None:
            function_count = self._scalar(
                "SELECT COUNT(*) FROM functions WHERE address_group_id = ?",
                (row["target_address_group_id"],),
            )
            function_ids = self._rows(
                """
                SELECT function_id FROM functions
                WHERE address_group_id = ? ORDER BY function_id LIMIT ?
                """,
                (row["target_address_group_id"], target_function_limit),
            )
            functions = [
                item
                for item in (
                    self._function_brief(str(item["function_id"]))
                    for item in function_ids
                )
                if item is not None
            ]
        row["target_functions"] = functions
        row["target_function_count"] = function_count
        row["unresolved_target"] = (
            self._target(str(row["unresolved_target_id"]))
            if row["unresolved_target_id"] is not None
            else None
        )
        alignments: list[dict[str, Any]] = []
        if alignment_ids:
            placeholders = self._placeholders(alignment_ids)
            alignments = self._rows(
                f"""
                SELECT a.slot_alignment_id, a.alignment_id, a.pc_vtable_id,
                       a.pc_slot_index, a.xbox_vtable_id, a.xbox_slot_index,
                       a.hypothesis_set_id, a.status, a.details_json
                FROM vtable_slot_alignments a
                WHERE a.alignment_id IN ({placeholders})
                  AND a.pc_slot_index = ?
                ORDER BY a.alignment_id, a.slot_alignment_id
                """,
                (*alignment_ids, slot_index),
            )
        for alignment in alignments:
            alignment["details"] = _decode_json(alignment.pop("details_json"))
        row["alignment_occurrences"] = alignments
        row["ambiguity"] = _ambiguity(
            "slot_target_address_has_multiple_logical_functions"
            if function_count > 1
            else ""
        )
        return row

    def _class_record(
        self,
        class_id: str,
        *,
        slot_limit: int,
        slot_offset: int,
    ) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT c.class_id, c.program_id, p.platform, c.identity_key,
                   c.type_index, c.size_bytes, c.module_id, c.details_json
            FROM classes c JOIN programs p USING (program_id)
            WHERE c.class_id = ?
            """,
            (class_id,),
        )
        if row is None:
            return None
        row["details"] = _decode_json(row.pop("details_json"))
        row["names"] = self._class_names(class_id)
        tables = self._rows(
            """
            SELECT v.*, (SELECT COUNT(*) FROM vtable_slots s
                         WHERE s.vtable_id = v.vtable_id) AS observed_slot_count
            FROM vtables v WHERE v.class_id = ?
            ORDER BY CASE v.vfptr_role WHEN 'primary' THEN 0
                                      WHEN 'secondary' THEN 1 ELSE 2 END,
                     COALESCE(v.subobject_offset, -1), v.vtable_id
            """,
            (class_id,),
        )
        normalized_tables: list[dict[str, Any]] = []
        for table in tables:
            table["address_hex"] = _hex(int(table["address"]))
            table["details"] = _decode_json(table.pop("details_json"))
            total_slots = int(table.pop("observed_slot_count"))
            alignments = self._rows(
                """
                SELECT a.*, CASE WHEN a.pc_vtable_id = ?
                                 THEN a.xbox_vtable_id ELSE a.pc_vtable_id END
                                 AS partner_vtable_id
                FROM vtable_alignment_candidates a
                WHERE a.pc_vtable_id = ? OR a.xbox_vtable_id = ?
                ORDER BY a.alignment_id
                """,
                (table["vtable_id"], table["vtable_id"], table["vtable_id"]),
            )
            alignment_ids = [str(item["alignment_id"]) for item in alignments]
            for alignment in alignments:
                alignment["details"] = _decode_json(
                    alignment.pop("details_json")
                )
            slot_rows = self._rows(
                """
                SELECT slot_index FROM vtable_slots WHERE vtable_id = ?
                ORDER BY slot_index LIMIT ? OFFSET ?
                """,
                (table["vtable_id"], slot_limit, slot_offset),
            )
            slots = [
                self._slot_record(
                    str(table["vtable_id"]),
                    int(item["slot_index"]),
                    alignment_ids=alignment_ids,
                    target_function_limit=slot_limit,
                )
                for item in slot_rows
            ]
            table["slots"] = slots
            table["slots_page"] = _paging(
                slot_limit, slot_offset, total_slots, len(slots)
            )
            table["alignment_candidates"] = alignments
            normalized_tables.append(table)
        row["vtables"] = normalized_tables
        return row

    def class_lookup(
        self,
        name: str,
        *,
        name_mode: str = "exact",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
        slot_limit: int = DEFAULT_LIMIT,
        slot_offset: int = 0,
    ) -> dict[str, Any]:
        """Return same-platform class identities, tables, slots, and alignments."""

        limit, offset = _validate_page(limit, offset)
        slot_limit, slot_offset = _validate_page(slot_limit, slot_offset)
        if name_mode not in {"exact", "contains"}:
            raise QueryError("name_mode must be 'exact' or 'contains'")
        predicate = (
            "n.name = ?"
            if name_mode == "exact"
            else "instr(lower(n.name), lower(?)) > 0"
        )
        base_sql = f"""
            SELECT DISTINCT c.class_id
            FROM class_names n JOIN classes c USING (class_id)
            JOIN programs p USING (program_id)
            WHERE {predicate}
        """
        total = self._scalar(f"SELECT COUNT(*) FROM ({base_sql})", (name,))
        ids = self._rows(
            f"SELECT class_id FROM ({base_sql}) ORDER BY class_id LIMIT ? OFFSET ?",
            (name, limit, offset),
        )
        classes = [
            item
            for item in (
                self._class_record(
                    str(row["class_id"]),
                    slot_limit=slot_limit,
                    slot_offset=slot_offset,
                )
                for row in ids
            )
            if item is not None
        ]
        issue_names = sorted(
            {
                str(item["name"])
                for class_record in classes
                for item in class_record["names"]
            }
            | {name}
        )
        issues: list[dict[str, Any]] = []
        if issue_names:
            placeholders = self._placeholders(issue_names)
            issues = self._rows(
                f"""
                SELECT * FROM vtable_alignment_issues
                WHERE class_name IN ({placeholders})
                ORDER BY class_name, issue_kind, issue_id
                """,
                issue_names,
            )
            for issue in issues:
                issue["details"] = _decode_json(issue.pop("details_json"))
        platforms = {str(item["platform"]) for item in classes}
        reasons: list[str] = []
        if total == 0:
            reasons.append("no_class_name_match")
        if total > len(platforms) and total > 1:
            reasons.append("multiple_class_identities_match")
        return {
            "kind": "class_lookup",
            "query": {"name": name, "name_mode": name_mode},
            "found": total > 0,
            "classes": classes,
            "classes_page": _paging(limit, offset, total, len(classes)),
            "alignment_issues": issues,
            "cross_platform_presence": sorted(platforms),
            "ambiguity": _ambiguity(*reasons),
        }

    def _flow_site_assertion(
        self, row: dict[str, Any], *, fold_member_limit: int
    ) -> dict[str, Any]:
        """Normalize one extraction-specific observation of a physical branch."""

        for field_name in ("link", "absolute", "conditional", "indirect"):
            row[field_name] = bool(row[field_name])
        row["site_address_hex"] = _hex(int(row["site_address"]))
        row["raw_site_va_hex"] = _hex(int(row["raw_site_va"]))
        row["raw_target_va_hex"] = _hex(
            None if row["raw_target_va"] is None else int(row["raw_target_va"])
        )
        row["target_address_hex"] = _hex(
            None if row["target_address"] is None else int(row["target_address"])
        )
        row["details"] = _decode_json(row.pop("details_json"))

        target_kind = str(row["target_kind"])
        if target_kind == "unique_procedure":
            row["target_endpoint"] = {
                "endpoint_kind": "unique_procedure",
                "function": self._function_brief(str(row["target_function_id"])),
            }
        elif target_kind == "fold_group":
            row["target_endpoint"] = {
                "endpoint_kind": "fold_group",
                "fold_group": self._fold_group(
                    str(row["target_fold_group_id"]),
                    member_limit=fold_member_limit,
                ),
            }
        elif target_kind in {"executable_non_entry", "outside_executable"}:
            row["target_endpoint"] = {
                "endpoint_kind": "address_only",
                "classification": target_kind,
                "address_group_id": row["target_address_group_id"],
                "address_space": row["target_address_space"],
                "address": row["target_address"],
                "address_hex": row["target_address_hex"],
            }
        else:
            row["target_endpoint"] = {
                "endpoint_kind": "indirect",
                "description": "runtime target is not statically identified",
            }
        return row

    def _flow_site(
        self,
        site_id: str,
        *,
        assertion_limit: int = DEFAULT_LIMIT,
        assertion_offset: int = 0,
    ) -> dict[str, Any] | None:
        assertion_limit, assertion_offset = _validate_page(
            assertion_limit, assertion_offset
        )
        site = self._one(
            """
            SELECT s.site_id, s.program_id, p.platform, s.address_group_id,
                   ag.address_space, ag.address
            FROM control_flow_sites s
            JOIN programs p USING (program_id)
            JOIN address_groups ag USING (address_group_id, program_id)
            WHERE s.site_id = ?
            """,
            (site_id,),
        )
        if site is None:
            return None
        site["address_hex"] = _hex(int(site["address"]))
        total = self._scalar(
            "SELECT COUNT(*) FROM control_flow_site_assertions WHERE site_id = ?",
            (site_id,),
        )
        rows = self._rows(
            """
            SELECT a.*, site_address.address_space,
                   site_address.address AS site_address,
                   target_address.address_space AS target_address_space,
                   target_address.address AS target_address,
                   e.persistence_policy, e.provenance_id AS extraction_provenance_id
            FROM control_flow_site_assertions a
            JOIN control_flow_extractions e USING (extraction_id, program_id)
            JOIN control_flow_sites s USING (site_id, program_id)
            JOIN address_groups site_address
              ON site_address.address_group_id = s.address_group_id
             AND site_address.program_id = s.program_id
            LEFT JOIN address_groups target_address
              ON target_address.address_group_id = a.target_address_group_id
             AND target_address.program_id = a.program_id
            WHERE a.site_id = ?
            ORDER BY a.extraction_id, a.assertion_id LIMIT ? OFFSET ?
            """,
            (site_id, assertion_limit, assertion_offset),
        )
        assertions = [
            self._flow_site_assertion(row, fold_member_limit=assertion_limit)
            for row in rows
        ]
        fold_assertion_count = self._scalar(
            """
            SELECT COUNT(*) FROM control_flow_site_assertions
            WHERE site_id = ? AND target_kind = 'fold_group'
            """,
            (site_id,),
        )
        site["assertions"] = assertions
        site["assertions_page"] = _paging(
            assertion_limit, assertion_offset, total, len(assertions)
        )
        site["ambiguity"] = _ambiguity(
            "multiple_extraction_assertions_for_site" if total > 1 else "",
            "one_or_more_targets_are_fold_groups"
            if fold_assertion_count
            else "",
        )
        return site

    def _flow_membership(
        self, use_id: str, *, assertion_limit: int
    ) -> dict[str, Any] | None:
        membership = self._one(
            """
            SELECT u.use_id, u.program_id, u.procedure_record_id,
                   u.function_id, u.site_id, ag.address_space,
                   ag.address AS site_address
            FROM control_flow_uses u
            JOIN control_flow_sites s USING (site_id, program_id)
            JOIN address_groups ag USING (address_group_id, program_id)
            WHERE u.use_id = ?
            """,
            (use_id,),
        )
        if membership is None:
            return None
        membership["site_address_hex"] = _hex(int(membership["site_address"]))
        membership["procedure"] = self._function_brief(
            str(membership["function_id"])
        )
        assertion_total = self._scalar(
            "SELECT COUNT(*) FROM control_flow_use_assertions WHERE use_id = ?",
            (use_id,),
        )
        assertions = self._rows(
            """
            SELECT a.assertion_id, a.extraction_id, a.role, a.details_json,
                   e.persistence_policy, e.provenance_id AS extraction_provenance_id
            FROM control_flow_use_assertions a
            JOIN control_flow_extractions e USING (extraction_id, program_id)
            WHERE a.use_id = ?
            ORDER BY a.extraction_id, a.role, a.assertion_id LIMIT ?
            """,
            (use_id, assertion_limit),
        )
        for assertion in assertions:
            assertion["details"] = _decode_json(assertion.pop("details_json"))
            site_assertion = self._one(
                """
                SELECT a.*, site_address.address_space,
                       site_address.address AS site_address,
                       target_address.address_space AS target_address_space,
                       target_address.address AS target_address,
                       e.persistence_policy,
                       e.provenance_id AS extraction_provenance_id
                FROM control_flow_site_assertions a
                JOIN control_flow_extractions e
                  USING (extraction_id, program_id)
                JOIN control_flow_sites s USING (site_id, program_id)
                JOIN address_groups site_address
                  ON site_address.address_group_id = s.address_group_id
                 AND site_address.program_id = s.program_id
                LEFT JOIN address_groups target_address
                  ON target_address.address_group_id = a.target_address_group_id
                 AND target_address.program_id = a.program_id
                WHERE a.extraction_id = ? AND a.program_id = ?
                  AND a.site_id = ?
                """,
                (
                    assertion["extraction_id"],
                    membership["program_id"],
                    membership["site_id"],
                ),
            )
            assertion["site_observation"] = (
                None
                if site_assertion is None
                else self._flow_site_assertion(
                    site_assertion, fold_member_limit=assertion_limit
                )
            )
        membership["role_assertions"] = assertions
        membership["role_assertions_page"] = _paging(
            assertion_limit, 0, assertion_total, len(assertions)
        )
        membership["roles"] = [
            str(row["role"])
            for row in self._rows(
                """
                SELECT DISTINCT role FROM control_flow_use_assertions
                WHERE use_id = ? ORDER BY role
                """,
                (use_id,),
            )
        ]
        membership["physical_site"] = self._flow_site(
            str(membership["site_id"]), assertion_limit=assertion_limit
        )
        return membership

    def _flow_scan(self, scan_id: str) -> dict[str, Any] | None:
        scan = self._one(
            """
            SELECT s.*, ag.address_space, ag.address AS scan_address,
                   e.persistence_policy, e.provenance_id AS extraction_provenance_id,
                   e.source_physical_site_count, e.source_logical_use_count,
                   e.persisted_physical_site_count, e.persisted_logical_use_count,
                   e.triggering_logical_use_count, e.procedure_scan_count
            FROM control_flow_scans s
            JOIN control_flow_extractions e USING (extraction_id, program_id)
            LEFT JOIN address_groups ag
              ON ag.address_group_id = s.scan_address_group_id
             AND ag.program_id = s.program_id
            WHERE s.scan_id = ?
            """,
            (scan_id,),
        )
        if scan is None:
            return None
        scan["scan_address_hex"] = _hex(
            None if scan["scan_address"] is None else int(scan["scan_address"])
        )
        scan["details"] = _decode_json(scan.pop("details_json"))
        if scan["function_id"] is not None:
            scan["procedure_identity"] = {
                "identity_kind": "physical_procedure",
                "function": self._function_brief(str(scan["function_id"])),
            }
        else:
            scan["procedure_identity"] = {
                "identity_kind": "unresolved_procedure",
                "target": self._target(str(scan["unresolved_target_id"])),
            }
        scan["coverage"] = {
            "bytes_complete": int(scan["unscanned_byte_count"]) == 0,
            "logical_uses_complete": (
                int(scan["source_branch_use_count"])
                == int(scan["persisted_branch_use_count"])
            ),
            "status": scan["status"],
        }
        return scan

    def flow(
        self,
        procedure: int | str | None = None,
        *,
        site_address: int | str | None = None,
        name_mode: str = "exact",
        address_space: str = "xbox-va",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Inspect persisted Xbox control flow without collapsing identities.

        ``procedure`` accepts a physical procedure/function ID, an exact or
        substring symbol, or an entry address.  ``site_address`` is the exact
        physical branch-instruction address.  Supplying both intersects those
        filters for logical memberships while retaining the independent
        procedure and site observations for audit.
        """

        limit, offset = _validate_page(limit, offset)
        if procedure is None and site_address is None:
            raise QueryError("flow requires a procedure query and/or --site")
        if name_mode not in {"exact", "contains"}:
            raise QueryError("name_mode must be 'exact' or 'contains'")
        site = (
            None if site_address is None else parse_query_address(site_address)
        )

        procedure_mode: str | None = None
        procedure_address: int | None = None
        procedure_text: str | None = None
        if procedure is not None:
            if isinstance(procedure, int):
                procedure_address = parse_query_address(procedure)
                procedure_mode = "address"
            else:
                stripped = str(procedure).strip()
                if stripped.lower().startswith("0x") or re.fullmatch(
                    r"[0-9]+", stripped
                ):
                    procedure_address = parse_query_address(stripped)
                    procedure_mode = "address"
                else:
                    if not stripped:
                        raise QueryError("procedure query cannot be empty")
                    procedure_text = stripped
                    procedure_mode = "identity_or_name"

        if procedure_mode == "address":
            function_sql = """
                SELECT DISTINCT f.function_id
                FROM functions f
                JOIN programs p USING (program_id)
                JOIN address_groups ag USING (address_group_id, program_id)
                WHERE p.platform = 'xbox360'
                  AND ag.address_space = ? AND ag.address = ?
            """
            function_parameters: tuple[object, ...] = (
                address_space,
                procedure_address,
            )
        elif procedure_mode == "identity_or_name":
            identity_predicate = (
                "f.function_id = ?"
                if name_mode == "exact"
                else "instr(lower(f.function_id), lower(?)) > 0"
            )
            name_predicate = (
                "n.name = ?"
                if name_mode == "exact"
                else "instr(lower(n.name), lower(?)) > 0"
            )
            function_sql = f"""
                SELECT DISTINCT f.function_id
                FROM functions f JOIN programs p USING (program_id)
                WHERE p.platform = 'xbox360' AND (
                    {identity_predicate} OR EXISTS (
                        SELECT 1 FROM function_names n
                        WHERE n.function_id = f.function_id
                          AND {name_predicate}
                    )
                )
            """
            function_parameters = (procedure_text, procedure_text)
        else:
            assert site is not None
            function_sql = """
                SELECT DISTINCT u.function_id
                FROM control_flow_uses u
                JOIN control_flow_sites s USING (site_id, program_id)
                JOIN address_groups ag USING (address_group_id, program_id)
                JOIN programs p USING (program_id)
                WHERE p.platform = 'xbox360'
                  AND ag.address_space = ? AND ag.address = ?
            """
            function_parameters = (address_space, site)

        procedure_total = self._scalar(
            f"SELECT COUNT(*) FROM ({function_sql})", function_parameters
        )
        procedure_rows = self._rows(
            f"SELECT function_id FROM ({function_sql}) "
            "ORDER BY function_id LIMIT ? OFFSET ?",
            (*function_parameters, limit, offset),
        )
        procedures = [
            item
            for item in (
                self._function_record(str(row["function_id"]), member_limit=limit)
                for row in procedure_rows
            )
            if item is not None
        ]

        use_clauses = ["p.platform = 'xbox360'"]
        use_parameters: list[object] = []
        if procedure is not None:
            procedure_clauses = [f"u.function_id IN ({function_sql})"]
            use_parameters.extend(function_parameters)
            if procedure_mode == "identity_or_name":
                record_predicate = (
                    "u.procedure_record_id = ?"
                    if name_mode == "exact"
                    else "instr(lower(u.procedure_record_id), lower(?)) > 0"
                )
                procedure_clauses.append(record_predicate)
                use_parameters.append(procedure_text)
            use_clauses.append("(" + " OR ".join(procedure_clauses) + ")")
        if site is not None:
            use_clauses.append("ag.address_space = ? AND ag.address = ?")
            use_parameters.extend((address_space, site))
        use_ids_sql = f"""
            SELECT DISTINCT u.use_id
            FROM control_flow_uses u
            JOIN control_flow_sites s USING (site_id, program_id)
            JOIN address_groups ag USING (address_group_id, program_id)
            JOIN programs p USING (program_id)
            WHERE {' AND '.join(use_clauses)}
        """
        membership_total = self._scalar(
            f"SELECT COUNT(*) FROM ({use_ids_sql})", use_parameters
        )
        use_rows = self._rows(
            f"SELECT use_id FROM ({use_ids_sql}) "
            "ORDER BY use_id LIMIT ? OFFSET ?",
            (*use_parameters, limit, offset),
        )
        memberships = [
            item
            for item in (
                self._flow_membership(
                    str(row["use_id"]), assertion_limit=limit
                )
                for row in use_rows
            )
            if item is not None
        ]

        if site is not None:
            site_ids_sql = """
                SELECT s.site_id
                FROM control_flow_sites s
                JOIN programs p USING (program_id)
                JOIN address_groups ag USING (address_group_id, program_id)
                WHERE p.platform = 'xbox360'
                  AND ag.address_space = ? AND ag.address = ?
            """
            site_parameters: tuple[object, ...] = (address_space, site)
        else:
            site_ids_sql = f"""
                SELECT DISTINCT u.site_id FROM control_flow_uses u
                WHERE u.use_id IN ({use_ids_sql})
            """
            site_parameters = tuple(use_parameters)
        site_total = self._scalar(
            f"SELECT COUNT(*) FROM ({site_ids_sql})", site_parameters
        )
        site_rows = self._rows(
            f"SELECT site_id FROM ({site_ids_sql}) "
            "ORDER BY site_id LIMIT ? OFFSET ?",
            (*site_parameters, limit, offset),
        )
        sites = [
            item
            for item in (
                self._flow_site(str(row["site_id"]), assertion_limit=limit)
                for row in site_rows
            )
            if item is not None
        ]

        if procedure is not None:
            scan_clauses = [f"s.function_id IN ({function_sql})"]
            scan_parameters: list[object] = list(function_parameters)
            if procedure_mode == "identity_or_name":
                scan_record_predicate = (
                    "s.procedure_record_id = ?"
                    if name_mode == "exact"
                    else "instr(lower(s.procedure_record_id), lower(?)) > 0"
                )
                scan_clauses.append(scan_record_predicate)
                scan_parameters.append(procedure_text)
            elif procedure_mode == "address":
                scan_clauses.append(
                    """
                    s.scan_address_group_id IN (
                        SELECT ag.address_group_id
                        FROM address_groups ag JOIN programs p USING (program_id)
                        WHERE p.platform = 'xbox360'
                          AND ag.address_space = ? AND ag.address = ?
                    )
                    """
                )
                scan_parameters.extend((address_space, procedure_address))
        else:
            scan_clauses = [
                f"s.function_id IN ({function_sql})",
                """
                s.procedure_record_id IN (
                    SELECT DISTINCT u.procedure_record_id
                    FROM control_flow_uses u
                    JOIN control_flow_sites site USING (site_id, program_id)
                    JOIN address_groups ag USING (address_group_id, program_id)
                    WHERE ag.address_space = ? AND ag.address = ?
                )
                """,
            ]
            scan_parameters = [*function_parameters, address_space, site]
        scan_ids_sql = f"""
            SELECT s.scan_id
            FROM control_flow_scans s JOIN programs p USING (program_id)
            WHERE p.platform = 'xbox360'
              AND ({' OR '.join(scan_clauses)})
        """
        scan_total = self._scalar(
            f"SELECT COUNT(*) FROM ({scan_ids_sql})", scan_parameters
        )
        scan_rows = self._rows(
            f"SELECT scan_id FROM ({scan_ids_sql}) "
            "ORDER BY scan_id LIMIT ? OFFSET ?",
            (*scan_parameters, limit, offset),
        )
        scans = [
            item
            for item in (
                self._flow_scan(str(row["scan_id"])) for row in scan_rows
            )
            if item is not None
        ]

        role_counts = {
            str(row["role"]): int(row["count"])
            for row in self._rows(
                f"""
                SELECT a.role, COUNT(*) AS count
                FROM control_flow_use_assertions a
                WHERE a.use_id IN ({use_ids_sql})
                GROUP BY a.role ORDER BY a.role
                """,
                use_parameters,
            )
        }
        target_kind_counts = {
            str(row["target_kind"]): int(row["count"])
            for row in self._rows(
                f"""
                SELECT a.target_kind, COUNT(*) AS count
                FROM control_flow_site_assertions a
                WHERE a.site_id IN ({site_ids_sql})
                GROUP BY a.target_kind ORDER BY a.target_kind
                """,
                site_parameters,
            )
        }
        scan_status_counts = {
            str(row["status"]): int(row["count"])
            for row in self._rows(
                f"""
                SELECT s.status, COUNT(*) AS count
                FROM control_flow_scans s
                WHERE s.scan_id IN ({scan_ids_sql})
                GROUP BY s.status ORDER BY s.status
                """,
                scan_parameters,
            )
        }
        reasons: list[str] = []
        if procedure_total > 1:
            reasons.append("multiple_physical_procedure_records_match")
        if target_kind_counts.get("fold_group", 0):
            reasons.append("one_or_more_targets_are_fold_groups")
        if site is not None and membership_total > 1:
            reasons.append("physical_site_has_multiple_logical_memberships")
        if any(scan["function_id"] is None for scan in scans):
            reasons.append("one_or_more_scan_identities_are_unresolved")
        return {
            "kind": "xbox_control_flow",
            "query": {
                "procedure": procedure,
                "procedure_mode": procedure_mode,
                "name_mode": name_mode if procedure_mode == "identity_or_name" else None,
                "procedure_address": procedure_address,
                "procedure_address_hex": _hex(procedure_address),
                "site_address": site,
                "site_address_hex": _hex(site),
                "address_space": address_space,
                "membership_scope": (
                    "intersection_of_procedure_and_site"
                    if procedure is not None and site is not None
                    else "procedure" if procedure is not None else "site"
                ),
            },
            "found": bool(
                procedure_total or site_total or membership_total or scan_total
            ),
            "procedure_records": procedures,
            "procedure_records_page": _paging(
                limit, offset, procedure_total, len(procedures)
            ),
            "physical_sites": sites,
            "physical_sites_page": _paging(limit, offset, site_total, len(sites)),
            "logical_memberships": memberships,
            "logical_memberships_page": _paging(
                limit, offset, membership_total, len(memberships)
            ),
            "scan_coverage": scans,
            "scan_coverage_page": _paging(limit, offset, scan_total, len(scans)),
            "role_counts": role_counts,
            "target_kind_counts": target_kind_counts,
            "scan_status_counts": scan_status_counts,
            "ambiguity": _ambiguity(*reasons),
            "identity_policy": (
                "all physical records, logical memberships, role assertions, "
                "and target observations are retained; no alias or fold member "
                "is selected"
            ),
        }

    def _codeview_tag_layout(
        self, tag_layout_id: str, *, member_limit: int, member_offset: int
    ) -> dict[str, Any] | None:
        """Expand one extraction-specific tag decode without merging identities."""

        row = self._one(
            """
            SELECT tag_layout_id, extraction_id, program_id, type_namespace,
                   type_record_id, tag_kind, declared_member_count,
                   decoded_member_count, physical_member_occurrence_count,
                   properties, field_list_type_index, derived_type_index,
                   vtable_shape_type_index, underlying_type_index, size_value,
                   display_name, unique_name, is_forward_reference,
                   record_sha256
            FROM codeview_tag_layouts WHERE tag_layout_id = ?
            """,
            (tag_layout_id,),
        )
        if row is None:
            return None
        row["is_forward_reference"] = bool(row["is_forward_reference"])
        for field_name in (
            "field_list_type_index",
            "derived_type_index",
            "vtable_shape_type_index",
            "underlying_type_index",
        ):
            value = row[field_name]
            row[f"{field_name}_hex"] = (
                None if value is None else f"0x{int(value):X}"
            )

        member_total = self._scalar(
            "SELECT COUNT(*) FROM codeview_tag_member_uses "
            "WHERE tag_layout_id = ?",
            (tag_layout_id,),
        )
        members = self._rows(
            """
            SELECT u.member_use_id, u.ordinal, f.field_member_id,
                   f.source_field_list_type_index, f.source_record_offset,
                   f.leaf_kind, f.member_kind, f.attributes, f.access,
                   f.method_kind, f.method_options, f.member_name,
                   f.referenced_type_index, f.rendered_type,
                   f.member_offset_value, f.enum_value, f.base_type_index,
                   f.vbptr_type_index, f.vbptr_offset_value,
                   f.vtable_index_value, f.method_list_type_index,
                   f.declared_overload_count, f.vtable_offset,
                   f.continuation_type_index
            FROM codeview_tag_member_uses u
            JOIN codeview_field_members f USING (field_member_id)
            WHERE u.tag_layout_id = ?
            ORDER BY u.ordinal, u.member_use_id LIMIT ? OFFSET ?
            """,
            (tag_layout_id, member_limit, member_offset),
        )
        for member in members:
            for field_name in (
                "source_field_list_type_index",
                "referenced_type_index",
                "base_type_index",
                "vbptr_type_index",
                "method_list_type_index",
                "continuation_type_index",
            ):
                value = member[field_name]
                member[f"{field_name}_hex"] = (
                    None if value is None else f"0x{int(value):X}"
                )
            method_list = member["method_list_type_index"]
            if method_list is None:
                member["overloads"] = []
            else:
                overloads = self._rows(
                    """
                    SELECT method_overload_id, ordinal, attributes, access,
                           method_kind, method_options, method_type_index,
                           rendered_type, vtable_offset
                    FROM codeview_method_overloads
                    WHERE extraction_id = ? AND method_list_type_index = ?
                    ORDER BY ordinal, method_overload_id
                    """,
                    (row["extraction_id"], method_list),
                )
                for overload in overloads:
                    overload["method_type_index_hex"] = (
                        f"0x{int(overload['method_type_index']):X}"
                    )
                member["overloads"] = overloads
        row["members"] = members
        row["members_page"] = _paging(
            member_limit, member_offset, member_total, len(members)
        )
        row["diagnostics"] = self._rows(
            """
            SELECT diagnostic_id, ordinal, code, source_type_index,
                   source_record_offset, message, remaining_hex
            FROM codeview_layout_diagnostics
            WHERE tag_layout_id = ? ORDER BY ordinal, diagnostic_id
            """,
            (tag_layout_id,),
        )
        for diagnostic in row["diagnostics"]:
            diagnostic["source_type_index_hex"] = (
                f"0x{int(diagnostic['source_type_index']):X}"
            )
        return row

    def _codeview_type_record(
        self,
        type_record_id: str,
        *,
        member_limit: int,
        member_offset: int,
    ) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT r.type_record_id, r.program_id, p.name AS program_name,
                   p.platform, r.type_namespace, r.type_index, r.leaf_kind,
                   r.record_length, r.raw_body_sha256,
                   lower(hex(r.raw_body)) AS raw_body_hex
            FROM codeview_type_records r JOIN programs p USING (program_id)
            WHERE r.type_record_id = ?
            """,
            (type_record_id,),
        )
        if row is None:
            return None
        row["type_index_hex"] = f"0x{int(row['type_index']):X}"
        row["leaf_kind_hex"] = f"0x{int(row['leaf_kind']):04X}"
        row["assertions"] = self._rows(
            """
            SELECT assertion_id, extraction_id, leaf_name, rendered_type
            FROM codeview_type_record_assertions
            WHERE type_record_id = ?
            ORDER BY extraction_id, assertion_id
            """,
            (type_record_id,),
        )
        layout_ids = self._rows(
            """
            SELECT tag_layout_id FROM codeview_tag_layouts
            WHERE type_record_id = ?
            ORDER BY extraction_id, tag_layout_id
            """,
            (type_record_id,),
        )
        row["tag_layouts"] = [
            layout
            for layout in (
                self._codeview_tag_layout(
                    str(item["tag_layout_id"]),
                    member_limit=member_limit,
                    member_offset=member_offset,
                )
                for item in layout_ids
            )
            if layout is not None
        ]
        row["identity_policy"] = (
            "this is one physical CodeView type-index record; extraction "
            "assertions and tag decodes are retained separately"
        )
        return row

    def codeview_type(
        self,
        query: int | str,
        *,
        name_mode: str = "exact",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
        member_limit: int = DEFAULT_LIMIT,
        member_offset: int = 0,
    ) -> dict[str, Any]:
        """Find raw CodeView records by type index or tag/rendered name."""

        limit, offset = _validate_page(limit, offset)
        member_limit, member_offset = _validate_page(
            member_limit, member_offset
        )
        if name_mode not in {"exact", "contains"}:
            raise QueryError("name_mode must be 'exact' or 'contains'")
        is_index = isinstance(query, int) and not isinstance(query, bool)
        type_index: int | None = None
        if isinstance(query, str):
            stripped = query.strip()
            if stripped.lower().startswith("0x") or re.fullmatch(r"[0-9]+", stripped):
                type_index = parse_query_address(stripped)
                is_index = True
        if is_index:
            type_index = parse_query_address(query)
            if type_index > 0xFFFFFFFF:
                raise QueryError("a CodeView type index cannot exceed uint32")
            base_sql = """
                SELECT r.type_record_id, r.program_id, r.type_index
                FROM codeview_type_records r
                WHERE r.type_index = ?
            """
            parameters: tuple[object, ...] = (type_index,)
            query_document = {
                "mode": "type_index",
                "type_index": type_index,
                "type_index_hex": f"0x{type_index:X}",
            }
        else:
            if not isinstance(query, str) or not query.strip():
                raise QueryError("a CodeView name query cannot be empty")
            name = query.strip()
            if name_mode == "exact":
                predicate = """
                    t.display_name = ? OR t.unique_name = ? OR
                    a.rendered_type = ?
                """
            else:
                predicate = """
                    instr(lower(t.display_name), lower(?)) > 0 OR
                    instr(lower(coalesce(t.unique_name, '')), lower(?)) > 0 OR
                    instr(lower(a.rendered_type), lower(?)) > 0
                """
            base_sql = f"""
                SELECT DISTINCT r.type_record_id, r.program_id, r.type_index
                FROM codeview_type_records r
                JOIN codeview_type_record_assertions a USING (type_record_id)
                LEFT JOIN codeview_tag_layouts t
                  ON t.type_record_id = r.type_record_id
                 AND t.extraction_id = a.extraction_id
                WHERE {predicate}
            """
            parameters = (name, name, name)
            query_document = {
                "mode": "name",
                "name": name,
                "name_mode": name_mode,
                "searched_fields": [
                    "display_name",
                    "unique_name",
                    "rendered_type",
                ],
            }
        total = self._scalar(f"SELECT COUNT(*) FROM ({base_sql})", parameters)
        ids = self._rows(
            f"SELECT type_record_id FROM ({base_sql}) "
            "ORDER BY program_id, type_index, type_record_id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        )
        records = [
            record
            for record in (
                self._codeview_type_record(
                    str(item["type_record_id"]),
                    member_limit=member_limit,
                    member_offset=member_offset,
                )
                for item in ids
            )
            if record is not None
        ]
        all_layout_flags = [
            bool(layout["is_forward_reference"])
            for record in records
            for layout in record["tag_layouts"]
        ]
        reasons: list[str] = []
        if total == 0:
            reasons.append("no_codeview_type_match")
        if total > 1:
            reasons.append("multiple_physical_type_identities_match")
        if any(all_layout_flags) and not all(all_layout_flags):
            reasons.append("forward_references_and_definitions_coexist")
        return {
            "kind": "codeview_type_lookup",
            "query": query_document,
            "found": total > 0,
            "physical_records": records,
            "physical_records_page": _paging(
                limit, offset, total, len(records)
            ),
            "ambiguity": _ambiguity(*reasons),
            "identity_policy": (
                "duplicate tag spellings, unique names, type indices, and "
                "forward references remain separate physical identities"
            ),
        }

    def _data_symbol_record(self, data_record_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT r.data_record_id, r.program_id, p.name AS program_name,
                   p.platform, r.source_record_id, r.module_index,
                   r.symbol_stream, r.record_offset
            FROM data_symbol_records r JOIN programs p USING (program_id)
            WHERE r.data_record_id = ?
            """,
            (data_record_id,),
        )
        if row is None:
            return None
        assertions = self._rows(
            """
            SELECT a.assertion_id, a.extraction_id, a.module_name,
                   a.record_length, a.record_kind, a.record_kind_code,
                   a.resolved_va, a.address_group_id, a.section,
                   a.section_offset, a.type_index, a.raw_name,
                   ag.address_space, ag.kind AS address_kind,
                   ag.details_json AS address_details_json
            FROM data_symbol_record_assertions a
            LEFT JOIN address_groups ag
              ON ag.address_group_id = a.address_group_id
             AND ag.program_id = a.program_id
            WHERE a.data_record_id = ?
            ORDER BY a.extraction_id, a.assertion_id
            """,
            (data_record_id,),
        )
        for assertion in assertions:
            assertion["is_resolved"] = assertion["resolved_va"] is not None
            assertion["resolved_va_hex"] = _hex(
                None
                if assertion["resolved_va"] is None
                else int(assertion["resolved_va"])
            )
            assertion["type_index_hex"] = (
                f"0x{int(assertion['type_index']):X}"
            )
            assertion["address_details"] = _decode_json(
                assertion.pop("address_details_json")
            )
        row["assertions"] = assertions
        return row

    def xbox_data(
        self,
        query: int | str,
        *,
        name_mode: str = "exact",
        address_space: str = "xbox-va",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Find typed Xbox data records without collapsing aliases."""

        limit, offset = _validate_page(limit, offset)
        if name_mode not in {"exact", "contains"}:
            raise QueryError("name_mode must be 'exact' or 'contains'")
        is_address = isinstance(query, int) and not isinstance(query, bool)
        address: int | None = None
        if isinstance(query, str):
            stripped = query.strip()
            if stripped.lower().startswith("0x") or re.fullmatch(r"[0-9]+", stripped):
                address = parse_query_address(stripped)
                is_address = True
        if is_address:
            address = parse_query_address(query)
            base_sql = """
                SELECT DISTINCT r.data_record_id, r.program_id,
                       r.module_index, r.symbol_stream, r.record_offset
                FROM data_symbol_records r
                JOIN programs p USING (program_id)
                JOIN data_symbol_record_assertions a USING (data_record_id)
                JOIN address_groups ag
                  ON ag.address_group_id = a.address_group_id
                 AND ag.program_id = a.program_id
                WHERE p.platform = 'xbox360' AND ag.address_space = ?
                  AND a.resolved_va = ?
            """
            parameters: tuple[object, ...] = (address_space, address)
            query_document = {
                "mode": "address",
                "address": address,
                "address_hex": _hex(address),
                "address_space": address_space,
            }
        else:
            if not isinstance(query, str) or not query.strip():
                raise QueryError("an Xbox data-symbol name cannot be empty")
            name = query.strip()
            predicate = (
                "a.raw_name = ?"
                if name_mode == "exact"
                else "instr(lower(a.raw_name), lower(?)) > 0"
            )
            base_sql = f"""
                SELECT DISTINCT r.data_record_id, r.program_id,
                       r.module_index, r.symbol_stream, r.record_offset
                FROM data_symbol_records r
                JOIN programs p USING (program_id)
                JOIN data_symbol_record_assertions a USING (data_record_id)
                WHERE p.platform = 'xbox360' AND {predicate}
            """
            parameters = (name,)
            query_document = {
                "mode": "name",
                "name": name,
                "name_mode": name_mode,
            }
        total = self._scalar(f"SELECT COUNT(*) FROM ({base_sql})", parameters)
        ids = self._rows(
            f"SELECT data_record_id FROM ({base_sql}) "
            "ORDER BY program_id, module_index, symbol_stream, record_offset, "
            "data_record_id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        )
        records = [
            record
            for record in (
                self._data_symbol_record(str(item["data_record_id"]))
                for item in ids
            )
            if record is not None
        ]
        unresolved = sum(
            1
            for record in records
            if any(not assertion["is_resolved"] for assertion in record["assertions"])
        )
        reasons: list[str] = []
        if total == 0:
            reasons.append("no_data_symbol_match")
        if is_address and total > 1:
            reasons.append("same_address_has_multiple_physical_data_records")
        if unresolved:
            reasons.append("one_or_more_records_have_unresolved_addresses")
        return {
            "kind": "xbox_data_lookup",
            "query": query_document,
            "found": total > 0,
            "physical_records": records,
            "physical_records_page": _paging(
                limit, offset, total, len(records)
            ),
            "ambiguity": _ambiguity(*reasons),
            "identity_policy": (
                "same-address aliases and unresolved physical records are "
                "returned independently; no preferred symbol is selected"
            ),
        }

    def _raw_vftable_record(
        self, vftable_record_id: str
    ) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT r.vftable_record_id, r.program_id, p.name AS program_name,
                   p.platform, r.source_record_id, r.symbol_record_stream,
                   r.record_offset, r.record_length, r.raw_record_sha256,
                   lower(hex(r.raw_record)) AS raw_record_hex
            FROM xbox_vftable_symbol_records r
            JOIN programs p USING (program_id)
            WHERE r.vftable_record_id = ?
            """,
            (vftable_record_id,),
        )
        if row is None:
            return None
        assertions = self._rows(
            """
            SELECT a.assertion_id, a.extraction_id, a.canonical_name_id,
                   n.decorated_name, n.decorated_name_sha256,
                   lower(hex(n.decorated_name_bytes)) AS decorated_name_hex,
                   a.record_kind, a.record_kind_code, a.public_flags,
                   a.section, a.section_offset, a.resolved_va,
                   a.address_group_id, a.owner_encoding,
                   a.qualifier_encoding, a.role_encoding, a.parse_status,
                   a.is_template_owner, a.is_template_qualifier
            FROM xbox_vftable_symbol_assertions a
            JOIN xbox_vftable_name_identities n USING (canonical_name_id)
            WHERE a.vftable_record_id = ?
            ORDER BY a.extraction_id, a.assertion_id
            """,
            (vftable_record_id,),
        )
        for assertion in assertions:
            assertion["resolved_va_hex"] = _hex(
                None
                if assertion["resolved_va"] is None
                else int(assertion["resolved_va"])
            )
            assertion["is_template_owner"] = bool(
                assertion["is_template_owner"]
            )
            assertion["is_template_qualifier"] = bool(
                assertion["is_template_qualifier"]
            )
        row["assertions"] = assertions
        return row

    def _vftable_pointer_run(
        self, pointer_run_id: str, *, slot_limit: int, slot_offset: int
    ) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT pointer_run_id, extraction_id, program_id, source_run_id,
                   address_observation_id, table_address_group_id, table_va,
                   observed_pointer_count, termination_kind, termination_va,
                   lower(hex(termination_word)) AS termination_word_hex,
                   next_vftable_address_group_id, next_vftable_va,
                   known_boundary_slot_index, boundary_relation,
                   extent_semantics
            FROM xbox_vftable_pointer_runs WHERE pointer_run_id = ?
            """,
            (pointer_run_id,),
        )
        if row is None:
            return None
        row["table_va_hex"] = _hex(int(row["table_va"]))
        row["termination_va_hex"] = _hex(
            None
            if row["termination_va"] is None
            else int(row["termination_va"])
        )
        row["next_vftable_va_hex"] = _hex(
            None
            if row["next_vftable_va"] is None
            else int(row["next_vftable_va"])
        )
        row["semantics"] = (
            "observed pointer prefix only; observed_pointer_count is not a "
            "declared or inferred vftable extent"
        )
        total = self._scalar(
            "SELECT COUNT(*) FROM xbox_vftable_pointer_slots "
            "WHERE pointer_run_id = ?",
            (pointer_run_id,),
        )
        slots = self._rows(
            """
            SELECT pointer_slot_id, source_slot_id, slot_index, slot_va,
                   slot_address_group_id, target_va,
                   target_address_group_id, lower(hex(raw_word)) AS raw_word_hex
            FROM xbox_vftable_pointer_slots
            WHERE pointer_run_id = ?
            ORDER BY slot_index, pointer_slot_id LIMIT ? OFFSET ?
            """,
            (pointer_run_id, slot_limit, slot_offset),
        )
        for slot in slots:
            slot["slot_va_hex"] = _hex(int(slot["slot_va"]))
            slot["target_va_hex"] = _hex(int(slot["target_va"]))
        row["observed_pointer_slots"] = slots
        row["observed_pointer_slots_page"] = _paging(
            slot_limit, slot_offset, total, len(slots)
        )
        row["symbol_memberships"] = self._rows(
            """
            SELECT s.run_symbol_id, s.membership_role, s.source_ordinal,
                   s.vftable_record_id, n.canonical_name_id,
                   n.decorated_name
            FROM xbox_vftable_pointer_run_symbols s
            JOIN xbox_vftable_symbol_assertions a
              ON a.extraction_id = s.extraction_id
             AND a.vftable_record_id = s.vftable_record_id
            JOIN xbox_vftable_name_identities n USING (canonical_name_id)
            WHERE s.pointer_run_id = ?
            ORDER BY s.membership_role, s.source_ordinal,
                     s.vftable_record_id
            """,
            (pointer_run_id,),
        )
        row["boundary_diagnostics"] = self._rows(
            """
            SELECT diagnostic_id, diagnostic_scope, source_ordinal,
                   subject_id, code, message
            FROM xbox_vftable_diagnostics
            WHERE pointer_run_id = ?
            ORDER BY source_ordinal, diagnostic_id
            """,
            (pointer_run_id,),
        )
        return row

    def _vftable_address_observation(
        self,
        address_observation_id: str,
        *,
        slot_limit: int,
        slot_offset: int,
    ) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT o.address_observation_id, o.extraction_id, o.program_id,
                   o.source_address_group_id, o.address_group_id,
                   o.table_va, o.member_count
            FROM xbox_vftable_address_observations o
            WHERE o.address_observation_id = ?
            """,
            (address_observation_id,),
        )
        if row is None:
            return None
        row["table_va_hex"] = _hex(int(row["table_va"]))
        members = self._rows(
            """
            SELECT m.membership_id, m.source_ordinal, m.is_ranked,
                   m.vftable_record_id, m.canonical_name_id,
                   n.decorated_name, a.owner_encoding,
                   a.qualifier_encoding, a.role_encoding, a.parse_status
            FROM xbox_vftable_address_members m
            JOIN xbox_vftable_name_identities n USING (canonical_name_id)
            JOIN xbox_vftable_symbol_assertions a
              ON a.extraction_id = m.extraction_id
             AND a.vftable_record_id = m.vftable_record_id
            WHERE m.address_observation_id = ?
            ORDER BY m.source_ordinal, m.vftable_record_id
            """,
            (address_observation_id,),
        )
        for member in members:
            member["is_ranked"] = bool(member["is_ranked"])
        row["physical_members"] = members
        run_id = self._one(
            """
            SELECT pointer_run_id FROM xbox_vftable_pointer_runs
            WHERE address_observation_id = ? ORDER BY pointer_run_id
            """,
            (address_observation_id,),
        )
        row["observed_pointer_prefix"] = (
            None
            if run_id is None
            else self._vftable_pointer_run(
                str(run_id["pointer_run_id"]),
                slot_limit=slot_limit,
                slot_offset=slot_offset,
            )
        )
        row["ambiguity"] = _ambiguity(
            "same_address_has_multiple_physical_vftable_records"
            if len(members) > 1
            else ""
        )
        return row

    def xbox_vftable(
        self,
        query: int | str,
        *,
        name_mode: str = "contains",
        address_space: str = "xbox-va",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
        slot_limit: int = DEFAULT_LIMIT,
        slot_offset: int = 0,
    ) -> dict[str, Any]:
        """Inspect raw Xbox vftable symbols and pointer-prefix observations."""

        limit, offset = _validate_page(limit, offset)
        slot_limit, slot_offset = _validate_page(slot_limit, slot_offset)
        if name_mode not in {"exact", "contains"}:
            raise QueryError("name_mode must be 'exact' or 'contains'")
        is_address = isinstance(query, int) and not isinstance(query, bool)
        address: int | None = None
        if isinstance(query, str):
            stripped = query.strip()
            if stripped.lower().startswith("0x") or re.fullmatch(r"[0-9]+", stripped):
                address = parse_query_address(stripped)
                is_address = True
        if is_address:
            address = parse_query_address(query)
            base_sql = """
                SELECT DISTINCT r.vftable_record_id, r.program_id,
                       r.symbol_record_stream, r.record_offset
                FROM xbox_vftable_symbol_records r
                JOIN programs p USING (program_id)
                JOIN xbox_vftable_symbol_assertions a
                  USING (vftable_record_id)
                JOIN address_groups ag
                  ON ag.address_group_id = a.address_group_id
                 AND ag.program_id = a.program_id
                WHERE p.platform = 'xbox360' AND ag.address_space = ?
                  AND a.resolved_va = ?
            """
            parameters: tuple[object, ...] = (address_space, address)
            query_document = {
                "mode": "address",
                "address": address,
                "address_hex": _hex(address),
                "address_space": address_space,
            }
        else:
            if not isinstance(query, str) or not query.strip():
                raise QueryError("an Xbox vftable name cannot be empty")
            name = query.strip()
            if name_mode == "exact":
                predicate = "n.decorated_name = ? OR a.owner_encoding = ?"
            else:
                predicate = """
                    instr(lower(n.decorated_name), lower(?)) > 0 OR
                    instr(lower(coalesce(a.owner_encoding, '')), lower(?)) > 0
                """
            base_sql = f"""
                SELECT DISTINCT r.vftable_record_id, r.program_id,
                       r.symbol_record_stream, r.record_offset
                FROM xbox_vftable_symbol_records r
                JOIN programs p USING (program_id)
                JOIN xbox_vftable_symbol_assertions a
                  USING (vftable_record_id)
                JOIN xbox_vftable_name_identities n USING (canonical_name_id)
                WHERE p.platform = 'xbox360' AND ({predicate})
            """
            parameters = (name, name)
            query_document = {
                "mode": "name",
                "name": name,
                "name_mode": name_mode,
                "searched_fields": ["decorated_name", "owner_encoding"],
            }
        total = self._scalar(f"SELECT COUNT(*) FROM ({base_sql})", parameters)
        ids = self._rows(
            f"SELECT vftable_record_id FROM ({base_sql}) "
            "ORDER BY program_id, symbol_record_stream, record_offset, "
            "vftable_record_id LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        )
        records = [
            record
            for record in (
                self._raw_vftable_record(str(item["vftable_record_id"]))
                for item in ids
            )
            if record is not None
        ]
        record_ids = [str(item["vftable_record_id"]) for item in records]
        observation_ids: list[str] = []
        if record_ids:
            placeholders = self._placeholders(record_ids)
            observation_ids = [
                str(item["address_observation_id"])
                for item in self._rows(
                    f"""
                    SELECT DISTINCT address_observation_id
                    FROM xbox_vftable_address_members
                    WHERE vftable_record_id IN ({placeholders})
                    ORDER BY address_observation_id
                    """,
                    record_ids,
                )
            ]
        observations = [
            observation
            for observation in (
                self._vftable_address_observation(
                    observation_id,
                    slot_limit=slot_limit,
                    slot_offset=slot_offset,
                )
                for observation_id in observation_ids
            )
            if observation is not None
        ]
        extraction_ids = sorted(
            {
                str(assertion["extraction_id"])
                for record in records
                for assertion in record["assertions"]
            }
        )
        diagnostics: list[dict[str, Any]] = []
        if extraction_ids:
            placeholders = self._placeholders(extraction_ids)
            diagnostics = self._rows(
                f"""
                SELECT diagnostic_id, extraction_id, diagnostic_scope,
                       pointer_run_id, source_ordinal, subject_id, code, message
                FROM xbox_vftable_diagnostics
                WHERE extraction_id IN ({placeholders})
                  AND diagnostic_scope IN ('symbol_extraction', 'pointer_scan')
                ORDER BY extraction_id, diagnostic_scope, source_ordinal,
                         diagnostic_id
                """,
                extraction_ids,
            )
        unresolved = any(
            assertion["resolved_va"] is None
            for record in records
            for assertion in record["assertions"]
        )
        reasons: list[str] = []
        if total == 0:
            reasons.append("no_vftable_symbol_match")
        if any(len(item["physical_members"]) > 1 for item in observations):
            reasons.append("same_address_has_multiple_physical_vftable_records")
        if unresolved:
            reasons.append("one_or_more_vftable_records_have_unresolved_addresses")
        return {
            "kind": "xbox_vftable_lookup",
            "query": query_document,
            "found": total > 0,
            "physical_records": records,
            "physical_records_page": _paging(
                limit, offset, total, len(records)
            ),
            "address_observations": observations,
            "extraction_diagnostics": diagnostics,
            "ambiguity": _ambiguity(*reasons),
            "measurement_policy": (
                "pointer runs are observed pointer prefixes with explicit "
                "termination and boundary diagnostics; their lengths are "
                "never promoted to declared vftable extents"
            ),
            "identity_policy": (
                "every physical S_PUB32 record and every unranked same-address "
                "membership is retained"
            ),
        }

    def _sdk_code_join(self, code_join_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT j.code_join_id, j.extraction_id, j.source_tree_sha256,
                   j.observation_kind, j.source_ordinal, j.program_variant,
                   j.address, j.classification, j.section_name,
                   j.section_executable, exact.function_id,
                   candidate.candidate_function_id
            FROM sdk_code_inventory_joins j
            LEFT JOIN sdk_game_exact_entry_links exact USING (code_join_id)
            LEFT JOIN sdk_unspecified_exact_entry_candidates candidate
              USING (code_join_id)
            WHERE j.code_join_id = ?
            """,
            (code_join_id,),
        )
        if row is None:
            return None
        row["address_hex"] = _hex(int(row["address"]))
        row["section_executable"] = (
            None
            if row["section_executable"] is None
            else bool(row["section_executable"])
        )
        definitive_id = row.pop("function_id")
        candidate_id = row.pop("candidate_function_id")
        if definitive_id is not None:
            row["pc_link"] = {
                "link_kind": "definitive_game_exact_entry",
                "is_definitive": True,
                "function": self._function_brief(str(definitive_id)),
            }
        elif candidate_id is not None:
            row["pc_link"] = {
                "link_kind": "variant_unspecified_exact_entry_candidate",
                "is_definitive": False,
                "candidate_function": self._function_brief(str(candidate_id)),
            }
        else:
            row["pc_link"] = {
                "link_kind": "none",
                "is_definitive": False,
            }
        boundaries = self._rows(
            """
            SELECT boundary_candidate_id, source_candidate_id,
                   prototype_observation_id, source_ordinal, address,
                   inventory_classification, candidate_reason,
                   containing_entry_count
            FROM sdk_boundary_candidates
            WHERE code_join_id = ?
            ORDER BY source_ordinal, boundary_candidate_id
            """,
            (code_join_id,),
        )
        for boundary in boundaries:
            boundary["address_hex"] = _hex(int(boundary["address"]))
            containers = self._rows(
                """
                SELECT container_id, source_ordinal, entry_address,
                       address_group_id
                FROM sdk_boundary_candidate_containers
                WHERE boundary_candidate_id = ?
                ORDER BY source_ordinal, entry_address, container_id
                """,
                (boundary["boundary_candidate_id"],),
            )
            for container in containers:
                container["entry_address_hex"] = _hex(
                    int(container["entry_address"])
                )
            boundary["containing_entries"] = containers
            boundary["promotion_status"] = "candidate_only"
        row["boundary_candidates"] = boundaries
        return row

    def _sdk_prototype(self, observation_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT prototype_observation_id, source_tree_sha256,
                   source_observation_id, source_file_id, program_variant,
                   address, declared_name, signature, evidence_kind,
                   source_path, source_file_sha256, address_line,
                   declaration_line, source_text, address_ordinal,
                   declaration_text
            FROM sdk_prototype_observations
            WHERE prototype_observation_id = ?
            """,
            (observation_id,),
        )
        if row is None:
            return None
        row["observation_kind"] = "prototype"
        row["address_hex"] = _hex(int(row["address"]))
        row["extraction_assertions"] = self._rows(
            """
            SELECT assertion_id, extraction_id, source_ordinal
            FROM sdk_prototype_extraction_assertions
            WHERE prototype_observation_id = ?
            ORDER BY extraction_id, source_ordinal, assertion_id
            """,
            (observation_id,),
        )
        join_ids = self._rows(
            """
            SELECT code_join_id FROM sdk_code_inventory_joins
            WHERE prototype_observation_id = ?
            ORDER BY extraction_id, source_ordinal, code_join_id
            """,
            (observation_id,),
        )
        row["inventory_joins"] = [
            join
            for join in (
                self._sdk_code_join(str(item["code_join_id"]))
                for item in join_ids
            )
            if join is not None
        ]
        return row

    def _sdk_call_target(self, observation_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT call_target_observation_id, source_tree_sha256,
                   source_observation_id, source_file_id, program_variant,
                   address, invocation_kind, helper_name,
                   calling_convention, rendered_return_type,
                   parameter_types_known, rendered_target_type,
                   enclosing_declared_name, enclosing_owner_hint,
                   enclosing_signature, declaration_text, source_path,
                   source_file_sha256, call_line, declaration_line,
                   source_text, address_ordinal
            FROM sdk_call_target_observations
            WHERE call_target_observation_id = ?
            """,
            (observation_id,),
        )
        if row is None:
            return None
        row["observation_kind"] = "call_target"
        row["address_hex"] = _hex(int(row["address"]))
        row["parameter_types_known"] = bool(row["parameter_types_known"])
        row["parameter_types"] = [
            str(item["rendered_type"])
            for item in self._rows(
                """
                SELECT rendered_type FROM sdk_call_parameter_types
                WHERE call_target_observation_id = ? ORDER BY ordinal
                """,
                (observation_id,),
            )
        ]
        row["argument_expressions"] = [
            str(item["expression"])
            for item in self._rows(
                """
                SELECT expression FROM sdk_call_argument_expressions
                WHERE call_target_observation_id = ? ORDER BY ordinal
                """,
                (observation_id,),
            )
        ]
        row["extraction_assertions"] = self._rows(
            """
            SELECT assertion_id, extraction_id, source_ordinal
            FROM sdk_call_target_extraction_assertions
            WHERE call_target_observation_id = ?
            ORDER BY extraction_id, source_ordinal, assertion_id
            """,
            (observation_id,),
        )
        join_ids = self._rows(
            """
            SELECT code_join_id FROM sdk_code_inventory_joins
            WHERE call_target_observation_id = ?
            ORDER BY extraction_id, source_ordinal, code_join_id
            """,
            (observation_id,),
        )
        row["inventory_joins"] = [
            join
            for join in (
                self._sdk_code_join(str(item["code_join_id"]))
                for item in join_ids
            )
            if join is not None
        ]
        return row

    def _sdk_data_observation(self, observation_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT data_observation_id, source_tree_sha256,
                   source_observation_id, source_file_id, program_variant,
                   address, data_kind, declared_name, member_name,
                   declared_type, owner_name, owner_basis, declaration_text,
                   source_path, source_file_sha256, declaration_line
            FROM sdk_data_observations WHERE data_observation_id = ?
            """,
            (observation_id,),
        )
        if row is None:
            return None
        row["observation_kind"] = "data"
        row["address_hex"] = _hex(int(row["address"]))
        row["extraction_assertions"] = self._rows(
            """
            SELECT assertion_id, extraction_id, source_ordinal
            FROM sdk_data_extraction_assertions
            WHERE data_observation_id = ?
            ORDER BY extraction_id, source_ordinal, assertion_id
            """,
            (observation_id,),
        )
        joins = self._rows(
            """
            SELECT data_join_id, extraction_id, source_tree_sha256,
                   source_ordinal, program_variant, address, data_kind,
                   classification, section_name, section_executable
            FROM sdk_data_inventory_joins WHERE data_observation_id = ?
            ORDER BY extraction_id, source_ordinal, data_join_id
            """,
            (observation_id,),
        )
        for join in joins:
            join["address_hex"] = _hex(int(join["address"]))
            join["section_executable"] = (
                None
                if join["section_executable"] is None
                else bool(join["section_executable"])
            )
            join["pc_link"] = {
                "link_kind": "none",
                "is_definitive": False,
                "reason": "SDK data observations are classified, not promoted to functions",
            }
        row["inventory_joins"] = joins
        return row

    def _sdk_observation(
        self, observation_kind: str, observation_id: str
    ) -> dict[str, Any] | None:
        if observation_kind == "prototype":
            return self._sdk_prototype(observation_id)
        if observation_kind == "call_target":
            return self._sdk_call_target(observation_id)
        return self._sdk_data_observation(observation_id)

    def sdk(
        self,
        query: int | str,
        *,
        name_mode: str = "contains",
        program_variant: str | None = None,
        observation_kind: str = "all",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Find SDK source observations and their non-promoting PC joins."""

        limit, offset = _validate_page(limit, offset)
        if name_mode not in {"exact", "contains"}:
            raise QueryError("name_mode must be 'exact' or 'contains'")
        variants = {"game", "geck", "unspecified_pc"}
        if program_variant is not None and program_variant not in variants:
            raise QueryError(
                "program_variant must be game, geck, unspecified_pc, or None"
            )
        kinds = {"prototype", "call_target", "data"}
        if observation_kind != "all" and observation_kind not in kinds:
            raise QueryError(
                "observation_kind must be prototype, call_target, data, or all"
            )
        selected_kinds = (
            ("prototype", "call_target", "data")
            if observation_kind == "all"
            else (observation_kind,)
        )
        is_address = isinstance(query, int) and not isinstance(query, bool)
        address: int | None = None
        text_query: str | None = None
        if isinstance(query, str):
            stripped = query.strip()
            if stripped.lower().startswith("0x") or re.fullmatch(r"[0-9]+", stripped):
                address = parse_query_address(stripped)
                is_address = True
            else:
                text_query = stripped
        if is_address:
            address = parse_query_address(query)
        elif not isinstance(query, str) or not text_query:
            raise QueryError("an SDK text query cannot be empty")

        table_specs = {
            "prototype": (
                "sdk_prototype_observations",
                "prototype_observation_id",
                (
                    "declared_name",
                    "signature",
                    "declaration_text",
                    "source_path",
                    "source_text",
                ),
            ),
            "call_target": (
                "sdk_call_target_observations",
                "call_target_observation_id",
                (
                    "helper_name",
                    "enclosing_declared_name",
                    "enclosing_owner_hint",
                    "enclosing_signature",
                    "declaration_text",
                    "rendered_target_type",
                    "source_path",
                    "source_text",
                ),
            ),
            "data": (
                "sdk_data_observations",
                "data_observation_id",
                (
                    "declared_name",
                    "member_name",
                    "owner_name",
                    "declared_type",
                    "declaration_text",
                    "source_path",
                ),
            ),
        }
        parts: list[str] = []
        parameters: list[object] = []
        for selected_kind in selected_kinds:
            table, id_column, text_fields = table_specs[selected_kind]
            if is_address:
                predicate = "o.address = ?"
                arm_parameters: list[object] = [address]
            else:
                if name_mode == "exact":
                    predicates = [f"coalesce(o.{field}, '') = ?" for field in text_fields]
                else:
                    predicates = [
                        f"instr(lower(coalesce(o.{field}, '')), lower(?)) > 0"
                        for field in text_fields
                    ]
                predicate = "(" + " OR ".join(predicates) + ")"
                arm_parameters = [text_query] * len(text_fields)
            if program_variant is not None:
                predicate += " AND o.program_variant = ?"
                arm_parameters.append(program_variant)
            parts.append(
                f"""
                SELECT '{selected_kind}' AS observation_kind,
                       o.{id_column} AS observation_id,
                       o.program_variant, o.address, o.source_tree_sha256,
                       o.source_path
                FROM {table} o WHERE {predicate}
                """
            )
            parameters.extend(arm_parameters)
        base_sql = " UNION ALL ".join(parts)
        total = self._scalar(f"SELECT COUNT(*) FROM ({base_sql})", parameters)
        ids = self._rows(
            f"SELECT observation_kind, observation_id FROM ({base_sql}) "
            "ORDER BY observation_kind, program_variant, address, "
            "source_tree_sha256, source_path, observation_id "
            "LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        )
        observations = [
            item
            for item in (
                self._sdk_observation(
                    str(row["observation_kind"]), str(row["observation_id"])
                )
                for row in ids
            )
            if item is not None
        ]
        observed_variants = sorted(
            {str(item["program_variant"]) for item in observations}
        )
        link_kinds = sorted(
            {
                str(join["pc_link"]["link_kind"])
                for item in observations
                for join in item["inventory_joins"]
            }
        )
        boundary_count = sum(
            len(join.get("boundary_candidates", []))
            for item in observations
            for join in item["inventory_joins"]
        )
        reasons: list[str] = []
        if total == 0:
            reasons.append("no_sdk_observation_match")
        if total > 1:
            reasons.append("multiple_source_observations_match")
        if len(observed_variants) > 1:
            reasons.append("multiple_program_variants_match")
        if "variant_unspecified_exact_entry_candidate" in link_kinds:
            reasons.append("one_or_more_pc_entry_links_are_candidates_only")
        if boundary_count:
            reasons.append("one_or_more_addresses_are_boundary_candidates")
        query_document: dict[str, Any] = {
            "mode": "address" if is_address else "source_text",
            "program_variant": program_variant,
            "observation_kind": observation_kind,
        }
        if is_address:
            query_document.update(
                {"address": address, "address_hex": _hex(address)}
            )
        else:
            query_document.update(
                {
                    "text": text_query,
                    "name_mode": name_mode,
                    "searched_categories": [
                        "declaration",
                        "name",
                        "signature_or_type",
                        "source_file",
                    ],
                }
            )
        return {
            "kind": "sdk_lookup",
            "query": query_document,
            "found": total > 0,
            "observations": observations,
            "observations_page": _paging(
                limit, offset, total, len(observations)
            ),
            "observed_program_variants": observed_variants,
            "observed_pc_link_kinds": link_kinds,
            "boundary_candidate_count_on_page": boundary_count,
            "ambiguity": _ambiguity(*reasons),
            "promotion_policy": (
                "only GAME pc_function_entry joins are definitive; "
                "unspecified-PC entry joins remain candidates, GECK joins "
                "never receive PC function links, and boundary observations "
                "remain candidates"
            ),
        }

    def candidates(
        self,
        category: str = "ambiguous",
        *,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List unresolved, conflicted, ambiguous, or all candidate records."""

        limit, offset = _validate_page(limit, offset)
        if category not in {"unresolved", "conflicted", "ambiguous", "all"}:
            raise QueryError(
                "category must be unresolved, conflicted, ambiguous, or all"
            )
        if category == "unresolved":
            base_sql = """
                SELECT u.target_id AS item_id
                FROM unresolved_targets u JOIN programs p USING (program_id)
                WHERE u.status = 'open'
            """
            total = self._scalar(f"SELECT COUNT(*) FROM ({base_sql})")
            ids = self._rows(
                f"SELECT item_id FROM ({base_sql}) ORDER BY item_id LIMIT ? OFFSET ?",
                (limit, offset),
            )
            items = [
                {"item_kind": "unresolved_target", "target": target}
                for target in (
                    self._target(str(row["item_id"])) for row in ids
                )
                if target is not None
            ]
        elif category == "conflicted":
            base_sql = """
                SELECT 'hypothesis_set' AS item_kind,
                       hypothesis_set_id AS item_id
                FROM match_hypothesis_sets WHERE status = 'conflicted'
                UNION ALL
                SELECT 'scalar_claim' AS item_kind, claim_id AS item_id
                FROM match_claims WHERE status = 'conflicted'
            """
            total = self._scalar(f"SELECT COUNT(*) FROM ({base_sql})")
            ids = self._rows(
                f"SELECT item_kind, item_id FROM ({base_sql}) "
                "ORDER BY item_kind, item_id LIMIT ? OFFSET ?",
                (limit, offset),
            )
            items = []
            for row in ids:
                if row["item_kind"] == "hypothesis_set":
                    record = self._hypothesis_set(str(row["item_id"]), fold_member_limit=limit)
                else:
                    record = self._claim(str(row["item_id"]))
                items.append({"item_kind": row["item_kind"], "record": record})
        else:
            where = "h.status IN ('candidate', 'conflicted')"
            if category == "ambiguous":
                where += """
                  AND (
                    (SELECT COUNT(*) FROM match_hypothesis_alternatives a
                     WHERE a.hypothesis_set_id = h.hypothesis_set_id) > 1
                    OR EXISTS (
                        SELECT 1 FROM match_hypothesis_alternatives a
                        WHERE a.hypothesis_set_id = h.hypothesis_set_id
                          AND a.xbox_fold_group_id IS NOT NULL
                    )
                  )
                """
            base_sql = f"""
                SELECT h.hypothesis_set_id FROM match_hypothesis_sets h
                WHERE {where}
            """
            page = self._hypothesis_page(
                base_sql, (), limit=limit, offset=offset
            )
            items = [
                {"item_kind": "hypothesis_set", "record": item}
                for item in page["items"]
            ]
            total = int(page["page"]["total"])
        return {
            "kind": "candidate_listing",
            "category": category,
            "items": items,
            "page": _paging(limit, offset, total, len(items)),
            "ambiguity_policy": (
                "multiple alternatives and fold bundles are listed; no winner is selected"
            ),
        }


def _display_names(endpoint: Mapping[str, Any] | None) -> str:
    if not endpoint:
        return "<missing>"
    names = endpoint.get("names")
    if isinstance(names, list) and names:
        return ", ".join(str(item.get("name")) for item in names[:3])
    return str(endpoint.get("name_hint") or endpoint.get("function_id") or endpoint.get("target_id"))


def _display_flow_endpoint(endpoint: Mapping[str, Any] | None) -> str:
    if not endpoint:
        return "<missing endpoint>"
    endpoint_kind = endpoint.get("endpoint_kind")
    if endpoint_kind == "unique_procedure":
        function = endpoint.get("function")
        if isinstance(function, Mapping):
            return (
                f"unique {function.get('function_id')} "
                f"({_display_names(function)})"
            )
        return "unique <missing procedure>"
    if endpoint_kind == "fold_group":
        group = endpoint.get("fold_group")
        if isinstance(group, Mapping):
            return (
                f"fold {group.get('fold_group_id')} "
                f"({group.get('member_count', 0)} members)"
            )
        return "fold <missing group>"
    if endpoint_kind == "address_only":
        return (
            f"address-only {endpoint.get('address_hex')} "
            f"[{endpoint.get('classification')}]"
        )
    return "indirect runtime target"


def render_human(document: Mapping[str, Any]) -> str:
    """Render one query document as compact, deterministic research text."""

    kind = document.get("kind")
    lines: list[str] = []
    if kind == "pc_address":
        query = document["query"]
        lines.append(
            f"PC {query['address_space']}:{query['address_hex']}"
        )
        page = document["functions_page"]
        lines.append(
            f"Functions: {page['total']} (showing {page['returned']} from {page['offset']})"
        )
        for function in document["functions"]:
            lines.append(
                f"  {function['function_id']}  {_display_names(function)}"
            )
            for source in function.get("sources", []):
                lines.append(
                    f"    source: {source['normalized_path']}:{source['line_start']}"
                )
            signature = function.get("signature")
            if signature:
                rendered = signature.get("rendered_signature") or signature.get("error_code")
                lines.append(f"    signature: {rendered}")
        lines.append(
            f"Vtable slot occurrences: {len(document['vtable_slots_targeting_address'])}"
        )
        hypotheses = document["mapping_hypotheses"]
        lines.append(f"Mapping hypotheses: {hypotheses['page']['total']}")
        for item in hypotheses["items"]:
            marker = "ambiguous" if item["ambiguity"]["is_ambiguous"] else "single"
            lines.append(
                f"  {item['hypothesis_set_id']} [{item['status']}; {marker}] "
                f"alternatives={item['alternative_count']} evidence={len(item['evidence'])}"
            )
    elif kind == "xbox_lookup":
        query = document["query"]
        label = (
            f"{query['address_space']}:{query['address_hex']}"
            if query["mode"] == "address"
            else f"{query['name_mode']} name {query['name']!r}"
        )
        lines.append(f"Xbox {label}")
        page = document["physical_records_page"]
        lines.append(
            f"Physical PDB records: {page['total']} "
            f"(showing {page['returned']} from {page['offset']})"
        )
        for record in document["physical_records"]:
            lines.append(
                f"  {record['address_hex']} {record['function_id']}  {_display_names(record)}"
            )
        lines.append(f"Fold groups: {len(document['fold_groups'])}")
        for group in document["fold_groups"]:
            lines.append(
                f"  {group['fold_group_id']} members={group.get('member_count', 0)}"
            )
        hypotheses = document["pc_mapping_hypotheses"]
        lines.append(f"PC mapping hypotheses: {hypotheses['page']['total']}")
    elif kind == "class_lookup":
        query = document["query"]
        lines.append(f"Class {query['name_mode']} {query['name']!r}")
        page = document["classes_page"]
        lines.append(
            f"Class identities: {page['total']} "
            f"(showing {page['returned']} from {page['offset']})"
        )
        for class_record in document["classes"]:
            lines.append(
                f"  [{class_record['platform']}] {class_record['class_id']} "
                f"tables={len(class_record['vtables'])}"
            )
            for table in class_record["vtables"]:
                lines.append(
                    f"    {table['vfptr_role']} {table['address_hex']} "
                    f"slots={table['slots_page']['total']} "
                    f"alignments={len(table['alignment_candidates'])}"
                )
        lines.append(f"Alignment issues: {len(document['alignment_issues'])}")
    elif kind == "xbox_control_flow":
        query = document["query"]
        lines.append("Xbox control flow")
        if query.get("procedure") is not None:
            if query.get("procedure_mode") == "address":
                lines.append(
                    f"Procedure entry: {query['address_space']}:"
                    f"{query['procedure_address_hex']}"
                )
            else:
                lines.append(
                    f"Procedure {query.get('name_mode')}: "
                    f"{query.get('procedure')!r}"
                )
        if query.get("site_address") is not None:
            lines.append(
                f"Physical site: {query['address_space']}:"
                f"{query['site_address_hex']}"
            )
        procedure_page = document["procedure_records_page"]
        lines.append(
            f"Procedure records: {procedure_page['total']} "
            f"(showing {procedure_page['returned']} from "
            f"{procedure_page['offset']})"
        )
        for procedure in document["procedure_records"]:
            lines.append(
                f"  {procedure['function_id']} {procedure['address_hex']}  "
                f"{_display_names(procedure)}"
            )
        site_page = document["physical_sites_page"]
        lines.append(
            f"Physical sites: {site_page['total']} "
            f"(showing {site_page['returned']} from {site_page['offset']})"
        )
        for site in document["physical_sites"]:
            lines.append(
                f"  {site['address_hex']} {site['site_id']} "
                f"assertions={site['assertions_page']['total']}"
            )
            for assertion in site["assertions"]:
                lines.append(
                    f"    {assertion['extraction_id']} "
                    f"{assertion['branch_kind']} -> "
                    f"{_display_flow_endpoint(assertion['target_endpoint'])}"
                )
        membership_page = document["logical_memberships_page"]
        lines.append(
            f"Logical memberships: {membership_page['total']} "
            f"(showing {membership_page['returned']} from "
            f"{membership_page['offset']})"
        )
        for membership in document["logical_memberships"]:
            lines.append(
                f"  {membership['procedure_record_id']} @ "
                f"{membership['site_address_hex']} "
                f"roles={','.join(membership['roles']) or '<none>'}"
            )
            for assertion in membership["role_assertions"]:
                site_observation = assertion.get("site_observation")
                endpoint = (
                    site_observation.get("target_endpoint")
                    if isinstance(site_observation, Mapping)
                    else None
                )
                lines.append(
                    f"    {assertion['extraction_id']} {assertion['role']} -> "
                    f"{_display_flow_endpoint(endpoint)}"
                )
        scan_page = document["scan_coverage_page"]
        lines.append(
            f"Scan coverage: {scan_page['total']} "
            f"(showing {scan_page['returned']} from {scan_page['offset']})"
        )
        for scan in document["scan_coverage"]:
            lines.append(
                f"  {scan['procedure_record_id']} [{scan['status']}] "
                f"bytes={scan['scanned_size']}/{scan['declared_size']} "
                f"uses={scan['persisted_branch_use_count']}/"
                f"{scan['source_branch_use_count']}"
            )
    elif kind == "codeview_type_lookup":
        query = document["query"]
        label = (
            query["type_index_hex"]
            if query["mode"] == "type_index"
            else f"{query['name_mode']} name {query['name']!r}"
        )
        page = document["physical_records_page"]
        lines.append(f"CodeView type {label}")
        lines.append(
            f"Physical records: {page['total']} "
            f"(showing {page['returned']} from {page['offset']})"
        )
        for record in document["physical_records"]:
            lines.append(
                f"  {record['type_index_hex']} {record['type_record_id']} "
                f"leaf={record['leaf_kind_hex']}"
            )
            for layout in record["tag_layouts"]:
                disposition = (
                    "forward" if layout["is_forward_reference"] else "definition"
                )
                lines.append(
                    f"    {layout['tag_kind']} {layout['display_name']} "
                    f"[{disposition}] members={layout['members_page']['total']}"
                )
    elif kind == "xbox_data_lookup":
        query = document["query"]
        label = (
            query["address_hex"]
            if query["mode"] == "address"
            else f"{query['name_mode']} name {query['name']!r}"
        )
        page = document["physical_records_page"]
        lines.append(f"Xbox data {label}")
        lines.append(
            f"Physical records: {page['total']} "
            f"(showing {page['returned']} from {page['offset']})"
        )
        for record in document["physical_records"]:
            for assertion in record["assertions"]:
                location = assertion["resolved_va_hex"] or "<unresolved>"
                lines.append(
                    f"  {location} {assertion['raw_name']} "
                    f"type={assertion['type_index_hex']} "
                    f"record={record['data_record_id']}"
                )
    elif kind == "xbox_vftable_lookup":
        query = document["query"]
        label = (
            query["address_hex"]
            if query["mode"] == "address"
            else f"{query['name_mode']} name {query['name']!r}"
        )
        page = document["physical_records_page"]
        lines.append(f"Xbox raw vftable {label}")
        lines.append(
            f"Physical records: {page['total']} "
            f"(showing {page['returned']} from {page['offset']})"
        )
        for record in document["physical_records"]:
            names = [
                str(assertion["decorated_name"])
                for assertion in record["assertions"]
            ]
            lines.append(
                f"  {record['vftable_record_id']} {', '.join(names)}"
            )
        for observation in document["address_observations"]:
            run = observation.get("observed_pointer_prefix")
            lines.append(
                f"  group {observation['table_va_hex']} "
                f"records={len(observation['physical_members'])}"
            )
            if isinstance(run, Mapping):
                lines.append(
                    f"    observed pointer prefix: "
                    f"{run['observed_pointer_count']} pointers; "
                    f"boundary={run['boundary_relation']}"
                )
    elif kind == "sdk_lookup":
        query = document["query"]
        label = (
            query["address_hex"]
            if query["mode"] == "address"
            else f"{query['name_mode']} source text {query['text']!r}"
        )
        page = document["observations_page"]
        lines.append(f"SDK {label}")
        lines.append(
            f"Source observations: {page['total']} "
            f"(showing {page['returned']} from {page['offset']})"
        )
        for observation in document["observations"]:
            name = (
                observation.get("declared_name")
                or observation.get("enclosing_declared_name")
                or observation.get("helper_name")
                or observation.get("member_name")
                or "<unnamed>"
            )
            classifications = sorted(
                {
                    str(join["classification"])
                    for join in observation["inventory_joins"]
                }
            )
            lines.append(
                f"  [{observation['program_variant']}] "
                f"{observation['observation_kind']} "
                f"{observation['address_hex']} {name} "
                f"classification={','.join(classifications) or '<none>'}"
            )
    elif kind == "candidate_listing":
        page = document["page"]
        lines.append(
            f"{str(document['category']).title()} candidates: {page['total']} "
            f"(showing {page['returned']} from {page['offset']})"
        )
        for item in document["items"]:
            record = item.get("record") or item.get("target") or {}
            identity = (
                record.get("hypothesis_set_id")
                or record.get("claim_id")
                or record.get("target_id")
                or "<missing>"
            )
            lines.append(f"  [{item['item_kind']}] {identity}")
    else:
        return json.dumps(document, indent=2, sort_keys=True)

    ambiguity = document.get("ambiguity")
    if isinstance(ambiguity, Mapping) and ambiguity.get("is_ambiguous"):
        lines.append("Ambiguity: " + ", ".join(ambiguity.get("reasons", [])))
    return "\n".join(lines)


__all__ = [
    "AtlasQuery",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "QueryError",
    "parse_query_address",
    "render_human",
]
