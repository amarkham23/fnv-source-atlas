"""Read-only SQLite adapter for :mod:`fnv_atlas.control_flow_matching`.

The adapter performs SELECTs only.  It does not open paths, change connection
pragmas, create temporary objects, or persist matcher output.  Logical Xbox
uses are paired with physical site assertions on the full producer identity:
``(extraction_id, program_id, site_id)``.
"""

from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from .control_flow_matching import (
    ControlFlowMatchingResult,
    Endpoint,
    FoldMembership,
    MappingAlternative,
    PcCallEdge,
    XboxFlowOccurrence,
    analyze_control_flow_candidates,
)


class ControlFlowMatchingAdapterError(RuntimeError):
    """Persisted rows cannot be represented by the pure matcher contract."""


@dataclass(frozen=True, slots=True)
class ControlFlowMatchingInputs:
    mapping_alternatives: tuple[MappingAlternative, ...]
    pc_call_edges: tuple[PcCallEdge, ...]
    xbox_flow_occurrences: tuple[XboxFlowOccurrence, ...]
    fold_memberships: tuple[FoldMembership, ...]


def _candidate_status(
    hypothesis_status: str,
    claim_status: str | None,
    *,
    producer: str,
) -> str:
    if producer == "fnv_atlas.control_flow_matching":
        return "derived_non_seed"
    if hypothesis_status == "candidate" and (
        claim_status is None or claim_status == "candidate"
    ):
        return "candidate"
    if claim_status is None:
        return f"hypothesis:{hypothesis_status}"
    return f"hypothesis:{hypothesis_status}|claim:{claim_status}"


def _load_mapping_alternatives(
    connection: sqlite3.Connection,
) -> tuple[MappingAlternative, ...]:
    rows = connection.execute(
        """
        SELECT a.alternative_id, a.hypothesis_set_id, a.claim_id,
               h.status AS hypothesis_status, h.provenance_id,
               provenance.producer,
               h.pc_function_id, h.pc_target_id,
               pc_target.address_group_id AS pc_target_address_group_id,
               c.pc_function_id AS claim_pc_function_id,
               c.pc_target_id AS claim_pc_target_id,
               c.xbox_function_id, c.xbox_target_id,
               c.status AS claim_status,
               xbox_target.address_group_id AS xbox_target_address_group_id,
               a.xbox_fold_group_id
        FROM match_hypothesis_alternatives a
        JOIN match_hypothesis_sets h USING (hypothesis_set_id)
        JOIN provenance ON provenance.provenance_id = h.provenance_id
        LEFT JOIN match_claims c ON c.claim_id = a.claim_id
        LEFT JOIN unresolved_targets pc_target
          ON pc_target.target_id = h.pc_target_id
        LEFT JOIN unresolved_targets xbox_target
          ON xbox_target.target_id = c.xbox_target_id
        ORDER BY a.alternative_id
        """
    )
    alternatives: list[MappingAlternative] = []
    for row in rows:
        (
            alternative_id,
            hypothesis_set_id,
            claim_id,
            hypothesis_status,
            provenance_id,
            producer,
            pc_function_id,
            pc_target_id,
            pc_target_address_group_id,
            claim_pc_function_id,
            claim_pc_target_id,
            xbox_function_id,
            xbox_target_id,
            claim_status,
            xbox_target_address_group_id,
            xbox_fold_group_id,
        ) = tuple(row)
        if pc_function_id is not None:
            pc_endpoint = Endpoint("pc", "function", str(pc_function_id))
            claim_pc_identity = (
                None
                if claim_id is None
                else ("function", claim_pc_function_id)
            )
            hypothesis_pc_identity = ("function", pc_function_id)
        else:
            pc_endpoint = Endpoint(
                "pc",
                "unresolved_target",
                str(pc_target_id),
                address_group_id=(
                    None
                    if pc_target_address_group_id is None
                    else str(pc_target_address_group_id)
                ),
            )
            claim_pc_identity = (
                None
                if claim_id is None
                else ("unresolved_target", claim_pc_target_id)
            )
            hypothesis_pc_identity = ("unresolved_target", pc_target_id)
        if claim_pc_identity is not None and claim_pc_identity != hypothesis_pc_identity:
            raise ControlFlowMatchingAdapterError(
                f"alternative {alternative_id!r} has different hypothesis and "
                "claim PC endpoints"
            )

        if claim_id is None:
            if xbox_fold_group_id is None:
                raise ControlFlowMatchingAdapterError(
                    f"alternative {alternative_id!r} has no scalar claim or fold bundle"
                )
            xbox_endpoint = Endpoint(
                "xbox360", "fold_group", str(xbox_fold_group_id)
            )
        elif xbox_function_id is not None:
            xbox_endpoint = Endpoint(
                "xbox360", "function", str(xbox_function_id)
            )
        elif xbox_target_id is not None:
            xbox_endpoint = Endpoint(
                "xbox360",
                "unresolved_target",
                str(xbox_target_id),
                address_group_id=(
                    None
                    if xbox_target_address_group_id is None
                    else str(xbox_target_address_group_id)
                ),
            )
        else:
            raise ControlFlowMatchingAdapterError(
                f"scalar alternative {alternative_id!r} has no Xbox endpoint"
            )
        alternatives.append(
            MappingAlternative(
                hypothesis_set_id=str(hypothesis_set_id),
                alternative_id=str(alternative_id),
                pc_endpoint=pc_endpoint,
                xbox_endpoint=xbox_endpoint,
                claim_id=None if claim_id is None else str(claim_id),
                provenance_id=str(provenance_id),
                producer=str(producer),
                status=_candidate_status(
                    str(hypothesis_status),
                    None if claim_status is None else str(claim_status),
                    producer=str(producer),
                ),
            )
        )
    return tuple(alternatives)


def _load_pc_call_edges(
    connection: sqlite3.Connection,
) -> tuple[PcCallEdge, ...]:
    rows = connection.execute(
        """
        SELECT e.edge_id, e.caller_function_id, e.callee_function_id,
               e.unresolved_target_id, target.address_group_id,
               e.edge_kind, e.provenance_id
        FROM call_edges e
        JOIN programs program USING (program_id)
        LEFT JOIN unresolved_targets target
          ON target.target_id = e.unresolved_target_id
        WHERE program.platform = 'pc'
        ORDER BY e.edge_id
        """
    )
    edges: list[PcCallEdge] = []
    for row in rows:
        (
            edge_id,
            caller_function_id,
            callee_function_id,
            unresolved_target_id,
            target_address_group_id,
            edge_kind,
            provenance_id,
        ) = tuple(row)
        if callee_function_id is not None:
            callee = Endpoint("pc", "function", str(callee_function_id))
        elif unresolved_target_id is not None:
            callee = Endpoint(
                "pc",
                "unresolved_target",
                str(unresolved_target_id),
                address_group_id=(
                    None
                    if target_address_group_id is None
                    else str(target_address_group_id)
                ),
            )
        else:
            raise ControlFlowMatchingAdapterError(
                f"PC call edge {edge_id!r} has no callee endpoint"
            )
        edges.append(
            PcCallEdge(
                edge_id=str(edge_id),
                caller_function_id=str(caller_function_id),
                callee_endpoint=callee,
                edge_kind=str(edge_kind),
                provenance_id=str(provenance_id),
            )
        )
    return tuple(edges)


def _load_xbox_flow_occurrences(
    connection: sqlite3.Connection,
) -> tuple[XboxFlowOccurrence, ...]:
    rows = connection.execute(
        """
        SELECT use_assertion.assertion_id AS use_assertion_id,
               use_assertion.extraction_id,
               use_assertion.use_id,
               use_row.function_id AS caller_function_id,
               use_row.procedure_record_id,
               use_assertion.role,
               site_assertion.assertion_id AS site_assertion_id,
               use_row.site_id,
               site_address.address_space AS site_address_space,
               site_address.address AS site_address,
               site_assertion.target_kind,
               site_assertion.target_function_id,
               site_assertion.target_fold_group_id,
               site_assertion.target_address_group_id,
               target_address.address_space AS target_address_space,
               target_address.address AS target_address,
               extraction.provenance_id
        FROM control_flow_use_assertions use_assertion
        JOIN control_flow_uses use_row
          USING (use_id, program_id)
        JOIN control_flow_site_assertions site_assertion
          ON site_assertion.extraction_id = use_assertion.extraction_id
         AND site_assertion.program_id = use_assertion.program_id
         AND site_assertion.site_id = use_row.site_id
        JOIN control_flow_sites site
          ON site.site_id = use_row.site_id
         AND site.program_id = use_row.program_id
        JOIN address_groups site_address
          ON site_address.address_group_id = site.address_group_id
         AND site_address.program_id = site.program_id
        LEFT JOIN address_groups target_address
          ON target_address.address_group_id = site_assertion.target_address_group_id
         AND target_address.program_id = site_assertion.program_id
        JOIN control_flow_extractions extraction
          ON extraction.extraction_id = use_assertion.extraction_id
         AND extraction.program_id = use_assertion.program_id
        JOIN programs program ON program.program_id = use_assertion.program_id
        WHERE program.platform = 'xbox360'
        ORDER BY use_assertion.assertion_id
        """
    )
    occurrences: list[XboxFlowOccurrence] = []
    for row in rows:
        (
            use_assertion_id,
            extraction_id,
            use_id,
            caller_function_id,
            procedure_record_id,
            role,
            site_assertion_id,
            site_id,
            site_address_space,
            site_address,
            target_kind,
            target_function_id,
            target_fold_group_id,
            target_address_group_id,
            target_address_space,
            target_address,
            provenance_id,
        ) = tuple(row)
        if target_kind == "unique_procedure":
            target = Endpoint(
                "xbox360", "function", str(target_function_id)
            )
        elif target_kind == "fold_group":
            target = Endpoint(
                "xbox360", "fold_group", str(target_fold_group_id)
            )
        elif target_kind in {"executable_non_entry", "outside_executable"}:
            if target_address_group_id is None:
                raise ControlFlowMatchingAdapterError(
                    f"address-only site assertion {site_assertion_id!r} has no "
                    "target address group"
                )
            target = Endpoint(
                "xbox360",
                "address_only",
                str(target_address_group_id),
                address_group_id=str(target_address_group_id),
                address_space=(
                    None
                    if target_address_space is None
                    else str(target_address_space)
                ),
                address=None if target_address is None else int(target_address),
                classification=str(target_kind),
            )
        elif target_kind == "indirect":
            target = Endpoint(
                "xbox360", "indirect", f"indirect:{site_assertion_id}"
            )
        else:
            raise ControlFlowMatchingAdapterError(
                f"unsupported Xbox control-flow target kind {target_kind!r}"
            )
        occurrences.append(
            XboxFlowOccurrence(
                occurrence_id=str(use_assertion_id),
                extraction_id=str(extraction_id),
                use_id=str(use_id),
                use_assertion_id=str(use_assertion_id),
                site_id=str(site_id),
                site_assertion_id=str(site_assertion_id),
                caller_function_id=str(caller_function_id),
                procedure_record_id=str(procedure_record_id),
                role=str(role),
                target_endpoint=target,
                site_address_space=str(site_address_space),
                site_address=int(site_address),
                provenance_id=str(provenance_id),
            )
        )
    return tuple(occurrences)


def _load_fold_memberships(
    connection: sqlite3.Connection,
) -> tuple[FoldMembership, ...]:
    return tuple(
        FoldMembership(str(row[0]), str(row[1]))
        for row in connection.execute(
            """
            SELECT member.fold_group_id, member.function_id
            FROM fold_group_members member
            JOIN fold_groups fold_group USING (fold_group_id)
            JOIN programs program USING (program_id)
            WHERE program.platform = 'xbox360'
            ORDER BY member.fold_group_id, member.function_id
            """
        )
    )


def load_control_flow_matching_inputs(
    connection: sqlite3.Connection,
) -> ControlFlowMatchingInputs:
    """Load normalized matcher inputs using SELECT statements only."""

    return ControlFlowMatchingInputs(
        mapping_alternatives=_load_mapping_alternatives(connection),
        pc_call_edges=_load_pc_call_edges(connection),
        xbox_flow_occurrences=_load_xbox_flow_occurrences(connection),
        fold_memberships=_load_fold_memberships(connection),
    )


def analyze_control_flow_candidates_from_sqlite(
    connection: sqlite3.Connection,
) -> ControlFlowMatchingResult:
    """Load one connection and run the pure candidate analysis without writes."""

    inputs = load_control_flow_matching_inputs(connection)
    return analyze_control_flow_candidates(
        inputs.mapping_alternatives,
        inputs.pc_call_edges,
        inputs.xbox_flow_occurrences,
        inputs.fold_memberships,
    )


__all__ = [
    "ControlFlowMatchingAdapterError",
    "ControlFlowMatchingInputs",
    "analyze_control_flow_candidates_from_sqlite",
    "load_control_flow_matching_inputs",
]
