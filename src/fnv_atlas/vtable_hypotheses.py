"""Materialize conservative vtable alignments as auditable hypotheses.

The structural aligner deliberately stops before resolving slot targets.  This
module performs that next, still non-committal, normalization step.  Every
physical PC/Xbox slot pairing becomes one distinct hypothesis set.  The PC
endpoint is either its canonical exported function or an unresolved address.
The Xbox alternative is exactly one of:

* the sole PDB procedure record at the target VA;
* one fold-group bundle when multiple PDB records share the VA; or
* an unresolved address when the PDB contains no procedure at the VA.

A fold group is never expanded into one alternative per member.  Choosing a
member would assert an identity that identical-code folding does not establish;
the lossless member list remains available through ``ProcedureExtraction`` and
the atlas ``fold_group_members`` relation.

Nothing here assigns confidence, accepts a match, or transfers a name.  Xbox
slot names remain context-only observations copied from the physical slot.
The module has no database dependency: its stable occurrence and semantic-pair
keys are suitable inputs to a persistence adapter, but are useful in tests and
other consumers on their own.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

from .pc_inventory import PCFunction, PCInventory
from .pdb_symbols import AliasGroup, ProcedureExtraction, ProcedureRecord
from .vtable_alignment import (
    VtableAlignmentCandidate,
    VtableAlignmentIssue,
    VtableAlignmentResult,
)
from .vtables import ExtentAssessment, SlotNameObservation, VtableSlot


class VtableHypothesisError(ValueError):
    """Input identities are inconsistent or would require lossy selection."""


_ENDPOINT_KINDS = frozenset(
    {"exact_function", "fold_group", "unresolved_address"}
)


def _stable_id(namespace: str, *components: object) -> str:
    payload = json.dumps(
        {"namespace": namespace, "components": components},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"{namespace}:sha256:{hashlib.sha256(payload).hexdigest()}"


@dataclass(frozen=True, slots=True)
class HypothesisEndpoint:
    """One resolved, folded, or unresolved endpoint without a name claim."""

    platform: str
    endpoint_kind: str
    address_space: str
    address: int
    function_id: str | None = None
    fold_group_id: str | None = None
    fold_member_count: int | None = None

    def __post_init__(self) -> None:
        if self.platform not in {"pc", "xbox360"}:
            raise VtableHypothesisError(
                f"unsupported endpoint platform {self.platform!r}"
            )
        if self.endpoint_kind not in _ENDPOINT_KINDS:
            raise VtableHypothesisError(
                f"unsupported endpoint kind {self.endpoint_kind!r}"
            )
        if not self.address_space:
            raise VtableHypothesisError("endpoint address space cannot be empty")
        if self.address < 0:
            raise VtableHypothesisError("endpoint address cannot be negative")

        if self.endpoint_kind == "exact_function":
            valid = (
                self.function_id is not None
                and self.fold_group_id is None
                and self.fold_member_count is None
            )
        elif self.endpoint_kind == "fold_group":
            valid = (
                self.platform == "xbox360"
                and self.function_id is None
                and self.fold_group_id is not None
                and self.fold_member_count is not None
                and self.fold_member_count > 1
            )
        else:
            valid = (
                self.function_id is None
                and self.fold_group_id is None
                and self.fold_member_count is None
            )
        if not valid:
            raise VtableHypothesisError(
                f"invalid fields for {self.endpoint_kind!r} endpoint"
            )

    @property
    def identity(self) -> tuple[object, ...]:
        """Return the semantic endpoint identity, excluding occurrence data."""

        return (
            self.platform,
            self.endpoint_kind,
            self.address_space,
            self.address,
            self.function_id,
            self.fold_group_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "endpoint_kind": self.endpoint_kind,
            "address_space": self.address_space,
            "address": self.address,
            "function_id": self.function_id,
            "fold_group_id": self.fold_group_id,
            "fold_member_count": self.fold_member_count,
        }


@dataclass(frozen=True, slots=True)
class VtableSlotHypothesisSet:
    """One occurrence-specific, candidate-only PC/Xbox slot hypothesis."""

    hypothesis_set_id: str
    alternative_id: str
    semantic_pair_id: str
    alignment_id: str
    class_name: str
    vfptr_role: str
    subobject_offset: int
    pc_vtable_id: str
    xbox_vtable_id: str
    pc_table_address_space: str
    pc_table_address: int
    xbox_table_address_space: str
    xbox_table_address: int
    pc_role_basis: str
    xbox_role_basis: str
    pc_qualifier: str | None
    xbox_qualifier: str | None
    pc_observed_slot_count: int
    xbox_observed_slot_count: int
    shared_prefix_slot_count: int
    pc_unpaired_tail_count: int
    xbox_unpaired_tail_count: int
    pc_extent: ExtentAssessment
    xbox_extent: ExtentAssessment
    slot_index: int
    pc_slot_id: str
    xbox_slot_id: str
    pc_slot_target_address_space: str
    xbox_slot_target_address_space: str
    pc_raw_target_address: str
    xbox_raw_target_address: str
    pc_subject: HypothesisEndpoint
    xbox_alternative: HypothesisEndpoint
    xbox_name_observations: tuple[SlotNameObservation, ...]
    evidence_effect: str
    evidence_reason: str
    evidence_diagnostics: tuple[str, ...]
    status: str = "candidate"
    scoring_status: str = "unscored"

    def __post_init__(self) -> None:
        if self.pc_subject.platform != "pc":
            raise VtableHypothesisError("hypothesis subject must be a PC endpoint")
        if self.pc_subject.endpoint_kind == "fold_group":
            raise VtableHypothesisError("a PC hypothesis subject cannot be a fold group")
        if self.xbox_alternative.platform != "xbox360":
            raise VtableHypothesisError(
                "hypothesis alternative must be an Xbox 360 endpoint"
            )
        if self.status != "candidate" or self.scoring_status != "unscored":
            raise VtableHypothesisError(
                "vtable hypotheses must remain candidate and unscored"
            )
        if self.evidence_effect not in {"supports", "context"}:
            raise VtableHypothesisError(
                "structural vtable evidence must be supports or context"
            )
        if not self.evidence_reason:
            raise VtableHypothesisError("structural evidence needs an explicit reason")
        if self.slot_index < 0:
            raise VtableHypothesisError("slot index cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_set_id": self.hypothesis_set_id,
            "alternative_id": self.alternative_id,
            "semantic_pair_id": self.semantic_pair_id,
            "status": self.status,
            "scoring_status": self.scoring_status,
            "alignment_id": self.alignment_id,
            "class_name": self.class_name,
            "vfptr_role": self.vfptr_role,
            "subobject_offset": self.subobject_offset,
            "pc_vtable_id": self.pc_vtable_id,
            "xbox_vtable_id": self.xbox_vtable_id,
            "pc_table_address_space": self.pc_table_address_space,
            "pc_table_address": self.pc_table_address,
            "xbox_table_address_space": self.xbox_table_address_space,
            "xbox_table_address": self.xbox_table_address,
            "pc_role_basis": self.pc_role_basis,
            "xbox_role_basis": self.xbox_role_basis,
            "pc_qualifier": self.pc_qualifier,
            "xbox_qualifier": self.xbox_qualifier,
            "pc_observed_slot_count": self.pc_observed_slot_count,
            "xbox_observed_slot_count": self.xbox_observed_slot_count,
            "shared_prefix_slot_count": self.shared_prefix_slot_count,
            "pc_unpaired_tail_count": self.pc_unpaired_tail_count,
            "xbox_unpaired_tail_count": self.xbox_unpaired_tail_count,
            "pc_extent": self.pc_extent.to_dict(),
            "xbox_extent": self.xbox_extent.to_dict(),
            "slot_index": self.slot_index,
            "pc_slot_id": self.pc_slot_id,
            "xbox_slot_id": self.xbox_slot_id,
            "pc_slot_target_address_space": self.pc_slot_target_address_space,
            "xbox_slot_target_address_space": self.xbox_slot_target_address_space,
            "pc_raw_target_address": self.pc_raw_target_address,
            "xbox_raw_target_address": self.xbox_raw_target_address,
            "pc_subject": self.pc_subject.to_dict(),
            # Singular by design.  A fold is a bundle reference, not N choices.
            "xbox_alternative": self.xbox_alternative.to_dict(),
            "xbox_name_observations_context_only": [
                observation.to_dict()
                for observation in self.xbox_name_observations
            ],
            "evidence_effect": self.evidence_effect,
            "evidence_reason": self.evidence_reason,
            "evidence_diagnostics": list(self.evidence_diagnostics),
        }


@dataclass(frozen=True, slots=True)
class VtableHypothesisMaterialization:
    """Deterministic table/slot hypotheses plus every alignment issue."""

    table_alignments: tuple[VtableAlignmentCandidate, ...]
    hypothesis_sets: tuple[VtableSlotHypothesisSet, ...]
    issues: tuple[VtableAlignmentIssue, ...]

    @property
    def table_alignment_count(self) -> int:
        return len(self.table_alignments)

    @property
    def hypothesis_set_count(self) -> int:
        return len(self.hypothesis_sets)

    @property
    def alternative_count(self) -> int:
        # Each set intentionally carries one scalar, fold bundle, or unresolved
        # alternative.  Keeping this explicit makes accidental fan-out visible.
        return len(self.hypothesis_sets)

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    @property
    def pc_exact_count(self) -> int:
        return sum(
            item.pc_subject.endpoint_kind == "exact_function"
            for item in self.hypothesis_sets
        )

    @property
    def pc_unresolved_count(self) -> int:
        return sum(
            item.pc_subject.endpoint_kind == "unresolved_address"
            for item in self.hypothesis_sets
        )

    @property
    def xbox_exact_count(self) -> int:
        return sum(
            item.xbox_alternative.endpoint_kind == "exact_function"
            for item in self.hypothesis_sets
        )

    @property
    def xbox_fold_group_count(self) -> int:
        return sum(
            item.xbox_alternative.endpoint_kind == "fold_group"
            for item in self.hypothesis_sets
        )

    @property
    def xbox_unresolved_count(self) -> int:
        return sum(
            item.xbox_alternative.endpoint_kind == "unresolved_address"
            for item in self.hypothesis_sets
        )

    @property
    def semantic_pair_count(self) -> int:
        return len({item.semantic_pair_id for item in self.hypothesis_sets})

    @property
    def scalar_or_unresolved_pair_count(self) -> int:
        return len(
            {
                item.semantic_pair_id
                for item in self.hypothesis_sets
                if item.xbox_alternative.endpoint_kind != "fold_group"
            }
        )

    @property
    def fold_pair_count(self) -> int:
        return len(
            {
                item.semantic_pair_id
                for item in self.hypothesis_sets
                if item.xbox_alternative.endpoint_kind == "fold_group"
            }
        )

    @property
    def supporting_evidence_count(self) -> int:
        return sum(
            item.evidence_effect == "supports" for item in self.hypothesis_sets
        )

    @property
    def context_evidence_count(self) -> int:
        return sum(
            item.evidence_effect == "context" for item in self.hypothesis_sets
        )

    @property
    def evidence_reason_counts(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for item in self.hypothesis_sets:
            counts[item.evidence_reason] += 1
        return dict(sorted(counts.items()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "table_alignment_count": self.table_alignment_count,
            "hypothesis_set_count": self.hypothesis_set_count,
            "alternative_count": self.alternative_count,
            "issue_count": self.issue_count,
            "pc_exact_count": self.pc_exact_count,
            "pc_unresolved_count": self.pc_unresolved_count,
            "xbox_exact_count": self.xbox_exact_count,
            "xbox_fold_group_count": self.xbox_fold_group_count,
            "xbox_unresolved_count": self.xbox_unresolved_count,
            "semantic_pair_count": self.semantic_pair_count,
            "scalar_or_unresolved_pair_count": self.scalar_or_unresolved_pair_count,
            "fold_pair_count": self.fold_pair_count,
            "supporting_evidence_count": self.supporting_evidence_count,
            "context_evidence_count": self.context_evidence_count,
            "evidence_reason_counts": self.evidence_reason_counts,
            "table_alignments": [
                alignment.to_dict() for alignment in self.table_alignments
            ],
            "hypothesis_sets": [item.to_dict() for item in self.hypothesis_sets],
            "issues": [issue.to_dict() for issue in self.issues],
        }


def _index_pc_functions(
    inventory: PCInventory,
) -> dict[tuple[str, int], PCFunction]:
    by_address: dict[tuple[str, int], PCFunction] = {}
    ids: set[str] = set()
    for function in inventory.functions:
        key = (function.address_space, function.address)
        if key in by_address:
            raise VtableHypothesisError(
                "multiple canonical PC functions share address-space/address "
                f"{function.address_space}:{function.address:#x}"
            )
        if function.function_id in ids:
            raise VtableHypothesisError(
                f"duplicate canonical PC function ID {function.function_id!r}"
            )
        by_address[key] = function
        ids.add(function.function_id)
    return by_address


def _index_xbox_procedures(
    extraction: ProcedureExtraction,
) -> tuple[dict[int, tuple[ProcedureRecord, ...]], dict[int, AliasGroup]]:
    records_by_va: dict[int, list[ProcedureRecord]] = defaultdict(list)
    records_by_id: dict[str, ProcedureRecord] = {}
    for record in extraction.records:
        if record.record_id in records_by_id:
            raise VtableHypothesisError(
                f"duplicate Xbox procedure record ID {record.record_id!r}"
            )
        records_by_id[record.record_id] = record
        if record.va is not None:
            records_by_va[record.va].append(record)

    groups_by_va: dict[int, AliasGroup] = {}
    group_ids: set[str] = set()
    for group in extraction.alias_groups:
        if group.group_id in group_ids:
            raise VtableHypothesisError(
                f"duplicate Xbox fold group ID {group.group_id!r}"
            )
        if group.va in groups_by_va:
            raise VtableHypothesisError(
                f"multiple Xbox fold groups share VA {group.va:#x}"
            )
        group_ids.add(group.group_id)
        groups_by_va[group.va] = group

        expected_records = records_by_va.get(group.va, ())
        expected_ids = {record.record_id for record in expected_records}
        actual_ids = set(group.record_ids)
        if len(actual_ids) != len(group.record_ids) or actual_ids != expected_ids:
            raise VtableHypothesisError(
                f"fold group {group.group_id!r} does not exactly describe "
                f"procedure records at VA {group.va:#x}"
            )
        expected_names = sorted(record.raw_name for record in expected_records)
        if sorted(group.raw_names) != expected_names:
            raise VtableHypothesisError(
                f"fold group {group.group_id!r} does not preserve member names"
            )

    normalized = {
        va: tuple(
            sorted(
                records,
                key=lambda record: (
                    record.module_index,
                    record.symbol_stream,
                    record.record_offset,
                    record.record_id,
                ),
            )
        )
        for va, records in records_by_va.items()
    }
    for va, records in normalized.items():
        if len(records) > 1 and va not in groups_by_va:
            raise VtableHypothesisError(
                f"{len(records)} Xbox procedures share VA {va:#x}, but no "
                "lossless fold group describes them"
            )
    return normalized, groups_by_va


def _normalized_space(source: str, aliases: Mapping[str, str]) -> str:
    normalized = aliases.get(source, source)
    if not normalized:
        raise VtableHypothesisError(
            f"address-space alias for {source!r} cannot be empty"
        )
    return normalized


def _pc_endpoint(
    slot: VtableSlot,
    functions: dict[tuple[str, int], PCFunction],
    address_space_aliases: Mapping[str, str],
) -> HypothesisEndpoint:
    address_space = _normalized_space(
        slot.target_address_space, address_space_aliases
    )
    function = functions.get((address_space, slot.target_address))
    if function is None:
        return HypothesisEndpoint(
            platform="pc",
            endpoint_kind="unresolved_address",
            address_space=address_space,
            address=slot.target_address,
        )
    return HypothesisEndpoint(
        platform="pc",
        endpoint_kind="exact_function",
        address_space=function.address_space,
        address=function.address,
        function_id=function.function_id,
    )


def _xbox_endpoint(
    slot: VtableSlot,
    procedures: dict[int, tuple[ProcedureRecord, ...]],
    groups: dict[int, AliasGroup],
    address_space_aliases: Mapping[str, str],
    procedure_address_space: str,
) -> HypothesisEndpoint:
    address_space = _normalized_space(
        slot.target_address_space, address_space_aliases
    )
    records = (
        procedures.get(slot.target_address, ())
        if address_space == procedure_address_space
        else ()
    )
    if not records:
        return HypothesisEndpoint(
            platform="xbox360",
            endpoint_kind="unresolved_address",
            address_space=address_space,
            address=slot.target_address,
        )
    if len(records) == 1:
        return HypothesisEndpoint(
            platform="xbox360",
            endpoint_kind="exact_function",
            address_space=procedure_address_space,
            address=slot.target_address,
            function_id=records[0].record_id,
        )
    group = groups[slot.target_address]
    return HypothesisEndpoint(
        platform="xbox360",
        endpoint_kind="fold_group",
        address_space=procedure_address_space,
        address=slot.target_address,
        fold_group_id=group.group_id,
        fold_member_count=len(records),
    )


def _candidate_key(candidate: VtableAlignmentCandidate) -> tuple[object, ...]:
    return (
        candidate.class_name,
        0 if candidate.vfptr_role == "primary" else 1,
        candidate.subobject_offset,
        candidate.pc_vtable_id,
        candidate.xbox_vtable_id,
        candidate.alignment_id,
    )


def _evidence_classification(
    candidate: VtableAlignmentCandidate, slot_index: int
) -> tuple[str, str, tuple[str, ...]]:
    """Classify equal-index evidence against the Xbox extent assessment.

    A pointer run beyond a complete, hole-free TPI declaration may have swept
    adjacent data into the legacy table.  Such overflow occurrences are kept,
    but cannot positively support a match.  Indices inside that same table's
    declared prefix remain usable.  A shorter observed run is not disproved by
    the declaration, so its existing slots support with an explicit diagnostic.
    """

    extent = candidate.xbox_extent
    reference = extent.reference_slot_count
    if extent.status == "pointer_run_exceeds_hole_free_xbox_tpi_map":
        if (
            extent.reference_hole_free is True
            and reference is not None
            and slot_index >= reference
        ):
            return (
                "context",
                "slot_at_or_beyond_declared_hole_free_tpi_extent",
                ("xbox_pointer_run_exceeds_hole_free_tpi_extent",),
            )
        return (
            "supports",
            "equal_index_within_declared_hole_free_tpi_extent",
            (
                "xbox_pointer_run_exceeds_hole_free_tpi_extent_"
                "but_slot_is_within_safe_prefix",
            ),
        )
    if extent.status == "shorter_than_hole_free_xbox_tpi_map":
        return (
            "supports",
            "equal_index_in_shorter_observed_pointer_run",
            ("xbox_observed_pointer_run_shorter_than_hole_free_tpi_extent",),
        )
    return (
        "supports",
        "equal_index_in_conservatively_paired_table",
        (),
    )


def materialize_vtable_hypotheses(
    alignment: VtableAlignmentResult,
    pc_inventory: PCInventory,
    xbox_procedures: ProcedureExtraction,
    *,
    pc_address_space_aliases: Mapping[str, str] | None = None,
    xbox_address_space_aliases: Mapping[str, str] | None = None,
    xbox_procedure_address_space: str = "xbox-va",
) -> VtableHypothesisMaterialization:
    """Resolve every aligned slot occurrence to one conservative alternative.

    Numeric slot targets are looked up in the canonical PC inventory and Xbox
    procedure VAs.  Source address-space strings are retained on unresolved
    endpoints and in the slot/table metadata; an exact PC endpoint uses the
    canonical function's address space.
    """

    if not xbox_procedure_address_space:
        raise VtableHypothesisError("Xbox procedure address space cannot be empty")
    pc_aliases = (
        {"va": "ram"}
        if pc_address_space_aliases is None
        else dict(pc_address_space_aliases)
    )
    xbox_aliases = (
        {"va": xbox_procedure_address_space}
        if xbox_address_space_aliases is None
        else dict(xbox_address_space_aliases)
    )
    pc_functions = _index_pc_functions(pc_inventory)
    xbox_by_va, fold_groups = _index_xbox_procedures(xbox_procedures)

    candidates = tuple(sorted(alignment.candidates, key=_candidate_key))
    issues = tuple(sorted(alignment.issues, key=lambda issue: issue.issue_id))
    items: list[VtableSlotHypothesisSet] = []
    seen_set_ids: set[str] = set()

    for candidate in candidates:
        for pair in sorted(
            candidate.slot_pairs,
            key=lambda item: (
                item.slot_index,
                item.pc_slot.slot_id,
                item.xbox_slot.slot_id,
            ),
        ):
            if pair.pc_slot.vtable_id != candidate.pc_vtable_id:
                raise VtableHypothesisError(
                    f"PC slot {pair.pc_slot.slot_id!r} does not belong to "
                    f"aligned table {candidate.pc_vtable_id!r}"
                )
            if pair.xbox_slot.vtable_id != candidate.xbox_vtable_id:
                raise VtableHypothesisError(
                    f"Xbox slot {pair.xbox_slot.slot_id!r} does not belong to "
                    f"aligned table {candidate.xbox_vtable_id!r}"
                )
            if (
                pair.pc_slot.slot_index != pair.slot_index
                or pair.xbox_slot.slot_index != pair.slot_index
            ):
                raise VtableHypothesisError(
                    "aligned slot occurrence disagrees with its numeric index"
                )

            pc_subject = _pc_endpoint(pair.pc_slot, pc_functions, pc_aliases)
            xbox_alternative = _xbox_endpoint(
                pair.xbox_slot,
                xbox_by_va,
                fold_groups,
                xbox_aliases,
                xbox_procedure_address_space,
            )
            semantic_pair_id = _stable_id(
                "vtable-endpoint-pair",
                pc_subject.identity,
                xbox_alternative.identity,
            )
            hypothesis_set_id = _stable_id(
                "vtable-hypothesis-set",
                candidate.alignment_id,
                candidate.pc_vtable_id,
                candidate.xbox_vtable_id,
                pair.slot_index,
                pair.pc_slot.slot_id,
                pair.xbox_slot.slot_id,
            )
            if hypothesis_set_id in seen_set_ids:
                raise VtableHypothesisError(
                    f"duplicate structural slot occurrence {hypothesis_set_id!r}"
                )
            seen_set_ids.add(hypothesis_set_id)
            alternative_id = _stable_id(
                "vtable-hypothesis-alternative",
                hypothesis_set_id,
                semantic_pair_id,
            )
            evidence_effect, evidence_reason, evidence_diagnostics = (
                _evidence_classification(candidate, pair.slot_index)
            )
            items.append(
                VtableSlotHypothesisSet(
                    hypothesis_set_id=hypothesis_set_id,
                    alternative_id=alternative_id,
                    semantic_pair_id=semantic_pair_id,
                    alignment_id=candidate.alignment_id,
                    class_name=candidate.class_name,
                    vfptr_role=candidate.vfptr_role,
                    subobject_offset=candidate.subobject_offset,
                    pc_vtable_id=candidate.pc_vtable_id,
                    xbox_vtable_id=candidate.xbox_vtable_id,
                    pc_table_address_space=candidate.pc_address_space,
                    pc_table_address=candidate.pc_address,
                    xbox_table_address_space=candidate.xbox_address_space,
                    xbox_table_address=candidate.xbox_address,
                    pc_role_basis=candidate.pc_role_basis,
                    xbox_role_basis=candidate.xbox_role_basis,
                    pc_qualifier=candidate.pc_qualifier,
                    xbox_qualifier=candidate.xbox_qualifier,
                    pc_observed_slot_count=candidate.pc_observed_slot_count,
                    xbox_observed_slot_count=candidate.xbox_observed_slot_count,
                    shared_prefix_slot_count=candidate.shared_prefix_slot_count,
                    pc_unpaired_tail_count=candidate.pc_unpaired_tail_count,
                    xbox_unpaired_tail_count=candidate.xbox_unpaired_tail_count,
                    pc_extent=candidate.pc_extent,
                    xbox_extent=candidate.xbox_extent,
                    slot_index=pair.slot_index,
                    pc_slot_id=pair.pc_slot.slot_id,
                    xbox_slot_id=pair.xbox_slot.slot_id,
                    pc_slot_target_address_space=(
                        pair.pc_slot.target_address_space
                    ),
                    xbox_slot_target_address_space=(
                        pair.xbox_slot.target_address_space
                    ),
                    pc_raw_target_address=pair.pc_slot.raw_target_address,
                    xbox_raw_target_address=pair.xbox_slot.raw_target_address,
                    pc_subject=pc_subject,
                    xbox_alternative=xbox_alternative,
                    xbox_name_observations=pair.xbox_slot.name_observations,
                    evidence_effect=evidence_effect,
                    evidence_reason=evidence_reason,
                    evidence_diagnostics=evidence_diagnostics,
                )
            )

    items.sort(key=lambda item: item.hypothesis_set_id)
    if len(items) != alignment.slot_pair_count:
        raise VtableHypothesisError(
            "materialization did not preserve every aligned slot occurrence"
        )
    return VtableHypothesisMaterialization(
        table_alignments=candidates,
        hypothesis_sets=tuple(items),
        issues=issues,
    )


__all__ = [
    "HypothesisEndpoint",
    "VtableHypothesisError",
    "VtableHypothesisMaterialization",
    "VtableSlotHypothesisSet",
    "materialize_vtable_hypotheses",
]
