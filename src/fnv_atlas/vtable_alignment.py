"""Conservative, read-only PC/Xbox vtable alignment candidates.

This module does not accept a match, assign confidence, or transfer a symbol.
It proposes table pairs only inside an exact class-name overlap and only when
the vfptr role is structural and unique:

* exactly one primary table exists on each platform; or
* exactly one secondary table exists at the same explicit subobject offset on
  each platform.

Source list position, table size, and address-derived slot names are never used
to select a table.  Slot candidates pair equal numeric indices in the shared
prefix, while both complete source extents and unpaired tails remain visible.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable

from .vtables import ExtentAssessment, VtableDataset, VtableRecord, VtableSlot


class VtableAlignmentError(ValueError):
    """The input datasets cannot participate in a PC/Xbox comparison."""


@dataclass(frozen=True, slots=True)
class SlotAlignmentCandidate:
    """Same numeric slot index in one conservatively paired table."""

    slot_index: int
    pc_slot: VtableSlot
    xbox_slot: VtableSlot

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_index": self.slot_index,
            "pc_slot_id": self.pc_slot.slot_id,
            "pc_target_address_space": self.pc_slot.target_address_space,
            "pc_target_address": self.pc_slot.target_address,
            "xbox_slot_id": self.xbox_slot.slot_id,
            "xbox_target_address_space": self.xbox_slot.target_address_space,
            "xbox_target_address": self.xbox_slot.target_address,
            "xbox_name_observations": [
                observation.to_dict()
                for observation in self.xbox_slot.name_observations
            ],
        }


@dataclass(frozen=True, slots=True)
class VtableAlignmentCandidate:
    """A structural table pair, not an accepted semantic correspondence."""

    alignment_id: str
    class_name: str
    vfptr_role: str
    subobject_offset: int
    pc_vtable_id: str
    xbox_vtable_id: str
    pc_address_space: str
    pc_address: int
    xbox_address_space: str
    xbox_address: int
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
    slot_pairs: tuple[SlotAlignmentCandidate, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "alignment_id": self.alignment_id,
            "class_name": self.class_name,
            "vfptr_role": self.vfptr_role,
            "subobject_offset": self.subobject_offset,
            "pc_vtable_id": self.pc_vtable_id,
            "xbox_vtable_id": self.xbox_vtable_id,
            "pc_address_space": self.pc_address_space,
            "pc_address": self.pc_address,
            "xbox_address_space": self.xbox_address_space,
            "xbox_address": self.xbox_address,
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
            "slot_pairs": [pair.to_dict() for pair in self.slot_pairs],
        }


@dataclass(frozen=True, slots=True)
class VtableAlignmentIssue:
    """An ambiguity or unmatched structural role retained for later work."""

    issue_id: str
    issue_kind: str
    class_name: str
    vfptr_role: str | None
    subobject_offset: int | None
    pc_vtable_ids: tuple[str, ...]
    xbox_vtable_ids: tuple[str, ...]
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "issue_kind": self.issue_kind,
            "class_name": self.class_name,
            "vfptr_role": self.vfptr_role,
            "subobject_offset": self.subobject_offset,
            "pc_vtable_ids": list(self.pc_vtable_ids),
            "xbox_vtable_ids": list(self.xbox_vtable_ids),
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class VtableAlignmentResult:
    """Deterministic candidate alignments and explicit non-alignments."""

    candidates: tuple[VtableAlignmentCandidate, ...]
    issues: tuple[VtableAlignmentIssue, ...]
    exact_class_overlap_count: int
    pc_only_class_count: int
    xbox_only_class_count: int

    @property
    def candidate_count(self) -> int:
        return len(self.candidates)

    @property
    def slot_pair_count(self) -> int:
        return sum(len(candidate.slot_pairs) for candidate in self.candidates)

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exact_class_overlap_count": self.exact_class_overlap_count,
            "pc_only_class_count": self.pc_only_class_count,
            "xbox_only_class_count": self.xbox_only_class_count,
            "candidate_count": self.candidate_count,
            "slot_pair_count": self.slot_pair_count,
            "issue_count": self.issue_count,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "issues": [issue.to_dict() for issue in self.issues],
        }


def _stable_id(namespace: str, *components: object) -> str:
    payload = json.dumps(
        components,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{namespace}:sha256:{hashlib.sha256(payload).hexdigest()}"


def _table_ids(tables: Iterable[VtableRecord]) -> tuple[str, ...]:
    return tuple(sorted(table.vtable_id for table in tables))


def _issue(
    issue_kind: str,
    class_name: str,
    *,
    vfptr_role: str | None,
    subobject_offset: int | None,
    pc_tables: Iterable[VtableRecord] = (),
    xbox_tables: Iterable[VtableRecord] = (),
    message: str,
) -> VtableAlignmentIssue:
    pc_ids = _table_ids(pc_tables)
    xbox_ids = _table_ids(xbox_tables)
    return VtableAlignmentIssue(
        issue_id=_stable_id(
            "vtable-alignment-issue",
            issue_kind,
            class_name,
            vfptr_role,
            subobject_offset,
            pc_ids,
            xbox_ids,
        ),
        issue_kind=issue_kind,
        class_name=class_name,
        vfptr_role=vfptr_role,
        subobject_offset=subobject_offset,
        pc_vtable_ids=pc_ids,
        xbox_vtable_ids=xbox_ids,
        message=message,
    )


def _candidate(
    class_name: str,
    vfptr_role: str,
    subobject_offset: int,
    pc: VtableRecord,
    xbox: VtableRecord,
) -> tuple[VtableAlignmentCandidate, tuple[VtableAlignmentIssue, ...]]:
    pc_by_index = {slot.slot_index: slot for slot in pc.slots}
    xbox_by_index = {slot.slot_index: slot for slot in xbox.slots}
    if len(pc_by_index) != len(pc.slots) or len(xbox_by_index) != len(xbox.slots):
        raise VtableAlignmentError("a vtable contains duplicate numeric slot indices")

    shared_prefix = min(pc.slot_count, xbox.slot_count)
    missing = tuple(
        index
        for index in range(shared_prefix)
        if index not in pc_by_index or index not in xbox_by_index
    )
    slot_pairs = tuple(
        SlotAlignmentCandidate(index, pc_by_index[index], xbox_by_index[index])
        for index in range(shared_prefix)
        if index in pc_by_index and index in xbox_by_index
    )
    issues: tuple[VtableAlignmentIssue, ...] = ()
    if missing:
        issues = (
            _issue(
                "shared_prefix_has_missing_slot_indices",
                class_name,
                vfptr_role=vfptr_role,
                subobject_offset=subobject_offset,
                pc_tables=(pc,),
                xbox_tables=(xbox,),
                message=(
                    "equal numeric indices are absent inside the shared prefix: "
                    + ", ".join(str(index) for index in missing)
                ),
            ),
        )

    alignment_id = _stable_id(
        "vtable-alignment",
        class_name,
        vfptr_role,
        subobject_offset,
        pc.vtable_id,
        xbox.vtable_id,
    )
    return (
        VtableAlignmentCandidate(
            alignment_id=alignment_id,
            class_name=class_name,
            vfptr_role=vfptr_role,
            subobject_offset=subobject_offset,
            pc_vtable_id=pc.vtable_id,
            xbox_vtable_id=xbox.vtable_id,
            pc_address_space=pc.address_space,
            pc_address=pc.address,
            xbox_address_space=xbox.address_space,
            xbox_address=xbox.address,
            pc_role_basis=pc.role_basis,
            xbox_role_basis=xbox.role_basis,
            pc_qualifier=pc.qualifier,
            xbox_qualifier=xbox.qualifier,
            pc_observed_slot_count=pc.slot_count,
            xbox_observed_slot_count=xbox.slot_count,
            shared_prefix_slot_count=shared_prefix,
            pc_unpaired_tail_count=max(0, pc.slot_count - shared_prefix),
            xbox_unpaired_tail_count=max(0, xbox.slot_count - shared_prefix),
            pc_extent=pc.extent,
            xbox_extent=xbox.extent,
            slot_pairs=slot_pairs,
        ),
        issues,
    )


def _by_class(dataset: VtableDataset) -> dict[str, tuple[VtableRecord, ...]]:
    grouped: dict[str, list[VtableRecord]] = defaultdict(list)
    for table in dataset.tables:
        if table.platform != dataset.platform:
            raise VtableAlignmentError(
                f"dataset {dataset.platform!r} contains {table.platform!r} table"
            )
        grouped[table.class_name].append(table)
    return {
        class_name: tuple(sorted(tables, key=lambda table: table.vtable_id))
        for class_name, tables in grouped.items()
    }


def _secondary_by_offset(
    tables: Iterable[VtableRecord],
) -> tuple[dict[int, tuple[VtableRecord, ...]], tuple[VtableRecord, ...]]:
    grouped: dict[int, list[VtableRecord]] = defaultdict(list)
    unresolved: list[VtableRecord] = []
    for table in tables:
        if table.vfptr_role == "secondary" and table.subobject_offset is not None:
            grouped[table.subobject_offset].append(table)
        elif table.vfptr_role != "primary":
            unresolved.append(table)
    return (
        {
            offset: tuple(sorted(items, key=lambda table: table.vtable_id))
            for offset, items in grouped.items()
        },
        tuple(sorted(unresolved, key=lambda table: table.vtable_id)),
    )


def propose_vtable_alignments(
    pc_dataset: VtableDataset,
    xbox_dataset: VtableDataset,
) -> VtableAlignmentResult:
    """Return structural candidates without assigning confidence or acceptance."""

    if pc_dataset.platform != "pc":
        raise VtableAlignmentError(
            f"first dataset must be PC, found {pc_dataset.platform!r}"
        )
    if xbox_dataset.platform != "xbox360":
        raise VtableAlignmentError(
            f"second dataset must be Xbox 360, found {xbox_dataset.platform!r}"
        )

    pc_classes = _by_class(pc_dataset)
    xbox_classes = _by_class(xbox_dataset)
    pc_names = set(pc_classes)
    xbox_names = set(xbox_classes)
    overlap = pc_names & xbox_names
    candidates: list[VtableAlignmentCandidate] = []
    issues: list[VtableAlignmentIssue] = []

    for class_name in sorted(pc_names - xbox_names):
        issues.append(
            _issue(
                "class_missing_on_xbox",
                class_name,
                vfptr_role=None,
                subobject_offset=None,
                pc_tables=pc_classes[class_name],
                message="class name has no exact Xbox 360 overlap",
            )
        )
    for class_name in sorted(xbox_names - pc_names):
        issues.append(
            _issue(
                "class_missing_on_pc",
                class_name,
                vfptr_role=None,
                subobject_offset=None,
                xbox_tables=xbox_classes[class_name],
                message="class name has no exact PC overlap",
            )
        )

    for class_name in sorted(overlap):
        pc_tables = pc_classes[class_name]
        xbox_tables = xbox_classes[class_name]

        pc_primary = tuple(
            table for table in pc_tables if table.vfptr_role == "primary"
        )
        xbox_primary = tuple(
            table for table in xbox_tables if table.vfptr_role == "primary"
        )
        if len(pc_primary) == 1 and len(xbox_primary) == 1:
            candidate, slot_issues = _candidate(
                class_name, "primary", 0, pc_primary[0], xbox_primary[0]
            )
            candidates.append(candidate)
            issues.extend(slot_issues)
        elif len(pc_primary) > 1 or len(xbox_primary) > 1:
            issues.append(
                _issue(
                    "primary_role_ambiguous",
                    class_name,
                    vfptr_role="primary",
                    subobject_offset=0,
                    pc_tables=pc_primary,
                    xbox_tables=xbox_primary,
                    message=(
                        "primary table is not unique on both platforms "
                        f"(PC={len(pc_primary)}, Xbox={len(xbox_primary)})"
                    ),
                )
            )
        elif pc_primary:
            issues.append(
                _issue(
                    "primary_role_missing_on_xbox",
                    class_name,
                    vfptr_role="primary",
                    subobject_offset=0,
                    pc_tables=pc_primary,
                    message="unique PC primary has no Xbox primary role",
                )
            )
        elif xbox_primary:
            issues.append(
                _issue(
                    "primary_role_missing_on_pc",
                    class_name,
                    vfptr_role="primary",
                    subobject_offset=0,
                    xbox_tables=xbox_primary,
                    message="unique Xbox primary has no PC primary role",
                )
            )

        pc_secondary, pc_unresolved = _secondary_by_offset(pc_tables)
        xbox_secondary, xbox_unresolved = _secondary_by_offset(xbox_tables)
        for table in pc_unresolved:
            issues.append(
                _issue(
                    "pc_role_or_offset_unresolved",
                    class_name,
                    vfptr_role=table.vfptr_role,
                    subobject_offset=table.subobject_offset,
                    pc_tables=(table,),
                    message="PC table has no matchable secondary offset or primary role",
                )
            )
        for table in xbox_unresolved:
            issues.append(
                _issue(
                    "xbox_role_or_offset_unresolved",
                    class_name,
                    vfptr_role=table.vfptr_role,
                    subobject_offset=table.subobject_offset,
                    xbox_tables=(table,),
                    message="Xbox table has no matchable secondary offset or primary role",
                )
            )

        for offset in sorted(set(pc_secondary) | set(xbox_secondary)):
            pc_at_offset = pc_secondary.get(offset, ())
            xbox_at_offset = xbox_secondary.get(offset, ())
            if len(pc_at_offset) == 1 and len(xbox_at_offset) == 1:
                candidate, slot_issues = _candidate(
                    class_name,
                    "secondary",
                    offset,
                    pc_at_offset[0],
                    xbox_at_offset[0],
                )
                candidates.append(candidate)
                issues.extend(slot_issues)
            elif len(pc_at_offset) > 1 or len(xbox_at_offset) > 1:
                issues.append(
                    _issue(
                        "secondary_offset_ambiguous",
                        class_name,
                        vfptr_role="secondary",
                        subobject_offset=offset,
                        pc_tables=pc_at_offset,
                        xbox_tables=xbox_at_offset,
                        message=(
                            f"secondary offset {offset} is not unique on both "
                            f"platforms (PC={len(pc_at_offset)}, "
                            f"Xbox={len(xbox_at_offset)})"
                        ),
                    )
                )
            elif pc_at_offset:
                issues.append(
                    _issue(
                        "secondary_offset_missing_on_xbox",
                        class_name,
                        vfptr_role="secondary",
                        subobject_offset=offset,
                        pc_tables=pc_at_offset,
                        message=f"PC secondary offset {offset} has no Xbox counterpart",
                    )
                )
            else:
                issues.append(
                    _issue(
                        "secondary_offset_missing_on_pc",
                        class_name,
                        vfptr_role="secondary",
                        subobject_offset=offset,
                        xbox_tables=xbox_at_offset,
                        message=f"Xbox secondary offset {offset} has no PC counterpart",
                    )
                )

    candidates.sort(
        key=lambda candidate: (
            candidate.class_name,
            0 if candidate.vfptr_role == "primary" else 1,
            candidate.subobject_offset,
            candidate.pc_vtable_id,
            candidate.xbox_vtable_id,
        )
    )
    issues.sort(
        key=lambda issue: (
            issue.class_name,
            issue.issue_kind,
            -1 if issue.subobject_offset is None else issue.subobject_offset,
            issue.pc_vtable_ids,
            issue.xbox_vtable_ids,
        )
    )
    return VtableAlignmentResult(
        candidates=tuple(candidates),
        issues=tuple(issues),
        exact_class_overlap_count=len(overlap),
        pc_only_class_count=len(pc_names - xbox_names),
        xbox_only_class_count=len(xbox_names - pc_names),
    )


__all__ = [
    "SlotAlignmentCandidate",
    "VtableAlignmentCandidate",
    "VtableAlignmentError",
    "VtableAlignmentIssue",
    "VtableAlignmentResult",
    "propose_vtable_alignments",
]
