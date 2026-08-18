"""Lossless, role-aware normalization of PC and Xbox 360 vtable artifacts.

The legacy JSON files are useful observations, but their list ordering and
single address-derived name per Xbox slot must not be mistaken for semantic
cross-build alignment.  This module preserves each physical table and each slot
occurrence independently.  It derives roles only from same-platform evidence:

* PC roles come from the Complete Object Locator subobject offset.
* Xbox roles come from the decorated vftable qualifier plus Xbox TPI base
  offsets, when that qualifier resolves uniquely.

No PC table is paired with an Xbox table here.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable, Mapping, Sequence


class VtableFormatError(ValueError):
    """Raised when a legacy artifact cannot be normalized without data loss."""


@dataclass(frozen=True, slots=True)
class SlotNameObservation:
    """A name observed at a slot target, not an assertion of unique identity."""

    observation_id: str
    raw_name: str
    observation_kind: str = "address_derived_symbol"
    ambiguity: str = "address_may_have_multiple_symbol_aliases"

    def to_dict(self) -> dict[str, object]:
        return {
            "observation_id": self.observation_id,
            "raw_name": self.raw_name,
            "observation_kind": self.observation_kind,
            "ambiguity": self.ambiguity,
        }


@dataclass(frozen=True, slots=True)
class VtableSlot:
    """One physical slot occurrence within one vtable."""

    slot_id: str
    vtable_id: str
    slot_index: int
    target_address_space: str
    target_address: int
    raw_target_address: str
    name_observations: tuple[SlotNameObservation, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "slot_id": self.slot_id,
            "vtable_id": self.vtable_id,
            "slot_index": self.slot_index,
            "target_address_space": self.target_address_space,
            "target_address": self.target_address,
            "raw_target_address": self.raw_target_address,
            "name_observations": [
                observation.to_dict() for observation in self.name_observations
            ],
        }


@dataclass(frozen=True, slots=True)
class ExtentAssessment:
    """Non-destructive metadata about a pointer-run table extent.

    ``reference_slot_count`` is populated only from a hole-free Xbox TPI map on
    the Xbox side.  It is never transferred to a PC table.
    """

    observed_slot_count: int
    reported_slot_count: int | None
    reported_count_matches_payload: bool | None
    status: str
    extent_suspect: bool
    reference_kind: str | None = None
    reference_class: str | None = None
    reference_slot_count: int | None = None
    reference_hole_free: bool | None = None
    excess_slot_count: int | None = None
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "observed_slot_count": self.observed_slot_count,
            "reported_slot_count": self.reported_slot_count,
            "reported_count_matches_payload": self.reported_count_matches_payload,
            "status": self.status,
            "extent_suspect": self.extent_suspect,
            "reference_kind": self.reference_kind,
            "reference_class": self.reference_class,
            "reference_slot_count": self.reference_slot_count,
            "reference_hole_free": self.reference_hole_free,
            "excess_slot_count": self.excess_slot_count,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class VtableRecord:
    """One source vtable record, without any cross-platform correspondence."""

    vtable_id: str
    platform: str
    class_name: str
    source_table_index: int
    address_space: str
    address: int
    raw_table_identity: str
    raw_qualifier: str | None
    qualifier: str | None
    vfptr_role: str
    role_basis: str
    subobject_offset: int | None
    subobject_offset_candidates: tuple[int, ...]
    col_address: int | None
    rtti_name: str | None
    slots: tuple[VtableSlot, ...]
    extent: ExtentAssessment

    @property
    def slot_count(self) -> int:
        return len(self.slots)

    def to_dict(self) -> dict[str, object]:
        return {
            "vtable_id": self.vtable_id,
            "platform": self.platform,
            "class_name": self.class_name,
            "source_table_index": self.source_table_index,
            "address_space": self.address_space,
            "address": self.address,
            "raw_table_identity": self.raw_table_identity,
            "raw_qualifier": self.raw_qualifier,
            "qualifier": self.qualifier,
            "vfptr_role": self.vfptr_role,
            "role_basis": self.role_basis,
            "subobject_offset": self.subobject_offset,
            "subobject_offset_candidates": list(
                self.subobject_offset_candidates
            ),
            "col_address": self.col_address,
            "rtti_name": self.rtti_name,
            "slot_count": self.slot_count,
            "slots": [slot.to_dict() for slot in self.slots],
            "extent": self.extent.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class VtableDataset:
    """Deterministically ordered normalized vtable records for one platform."""

    platform: str
    tables: tuple[VtableRecord, ...]

    @property
    def table_count(self) -> int:
        return len(self.tables)

    @property
    def slot_count(self) -> int:
        return sum(table.slot_count for table in self.tables)

    @property
    def class_count(self) -> int:
        return len({table.class_name for table in self.tables})

    @property
    def extent_suspect_count(self) -> int:
        return sum(table.extent.extent_suspect for table in self.tables)


@dataclass(frozen=True, slots=True)
class XboxVftableSymbol:
    """Conservative parsing of an MSVC Xbox vftable symbol."""

    raw_symbol: str
    raw_qualifier: str | None
    simple_qualifier: str | None
    is_unqualified: bool
    parse_status: str


@dataclass(frozen=True, slots=True)
class _TpiPrimaryLayout:
    slots: frozenset[int]
    hole_free: bool
    complete: bool

    @property
    def slot_count(self) -> int | None:
        if not self.slots or not self.hole_free or not self.complete:
            return None
        return max(self.slots) + 1


def _parse_address(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise VtableFormatError(f"{field} cannot be boolean")
    if isinstance(value, int):
        if value < 0:
            raise VtableFormatError(f"{field} cannot be negative")
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            # Current artifacts use 0x-prefixed strings.  Plain decimal is also
            # accepted for synthetic or future normalized inputs.
            base = 16 if text.lower().startswith("0x") else 10
            parsed = int(text, base)
        except ValueError as error:
            raise VtableFormatError(f"invalid {field}: {value!r}") from error
        if parsed < 0:
            raise VtableFormatError(f"{field} cannot be negative")
        return parsed
    raise VtableFormatError(f"invalid {field} type: {type(value).__name__}")


def _class_token(class_name: str) -> str:
    return hashlib.sha256(class_name.encode("utf-8")).hexdigest()[:12]


def make_vtable_id(
    platform: str, class_name: str, source_table_index: int, address: int
) -> str:
    """Return a stable ID for a source table occurrence.

    The address is globally unique in the current artifacts.  The class token
    and per-class source index keep future duplicate-address records distinct.
    """

    return (
        f"{platform}-vtable:a{address:08X}:"
        f"c{_class_token(class_name)}:t{source_table_index:04d}"
    )


def make_slot_id(vtable_id: str, slot_index: int) -> str:
    return f"{vtable_id}:slot:{slot_index:04d}"


def parse_xbox_vftable_symbol(symbol: str) -> XboxVftableSymbol:
    """Preserve a vftable symbol and conservatively expose its qualifier.

    MSVC names can use namespace and template back-references.  Only a simple
    one-component qualifier is decoded.  Complex encodings remain available in
    ``raw_qualifier`` and are never guessed.
    """

    marker = "@@6B"
    marker_at = symbol.rfind(marker)
    if not symbol.startswith("??_7") or marker_at < 0:
        return XboxVftableSymbol(
            raw_symbol=symbol,
            raw_qualifier=None,
            simple_qualifier=None,
            is_unqualified=False,
            parse_status="unrecognized",
        )

    tail = symbol[marker_at + len(marker) :]
    if tail == "@":
        return XboxVftableSymbol(
            raw_symbol=symbol,
            raw_qualifier=None,
            simple_qualifier=None,
            is_unqualified=True,
            parse_status="unqualified",
        )

    # Remove only the final terminator.  The rest is retained verbatim.
    if not tail.endswith("@"):
        return XboxVftableSymbol(
            raw_symbol=symbol,
            raw_qualifier=tail,
            simple_qualifier=None,
            is_unqualified=False,
            parse_status="unterminated_qualifier",
        )
    raw_qualifier = tail[:-1]
    simple = None
    if re.fullmatch(r"[^@]+@@", raw_qualifier):
        simple = raw_qualifier[:-2]
    return XboxVftableSymbol(
        raw_symbol=symbol,
        raw_qualifier=raw_qualifier,
        simple_qualifier=simple,
        is_unqualified=False,
        parse_status="simple_qualifier" if simple else "complex_qualifier",
    )


class _XboxTpiIndex:
    """Same-platform TPI facts used for role and extent observations."""

    def __init__(self, types: Mapping[str, object] | None):
        self.types = types or {}
        self._base_offset_cache: dict[str, dict[str, frozenset[int]]] = {}
        self._layout_cache: dict[str, _TpiPrimaryLayout] = {}

    def base_offsets(self, class_name: str) -> dict[str, frozenset[int]]:
        return self._base_offsets(class_name, set())

    def _base_offsets(
        self, class_name: str, visiting: set[str]
    ) -> dict[str, frozenset[int]]:
        cached = self._base_offset_cache.get(class_name)
        if cached is not None:
            return cached
        if class_name in visiting:
            return {}
        visiting = set(visiting)
        visiting.add(class_name)

        collected: dict[str, set[int]] = defaultdict(set)
        info = self.types.get(class_name)
        if isinstance(info, Mapping):
            bases = info.get("bases", [])
            if isinstance(bases, Sequence) and not isinstance(bases, (str, bytes)):
                for raw_base in bases:
                    if not isinstance(raw_base, Mapping):
                        continue
                    base_name = raw_base.get("name")
                    base_offset = raw_base.get("offset")
                    if not isinstance(base_name, str) or not isinstance(
                        base_offset, int
                    ):
                        continue
                    collected[base_name].add(base_offset)
                    inherited = self._base_offsets(base_name, visiting)
                    for inherited_name, inherited_offsets in inherited.items():
                        collected[inherited_name].update(
                            base_offset + offset for offset in inherited_offsets
                        )
        result = {
            name: frozenset(sorted(offsets))
            for name, offsets in collected.items()
        }
        self._base_offset_cache[class_name] = result
        return result

    def primary_layout(self, class_name: str) -> _TpiPrimaryLayout:
        return self._primary_layout(class_name, set())

    def _primary_layout(
        self, class_name: str, visiting: set[str]
    ) -> _TpiPrimaryLayout:
        cached = self._layout_cache.get(class_name)
        if cached is not None:
            return cached
        if class_name in visiting:
            return _TpiPrimaryLayout(frozenset(), False, False)
        visiting = set(visiting)
        visiting.add(class_name)

        info = self.types.get(class_name)
        if not isinstance(info, Mapping):
            return _TpiPrimaryLayout(frozenset(), False, False)

        zero_bases: list[str] = []
        raw_bases = info.get("bases", [])
        if isinstance(raw_bases, Sequence) and not isinstance(
            raw_bases, (str, bytes)
        ):
            for raw_base in raw_bases:
                if (
                    isinstance(raw_base, Mapping)
                    and raw_base.get("offset") == 0
                    and isinstance(raw_base.get("name"), str)
                ):
                    zero_bases.append(str(raw_base["name"]))

        slots: set[int] = set()
        complete = len(zero_bases) <= 1
        if len(zero_bases) == 1:
            inherited = self._primary_layout(zero_bases[0], visiting)
            slots.update(inherited.slots)
            complete = complete and inherited.complete

        raw_virtuals = info.get("virtuals", [])
        if isinstance(raw_virtuals, Sequence) and not isinstance(
            raw_virtuals, (str, bytes)
        ):
            for raw_virtual in raw_virtuals:
                if not isinstance(raw_virtual, Mapping):
                    continue
                slot = raw_virtual.get("slot")
                if isinstance(slot, int) and slot >= 0:
                    slots.add(slot)

        hole_free = bool(slots) and slots == set(range(max(slots) + 1))
        layout = _TpiPrimaryLayout(
            slots=frozenset(slots),
            hole_free=hole_free,
            complete=complete,
        )
        self._layout_cache[class_name] = layout
        return layout


def _reported_slot_count(table: Mapping[str, object]) -> int | None:
    value = table.get("slot_count")
    if value is None:
        return None
    if isinstance(value, bool):
        raise VtableFormatError("slot_count cannot be boolean")
    try:
        count = int(value)
    except (TypeError, ValueError) as error:
        raise VtableFormatError(f"invalid slot_count: {value!r}") from error
    if count < 0:
        raise VtableFormatError("slot_count cannot be negative")
    return count


def _base_extent_assessment(
    observed: int, reported: int | None
) -> tuple[bool | None, list[str]]:
    matches = None if reported is None else reported == observed
    reasons: list[str] = []
    if matches is False:
        reasons.append("source_reported_slot_count_differs_from_payload")
    return matches, reasons


def _pc_extent(table: Mapping[str, object], observed: int) -> ExtentAssessment:
    reported = _reported_slot_count(table)
    matches, reasons = _base_extent_assessment(observed, reported)
    return ExtentAssessment(
        observed_slot_count=observed,
        reported_slot_count=reported,
        reported_count_matches_payload=matches,
        status="unassessed_same_platform_declaration_unavailable",
        extent_suspect=bool(reasons),
        reasons=tuple(reasons),
    )


def _xbox_extent(
    *,
    table: Mapping[str, object],
    observed: int,
    reference_class: str | None,
    tpi: _XboxTpiIndex,
) -> ExtentAssessment:
    reported = _reported_slot_count(table)
    matches, reasons = _base_extent_assessment(observed, reported)
    layout = tpi.primary_layout(reference_class) if reference_class else None
    declared = layout.slot_count if layout else None

    if declared is None:
        status = "unassessed_no_hole_free_xbox_tpi_map"
        excess = None
    elif observed > declared:
        status = "pointer_run_exceeds_hole_free_xbox_tpi_map"
        excess = observed - declared
        reasons.append(status)
    elif observed < declared:
        status = "shorter_than_hole_free_xbox_tpi_map"
        excess = 0
        reasons.append(status)
    else:
        status = "matches_hole_free_xbox_tpi_map"
        excess = 0

    return ExtentAssessment(
        observed_slot_count=observed,
        reported_slot_count=reported,
        reported_count_matches_payload=matches,
        status=status,
        extent_suspect=bool(reasons),
        reference_kind=(
            "xbox_tpi_primary_virtual_slot_map" if layout else None
        ),
        reference_class=reference_class if layout else None,
        reference_slot_count=declared,
        reference_hole_free=layout.hole_free if layout else None,
        excess_slot_count=excess,
        reasons=tuple(reasons),
    )


def _table_list(value: object, *, class_name: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise VtableFormatError(
            f"vtable collection for {class_name!r} must be a list"
        )
    return value


def _slot_list(value: object, *, vtable_id: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise VtableFormatError(f"slots for {vtable_id} must be a list")
    return value


def parse_pc_vtables(document: Mapping[str, object]) -> VtableDataset:
    """Normalize the current ``pc_classes.json`` shape without selecting tables."""

    raw_classes = document.get("classes", document)
    if not isinstance(raw_classes, Mapping):
        raise VtableFormatError("PC vtable document must contain a classes map")

    records: list[VtableRecord] = []
    for raw_class_name in sorted(raw_classes, key=str):
        class_name = str(raw_class_name)
        raw_tables = _table_list(
            raw_classes[raw_class_name], class_name=class_name
        )
        for table_index, raw_table in enumerate(raw_tables):
            if not isinstance(raw_table, Mapping):
                raise VtableFormatError(
                    f"PC table {class_name}[{table_index}] must be an object"
                )
            address = _parse_address(
                raw_table.get("vtable_va"), field="PC vtable_va"
            )
            vtable_id = make_vtable_id(
                "pc", class_name, table_index, address
            )
            raw_slots = _slot_list(
                raw_table.get("slots"), vtable_id=vtable_id
            )
            slots = tuple(
                VtableSlot(
                    slot_id=make_slot_id(vtable_id, slot_index),
                    vtable_id=vtable_id,
                    slot_index=slot_index,
                    target_address_space="va",
                    target_address=_parse_address(
                        raw_target, field="PC slot target"
                    ),
                    raw_target_address=str(raw_target),
                )
                for slot_index, raw_target in enumerate(raw_slots)
            )
            offset_value = raw_table.get("offset")
            if isinstance(offset_value, bool) or not isinstance(offset_value, int):
                raise VtableFormatError(
                    f"PC table {vtable_id} has invalid COL offset {offset_value!r}"
                )
            col_address = _parse_address(
                raw_table.get("col_va"), field="PC col_va"
            )
            rtti_name = raw_table.get("rtti_name")
            if not isinstance(rtti_name, str):
                raise VtableFormatError(
                    f"PC table {vtable_id} has invalid rtti_name"
                )
            records.append(
                VtableRecord(
                    vtable_id=vtable_id,
                    platform="pc",
                    class_name=class_name,
                    source_table_index=table_index,
                    address_space="va",
                    address=address,
                    raw_table_identity=rtti_name,
                    raw_qualifier=None,
                    qualifier=None,
                    vfptr_role="primary" if offset_value == 0 else "secondary",
                    role_basis="pc_complete_object_locator_offset",
                    subobject_offset=offset_value,
                    subobject_offset_candidates=(offset_value,),
                    col_address=col_address,
                    rtti_name=rtti_name,
                    slots=slots,
                    extent=_pc_extent(raw_table, len(slots)),
                )
            )

    return VtableDataset(platform="pc", tables=tuple(records))


def _xbox_role(
    class_name: str,
    symbol: XboxVftableSymbol,
    tpi: _XboxTpiIndex,
) -> tuple[str, str, int | None, tuple[int, ...]]:
    if symbol.is_unqualified:
        return "primary", "unqualified_xbox_vftable_symbol", 0, (0,)
    if symbol.simple_qualifier is None:
        return "unknown", "complex_or_unrecognized_vftable_qualifier", None, ()

    candidates = tuple(
        sorted(tpi.base_offsets(class_name).get(symbol.simple_qualifier, ()))
    )
    if len(candidates) != 1:
        return (
            "unknown",
            "xbox_tpi_qualifier_offset_not_unique",
            None,
            candidates,
        )
    offset = candidates[0]
    return (
        "primary" if offset == 0 else "secondary",
        "xbox_tpi_qualified_base_offset",
        offset,
        candidates,
    )


def parse_xbox_vtables(
    document: Mapping[str, object],
    *,
    types: Mapping[str, object] | None = None,
) -> VtableDataset:
    """Normalize every current ``vtables_360.json`` table and slot occurrence."""

    tpi = _XboxTpiIndex(types)
    records: list[VtableRecord] = []
    for raw_class_name in sorted(document, key=str):
        class_name = str(raw_class_name)
        raw_tables = _table_list(document[raw_class_name], class_name=class_name)
        for table_index, raw_table in enumerate(raw_tables):
            if not isinstance(raw_table, Mapping):
                raise VtableFormatError(
                    f"Xbox table {class_name}[{table_index}] must be an object"
                )
            address = _parse_address(
                raw_table.get("vtable_va"), field="Xbox vtable_va"
            )
            vtable_id = make_vtable_id(
                "xbox360", class_name, table_index, address
            )
            raw_symbol = raw_table.get("symbol")
            if not isinstance(raw_symbol, str):
                raise VtableFormatError(
                    f"Xbox table {vtable_id} has invalid symbol"
                )
            symbol = parse_xbox_vftable_symbol(raw_symbol)
            role, role_basis, subobject_offset, candidates = _xbox_role(
                class_name, symbol, tpi
            )

            raw_slots = _slot_list(
                raw_table.get("slots"), vtable_id=vtable_id
            )
            slots: list[VtableSlot] = []
            for slot_index, raw_slot in enumerate(raw_slots):
                if not isinstance(raw_slot, Mapping):
                    raise VtableFormatError(
                        f"Xbox slot {vtable_id}[{slot_index}] must be an object"
                    )
                target_value = raw_slot.get("va")
                raw_name = raw_slot.get("name")
                if not isinstance(raw_name, str):
                    raise VtableFormatError(
                        f"Xbox slot {vtable_id}[{slot_index}] has invalid name"
                    )
                slot_id = make_slot_id(vtable_id, slot_index)
                slots.append(
                    VtableSlot(
                        slot_id=slot_id,
                        vtable_id=vtable_id,
                        slot_index=slot_index,
                        target_address_space="va",
                        target_address=_parse_address(
                            target_value, field="Xbox slot target"
                        ),
                        raw_target_address=str(target_value),
                        name_observations=(
                            SlotNameObservation(
                                observation_id=f"{slot_id}:name:address-derived:0",
                                raw_name=raw_name,
                            ),
                        ),
                    )
                )

            reference_class = None
            if role == "primary":
                reference_class = class_name
            elif role == "secondary":
                reference_class = symbol.simple_qualifier
            extent = _xbox_extent(
                table=raw_table,
                observed=len(slots),
                reference_class=reference_class,
                tpi=tpi,
            )
            records.append(
                VtableRecord(
                    vtable_id=vtable_id,
                    platform="xbox360",
                    class_name=class_name,
                    source_table_index=table_index,
                    address_space="va",
                    address=address,
                    raw_table_identity=raw_symbol,
                    raw_qualifier=symbol.raw_qualifier,
                    qualifier=symbol.simple_qualifier,
                    vfptr_role=role,
                    role_basis=role_basis,
                    subobject_offset=subobject_offset,
                    subobject_offset_candidates=candidates,
                    col_address=None,
                    rtti_name=None,
                    slots=tuple(slots),
                    extent=extent,
                )
            )

    return VtableDataset(platform="xbox360", tables=tuple(records))


def _load_json_object(path: str | Path) -> Mapping[str, object]:
    with Path(path).open("r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, Mapping):
        raise VtableFormatError(f"{path!s} must contain a JSON object")
    return document


def load_pc_vtables(path: str | Path) -> VtableDataset:
    """Load and normalize ``pc_classes.json`` from an explicit path."""

    return parse_pc_vtables(_load_json_object(path))


def load_xbox_vtables(
    path: str | Path, *, types_path: str | Path | None = None
) -> VtableDataset:
    """Load Xbox vtables and optional same-build TPI facts from explicit paths."""

    types = _load_json_object(types_path) if types_path is not None else None
    return parse_xbox_vtables(_load_json_object(path), types=types)


__all__ = [
    "ExtentAssessment",
    "SlotNameObservation",
    "VtableDataset",
    "VtableFormatError",
    "VtableRecord",
    "VtableSlot",
    "XboxVftableSymbol",
    "load_pc_vtables",
    "load_xbox_vtables",
    "make_slot_id",
    "make_vtable_id",
    "parse_pc_vtables",
    "parse_xbox_vftable_symbol",
    "parse_xbox_vtables",
]
