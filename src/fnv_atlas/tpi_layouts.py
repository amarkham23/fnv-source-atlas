"""Identity-safe CodeView class, enum, field, and method layout records.

The legacy ``types_360.json`` export keyed definitions by display name and kept
only one record for duplicate names.  It also discarded the CodeView type index
on methods and fields.  This module instead treats the PDB TPI type index as the
record identity, preserves forward declarations and duplicate definitions, and
keeps every referenced type index alongside best-effort readable spelling.

Unknown or malformed embedded field-list records are never silently skipped.
They terminate only the affected list and produce an explicit diagnostic with
the unparsed bytes retained as hexadecimal context.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import struct
from typing import Any

from .tpi_signatures import TpiRecord, TpiTypeResolver


LF_METHODLIST = 0x1206
LF_FIELDLIST = 0x1203
LF_CLASS = 0x1504
LF_STRUCTURE = 0x1505
LF_UNION = 0x1506
LF_ENUM = 0x1507

LF_BCLASS = 0x1400
LF_VBCLASS = 0x1401
LF_IVBCLASS = 0x1402
LF_INDEX = 0x1404
LF_VFUNCTAB = 0x1409
LF_ENUMERATE = 0x1502
LF_MEMBER = 0x150D
LF_STMEMBER = 0x150E
LF_METHOD = 0x150F
LF_NESTTYPE = 0x1510
LF_ONEMETHOD = 0x1511
LF_NESTTYPEEX = 0x1512
LF_BINTERFACE = 0x151A

CV_PROP_FORWARD_REFERENCE = 0x0080
CV_PROP_HAS_UNIQUE_NAME = 0x0200


TAG_KINDS = {
    LF_CLASS: "class",
    LF_STRUCTURE: "structure",
    LF_UNION: "union",
    LF_ENUM: "enum",
}

MEMBER_KINDS = {
    LF_BCLASS: "base_class",
    LF_BINTERFACE: "base_interface",
    LF_VBCLASS: "virtual_base_class",
    LF_IVBCLASS: "indirect_virtual_base_class",
    LF_VFUNCTAB: "vtable_pointer",
    LF_ENUMERATE: "enumerator",
    LF_MEMBER: "data_member",
    LF_STMEMBER: "static_data_member",
    LF_METHOD: "overloaded_method",
    LF_NESTTYPE: "nested_type",
    LF_NESTTYPEEX: "nested_type_ex",
    LF_ONEMETHOD: "one_method",
    LF_INDEX: "continuation",
}

ACCESS_NAMES = {
    0: "none",
    1: "private",
    2: "protected",
    3: "public",
}

METHOD_KIND_NAMES = {
    0: "vanilla",
    1: "virtual",
    2: "static",
    3: "friend",
    4: "introducing_virtual",
    5: "pure_virtual",
    6: "pure_introducing_virtual",
}


class LayoutFormatError(ValueError):
    """A selected TPI layout record cannot be decoded structurally."""


@dataclass(frozen=True, slots=True)
class RawTypeRecord:
    """One exact TPI record, including bytes needed for future re-decoding."""

    type_index: int
    leaf_kind: int
    leaf_name: str
    record_length: int
    body: bytes
    body_sha256: str
    rendered_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type_index": self.type_index,
            "leaf_kind": self.leaf_kind,
            "leaf_name": self.leaf_name,
            "record_length": self.record_length,
            "body_hex": self.body.hex(),
            "body_sha256": self.body_sha256,
            "rendered_type": self.rendered_type,
        }


@dataclass(frozen=True, slots=True)
class TypeRecordExtraction:
    records: tuple[RawTypeRecord, ...]

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def body_bytes(self) -> int:
        return sum(len(record.body) for record in self.records)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_count": self.record_count,
            "body_bytes": self.body_bytes,
            "records": [record.to_dict() for record in self.records],
        }


@dataclass(frozen=True, slots=True)
class LayoutDiagnostic:
    code: str
    type_index: int
    offset: int
    message: str
    remaining_hex: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class MethodOverload:
    ordinal: int
    attributes: int
    access: str
    method_kind: str
    method_options: int
    type_index: int
    rendered_type: str
    vtable_offset: int | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class LayoutMember:
    ordinal: int
    source_field_list_type_index: int
    source_record_offset: int
    leaf_kind: int
    member_kind: str
    attributes: int | None = None
    access: str | None = None
    method_kind: str | None = None
    method_options: int | None = None
    name: str | None = None
    type_index: int | None = None
    rendered_type: str | None = None
    offset: int | None = None
    value: int | None = None
    base_type_index: int | None = None
    vbptr_type_index: int | None = None
    vbptr_offset: int | None = None
    vtable_index: int | None = None
    method_list_type_index: int | None = None
    declared_overload_count: int | None = None
    overloads: tuple[MethodOverload, ...] = ()
    vtable_offset: int | None = None
    continuation_type_index: int | None = None

    @property
    def physical_key(self) -> tuple[int, int]:
        return (self.source_field_list_type_index, self.source_record_offset)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["overloads"] = [overload.to_dict() for overload in self.overloads]
        return result


@dataclass(frozen=True, slots=True)
class TagLayout:
    type_index: int
    leaf_kind: int
    tag_kind: str
    member_count: int
    properties: int
    field_list_type_index: int
    derived_type_index: int | None
    vtable_shape_type_index: int | None
    underlying_type_index: int | None
    size: int | None
    name: str
    unique_name: str | None
    is_forward_reference: bool
    record_sha256: str
    members: tuple[LayoutMember, ...]
    diagnostics: tuple[LayoutDiagnostic, ...]

    @property
    def identity_name(self) -> str:
        """Canonical readable identity when CodeView supplied one."""

        return self.unique_name or self.name

    @property
    def decoded_member_count(self) -> int:
        """CodeView count, expanding LF_METHOD overload groups."""

        return sum(
            (member.declared_overload_count or 0)
            if member.member_kind == "overloaded_method"
            else (0 if member.member_kind == "continuation" else 1)
            for member in self.members
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["decoded_member_count"] = self.decoded_member_count
        result["members"] = [member.to_dict() for member in self.members]
        result["diagnostics"] = [item.to_dict() for item in self.diagnostics]
        return result


@dataclass(frozen=True, slots=True)
class LayoutExtraction:
    records: tuple[TagLayout, ...]

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def definition_count(self) -> int:
        return sum(not record.is_forward_reference for record in self.records)

    @property
    def forward_reference_count(self) -> int:
        return self.record_count - self.definition_count

    @property
    def member_count(self) -> int:
        return sum(len(record.members) for record in self.records)

    @property
    def physical_member_count(self) -> int:
        return len(
            {
                member.physical_key
                for record in self.records
                for member in record.members
            }
        )

    @property
    def diagnostic_count(self) -> int:
        return sum(len(record.diagnostics) for record in self.records)

    @property
    def duplicate_display_name_count(self) -> int:
        counts = Counter(
            record.name for record in self.records if not record.is_forward_reference
        )
        return sum(count > 1 for count in counts.values())

    def definitions_by_identity_name(self) -> dict[str, tuple[TagLayout, ...]]:
        grouped: dict[str, list[TagLayout]] = defaultdict(list)
        for record in self.records:
            if not record.is_forward_reference:
                grouped[record.identity_name].append(record)
        return {
            name: tuple(sorted(records, key=lambda record: record.type_index))
            for name, records in sorted(grouped.items())
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_count": self.record_count,
            "definition_count": self.definition_count,
            "forward_reference_count": self.forward_reference_count,
            "member_count": self.member_count,
            "physical_member_count": self.physical_member_count,
            "diagnostic_count": self.diagnostic_count,
            "duplicate_display_name_count": self.duplicate_display_name_count,
            "records": [record.to_dict() for record in self.records],
        }


@dataclass(frozen=True, slots=True)
class TpiLayoutCorpus:
    type_records: TypeRecordExtraction
    layouts: LayoutExtraction

    def to_dict(self) -> dict[str, Any]:
        return {
            "type_records": self.type_records.to_dict(),
            "layouts": self.layouts.to_dict(),
        }


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _cstring(data: bytes, offset: int) -> tuple[str, int]:
    if offset < 0 or offset >= len(data):
        raise LayoutFormatError(f"string offset {offset} is outside record")
    end = data.find(b"\0", offset)
    if end < 0:
        raise LayoutFormatError("unterminated CodeView string")
    return data[offset:end].decode("latin-1"), end + 1


def _numeric(data: bytes, offset: int) -> tuple[int, int]:
    """Decode an integral CodeView numeric leaf without losing signedness."""

    if offset + 2 > len(data):
        raise LayoutFormatError("truncated CodeView numeric leaf")
    leaf = _u16(data, offset)
    if leaf < 0x8000:
        return leaf, offset + 2
    formats = {
        0x8000: "<b",   # LF_CHAR
        0x8001: "<h",   # LF_SHORT
        0x8002: "<H",   # LF_USHORT
        0x8003: "<i",   # LF_LONG
        0x8004: "<I",   # LF_ULONG
        0x8009: "<q",   # LF_QUADWORD
        0x800A: "<Q",   # LF_UQUADWORD
    }
    fmt = formats.get(leaf)
    if fmt is None:
        raise LayoutFormatError(f"unsupported integral numeric leaf 0x{leaf:04X}")
    size = struct.calcsize(fmt)
    start = offset + 2
    if start + size > len(data):
        raise LayoutFormatError(f"truncated numeric leaf 0x{leaf:04X}")
    return struct.unpack_from(fmt, data, start)[0], start + size


def _skip_padding(data: bytes, offset: int) -> int:
    while offset < len(data) and data[offset] >= 0xF0:
        count = data[offset] & 0x0F
        if count == 0:
            offset += 1
            continue
        end = offset + count
        if end > len(data):
            raise LayoutFormatError("CodeView padding extends past record")
        offset = end
    return offset


def _record_hash(record: TpiRecord) -> str:
    payload = struct.pack("<H", record.leaf_kind) + record.body
    return hashlib.sha256(payload).hexdigest()


def _attributes(attributes: int) -> tuple[str, str, int]:
    method_kind_value = (attributes >> 2) & 0x07
    return (
        ACCESS_NAMES.get(attributes & 0x03, f"access_{attributes & 0x03}"),
        METHOD_KIND_NAMES.get(method_kind_value, f"method_{method_kind_value}"),
        attributes >> 5,
    )


def _parse_method_list(
    resolver: TpiTypeResolver,
    type_index: int,
) -> tuple[tuple[MethodOverload, ...], tuple[LayoutDiagnostic, ...]]:
    record = resolver.record(type_index)
    if record is None:
        return (), (
            LayoutDiagnostic(
                "missing_method_list",
                type_index,
                0,
                f"method-list type 0x{type_index:X} is missing",
            ),
        )
    if record.leaf_kind != LF_METHODLIST:
        return (), (
            LayoutDiagnostic(
                "wrong_method_list_leaf",
                type_index,
                0,
                f"type 0x{type_index:X} is {record.leaf_name}, not LF_METHODLIST",
                record.body.hex(),
            ),
        )
    data = record.body
    offset = 0
    overloads: list[MethodOverload] = []
    diagnostics: list[LayoutDiagnostic] = []
    while offset < len(data):
        try:
            offset = _skip_padding(data, offset)
            if offset == len(data):
                break
            start = offset
            if offset + 8 > len(data):
                raise LayoutFormatError("truncated LF_METHODLIST entry")
            attributes = _u16(data, offset)
            method_type_index = _u32(data, offset + 4)
            offset += 8
            access, method_kind, method_options = _attributes(attributes)
            vtable_offset = None
            if method_kind in ("introducing_virtual", "pure_introducing_virtual"):
                if offset + 4 > len(data):
                    raise LayoutFormatError("truncated introducing-virtual offset")
                vtable_offset = _i32(data, offset)
                offset += 4
            overloads.append(
                MethodOverload(
                    ordinal=len(overloads),
                    attributes=attributes,
                    access=access,
                    method_kind=method_kind,
                    method_options=method_options,
                    type_index=method_type_index,
                    rendered_type=resolver.render_type(method_type_index),
                    vtable_offset=vtable_offset,
                )
            )
        except (IndexError, struct.error, LayoutFormatError) as exc:
            diagnostics.append(
                LayoutDiagnostic(
                    "malformed_method_list",
                    type_index,
                    start if "start" in locals() else offset,
                    str(exc),
                    data[offset:].hex(),
                )
            )
            break
    return tuple(overloads), tuple(diagnostics)


def _parse_field_lists(
    resolver: TpiTypeResolver,
    root_type_index: int,
) -> tuple[tuple[LayoutMember, ...], tuple[LayoutDiagnostic, ...]]:
    if root_type_index == 0:
        return (), ()
    members: list[LayoutMember] = []
    diagnostics: list[LayoutDiagnostic] = []
    pending = [root_type_index]
    visited: set[int] = set()
    while pending:
        field_list_type_index = pending.pop(0)
        if field_list_type_index in visited:
            diagnostics.append(
                LayoutDiagnostic(
                    "field_list_cycle",
                    field_list_type_index,
                    0,
                    f"field-list continuation cycle at 0x{field_list_type_index:X}",
                )
            )
            continue
        visited.add(field_list_type_index)
        record = resolver.record(field_list_type_index)
        if record is None:
            diagnostics.append(
                LayoutDiagnostic(
                    "missing_field_list",
                    field_list_type_index,
                    0,
                    f"field-list type 0x{field_list_type_index:X} is missing",
                )
            )
            continue
        if record.leaf_kind != LF_FIELDLIST:
            diagnostics.append(
                LayoutDiagnostic(
                    "wrong_field_list_leaf",
                    field_list_type_index,
                    0,
                    f"type 0x{field_list_type_index:X} is {record.leaf_name}, "
                    "not LF_FIELDLIST",
                    record.body.hex(),
                )
            )
            continue
        data = record.body
        offset = 0
        while offset < len(data):
            try:
                offset = _skip_padding(data, offset)
                if offset == len(data):
                    break
                start = offset
                if offset + 2 > len(data):
                    raise LayoutFormatError("truncated field-list member kind")
                leaf_kind = _u16(data, offset)
                offset += 2
                ordinal = len(members)
                common = dict(
                    ordinal=ordinal,
                    source_field_list_type_index=field_list_type_index,
                    source_record_offset=start,
                    leaf_kind=leaf_kind,
                    member_kind=MEMBER_KINDS.get(
                        leaf_kind, f"member_0x{leaf_kind:04X}"
                    ),
                )
                if leaf_kind in (LF_BCLASS, LF_BINTERFACE):
                    attributes = _u16(data, offset)
                    base_type = _u32(data, offset + 2)
                    base_offset, offset = _numeric(data, offset + 6)
                    members.append(
                        LayoutMember(
                            **common,
                            attributes=attributes,
                            access=ACCESS_NAMES.get(attributes & 3),
                            base_type_index=base_type,
                            type_index=base_type,
                            rendered_type=resolver.render_type(base_type),
                            offset=base_offset,
                        )
                    )
                elif leaf_kind in (LF_VBCLASS, LF_IVBCLASS):
                    attributes = _u16(data, offset)
                    base_type = _u32(data, offset + 2)
                    vbptr_type = _u32(data, offset + 6)
                    vbptr_offset, next_offset = _numeric(data, offset + 10)
                    vtable_index, offset = _numeric(data, next_offset)
                    members.append(
                        LayoutMember(
                            **common,
                            attributes=attributes,
                            access=ACCESS_NAMES.get(attributes & 3),
                            base_type_index=base_type,
                            type_index=base_type,
                            rendered_type=resolver.render_type(base_type),
                            vbptr_type_index=vbptr_type,
                            vbptr_offset=vbptr_offset,
                            vtable_index=vtable_index,
                        )
                    )
                elif leaf_kind == LF_VFUNCTAB:
                    if offset + 6 > len(data):
                        raise LayoutFormatError("truncated LF_VFUNCTAB")
                    vtable_type = _u32(data, offset + 2)
                    offset += 6
                    members.append(
                        LayoutMember(
                            **common,
                            type_index=vtable_type,
                            rendered_type=resolver.render_type(vtable_type),
                        )
                    )
                elif leaf_kind == LF_ENUMERATE:
                    attributes = _u16(data, offset)
                    value, string_offset = _numeric(data, offset + 2)
                    name, offset = _cstring(data, string_offset)
                    members.append(
                        LayoutMember(
                            **common,
                            attributes=attributes,
                            access=ACCESS_NAMES.get(attributes & 3),
                            name=name,
                            value=value,
                        )
                    )
                elif leaf_kind == LF_MEMBER:
                    attributes = _u16(data, offset)
                    member_type = _u32(data, offset + 2)
                    member_offset, string_offset = _numeric(data, offset + 6)
                    name, offset = _cstring(data, string_offset)
                    members.append(
                        LayoutMember(
                            **common,
                            attributes=attributes,
                            access=ACCESS_NAMES.get(attributes & 3),
                            name=name,
                            type_index=member_type,
                            rendered_type=resolver.render_type(member_type),
                            offset=member_offset,
                        )
                    )
                elif leaf_kind == LF_STMEMBER:
                    attributes = _u16(data, offset)
                    member_type = _u32(data, offset + 2)
                    name, offset = _cstring(data, offset + 6)
                    members.append(
                        LayoutMember(
                            **common,
                            attributes=attributes,
                            access=ACCESS_NAMES.get(attributes & 3),
                            name=name,
                            type_index=member_type,
                            rendered_type=resolver.render_type(member_type),
                        )
                    )
                elif leaf_kind == LF_METHOD:
                    declared_count = _u16(data, offset)
                    method_list_type_index = _u32(data, offset + 2)
                    name, offset = _cstring(data, offset + 6)
                    overloads, method_diagnostics = _parse_method_list(
                        resolver, method_list_type_index
                    )
                    diagnostics.extend(method_diagnostics)
                    if len(overloads) != declared_count:
                        diagnostics.append(
                            LayoutDiagnostic(
                                "method_overload_count_mismatch",
                                field_list_type_index,
                                start,
                                f"{name!r} declares {declared_count} overloads but "
                                f"method list 0x{method_list_type_index:X} has "
                                f"{len(overloads)}",
                            )
                        )
                    members.append(
                        LayoutMember(
                            **common,
                            name=name,
                            method_list_type_index=method_list_type_index,
                            declared_overload_count=declared_count,
                            overloads=overloads,
                        )
                    )
                elif leaf_kind in (LF_NESTTYPE, LF_NESTTYPEEX):
                    attributes = _u16(data, offset)
                    nested_type = _u32(data, offset + 2)
                    name, offset = _cstring(data, offset + 6)
                    members.append(
                        LayoutMember(
                            **common,
                            attributes=attributes,
                            access=ACCESS_NAMES.get(attributes & 3),
                            name=name,
                            type_index=nested_type,
                            rendered_type=resolver.render_type(nested_type),
                        )
                    )
                elif leaf_kind == LF_ONEMETHOD:
                    attributes = _u16(data, offset)
                    method_type = _u32(data, offset + 2)
                    offset += 6
                    access, method_kind, method_options = _attributes(attributes)
                    vtable_offset = None
                    if method_kind in (
                        "introducing_virtual",
                        "pure_introducing_virtual",
                    ):
                        if offset + 4 > len(data):
                            raise LayoutFormatError(
                                "truncated LF_ONEMETHOD vtable offset"
                            )
                        vtable_offset = _i32(data, offset)
                        offset += 4
                    name, offset = _cstring(data, offset)
                    members.append(
                        LayoutMember(
                            **common,
                            attributes=attributes,
                            access=access,
                            method_kind=method_kind,
                            method_options=method_options,
                            name=name,
                            type_index=method_type,
                            rendered_type=resolver.render_type(method_type),
                            vtable_offset=vtable_offset,
                        )
                    )
                elif leaf_kind == LF_INDEX:
                    if offset + 6 > len(data):
                        raise LayoutFormatError("truncated LF_INDEX")
                    continuation = _u32(data, offset + 2)
                    offset += 6
                    pending.append(continuation)
                    members.append(
                        LayoutMember(
                            **common,
                            continuation_type_index=continuation,
                        )
                    )
                else:
                    diagnostics.append(
                        LayoutDiagnostic(
                            "unknown_field_member",
                            field_list_type_index,
                            start,
                            f"unsupported field member 0x{leaf_kind:04X}",
                            data[start:].hex(),
                        )
                    )
                    break
            except (IndexError, struct.error, LayoutFormatError) as exc:
                diagnostics.append(
                    LayoutDiagnostic(
                        "malformed_field_member",
                        field_list_type_index,
                        start if "start" in locals() else offset,
                        str(exc),
                        data[offset:].hex(),
                    )
                )
                break
    return tuple(members), tuple(diagnostics)


def _tag_layout(resolver: TpiTypeResolver, record: TpiRecord) -> TagLayout:
    data = record.body
    diagnostics: list[LayoutDiagnostic] = []
    try:
        if record.leaf_kind in (LF_CLASS, LF_STRUCTURE):
            if len(data) < 18:
                raise LayoutFormatError("class/structure record is shorter than 18 bytes")
            member_count, properties, field_list, derived, vtable_shape = (
                struct.unpack_from("<HHIII", data, 0)
            )
            size, string_offset = _numeric(data, 16)
            underlying = None
        elif record.leaf_kind == LF_UNION:
            if len(data) < 10:
                raise LayoutFormatError("union record is shorter than 10 bytes")
            member_count, properties, field_list = struct.unpack_from("<HHI", data, 0)
            size, string_offset = _numeric(data, 8)
            derived = None
            vtable_shape = None
            underlying = None
        elif record.leaf_kind == LF_ENUM:
            if len(data) < 13:
                raise LayoutFormatError("enum record is shorter than 13 bytes")
            member_count, properties, underlying, field_list = struct.unpack_from(
                "<HHII", data, 0
            )
            size = None
            string_offset = 12
            derived = None
            vtable_shape = None
        else:
            raise LayoutFormatError(f"unsupported tag leaf 0x{record.leaf_kind:04X}")
        name, after_name = _cstring(data, string_offset)
        unique_name = None
        if properties & CV_PROP_HAS_UNIQUE_NAME:
            unique_name, _ = _cstring(data, after_name)
        is_forward = bool(properties & CV_PROP_FORWARD_REFERENCE)
        members, field_diagnostics = (
            ((), ())
            if is_forward
            else _parse_field_lists(resolver, field_list)
        )
        diagnostics.extend(field_diagnostics)
        decoded_member_count = sum(
            (member.declared_overload_count or 0)
            if member.member_kind == "overloaded_method"
            else (0 if member.member_kind == "continuation" else 1)
            for member in members
        )
        if decoded_member_count != member_count:
            diagnostics.append(
                LayoutDiagnostic(
                    "tag_member_count_mismatch",
                    record.type_index,
                    0,
                    f"tag declares {member_count} members but decoded "
                    f"{decoded_member_count}",
                )
            )
    except (IndexError, struct.error, LayoutFormatError) as exc:
        diagnostics.append(
            LayoutDiagnostic(
                "malformed_tag_record",
                record.type_index,
                0,
                str(exc),
                data.hex(),
            )
        )
        member_count = 0
        properties = 0
        field_list = 0
        derived = None
        vtable_shape = None
        underlying = None
        size = None
        name = f"<malformed-type-0x{record.type_index:X}>"
        unique_name = None
        is_forward = False
        members = ()
    return TagLayout(
        type_index=record.type_index,
        leaf_kind=record.leaf_kind,
        tag_kind=TAG_KINDS[record.leaf_kind],
        member_count=member_count,
        properties=properties,
        field_list_type_index=field_list,
        derived_type_index=derived,
        vtable_shape_type_index=vtable_shape,
        underlying_type_index=underlying,
        size=size,
        name=name,
        unique_name=unique_name,
        is_forward_reference=is_forward,
        record_sha256=_record_hash(record),
        members=members,
        diagnostics=tuple(diagnostics),
    )


def extract_type_layouts_from_resolver(resolver: TpiTypeResolver) -> LayoutExtraction:
    """Extract every exact class/structure/union/enum TPI record in index order."""

    records = tuple(
        _tag_layout(resolver, record)
        for record in resolver.iter_records()
        if record.leaf_kind in TAG_KINDS
    )
    return LayoutExtraction(records)


def extract_type_records_from_resolver(
    resolver: TpiTypeResolver,
) -> TypeRecordExtraction:
    """Retain every raw TPI record and its best-effort readable rendering."""

    return TypeRecordExtraction(
        tuple(
            RawTypeRecord(
                type_index=record.type_index,
                leaf_kind=record.leaf_kind,
                leaf_name=record.leaf_name,
                record_length=record.record_length,
                body=record.body,
                body_sha256=hashlib.sha256(record.body).hexdigest(),
                rendered_type=resolver.render_type(record.type_index),
            )
            for record in resolver.iter_records()
        )
    )


def extract_tpi_layout_corpus(pdb_path: str | Path) -> TpiLayoutCorpus:
    """Extract the complete raw type map plus decoded tag layouts once."""

    resolver = TpiTypeResolver.from_pdb(pdb_path)
    return TpiLayoutCorpus(
        type_records=extract_type_records_from_resolver(resolver),
        layouts=extract_type_layouts_from_resolver(resolver),
    )


def extract_type_layouts(pdb_path: str | Path) -> LayoutExtraction:
    """Extract identity-safe layouts from an explicitly named PDB."""

    return extract_type_layouts_from_resolver(TpiTypeResolver.from_pdb(pdb_path))


__all__ = [
    "ACCESS_NAMES",
    "CV_PROP_FORWARD_REFERENCE",
    "CV_PROP_HAS_UNIQUE_NAME",
    "LayoutDiagnostic",
    "LayoutExtraction",
    "LayoutFormatError",
    "LayoutMember",
    "MethodOverload",
    "RawTypeRecord",
    "TAG_KINDS",
    "TagLayout",
    "TpiLayoutCorpus",
    "TypeRecordExtraction",
    "extract_tpi_layout_corpus",
    "extract_type_layouts",
    "extract_type_layouts_from_resolver",
    "extract_type_records_from_resolver",
]
