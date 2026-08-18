"""Lossless Xbox vftable symbols and separate pointer-run observations.

MSVC vftable names in the Fallout Xbox PDB are ``S_PUB32`` records in the
DBI symbol-record stream.  They are not typed data records in the per-module
streams.  A physical CodeView record is therefore the primary identity here;
its decorated name and virtual address are attributes, not map keys.

Reading code pointers after a vftable address is useful, but that scan does not
declare a table extent.  Adjacent tables can form one uninterrupted run of
valid pointers.  This module consequently exposes executable pointer runs as a
second dataset, records known-symbol boundaries without choosing one, and
never promotes either a longest run or one same-address alias.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
from typing import Iterable, Sequence

from .pdb_symbols import PdbFormatError, _MsfReader


DBI_STREAM_INDEX = 3
S_PUB32 = 0x110E
IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass(frozen=True, slots=True)
class VftableDiagnostic:
    """An explicit limitation or ambiguity retained with an extraction."""

    code: str
    subject_id: str | None
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "subject_id": self.subject_id,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class DbiSymbolStreamReference:
    """The three DBI symbol stream references relevant to this inventory."""

    dbi_stream: int
    global_symbol_hash_stream: int | None
    public_symbol_hash_stream: int | None
    symbol_record_stream: int

    def to_dict(self) -> dict[str, object]:
        return {
            "dbi_stream": self.dbi_stream,
            "global_symbol_hash_stream": self.global_symbol_hash_stream,
            "public_symbol_hash_stream": self.public_symbol_hash_stream,
            "symbol_record_stream": self.symbol_record_stream,
        }


@dataclass(frozen=True, slots=True)
class VftableNameParts:
    """Conservative pieces of one exact MSVC decorated vftable name.

    The owner and qualifier values are still mangled encodings.  In particular,
    they are not guessed display names.  ``role_encoding`` reports only whether
    MSVC encoded a qualifier; it does not assert primary/secondary object
    layout semantics.
    """

    owner_encoding: str | None
    qualifier_encoding: str | None
    role_encoding: str
    parse_status: str
    is_template_owner: bool
    is_template_qualifier: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "owner_encoding": self.owner_encoding,
            "qualifier_encoding": self.qualifier_encoding,
            "role_encoding": self.role_encoding,
            "parse_status": self.parse_status,
            "is_template_owner": self.is_template_owner,
            "is_template_qualifier": self.is_template_qualifier,
        }


@dataclass(frozen=True, slots=True)
class VftableSymbolRecord:
    """One physical ``S_PUB32`` vftable record from the DBI record stream."""

    record_id: str
    canonical_name_id: str
    symbol_record_stream: int
    record_offset: int
    record_length: int
    record_kind: str
    record_kind_code: int
    public_flags: int
    section: int
    section_offset: int
    va: int | None
    decorated_name: str
    name_parts: VftableNameParts
    raw_record: bytes

    @property
    def is_template_owner(self) -> bool:
        return self.name_parts.is_template_owner

    @property
    def has_template_encoding(self) -> bool:
        return (
            self.name_parts.is_template_owner
            or self.name_parts.is_template_qualifier
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "canonical_name_id": self.canonical_name_id,
            "symbol_record_stream": self.symbol_record_stream,
            "record_offset": self.record_offset,
            "record_length": self.record_length,
            "record_kind": self.record_kind,
            "record_kind_code": self.record_kind_code,
            "public_flags": self.public_flags,
            "section": self.section,
            "section_offset": self.section_offset,
            "va": self.va,
            "decorated_name": self.decorated_name,
            "name_parts": self.name_parts.to_dict(),
            "raw_record_hex": self.raw_record.hex(),
        }


@dataclass(frozen=True, slots=True)
class VftableAddressGroup:
    """Every physical vftable record at one resolved address, unranked."""

    group_id: str
    va: int
    record_ids: tuple[str, ...]
    canonical_name_ids: tuple[str, ...]
    decorated_names: tuple[str, ...]

    @property
    def count(self) -> int:
        return len(self.record_ids)

    def to_dict(self) -> dict[str, object]:
        return {
            "group_id": self.group_id,
            "va": self.va,
            "record_ids": list(self.record_ids),
            "canonical_name_ids": list(self.canonical_name_ids),
            "decorated_names": list(self.decorated_names),
            "count": self.count,
        }


@dataclass(frozen=True, slots=True)
class VftableSymbolExtraction:
    """The DBI reference, physical records, address groups, and diagnostics."""

    stream_reference: DbiSymbolStreamReference
    records: tuple[VftableSymbolRecord, ...]
    address_groups: tuple[VftableAddressGroup, ...]
    diagnostics: tuple[VftableDiagnostic, ...]

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def unique_va_count(self) -> int:
        return len(self.address_groups)

    @property
    def unresolved_va_count(self) -> int:
        return sum(record.va is None for record in self.records)


@dataclass(frozen=True, slots=True)
class PeSection:
    """One PE section with both memory and file extents preserved."""

    index: int
    name: str
    va: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def memory_end(self) -> int:
        return self.va + self.virtual_size

    @property
    def raw_mapped_end(self) -> int:
        return self.va + min(self.virtual_size, self.raw_size)

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "name": self.name,
            "va": self.va,
            "virtual_size": self.virtual_size,
            "raw_offset": self.raw_offset,
            "raw_size": self.raw_size,
            "characteristics": self.characteristics,
        }


@dataclass(frozen=True, slots=True)
class PeImage:
    """The executable bytes and exact section mappings used by a scan."""

    image_base: int
    sections: tuple[PeSection, ...]
    data: bytes

    @property
    def section_bases(self) -> tuple[int, ...]:
        return tuple(section.va for section in self.sections)


@dataclass(frozen=True, slots=True)
class PointerSlotObservation:
    """One four-byte, big-endian text pointer in an observed run."""

    slot_id: str
    run_id: str
    slot_index: int
    slot_va: int
    target_va: int
    raw_word_hex: str

    def to_dict(self) -> dict[str, object]:
        return {
            "slot_id": self.slot_id,
            "run_id": self.run_id,
            "slot_index": self.slot_index,
            "slot_va": self.slot_va,
            "target_va": self.target_va,
            "raw_word_hex": self.raw_word_hex,
        }


@dataclass(frozen=True, slots=True)
class PointerRunObservation:
    """A maximal observed prefix of text pointers, not a table extent.

    ``known_boundary_slot_index`` is a table-relative coordinate for the next
    known vftable symbol.  It may therefore lie before, at, or after the end of
    ``slots``, which contains only the independently observed pointer prefix.
    """

    run_id: str
    address_group_id: str
    table_va: int
    symbol_record_ids: tuple[str, ...]
    slots: tuple[PointerSlotObservation, ...]
    termination_kind: str
    termination_va: int | None
    termination_word_hex: str | None
    next_vftable_va: int | None
    next_vftable_record_ids: tuple[str, ...]
    known_boundary_slot_index: int | None
    boundary_relation: str
    diagnostics: tuple[VftableDiagnostic, ...]

    @property
    def observed_pointer_count(self) -> int:
        return len(self.slots)

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "address_group_id": self.address_group_id,
            "table_va": self.table_va,
            "symbol_record_ids": list(self.symbol_record_ids),
            "observed_pointer_count": self.observed_pointer_count,
            "slots": [slot.to_dict() for slot in self.slots],
            "termination_kind": self.termination_kind,
            "termination_va": self.termination_va,
            "termination_word_hex": self.termination_word_hex,
            "next_vftable_va": self.next_vftable_va,
            "next_vftable_record_ids": list(self.next_vftable_record_ids),
            "known_boundary_slot_index": self.known_boundary_slot_index,
            "boundary_relation": self.boundary_relation,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True, slots=True)
class PointerRunExtraction:
    """Deterministic runs and scan-wide diagnostics."""

    runs: tuple[PointerRunObservation, ...]
    diagnostics: tuple[VftableDiagnostic, ...]

    @property
    def run_count(self) -> int:
        return len(self.runs)

    @property
    def slot_count(self) -> int:
        return sum(run.observed_pointer_count for run in self.runs)


@dataclass(frozen=True, slots=True)
class VftableCorpus:
    """Lossless symbols plus explicitly non-declarative executable scans."""

    symbols: VftableSymbolExtraction
    pointer_runs: PointerRunExtraction


def _u16(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<H", blob, offset)[0]


def _u32(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _optional_stream(value: int) -> int | None:
    return None if value == 0xFFFF else value


def parse_dbi_symbol_stream_reference(
    dbi_blob: bytes,
) -> DbiSymbolStreamReference:
    """Read DBI stream references without interpreting GSI hash buckets.

    GSI/public streams index records in the shared symbol-record stream.  The
    record stream and physical record offsets remain the authoritative source.
    """

    if len(dbi_blob) < 64:
        raise PdbFormatError("DBI stream is shorter than its 64-byte header")
    global_stream, _, public_stream, _, record_stream, _ = struct.unpack_from(
        "<6H", dbi_blob, 12
    )
    if record_stream == 0xFFFF:
        raise PdbFormatError("DBI has no symbol-record stream")
    return DbiSymbolStreamReference(
        dbi_stream=DBI_STREAM_INDEX,
        global_symbol_hash_stream=_optional_stream(global_stream),
        public_symbol_hash_stream=_optional_stream(public_stream),
        symbol_record_stream=record_stream,
    )


def parse_vftable_name(decorated_name: str) -> VftableNameParts:
    """Split only the stable outer vftable grammar, retaining mangled pieces."""

    if not decorated_name.startswith("??_7"):
        return VftableNameParts(
            owner_encoding=None,
            qualifier_encoding=None,
            role_encoding="not_vftable",
            parse_status="not_vftable",
            is_template_owner=False,
            is_template_qualifier=False,
        )

    marker = "@@6B"
    marker_at = decorated_name.rfind(marker)
    if marker_at < 4:
        return VftableNameParts(
            owner_encoding=None,
            qualifier_encoding=None,
            role_encoding="unparsed",
            parse_status="unrecognized_msvc_vftable_form",
            is_template_owner=False,
            is_template_qualifier=False,
        )

    owner = decorated_name[4:marker_at]
    tail = decorated_name[marker_at + len(marker) :]
    if tail == "@":
        qualifier = None
        role = "unqualified_vfptr_symbol"
        status = "parsed_unqualified"
    elif tail.endswith("@") and len(tail) > 1:
        qualifier = tail[:-1]
        role = "qualified_vfptr_symbol"
        status = "parsed_qualified"
    else:
        qualifier = tail or None
        role = "unparsed"
        status = "unterminated_role_encoding"

    return VftableNameParts(
        owner_encoding=owner,
        qualifier_encoding=qualifier,
        role_encoding=role,
        parse_status=status,
        is_template_owner="?$" in owner,
        is_template_qualifier=bool(qualifier and "?$" in qualifier),
    )


def make_vftable_record_id(
    symbol_record_stream: int, record_offset: int
) -> str:
    return (
        f"x360-vftable:s{symbol_record_stream:04d}:"
        f"o{record_offset:08X}"
    )


def make_canonical_name_id(decorated_name: str) -> str:
    """Identify the exact decorated byte string independently of its address."""

    digest = hashlib.sha256(decorated_name.encode("latin-1")).hexdigest()
    return f"x360-msvc-vftable-name:sha256:{digest}"


def _record_key(record: VftableSymbolRecord) -> tuple[int, int, str]:
    return (
        record.symbol_record_stream,
        record.record_offset,
        record.record_id,
    )


def _make_address_group_id(va: int, record_ids: Sequence[str]) -> str:
    membership = "\0".join(record_ids).encode("utf-8")
    digest = hashlib.sha256(membership).hexdigest()[:16]
    return f"x360-vftable-address:a{va:08X}:g{digest}"


def build_vftable_address_groups(
    records: Iterable[VftableSymbolRecord],
) -> tuple[VftableAddressGroup, ...]:
    """Group resolved records without choosing a preferred decorated name."""

    by_va: dict[int, list[VftableSymbolRecord]] = defaultdict(list)
    for record in records:
        if record.va is not None:
            by_va[record.va].append(record)

    groups: list[VftableAddressGroup] = []
    for va in sorted(by_va):
        members = sorted(by_va[va], key=_record_key)
        record_ids = tuple(member.record_id for member in members)
        groups.append(
            VftableAddressGroup(
                group_id=_make_address_group_id(va, record_ids),
                va=va,
                record_ids=record_ids,
                canonical_name_ids=tuple(
                    member.canonical_name_id for member in members
                ),
                decorated_names=tuple(
                    member.decorated_name for member in members
                ),
            )
        )
    return tuple(groups)


def parse_vftable_symbol_records(
    blob: bytes,
    *,
    symbol_record_stream: int,
    section_bases: Sequence[int],
) -> VftableSymbolExtraction:
    """Walk a DBI symbol-record stream and retain every vftable ``S_PUB32``.

    Any malformed ``S_PUB32`` is fatal because it could otherwise hide a
    vftable.  Unknown well-formed record kinds are advanced over normally.
    """

    if symbol_record_stream < 0:
        raise ValueError("symbol_record_stream cannot be negative")

    records: list[VftableSymbolRecord] = []
    diagnostics: list[VftableDiagnostic] = []
    cursor = 0
    while cursor + 4 <= len(blob):
        record_length = _u16(blob, cursor)
        if record_length < 2:
            if not any(blob[cursor:]):
                break
            raise PdbFormatError(
                f"invalid CodeView record length {record_length} in symbol "
                f"stream {symbol_record_stream} at offset 0x{cursor:X}"
            )
        record_end = cursor + 2 + record_length
        if record_end > len(blob):
            raise PdbFormatError(
                f"CodeView record in symbol stream {symbol_record_stream} at "
                f"offset 0x{cursor:X} ends past stream size"
            )

        kind = _u16(blob, cursor + 2)
        if kind == S_PUB32:
            body = cursor + 4
            if record_end - body < 11:
                raise PdbFormatError(
                    f"truncated S_PUB32 in symbol stream "
                    f"{symbol_record_stream} at offset 0x{cursor:X}"
                )
            nul = blob.find(b"\0", body + 10, record_end)
            if nul < 0:
                raise PdbFormatError(
                    f"unterminated S_PUB32 name in symbol stream "
                    f"{symbol_record_stream} at offset 0x{cursor:X}"
                )
            name_bytes = blob[body + 10 : nul]
            decorated_name = name_bytes.decode("latin-1")
            if decorated_name.startswith("??_7"):
                flags, section_offset = struct.unpack_from("<2I", blob, body)
                section = _u16(blob, body + 8)
                va = None
                if 1 <= section <= len(section_bases):
                    va = int(section_bases[section - 1]) + section_offset
                record_id = make_vftable_record_id(
                    symbol_record_stream, cursor
                )
                parts = parse_vftable_name(decorated_name)
                records.append(
                    VftableSymbolRecord(
                        record_id=record_id,
                        canonical_name_id=make_canonical_name_id(
                            decorated_name
                        ),
                        symbol_record_stream=symbol_record_stream,
                        record_offset=cursor,
                        record_length=record_length,
                        record_kind="S_PUB32",
                        record_kind_code=kind,
                        public_flags=flags,
                        section=section,
                        section_offset=section_offset,
                        va=va,
                        decorated_name=decorated_name,
                        name_parts=parts,
                        raw_record=blob[cursor:record_end],
                    )
                )
                if va is None:
                    diagnostics.append(
                        VftableDiagnostic(
                            code="unresolved_pe_section",
                            subject_id=record_id,
                            message=(
                                f"one-based section {section} is outside the "
                                f"{len(section_bases)} supplied PE sections"
                            ),
                        )
                    )
                if parts.parse_status not in {
                    "parsed_unqualified",
                    "parsed_qualified",
                }:
                    diagnostics.append(
                        VftableDiagnostic(
                            code="vftable_name_form_unparsed",
                            subject_id=record_id,
                            message=(
                                "the exact decorated name is retained, but its "
                                "outer owner/qualifier grammar was not decoded"
                            ),
                        )
                    )

        cursor = _align4(record_end)

    ordered = tuple(sorted(records, key=_record_key))
    if len({record.record_id for record in ordered}) != len(ordered):
        raise PdbFormatError("duplicate physical vftable record identity")
    return VftableSymbolExtraction(
        stream_reference=DbiSymbolStreamReference(
            dbi_stream=DBI_STREAM_INDEX,
            global_symbol_hash_stream=None,
            public_symbol_hash_stream=None,
            symbol_record_stream=symbol_record_stream,
        ),
        records=ordered,
        address_groups=build_vftable_address_groups(ordered),
        diagnostics=tuple(
            sorted(
                diagnostics,
                key=lambda item: (item.code, item.subject_id or "", item.message),
            )
        ),
    )


def parse_pe_image(blob: bytes) -> PeImage:
    """Parse only the PE fields needed for exact VA-to-file observations."""

    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise PdbFormatError("executable is not a PE image")
    pe_offset = _u32(blob, 0x3C)
    if pe_offset + 24 > len(blob) or blob[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PdbFormatError("missing or truncated PE signature")

    section_count = _u16(blob, pe_offset + 6)
    optional_size = _u16(blob, pe_offset + 20)
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(blob):
        raise PdbFormatError("truncated PE optional header")
    magic = _u16(blob, optional_offset)
    if magic == 0x10B:
        image_base = _u32(blob, optional_offset + 28)
    elif magic == 0x20B:
        image_base = struct.unpack_from("<Q", blob, optional_offset + 24)[0]
    else:
        raise PdbFormatError(
            f"unsupported PE optional-header magic 0x{magic:04X}"
        )

    section_offset = optional_offset + optional_size
    if section_offset + section_count * 40 > len(blob):
        raise PdbFormatError("truncated PE section table")
    sections: list[PeSection] = []
    for index in range(section_count):
        offset = section_offset + index * 40
        raw_name = blob[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("latin-1")
        virtual_size, relative_va, raw_size, raw_offset = struct.unpack_from(
            "<4I", blob, offset + 8
        )
        characteristics = _u32(blob, offset + 36)
        if raw_size and raw_offset + raw_size > len(blob):
            raise PdbFormatError(
                f"PE section {index + 1} raw data is out of bounds"
            )
        sections.append(
            PeSection(
                index=index + 1,
                name=name,
                va=image_base + relative_va,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=characteristics,
            )
        )
    return PeImage(image_base=image_base, sections=tuple(sections), data=blob)


def _mapped_sections(image: PeImage, va: int, size: int) -> list[PeSection]:
    return [
        section
        for section in image.sections
        if section.va <= va and va + size <= section.raw_mapped_end
    ]


def _file_offset(section: PeSection, va: int) -> int:
    return section.raw_offset + (va - section.va)


def _text_sections(image: PeImage) -> tuple[tuple[PeSection, ...], str]:
    named = tuple(section for section in image.sections if section.name == ".text")
    if named:
        return named, "named_text_section"
    executable = tuple(
        section
        for section in image.sections
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE
    )
    return executable, "executable_section_fallback"


def _is_text_va(va: int, sections: Sequence[PeSection]) -> bool:
    return any(section.va <= va < section.memory_end for section in sections)


def _make_run_id(group: VftableAddressGroup) -> str:
    digest = hashlib.sha256(group.group_id.encode("utf-8")).hexdigest()[:16]
    return f"x360-vftable-pointer-run:a{group.va:08X}:g{digest}"


def scan_vftable_pointer_runs(
    image: PeImage,
    address_groups: Iterable[VftableAddressGroup],
    *,
    max_slots: int = 4096,
) -> PointerRunExtraction:
    """Observe big-endian text-pointer prefixes at every distinct vftable VA.

    ``max_slots`` is a safety bound and is reported as a diagnostic if reached.
    The returned slot count is always an observation, never a declared extent.
    """

    if max_slots <= 0:
        raise ValueError("max_slots must be positive")
    groups = tuple(sorted(address_groups, key=lambda item: item.va))
    if len({group.va for group in groups}) != len(groups):
        raise ValueError("address_groups must contain one group per VA")

    text_sections, text_basis = _text_sections(image)
    global_diagnostics: list[VftableDiagnostic] = []
    if not text_sections:
        global_diagnostics.append(
            VftableDiagnostic(
                code="no_text_or_executable_section",
                subject_id=None,
                message="no PE section can define valid code-pointer targets",
            )
        )
    elif text_basis == "executable_section_fallback":
        global_diagnostics.append(
            VftableDiagnostic(
                code="text_section_name_missing",
                subject_id=None,
                message=(
                    "no section named .text exists; executable-section flags "
                    "define code-pointer targets"
                ),
            )
        )

    runs: list[PointerRunObservation] = []
    for group_index, group in enumerate(groups):
        run_id = _make_run_id(group)
        next_group = (
            groups[group_index + 1] if group_index + 1 < len(groups) else None
        )
        run_diagnostics: list[VftableDiagnostic] = []
        mapped = _mapped_sections(image, group.va, 4)
        slots: list[PointerSlotObservation] = []
        termination_kind: str
        termination_va: int | None = group.va
        termination_word_hex: str | None = None

        if not mapped:
            termination_kind = "unmapped_table_address"
            run_diagnostics.append(
                VftableDiagnostic(
                    code=termination_kind,
                    subject_id=run_id,
                    message=(
                        f"table VA 0x{group.va:08X} has no four-byte PE file "
                        "mapping"
                    ),
                )
            )
        elif len(mapped) > 1:
            termination_kind = "ambiguous_table_mapping"
            run_diagnostics.append(
                VftableDiagnostic(
                    code=termination_kind,
                    subject_id=run_id,
                    message=(
                        f"table VA 0x{group.va:08X} maps to multiple PE "
                        "sections"
                    ),
                )
            )
        else:
            table_section = mapped[0]
            while True:
                slot_index = len(slots)
                slot_va = group.va + slot_index * 4
                if slot_index >= max_slots:
                    termination_kind = "max_slots_reached"
                    termination_va = slot_va
                    run_diagnostics.append(
                        VftableDiagnostic(
                            code=termination_kind,
                            subject_id=run_id,
                            message=(
                                f"pointer observation reached the explicit "
                                f"{max_slots}-slot safety cap"
                            ),
                        )
                    )
                    break
                if not (
                    table_section.va <= slot_va
                    and slot_va + 4 <= table_section.raw_mapped_end
                ):
                    termination_kind = "mapped_section_end"
                    termination_va = slot_va
                    break
                offset = _file_offset(table_section, slot_va)
                raw_word = image.data[offset : offset + 4]
                target = struct.unpack(">I", raw_word)[0]
                if not _is_text_va(target, text_sections):
                    termination_kind = "first_non_text_pointer"
                    termination_va = slot_va
                    termination_word_hex = raw_word.hex()
                    if not slots:
                        run_diagnostics.append(
                            VftableDiagnostic(
                                code="no_leading_text_pointer",
                                subject_id=run_id,
                                message=(
                                    f"first word 0x{target:08X} is not a "
                                    "pointer into an observed code section"
                                ),
                            )
                        )
                    break
                slot_id = f"{run_id}:slot:{slot_index:04d}"
                slots.append(
                    PointerSlotObservation(
                        slot_id=slot_id,
                        run_id=run_id,
                        slot_index=slot_index,
                        slot_va=slot_va,
                        target_va=target,
                        raw_word_hex=raw_word.hex(),
                    )
                )

        boundary_index = None
        if next_group is None:
            boundary_relation = "no_later_vftable_symbol"
        else:
            delta = next_group.va - group.va
            if delta <= 0:
                raise ValueError("address groups are not strictly increasing")
            if delta % 4:
                boundary_relation = "next_vftable_symbol_unaligned"
                run_diagnostics.append(
                    VftableDiagnostic(
                        code=boundary_relation,
                        subject_id=run_id,
                        message=(
                            f"next vftable VA 0x{next_group.va:08X} is not "
                            "four-byte aligned relative to this address"
                        ),
                    )
                )
            else:
                boundary_index = delta // 4
                if boundary_index < len(slots):
                    boundary_relation = "next_vftable_inside_pointer_run"
                    run_diagnostics.append(
                        VftableDiagnostic(
                            code="pointer_run_crosses_known_vftable_symbol",
                            subject_id=run_id,
                            message=(
                                f"raw pointer run crosses the next known "
                                f"vftable at slot {boundary_index}; neither "
                                "boundary is selected as a declared extent"
                            ),
                        )
                    )
                elif boundary_index == len(slots):
                    boundary_relation = "next_vftable_at_pointer_run_end"
                else:
                    boundary_relation = "next_vftable_after_pointer_run"

        runs.append(
            PointerRunObservation(
                run_id=run_id,
                address_group_id=group.group_id,
                table_va=group.va,
                symbol_record_ids=group.record_ids,
                slots=tuple(slots),
                termination_kind=termination_kind,
                termination_va=termination_va,
                termination_word_hex=termination_word_hex,
                next_vftable_va=(next_group.va if next_group else None),
                next_vftable_record_ids=(
                    next_group.record_ids if next_group else ()
                ),
                known_boundary_slot_index=boundary_index,
                boundary_relation=boundary_relation,
                diagnostics=tuple(
                    sorted(
                        run_diagnostics,
                        key=lambda item: (item.code, item.message),
                    )
                ),
            )
        )

    return PointerRunExtraction(
        runs=tuple(runs),
        diagnostics=tuple(global_diagnostics),
    )


def extract_vftable_symbols(
    pdb_path: str | Path, executable_path: str | Path
) -> VftableSymbolExtraction:
    """Extract all physical Xbox vftable records from explicit input paths."""

    image = parse_pe_image(Path(executable_path).read_bytes())
    msf = _MsfReader(pdb_path)
    if DBI_STREAM_INDEX >= msf.stream_count:
        raise PdbFormatError("PDB has no DBI stream")
    reference = parse_dbi_symbol_stream_reference(
        msf.read_stream(DBI_STREAM_INDEX)
    )
    if reference.symbol_record_stream >= msf.stream_count:
        raise PdbFormatError(
            f"DBI refers to missing symbol-record stream "
            f"{reference.symbol_record_stream}"
        )
    parsed = parse_vftable_symbol_records(
        msf.read_stream(reference.symbol_record_stream),
        symbol_record_stream=reference.symbol_record_stream,
        section_bases=image.section_bases,
    )
    return VftableSymbolExtraction(
        stream_reference=reference,
        records=parsed.records,
        address_groups=parsed.address_groups,
        diagnostics=parsed.diagnostics,
    )


def extract_vftable_corpus(
    pdb_path: str | Path,
    executable_path: str | Path,
    *,
    max_slots: int = 4096,
) -> VftableCorpus:
    """Extract symbols and separately observe executable pointer prefixes."""

    image = parse_pe_image(Path(executable_path).read_bytes())
    msf = _MsfReader(pdb_path)
    if DBI_STREAM_INDEX >= msf.stream_count:
        raise PdbFormatError("PDB has no DBI stream")
    reference = parse_dbi_symbol_stream_reference(
        msf.read_stream(DBI_STREAM_INDEX)
    )
    if reference.symbol_record_stream >= msf.stream_count:
        raise PdbFormatError(
            f"DBI refers to missing symbol-record stream "
            f"{reference.symbol_record_stream}"
        )
    parsed = parse_vftable_symbol_records(
        msf.read_stream(reference.symbol_record_stream),
        symbol_record_stream=reference.symbol_record_stream,
        section_bases=image.section_bases,
    )
    symbols = VftableSymbolExtraction(
        stream_reference=reference,
        records=parsed.records,
        address_groups=parsed.address_groups,
        diagnostics=parsed.diagnostics,
    )
    return VftableCorpus(
        symbols=symbols,
        pointer_runs=scan_vftable_pointer_runs(
            image, symbols.address_groups, max_slots=max_slots
        ),
    )


def _write_jsonl(
    rows: Iterable[object], output_path: str | Path, *, sort_key
) -> None:
    ordered = sorted(rows, key=sort_key)
    with Path(output_path).open("w", encoding="utf-8", newline="\n") as handle:
        for row in ordered:
            handle.write(
                json.dumps(
                    row.to_dict(),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            handle.write("\n")


def write_vftable_symbols_jsonl(
    records: Iterable[VftableSymbolRecord], output_path: str | Path
) -> None:
    """Write physical records deterministically with raw bytes as hex."""

    _write_jsonl(records, output_path, sort_key=_record_key)


def write_pointer_runs_jsonl(
    runs: Iterable[PointerRunObservation], output_path: str | Path
) -> None:
    """Write pointer-run observations without converting them to extents."""

    _write_jsonl(
        runs,
        output_path,
        sort_key=lambda run: (run.table_va, run.run_id),
    )


__all__ = [
    "DBI_STREAM_INDEX",
    "DbiSymbolStreamReference",
    "IMAGE_SCN_MEM_EXECUTE",
    "PeImage",
    "PeSection",
    "PointerRunExtraction",
    "PointerRunObservation",
    "PointerSlotObservation",
    "S_PUB32",
    "VftableAddressGroup",
    "VftableCorpus",
    "VftableDiagnostic",
    "VftableNameParts",
    "VftableSymbolExtraction",
    "VftableSymbolRecord",
    "build_vftable_address_groups",
    "extract_vftable_corpus",
    "extract_vftable_symbols",
    "make_canonical_name_id",
    "make_vftable_record_id",
    "parse_dbi_symbol_stream_reference",
    "parse_pe_image",
    "parse_vftable_name",
    "parse_vftable_symbol_records",
    "scan_vftable_pointer_runs",
    "write_pointer_runs_jsonl",
    "write_vftable_symbols_jsonl",
]
