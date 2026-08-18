"""Lossless extraction of procedure records from CodeView module streams.

The legacy symbol-port extractor keyed procedures by virtual address, which is
convenient for applying labels but loses precisely the aliases created by
identical COMDAT folding (ICF).  This module treats a CodeView symbol record as
the primary object.  A virtual address is an attribute of that record, not its
identity.

Only standard-library code is used.  :func:`extract_procedures` accepts all of
its input paths explicitly; the lower-level :func:`extract_module_streams` and
:func:`parse_module_procedures` entry points make the parser independently
testable and reusable with a different MSF reader.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import struct
from typing import Callable, Iterable, Mapping, Sequence


S_LPROC32 = 0x110F
S_GPROC32 = 0x1110

_PROCEDURE_KINDS = {
    S_LPROC32: "S_LPROC32",
    S_GPROC32: "S_GPROC32",
}

_MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


class PdbFormatError(ValueError):
    """Raised when structural corruption would otherwise silently lose data."""


@dataclass(frozen=True, slots=True)
class ProcedureRecord:
    """One S_GPROC32 or S_LPROC32 record from a module symbol stream.

    ``record_offset`` is relative to the beginning of the PDB stream, including
    the four-byte CodeView signature.  ``section`` is the one-based PE section
    number used by CodeView.  ``va`` is ``None`` only when the record refers to
    a section not present in the supplied executable; the record is retained so
    an input problem cannot masquerade as successful extraction.

    ``raw_name`` is decoded with Latin-1.  That codec is deliberately used as a
    byte-for-byte mapping, so encoding it back to Latin-1 recovers the original
    CodeView name bytes exactly.
    """

    record_id: str
    module_index: int
    module_name: str
    symbol_stream: int
    record_offset: int
    record_length: int
    record_kind: str
    record_kind_code: int
    va: int | None
    section: int
    section_offset: int
    size: int
    type_index: int
    flags: int
    raw_name: str
    parent_offset: int
    end_offset: int
    next_offset: int
    debug_start: int
    debug_end: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation without formatting loss."""

        return asdict(self)


@dataclass(frozen=True, slots=True)
class AliasGroup:
    """All procedure records sharing one VA (an alias/ICF fold group)."""

    group_id: str
    va: int
    record_ids: tuple[str, ...]
    raw_names: tuple[str, ...]

    @property
    def count(self) -> int:
        return len(self.record_ids)

    def to_dict(self) -> dict[str, object]:
        return {
            "group_id": self.group_id,
            "va": self.va,
            "record_ids": list(self.record_ids),
            "raw_names": list(self.raw_names),
            "count": self.count,
        }


@dataclass(frozen=True, slots=True)
class ProcedureExtraction:
    """Deterministic procedure records and multi-record VA groups."""

    records: tuple[ProcedureRecord, ...]
    alias_groups: tuple[AliasGroup, ...]

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def unique_va_count(self) -> int:
        return len({record.va for record in self.records if record.va is not None})


def make_record_id(module_index: int, symbol_stream: int, record_offset: int) -> str:
    """Return the stable physical identity of a module symbol record."""

    return (
        f"x360-proc:m{module_index:04d}:s{symbol_stream:04d}:"
        f"o{record_offset:08X}"
    )


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _u16(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<H", blob, offset)[0]


def _u32(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def parse_module_procedures(
    blob: bytes,
    *,
    module_index: int,
    module_name: str,
    symbol_stream: int,
    section_bases: Sequence[int],
    symbol_bytes: int | None = None,
) -> tuple[ProcedureRecord, ...]:
    """Parse every procedure record in one PDB module symbol stream.

    Module streams begin with a four-byte CodeView signature.  ``symbol_bytes``
    is the DBI module's ``symByteSize`` and includes that signature; restricting
    parsing to it prevents C11/C13 line data from being mistaken for symbols.

    Unknown symbol record kinds are skipped but still used to advance the
    stream.  A malformed record raises :class:`PdbFormatError` instead of being
    silently dropped.
    """

    if symbol_bytes is None:
        limit = len(blob)
    else:
        if symbol_bytes < 0:
            raise ValueError("symbol_bytes cannot be negative")
        if symbol_bytes > len(blob):
            raise PdbFormatError(
                f"module {module_index} declares {symbol_bytes} symbol bytes, "
                f"but stream {symbol_stream} has only {len(blob)} bytes"
            )
        limit = symbol_bytes

    # A zero-sized symbol contribution is valid.  A nonzero module contribution
    # must at least contain its four-byte CodeView signature.
    if limit == 0:
        return ()
    if limit < 4:
        raise PdbFormatError(
            f"module {module_index} symbol contribution is shorter than its "
            "four-byte CodeView signature"
        )

    records: list[ProcedureRecord] = []
    cursor = 4
    while cursor + 4 <= limit:
        record_length = _u16(blob, cursor)
        if record_length < 2:
            # All-zero tail padding is benign.  Anything else is evidence that
            # the stream limit or record walk is wrong.
            if not any(blob[cursor:limit]):
                break
            raise PdbFormatError(
                f"invalid CodeView record length {record_length} at stream "
                f"{symbol_stream} offset 0x{cursor:X}"
            )

        record_end = cursor + 2 + record_length
        if record_end > limit:
            raise PdbFormatError(
                f"CodeView record at stream {symbol_stream} offset "
                f"0x{cursor:X} ends at 0x{record_end:X}, past symbol limit "
                f"0x{limit:X}"
            )

        record_kind_code = _u16(blob, cursor + 2)
        if record_kind_code in _PROCEDURE_KINDS:
            body = cursor + 4
            body_size = record_end - body
            # Fixed S_*PROC32 fields occupy 35 bytes, followed by a NUL name.
            if body_size < 36:
                raise PdbFormatError(
                    f"truncated {_PROCEDURE_KINDS[record_kind_code]} at stream "
                    f"{symbol_stream} offset 0x{cursor:X}"
                )

            nul = blob.find(b"\0", body + 35, record_end)
            if nul < 0:
                raise PdbFormatError(
                    f"unterminated procedure name at stream {symbol_stream} "
                    f"offset 0x{cursor:X}"
                )

            (
                parent_offset,
                end_offset,
                next_offset,
                size,
                debug_start,
                debug_end,
                type_index,
                section_offset,
            ) = struct.unpack_from("<8I", blob, body)
            section = _u16(blob, body + 32)
            flags = blob[body + 34]
            raw_name = blob[body + 35 : nul].decode("latin-1")

            va = None
            if 1 <= section <= len(section_bases):
                va = int(section_bases[section - 1]) + section_offset

            records.append(
                ProcedureRecord(
                    record_id=make_record_id(
                        module_index, symbol_stream, cursor
                    ),
                    module_index=module_index,
                    module_name=module_name,
                    symbol_stream=symbol_stream,
                    record_offset=cursor,
                    record_length=record_length,
                    record_kind=_PROCEDURE_KINDS[record_kind_code],
                    record_kind_code=record_kind_code,
                    va=va,
                    section=section,
                    section_offset=section_offset,
                    size=size,
                    type_index=type_index,
                    flags=flags,
                    raw_name=raw_name,
                    parent_offset=parent_offset,
                    end_offset=end_offset,
                    next_offset=next_offset,
                    debug_start=debug_start,
                    debug_end=debug_end,
                )
            )

        cursor = _align4(record_end)

    return tuple(records)


def _record_sort_key(record: ProcedureRecord) -> tuple[int, int, int, str]:
    return (
        record.module_index,
        record.symbol_stream,
        record.record_offset,
        record.record_id,
    )


def build_alias_groups(
    records: Iterable[ProcedureRecord], *, include_singletons: bool = False
) -> tuple[AliasGroup, ...]:
    """Group procedure records by resolved VA without discarding duplicates."""

    by_va: dict[int, list[ProcedureRecord]] = defaultdict(list)
    for record in records:
        if record.va is not None:
            by_va[record.va].append(record)

    groups: list[AliasGroup] = []
    for va in sorted(by_va):
        members = sorted(by_va[va], key=_record_sort_key)
        if len(members) == 1 and not include_singletons:
            continue
        groups.append(
            AliasGroup(
                group_id=f"x360-fold:{va:08X}",
                va=va,
                record_ids=tuple(member.record_id for member in members),
                raw_names=tuple(member.raw_name for member in members),
            )
        )
    return tuple(groups)


def extract_module_streams(
    *,
    modules: Sequence[Mapping[str, object]],
    section_bases: Sequence[int],
    read_stream: Callable[[int], bytes],
    stream_count: int | None = None,
) -> ProcedureExtraction:
    """Extract procedures from module metadata and a PDB stream callback.

    This is the dependency-injection seam for tests and alternate PDB readers.
    Module input order does not affect record or alias-group output order.
    Modules with ``sym_stream: null`` are valid and skipped.
    """

    def module_key(module: Mapping[str, object]) -> tuple[int, int, str]:
        stream = module.get("sym_stream")
        return (
            int(module["index"]),
            -1 if stream is None else int(stream),
            str(module.get("name", "")),
        )

    records: list[ProcedureRecord] = []
    seen_ids: set[str] = set()
    for module in sorted(modules, key=module_key):
        stream_value = module.get("sym_stream")
        if stream_value is None:
            continue

        module_index = int(module["index"])
        symbol_stream = int(stream_value)
        module_name = str(module.get("name", ""))
        if symbol_stream < 0:
            raise PdbFormatError(
                f"module {module_index} has negative symbol stream "
                f"{symbol_stream}"
            )
        if stream_count is not None and symbol_stream >= stream_count:
            raise PdbFormatError(
                f"module {module_index} refers to missing symbol stream "
                f"{symbol_stream} (PDB has {stream_count})"
            )

        raw_symbol_bytes = module.get("sym_bytes")
        symbol_bytes = (
            None if raw_symbol_bytes is None else int(raw_symbol_bytes)
        )
        parsed = parse_module_procedures(
            read_stream(symbol_stream),
            module_index=module_index,
            module_name=module_name,
            symbol_stream=symbol_stream,
            section_bases=section_bases,
            symbol_bytes=symbol_bytes,
        )
        for record in parsed:
            if record.record_id in seen_ids:
                raise PdbFormatError(
                    f"duplicate physical procedure identity {record.record_id}"
                )
            seen_ids.add(record.record_id)
            records.append(record)

    ordered = tuple(sorted(records, key=_record_sort_key))
    return ProcedureExtraction(
        records=ordered,
        alias_groups=build_alias_groups(ordered),
    )


class _MsfReader:
    """Minimal read-only MSF 7.0 adapter used by :func:`extract_procedures`."""

    def __init__(self, path: str | Path):
        self._data = Path(path).read_bytes()
        if not self._data.startswith(_MSF7_MAGIC):
            raise PdbFormatError(f"{path!s} is not an MSF 7.0 PDB")
        if len(self._data) < 56:
            raise PdbFormatError("truncated MSF superblock")

        (
            self.block_size,
            _free_map,
            self.num_blocks,
            directory_size,
            _reserved,
            block_map_address,
        ) = struct.unpack_from("<6I", self._data, 32)
        if self.block_size == 0:
            raise PdbFormatError("MSF block size is zero")

        directory_block_count = (
            directory_size + self.block_size - 1
        ) // self.block_size
        block_map_offset = block_map_address * self.block_size
        block_map_size = directory_block_count * 4
        if block_map_offset + block_map_size > len(self._data):
            raise PdbFormatError("MSF directory block map is out of bounds")
        directory_blocks = struct.unpack_from(
            f"<{directory_block_count}I", self._data, block_map_offset
        )
        raw_directory = self._join_blocks(directory_blocks)[:directory_size]
        if len(raw_directory) < 4:
            raise PdbFormatError("truncated MSF stream directory")

        stream_count = _u32(raw_directory, 0)
        sizes_end = 4 + stream_count * 4
        if sizes_end > len(raw_directory):
            raise PdbFormatError("truncated MSF stream-size table")
        sizes = struct.unpack_from(f"<{stream_count}I", raw_directory, 4)

        cursor = sizes_end
        streams: list[tuple[int, tuple[int, ...]]] = []
        for size in sizes:
            if size == 0xFFFFFFFF:
                streams.append((0, ()))
                continue
            block_count = (size + self.block_size - 1) // self.block_size
            blocks_end = cursor + block_count * 4
            if blocks_end > len(raw_directory):
                raise PdbFormatError("truncated MSF stream block table")
            blocks = struct.unpack_from(
                f"<{block_count}I", raw_directory, cursor
            )
            cursor = blocks_end
            streams.append((size, blocks))
        self._streams = tuple(streams)

    @property
    def stream_count(self) -> int:
        return len(self._streams)

    def _join_blocks(self, blocks: Iterable[int]) -> bytes:
        chunks: list[bytes] = []
        for block in blocks:
            start = block * self.block_size
            end = start + self.block_size
            if block >= self.num_blocks or end > len(self._data):
                raise PdbFormatError(f"MSF block {block} is out of bounds")
            chunks.append(self._data[start:end])
        return b"".join(chunks)

    def read_stream(self, index: int) -> bytes:
        if not 0 <= index < len(self._streams):
            raise PdbFormatError(f"PDB stream {index} is out of range")
        size, blocks = self._streams[index]
        return self._join_blocks(blocks)[:size]


def read_pe_section_bases(exe_path: str | Path) -> tuple[int, ...]:
    """Return absolute bases for the executable's one-based PE sections."""

    data = Path(exe_path).read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PdbFormatError(f"{exe_path!s} is not a PE executable")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PdbFormatError("missing or truncated PE signature")

    section_count = _u16(data, pe_offset + 6)
    optional_size = _u16(data, pe_offset + 20)
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data):
        raise PdbFormatError("truncated PE optional header")
    optional_magic = _u16(data, optional_offset)
    if optional_magic == 0x10B:  # PE32
        image_base = _u32(data, optional_offset + 28)
    elif optional_magic == 0x20B:  # PE32+
        image_base = struct.unpack_from("<Q", data, optional_offset + 24)[0]
    else:
        raise PdbFormatError(
            f"unsupported PE optional-header magic 0x{optional_magic:04X}"
        )

    sections_offset = optional_offset + optional_size
    sections_end = sections_offset + section_count * 40
    if sections_end > len(data):
        raise PdbFormatError("truncated PE section table")
    return tuple(
        image_base + _u32(data, sections_offset + index * 40 + 12)
        for index in range(section_count)
    )


def _load_modules(path: str | Path) -> list[Mapping[str, object]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict):
        payload = payload.get("modules")
    if not isinstance(payload, list) or not all(
        isinstance(module, dict) for module in payload
    ):
        raise ValueError("modules JSON must be a list (or {'modules': [...]})")
    return payload


def extract_procedures(
    pdb_path: str | Path,
    exe_path: str | Path,
    modules_path: str | Path,
) -> ProcedureExtraction:
    """Extract all Xbox procedure records using explicit input paths."""

    msf = _MsfReader(pdb_path)
    return extract_module_streams(
        modules=_load_modules(modules_path),
        section_bases=read_pe_section_bases(exe_path),
        read_stream=msf.read_stream,
        stream_count=msf.stream_count,
    )


def write_jsonl(
    records: Iterable[ProcedureRecord], output_path: str | Path
) -> None:
    """Write procedure records deterministically as one JSON object per line."""

    ordered = sorted(records, key=_record_sort_key)
    with Path(output_path).open("w", encoding="utf-8", newline="\n") as handle:
        for record in ordered:
            handle.write(
                json.dumps(
                    record.to_dict(),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            handle.write("\n")


__all__ = [
    "AliasGroup",
    "PdbFormatError",
    "ProcedureExtraction",
    "ProcedureRecord",
    "S_GPROC32",
    "S_LPROC32",
    "build_alias_groups",
    "extract_module_streams",
    "extract_procedures",
    "make_record_id",
    "parse_module_procedures",
    "read_pe_section_bases",
    "write_jsonl",
]
