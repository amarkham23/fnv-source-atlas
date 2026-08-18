"""Lossless extraction of typed data records from CodeView module streams.

The legacy exporter keyed globals by virtual address and used ``setdefault``.
That representation silently discarded every later S_GDATA32/S_LDATA32 record
at a shared address.  This module instead treats the physical CodeView record
as the identity and exposes address groups as a separate, lossless view.

Only standard-library code is used.  The lower-level parser and stream adapter
are dependency-injection seams for tests and alternate PDB readers; the
high-level :func:`extract_data_symbols` accepts every input path explicitly.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import struct
from typing import Callable, Iterable, Mapping, Sequence

from .pdb_symbols import PdbFormatError, _MsfReader, read_pe_section_bases


S_LDATA32 = 0x110C
S_GDATA32 = 0x110D

_DATA_KINDS = {
    S_LDATA32: "S_LDATA32",
    S_GDATA32: "S_GDATA32",
}


@dataclass(frozen=True, slots=True)
class DataSymbolRecord:
    """One physical S_GDATA32 or S_LDATA32 module-stream record.

    ``record_offset`` is relative to the beginning of the PDB stream and
    includes the four-byte CodeView signature.  ``va`` remains ``None`` when
    the supplied executable cannot resolve the record's one-based section;
    such a record is retained rather than disappearing as an input failure.

    ``raw_name`` uses Latin-1 as a reversible byte mapping.  Encoding it back
    to Latin-1 reproduces the original CodeView name bytes exactly.
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
    type_index: int
    raw_name: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DataAddressGroup:
    """Every physical data record sharing one resolved virtual address."""

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
class DataSymbolExtraction:
    """Deterministic physical records plus their complete address groups."""

    records: tuple[DataSymbolRecord, ...]
    address_groups: tuple[DataAddressGroup, ...]

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def unique_va_count(self) -> int:
        return len(self.address_groups)

    @property
    def unresolved_va_count(self) -> int:
        return sum(record.va is None for record in self.records)


def make_data_record_id(
    module_index: int, symbol_stream: int, record_offset: int
) -> str:
    """Return the stable physical identity of a module data record."""

    return (
        f"x360-data:m{module_index:04d}:s{symbol_stream:04d}:"
        f"o{record_offset:08X}"
    )


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _u16(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<H", blob, offset)[0]


def parse_module_data_symbols(
    blob: bytes,
    *,
    module_index: int,
    module_name: str,
    symbol_stream: int,
    section_bases: Sequence[int],
    symbol_bytes: int | None = None,
) -> tuple[DataSymbolRecord, ...]:
    """Parse every typed data symbol from one PDB module stream.

    ``symbol_bytes`` is the DBI module's ``symByteSize`` and includes the
    four-byte CodeView signature.  Honoring it is essential: bytes after that
    boundary are C11/C13 debug data, not symbol records.

    Unknown record kinds advance the record walk.  Structural damage to a
    selected record raises :class:`PdbFormatError` instead of losing a row.
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

    if limit == 0:
        return ()
    if limit < 4:
        raise PdbFormatError(
            f"module {module_index} symbol contribution is shorter than its "
            "four-byte CodeView signature"
        )

    records: list[DataSymbolRecord] = []
    cursor = 4
    while cursor + 4 <= limit:
        record_length = _u16(blob, cursor)
        if record_length < 2:
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
        if record_kind_code in _DATA_KINDS:
            body = cursor + 4
            body_size = record_end - body
            # type index + section offset + section = 10 bytes, followed by a
            # required NUL-terminated name (which may itself be empty).
            if body_size < 11:
                raise PdbFormatError(
                    f"truncated {_DATA_KINDS[record_kind_code]} at stream "
                    f"{symbol_stream} offset 0x{cursor:X}"
                )

            nul = blob.find(b"\0", body + 10, record_end)
            if nul < 0:
                raise PdbFormatError(
                    f"unterminated data-symbol name at stream {symbol_stream} "
                    f"offset 0x{cursor:X}"
                )

            type_index, section_offset = struct.unpack_from("<2I", blob, body)
            section = _u16(blob, body + 8)
            raw_name = blob[body + 10 : nul].decode("latin-1")

            va = None
            if 1 <= section <= len(section_bases):
                va = int(section_bases[section - 1]) + section_offset

            records.append(
                DataSymbolRecord(
                    record_id=make_data_record_id(
                        module_index, symbol_stream, cursor
                    ),
                    module_index=module_index,
                    module_name=module_name,
                    symbol_stream=symbol_stream,
                    record_offset=cursor,
                    record_length=record_length,
                    record_kind=_DATA_KINDS[record_kind_code],
                    record_kind_code=record_kind_code,
                    va=va,
                    section=section,
                    section_offset=section_offset,
                    type_index=type_index,
                    raw_name=raw_name,
                )
            )

        cursor = _align4(record_end)

    return tuple(records)


def _record_sort_key(record: DataSymbolRecord) -> tuple[int, int, int, str]:
    return (
        record.module_index,
        record.symbol_stream,
        record.record_offset,
        record.record_id,
    )


def build_data_address_groups(
    records: Iterable[DataSymbolRecord],
) -> tuple[DataAddressGroup, ...]:
    """Group all resolved records by address without selecting an alias."""

    by_va: dict[int, list[DataSymbolRecord]] = defaultdict(list)
    for record in records:
        if record.va is not None:
            by_va[record.va].append(record)

    groups: list[DataAddressGroup] = []
    for va in sorted(by_va):
        members = sorted(by_va[va], key=_record_sort_key)
        groups.append(
            DataAddressGroup(
                group_id=f"x360-data-address:{va:08X}",
                va=va,
                record_ids=tuple(member.record_id for member in members),
                raw_names=tuple(member.raw_name for member in members),
            )
        )
    return tuple(groups)


def extract_data_module_streams(
    *,
    modules: Sequence[Mapping[str, object]],
    section_bases: Sequence[int],
    read_stream: Callable[[int], bytes],
    stream_count: int | None = None,
) -> DataSymbolExtraction:
    """Extract typed data records using module metadata and a stream reader."""

    def module_key(module: Mapping[str, object]) -> tuple[int, int, str]:
        stream = module.get("sym_stream")
        return (
            int(module["index"]),
            -1 if stream is None else int(stream),
            str(module.get("name", "")),
        )

    records: list[DataSymbolRecord] = []
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
        parsed = parse_module_data_symbols(
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
                    f"duplicate physical data-symbol identity {record.record_id}"
                )
            seen_ids.add(record.record_id)
            records.append(record)

    ordered = tuple(sorted(records, key=_record_sort_key))
    return DataSymbolExtraction(
        records=ordered,
        address_groups=build_data_address_groups(ordered),
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


def extract_data_symbols(
    pdb_path: str | Path,
    exe_path: str | Path,
    modules_path: str | Path,
) -> DataSymbolExtraction:
    """Extract every Xbox typed data record using explicit input paths."""

    msf = _MsfReader(pdb_path)
    return extract_data_module_streams(
        modules=_load_modules(modules_path),
        section_bases=read_pe_section_bases(exe_path),
        read_stream=msf.read_stream,
        stream_count=msf.stream_count,
    )


def write_data_jsonl(
    records: Iterable[DataSymbolRecord], output_path: str | Path
) -> None:
    """Write physical data records deterministically, one object per line."""

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
    "DataAddressGroup",
    "DataSymbolExtraction",
    "DataSymbolRecord",
    "S_GDATA32",
    "S_LDATA32",
    "build_data_address_groups",
    "extract_data_module_streams",
    "extract_data_symbols",
    "make_data_record_id",
    "parse_module_data_symbols",
    "write_data_jsonl",
]
