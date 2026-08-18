"""Canonical PC function inventory loaders.

The legacy Ghidra export mixes real function entries with callee offsets from
other address spaces.  This module deliberately treats only dictionary keys in
``ghidra_functions.json["functions"]`` as function identities.  Callees are
references which must be classified before they can participate in matching.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import struct
from typing import Iterable, Iterator, Mapping, Sequence


def parse_address(value: int | str) -> int:
    """Parse an integer or a conventional hexadecimal address string."""

    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        raise TypeError(f"address must be int or str, got {type(value).__name__}")
    return int(value, 0)


def stable_pc_function_id(address: int, address_space: str = "ram") -> str:
    """Return the stable identity used for one PC function entry."""

    if address < 0:
        raise ValueError("function addresses cannot be negative")
    if not address_space or ":" in address_space:
        raise ValueError("address_space must be non-empty and cannot contain ':'")
    return f"pc:{address_space}:{address:08x}"


def _in_ranges(address: int, ranges: Sequence[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


@dataclass(frozen=True, slots=True)
class CalleeReference:
    address: int
    classification: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PCFunction:
    function_id: str
    address: int
    address_space: str
    name: str
    size: int
    thunk: bool
    in_executable_range: bool | None
    callees: tuple[CalleeReference, ...]

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["callees"] = [c.to_dict() for c in self.callees]
        return result


@dataclass(frozen=True, slots=True)
class PCInventory:
    image_base: int | None
    functions: tuple[PCFunction, ...]

    @property
    def entries(self) -> frozenset[int]:
        return frozenset(function.address for function in self.functions)

    def by_address(self) -> dict[int, PCFunction]:
        return {function.address: function for function in self.functions}

    def iter_callees(self, classification: str | None = None) -> Iterator[CalleeReference]:
        for function in self.functions:
            for callee in function.callees:
                if classification is None or callee.classification == classification:
                    yield callee


@dataclass(frozen=True, slots=True)
class PESection:
    name: str
    start: int
    end: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)


def read_pe_sections(path: str | Path) -> tuple[PESection, ...]:
    """Read image-relative section ranges from a PE32/PE32+ executable."""

    source = Path(path)
    data = source.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{source}: not an MZ executable")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{source}: invalid PE header")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 32:
        raise ValueError(f"{source}: truncated optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:  # PE32
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
    elif magic == 0x20B:  # PE32+
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    else:
        raise ValueError(f"{source}: unsupported PE optional-header magic {magic:#x}")

    section_table = optional + optional_size
    sections: list[PESection] = []
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            raise ValueError(f"{source}: truncated section table")
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size = struct.unpack_from("<III", data, offset + 8)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        extent = max(virtual_size, raw_size)
        sections.append(
            PESection(
                name=name,
                start=image_base + virtual_address,
                end=image_base + virtual_address + extent,
                characteristics=characteristics,
            )
        )
    return tuple(sections)


def executable_ranges_from_pe(path: str | Path) -> tuple[tuple[int, int], ...]:
    """Return sorted executable section ranges from a PE image."""

    return tuple(
        (section.start, section.end)
        for section in read_pe_sections(path)
        if section.executable and section.end > section.start
    )


def _classify_callee(
    address: int,
    entries: frozenset[int],
    executable_ranges: Sequence[tuple[int, int]],
) -> str:
    if address in entries:
        return "function_entry"
    if executable_ranges:
        if _in_ranges(address, executable_ranges):
            return "executable_non_entry"
        return "outside_executable_ranges"
    return "unresolved_non_entry"


def load_ghidra_inventory(
    path: str | Path,
    *,
    executable_ranges: Iterable[tuple[int, int]] = (),
    address_space: str = "ram",
) -> PCInventory:
    """Load a deterministic PC inventory from a Ghidra JSON export.

    Only the keys of the ``functions`` object become function identities.
    Callees absent from that key set remain explicit non-entry references.
    When executable ranges are supplied, both entries and non-entry callees are
    classified against those ranges.
    """

    source = Path(path)
    with source.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, Mapping):
        raise ValueError(f"{source}: root must be an object")
    raw_functions = document.get("functions")
    if not isinstance(raw_functions, Mapping):
        raise ValueError(f"{source}: missing object field 'functions'")

    ranges = tuple(sorted((parse_address(a), parse_address(b)) for a, b in executable_ranges))
    for start, end in ranges:
        if start < 0 or end <= start:
            raise ValueError(f"invalid executable range: {start:#x}..{end:#x}")

    raw_by_address: dict[int, Mapping[str, object]] = {}
    for raw_address, record in raw_functions.items():
        address = parse_address(raw_address)
        if address in raw_by_address:
            raise ValueError(f"duplicate function entry after address normalization: {address:#x}")
        if not isinstance(record, Mapping):
            raise ValueError(f"{source}: function {raw_address!r} is not an object")
        raw_by_address[address] = record

    entries = frozenset(raw_by_address)
    functions: list[PCFunction] = []
    for address in sorted(raw_by_address):
        record = raw_by_address[address]
        raw_callees = record.get("callees", [])
        if not isinstance(raw_callees, list):
            raise ValueError(f"{source}: callees for {address:#x} must be an array")
        callee_addresses = sorted({parse_address(callee) for callee in raw_callees})
        callees = tuple(
            CalleeReference(
                address=callee,
                classification=_classify_callee(callee, entries, ranges),
            )
            for callee in callee_addresses
        )
        executable = _in_ranges(address, ranges) if ranges else None
        functions.append(
            PCFunction(
                function_id=stable_pc_function_id(address, address_space),
                address=address,
                address_space=address_space,
                name=str(record.get("name") or ""),
                size=max(0, int(record.get("size") or 0)),
                thunk=bool(record.get("thunk", False)),
                in_executable_range=executable,
                callees=callees,
            )
        )

    image_base = document.get("image_base")
    return PCInventory(
        image_base=parse_address(image_base) if image_base is not None else None,
        functions=tuple(functions),
    )
