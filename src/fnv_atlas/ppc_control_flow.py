"""Lossless, identity-safe PowerPC control-flow observations.

The legacy Xbox call graph was keyed by demangled function name.  Overloads and
ICF aliases therefore overwrote one another before a matcher ever saw them.
This module keeps the three relevant identities separate:

* a physical branch instruction is identified by its Xbox virtual address;
* a logical procedure is identified by its CodeView record ID; and
* a folded target is represented by one fold-group reference, not by expanding
  the observation into hundreds of apparently independent callees.

The decoder is deliberately small and conservative.  It recognizes the four
PowerPC branch forms needed to describe direct and indirect control transfer;
it does not claim that every decoded instruction is semantically a C/C++ call.
Per-procedure ``role`` values are syntactic observations that later evidence
layers may interpret.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import struct
from typing import Iterable, Iterator, Protocol, TextIO


IMAGE_FILE_MACHINE_POWERPCBE = 0x01F2
IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Versioned persistence policies are intentionally expressed in terms of the
# per-procedure syntactic roles, never symbol names.  A physical site selected
# by any logical use retains every use at that site.
CALL_RELEVANT_V1_ROLES = frozenset(
    {
        "direct_call",
        "local_direct_call",
        "conditional_call",
        "local_conditional_call",
        "tail_transfer",
        "conditional_transfer",
        "indirect_call",
        "indirect_link_register_call",
    }
)
CONTROL_FLOW_POLICIES = frozenset({"call_relevant_v1", "all_branches_v1"})


class ExecutableFormatError(ValueError):
    """Raised when a malformed executable would make address mapping unsafe."""


class ProcedureLike(Protocol):
    """The subset of :class:`ProcedureRecord` needed by this extractor."""

    record_id: str
    va: int | None
    size: int


@dataclass(frozen=True, slots=True)
class ProcedureExtent:
    """Stable procedure identity plus its declared physical code extent."""

    record_id: str
    va: int | None
    size: int


@dataclass(frozen=True, slots=True)
class ExecutableSection:
    """One PE section with both virtual and raw-file coordinates."""

    name: str
    start: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)

    @property
    def end(self) -> int:
        return self.start + self.mapped_size

    @property
    def raw_end_va(self) -> int:
        return self.start + self.raw_size

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end

    def contains_raw(self, address: int) -> bool:
        return self.start <= address < self.raw_end_va


@dataclass(frozen=True, slots=True)
class ExecutableImage:
    """A validated PE image used for deterministic VA-to-file mapping."""

    data: bytes = field(repr=False)
    machine: int
    image_base: int
    sections: tuple[ExecutableSection, ...]

    def section_at(self, address: int) -> ExecutableSection | None:
        matches = tuple(section for section in self.sections if section.contains(address))
        if len(matches) > 1:
            raise ExecutableFormatError(
                f"virtual address 0x{address:X} belongs to overlapping PE sections"
            )
        return matches[0] if matches else None

    def raw_bytes_available(self, address: int) -> int:
        section = self.section_at(address)
        if section is None or not section.contains_raw(address):
            return 0
        return section.raw_end_va - address

    def read(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("read size cannot be negative")
        if size == 0:
            return b""
        section = self.section_at(address)
        if section is None or not section.contains_raw(address):
            raise ExecutableFormatError(
                f"virtual address 0x{address:X} has no raw-file backing"
            )
        delta = address - section.start
        if delta + size > section.raw_size:
            raise ExecutableFormatError(
                f"read at 0x{address:X} crosses the raw extent of {section.name!r}"
            )
        start = section.raw_offset + delta
        return self.data[start : start + size]

    @property
    def executable_ranges(self) -> tuple[tuple[int, int], ...]:
        return tuple(
            (section.start, section.end)
            for section in self.sections
            if section.executable and section.end > section.start
        )


@dataclass(frozen=True, slots=True)
class DecodedBranch:
    """A single recognized PowerPC branch instruction.

    ``conditional`` identifies an instruction *form* carrying BO/BI fields.
    A canonical ``blr``/``bctrl`` still uses that form even when its BO value
    makes the particular transfer unconditional.
    """

    address: int
    instruction_word: int
    branch_kind: str
    target_va: int | None
    link: bool
    absolute: bool
    conditional: bool
    indirect: bool
    bo: int | None = None
    bi: int | None = None


@dataclass(frozen=True, slots=True)
class BranchSite:
    """One physical branch site, classified against all PDB procedure entries."""

    site_id: str
    site_va: int
    instruction_word: int
    branch_kind: str
    target_va: int | None
    link: bool
    absolute: bool
    conditional: bool
    indirect: bool
    bo: int | None
    bi: int | None
    target_kind: str
    target_record_id: str | None
    target_fold_group_id: str | None
    target_record_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProcedureBranchUse:
    """One logical procedure record's relationship to a physical branch site."""

    use_id: str
    record_id: str
    site_id: str
    site_va: int
    role: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProcedureScan:
    """Auditable scan coverage for one PDB procedure record."""

    record_id: str
    va: int | None
    declared_size: int
    scanned_size: int
    unscanned_byte_count: int
    status: str
    branch_use_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ControlFlowExtraction:
    """Deterministic physical branch sites, logical uses, and scan diagnostics."""

    sites: tuple[BranchSite, ...]
    uses: tuple[ProcedureBranchUse, ...]
    scans: tuple[ProcedureScan, ...]

    @property
    def physical_site_count(self) -> int:
        return len(self.sites)

    @property
    def logical_use_count(self) -> int:
        return len(self.uses)

    @property
    def direct_target_site_count(self) -> int:
        return sum(site.target_va is not None for site in self.sites)

    @property
    def indirect_site_count(self) -> int:
        return sum(site.indirect for site in self.sites)

    def to_summary(self) -> dict[str, object]:
        statuses: dict[str, int] = {}
        target_kinds: dict[str, int] = {}
        roles: dict[str, int] = {}
        for scan in self.scans:
            statuses[scan.status] = statuses.get(scan.status, 0) + 1
        for site in self.sites:
            target_kinds[site.target_kind] = target_kinds.get(site.target_kind, 0) + 1
        for use in self.uses:
            roles[use.role] = roles.get(use.role, 0) + 1
        return {
            "physical_sites": self.physical_site_count,
            "logical_uses": self.logical_use_count,
            "direct_target_sites": self.direct_target_site_count,
            "indirect_sites": self.indirect_site_count,
            "scan_statuses": dict(sorted(statuses.items())),
            "target_kinds": dict(sorted(target_kinds.items())),
            "use_roles": dict(sorted(roles.items())),
        }


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _address32(value: int) -> int:
    return value & 0xFFFFFFFF


def read_xbox_pe_image(path: str | Path) -> ExecutableImage:
    """Read a PowerPC-BE PE image with validated raw section mappings."""

    source = Path(path)
    data = source.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ExecutableFormatError(f"{source}: not an MZ executable")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ExecutableFormatError(f"{source}: invalid or truncated PE header")

    machine = _u16(data, pe_offset + 4)
    if machine != IMAGE_FILE_MACHINE_POWERPCBE:
        raise ExecutableFormatError(
            f"{source}: expected PowerPC-BE machine 0x{IMAGE_FILE_MACHINE_POWERPCBE:04X}, "
            f"found 0x{machine:04X}"
        )
    section_count = _u16(data, pe_offset + 6)
    optional_size = _u16(data, pe_offset + 20)
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data):
        raise ExecutableFormatError(f"{source}: truncated optional header")

    magic = _u16(data, optional_offset)
    if magic == 0x10B:
        if optional_size < 32:
            raise ExecutableFormatError(f"{source}: truncated PE32 optional header")
        image_base = _u32(data, optional_offset + 28)
    elif magic == 0x20B:
        if optional_size < 32:
            raise ExecutableFormatError(f"{source}: truncated PE32+ optional header")
        image_base = struct.unpack_from("<Q", data, optional_offset + 24)[0]
    else:
        raise ExecutableFormatError(
            f"{source}: unsupported optional-header magic 0x{magic:04X}"
        )

    section_table = optional_offset + optional_size
    if section_table + section_count * 40 > len(data):
        raise ExecutableFormatError(f"{source}: truncated section table")
    sections: list[ExecutableSection] = []
    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode(
            "ascii", "replace"
        )
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        characteristics = _u32(data, offset + 36)
        if raw_size and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
            raise ExecutableFormatError(
                f"{source}: raw extent for section {name!r} is outside the file"
            )
        sections.append(
            ExecutableSection(
                name=name,
                start=image_base + virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=characteristics,
            )
        )

    ordered = tuple(sorted(sections, key=lambda section: (section.start, section.name)))
    for left, right in zip(ordered, ordered[1:]):
        if left.end > right.start:
            raise ExecutableFormatError(
                f"{source}: PE sections {left.name!r} and {right.name!r} overlap"
            )
    return ExecutableImage(
        data=data,
        machine=machine,
        image_base=image_base,
        sections=ordered,
    )


def decode_ppc_branch(instruction_word: int, address: int) -> DecodedBranch | None:
    """Decode a 32-bit PowerPC branch instruction, or return ``None``.

    ``instruction_word`` is the host integer value of the big-endian Xbox
    instruction.  Returned targets use 32-bit effective-address arithmetic.
    """

    if not 0 <= instruction_word <= 0xFFFFFFFF:
        raise ValueError("PowerPC instruction word must fit in 32 bits")
    if not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("PowerPC instruction address must fit in 32 bits")

    opcode = instruction_word >> 26
    link = bool(instruction_word & 1)
    absolute = bool(instruction_word & 2)
    if opcode == 18:  # b, ba, bl, bla
        displacement = _sign_extend(instruction_word & 0x03FFFFFC, 26)
        target = displacement if absolute else address + displacement
        return DecodedBranch(
            address=address,
            instruction_word=instruction_word,
            branch_kind="branch_immediate",
            target_va=_address32(target),
            link=link,
            absolute=absolute,
            conditional=False,
            indirect=False,
        )

    if opcode == 16:  # bc, bca, bcl, bcla
        displacement = _sign_extend(instruction_word & 0xFFFC, 16)
        target = displacement if absolute else address + displacement
        return DecodedBranch(
            address=address,
            instruction_word=instruction_word,
            branch_kind="branch_conditional",
            target_va=_address32(target),
            link=link,
            absolute=absolute,
            conditional=True,
            indirect=False,
            bo=(instruction_word >> 21) & 0x1F,
            bi=(instruction_word >> 16) & 0x1F,
        )

    if opcode == 19:
        extended_opcode = (instruction_word >> 1) & 0x3FF
        if extended_opcode == 16:  # bclr / bclrl
            return DecodedBranch(
                address=address,
                instruction_word=instruction_word,
                branch_kind="branch_to_link_register",
                target_va=None,
                link=link,
                absolute=False,
                conditional=True,
                indirect=True,
                bo=(instruction_word >> 21) & 0x1F,
                bi=(instruction_word >> 16) & 0x1F,
            )
        if extended_opcode == 528:  # bcctr / bcctrl
            return DecodedBranch(
                address=address,
                instruction_word=instruction_word,
                branch_kind="branch_to_count_register",
                target_va=None,
                link=link,
                absolute=False,
                conditional=True,
                indirect=True,
                bo=(instruction_word >> 21) & 0x1F,
                bi=(instruction_word >> 16) & 0x1F,
            )
    return None


def _in_ranges(address: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= address < end for start, end in ranges)


def _site_id(address: int) -> str:
    return f"x360-ppc-branch:xbox-va:{address:08X}"


def _use_role(branch: DecodedBranch, procedure_va: int, procedure_size: int) -> str:
    target = branch.target_va
    within_extent = (
        target is not None
        and procedure_va <= target < procedure_va + procedure_size
    )
    if branch.branch_kind == "branch_immediate":
        if branch.link:
            if target == _address32(branch.address + 4):
                return "link_register_setup"
            return "local_direct_call" if within_extent else "direct_call"
        return "local_branch" if within_extent else "tail_transfer"
    if branch.branch_kind == "branch_conditional":
        if branch.link:
            if target == _address32(branch.address + 4):
                return "conditional_link_register_setup"
            return "local_conditional_call" if within_extent else "conditional_call"
        return "local_conditional_branch" if within_extent else "conditional_transfer"
    if branch.branch_kind == "branch_to_count_register":
        return "indirect_call" if branch.link else "indirect_tail_or_switch"
    if branch.branch_kind == "branch_to_link_register":
        return "indirect_link_register_call" if branch.link else "return_or_indirect_branch"
    raise AssertionError(branch.branch_kind)


def _coerce_procedures(procedures: Iterable[ProcedureLike]) -> tuple[ProcedureExtent, ...]:
    result: list[ProcedureExtent] = []
    seen: set[str] = set()
    for procedure in procedures:
        record_id = str(procedure.record_id)
        if not record_id:
            raise ValueError("procedure record ID cannot be empty")
        if record_id in seen:
            raise ValueError(f"duplicate procedure record ID {record_id!r}")
        seen.add(record_id)
        va = procedure.va
        if va is not None and (not isinstance(va, int) or isinstance(va, bool)):
            raise TypeError(f"procedure {record_id!r} has a non-integer VA")
        if va is not None and not 0 <= va <= 0xFFFFFFFF:
            raise ValueError(f"procedure {record_id!r} VA is outside 32-bit space")
        size = procedure.size
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= 0xFFFFFFFF
        ):
            raise ValueError(f"procedure {record_id!r} has an invalid size")
        if va is not None and va + size > 0x100000000:
            raise ValueError(f"procedure {record_id!r} extent wraps 32-bit space")
        result.append(ProcedureExtent(record_id=record_id, va=va, size=size))
    return tuple(sorted(result, key=lambda item: item.record_id))


def extract_ppc_control_flow(
    image: ExecutableImage,
    procedures: Iterable[ProcedureLike],
) -> ControlFlowExtraction:
    """Extract physical branch sites and their logical procedure memberships."""

    if image.machine != IMAGE_FILE_MACHINE_POWERPCBE:
        raise ValueError("control-flow extraction requires a PowerPC-BE PE image")
    records = _coerce_procedures(procedures)
    entries: dict[int, list[str]] = {}
    for record in records:
        if record.va is not None:
            entries.setdefault(record.va, []).append(record.record_id)
    for record_ids in entries.values():
        record_ids.sort()

    decoded_by_address: dict[int, DecodedBranch] = {}
    interval_sites: dict[tuple[int, int], tuple[DecodedBranch, ...]] = {}
    scans: list[ProcedureScan] = []
    uses: list[ProcedureBranchUse] = []

    for record in records:
        if record.va is None:
            scans.append(
                ProcedureScan(
                    record_id=record.record_id,
                    va=None,
                    declared_size=record.size,
                    scanned_size=0,
                    unscanned_byte_count=record.size,
                    status="unresolved_va",
                    branch_use_count=0,
                )
            )
            continue
        section = image.section_at(record.va)
        if section is None or not section.contains_raw(record.va):
            scans.append(
                ProcedureScan(
                    record_id=record.record_id,
                    va=record.va,
                    declared_size=record.size,
                    scanned_size=0,
                    unscanned_byte_count=record.size,
                    status="unmapped_va",
                    branch_use_count=0,
                )
            )
            continue
        if not section.executable:
            scans.append(
                ProcedureScan(
                    record_id=record.record_id,
                    va=record.va,
                    declared_size=record.size,
                    scanned_size=0,
                    unscanned_byte_count=record.size,
                    status="non_executable_section",
                    branch_use_count=0,
                )
            )
            continue

        raw_available = image.raw_bytes_available(record.va)
        available = min(record.size, raw_available)
        scanned_size = available - (available % 4)
        if record.size == 0:
            status = "empty"
        elif raw_available < record.size:
            status = "truncated_raw_extent"
        elif record.size % 4:
            status = "unaligned_size"
        else:
            status = "ok"

        key = (record.va, scanned_size)
        decoded = interval_sites.get(key)
        if decoded is None:
            found: list[DecodedBranch] = []
            if scanned_size:
                code = image.read(record.va, scanned_size)
                for offset in range(0, scanned_size, 4):
                    address = record.va + offset
                    word = struct.unpack_from(">I", code, offset)[0]
                    branch = decoded_by_address.get(address)
                    if branch is None:
                        branch = decode_ppc_branch(word, address)
                        if branch is not None:
                            decoded_by_address[address] = branch
                    elif branch.instruction_word != word:
                        raise ExecutableFormatError(
                            f"instruction bytes changed while scanning 0x{address:X}"
                        )
                    if branch is not None:
                        found.append(branch)
            decoded = tuple(found)
            interval_sites[key] = decoded

        for branch in decoded:
            site_id = _site_id(branch.address)
            role = _use_role(branch, record.va, record.size)
            uses.append(
                ProcedureBranchUse(
                    use_id=f"x360-ppc-use:{record.record_id}:{branch.address:08X}",
                    record_id=record.record_id,
                    site_id=site_id,
                    site_va=branch.address,
                    role=role,
                )
            )
        scans.append(
            ProcedureScan(
                record_id=record.record_id,
                va=record.va,
                declared_size=record.size,
                scanned_size=scanned_size,
                unscanned_byte_count=record.size - scanned_size,
                status=status,
                branch_use_count=len(decoded),
            )
        )

    executable_ranges = image.executable_ranges
    sites: list[BranchSite] = []
    for address, branch in sorted(decoded_by_address.items()):
        target_record_id: str | None = None
        target_fold_group_id: str | None = None
        target_count = 0
        if branch.target_va is None:
            target_kind = "indirect"
        else:
            target_records = entries.get(branch.target_va, [])
            target_count = len(target_records)
            if target_count == 1:
                target_kind = "unique_procedure"
                target_record_id = target_records[0]
            elif target_count > 1:
                target_kind = "fold_group"
                target_fold_group_id = f"x360-fold:{branch.target_va:08X}"
            elif _in_ranges(branch.target_va, executable_ranges):
                target_kind = "executable_non_entry"
            else:
                target_kind = "outside_executable"
        sites.append(
            BranchSite(
                site_id=_site_id(address),
                site_va=address,
                instruction_word=branch.instruction_word,
                branch_kind=branch.branch_kind,
                target_va=branch.target_va,
                link=branch.link,
                absolute=branch.absolute,
                conditional=branch.conditional,
                indirect=branch.indirect,
                bo=branch.bo,
                bi=branch.bi,
                target_kind=target_kind,
                target_record_id=target_record_id,
                target_fold_group_id=target_fold_group_id,
                target_record_count=target_count,
            )
        )

    return ControlFlowExtraction(
        sites=tuple(sites),
        uses=tuple(sorted(uses, key=lambda use: (use.record_id, use.site_va))),
        scans=tuple(scans),
    )


def select_control_flow(
    extraction: ControlFlowExtraction,
    *,
    policy: str = "call_relevant_v1",
) -> ControlFlowExtraction:
    """Select a documented persistence subset without losing scan coverage.

    ``call_relevant_v1`` retains a physical site when at least one logical use
    has a call/tail-transfer role, then retains *all* uses of that site.
    ``all_branches_v1`` is the lossless full-CFG option.  Scans always remain
    complete and continue to report their source extraction counts.
    """

    if policy not in CONTROL_FLOW_POLICIES:
        raise ValueError(f"unsupported control-flow persistence policy {policy!r}")
    if policy == "all_branches_v1":
        return extraction
    selected_site_ids = frozenset(
        use.site_id
        for use in extraction.uses
        if use.role in CALL_RELEVANT_V1_ROLES
    )
    return ControlFlowExtraction(
        sites=tuple(
            site for site in extraction.sites if site.site_id in selected_site_ids
        ),
        uses=tuple(
            use for use in extraction.uses if use.site_id in selected_site_ids
        ),
        scans=extraction.scans,
    )


def extract_ppc_control_flow_from_files(
    *,
    pdb_path: str | Path,
    executable_path: str | Path,
    modules_path: str | Path,
) -> ControlFlowExtraction:
    """Extract PDB records and PowerPC control flow from explicit input paths."""

    # The local import keeps the low-level decoder independently reusable and
    # avoids making its synthetic tests construct an MSF container.
    from .pdb_symbols import extract_procedures

    procedures = extract_procedures(pdb_path, executable_path, modules_path)
    image = read_xbox_pe_image(executable_path)
    return extract_ppc_control_flow(image, procedures.records)


def iter_jsonl_rows(extraction: ControlFlowExtraction) -> Iterator[dict[str, object]]:
    """Yield a deterministic tagged JSONL representation."""

    yield {"record_type": "summary", **extraction.to_summary()}
    for site in extraction.sites:
        yield {"record_type": "branch_site", **site.to_dict()}
    for use in extraction.uses:
        yield {"record_type": "procedure_branch_use", **use.to_dict()}
    for scan in extraction.scans:
        yield {"record_type": "procedure_scan", **scan.to_dict()}


def write_control_flow_jsonl(
    extraction: ControlFlowExtraction,
    output: str | Path | TextIO,
) -> None:
    """Write deterministic UTF-8 JSONL without discarding diagnostics."""

    close = False
    if hasattr(output, "write"):
        handle = output
    else:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("w", encoding="utf-8", newline="\n")
        close = True
    try:
        for row in iter_jsonl_rows(extraction):
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
    finally:
        if close:
            handle.close()


__all__ = [
    "BranchSite",
    "CALL_RELEVANT_V1_ROLES",
    "CONTROL_FLOW_POLICIES",
    "ControlFlowExtraction",
    "DecodedBranch",
    "ExecutableFormatError",
    "ExecutableImage",
    "ExecutableSection",
    "IMAGE_FILE_MACHINE_POWERPCBE",
    "ProcedureBranchUse",
    "ProcedureExtent",
    "ProcedureScan",
    "decode_ppc_branch",
    "extract_ppc_control_flow",
    "extract_ppc_control_flow_from_files",
    "iter_jsonl_rows",
    "read_xbox_pe_image",
    "select_control_flow",
    "write_control_flow_jsonl",
]
