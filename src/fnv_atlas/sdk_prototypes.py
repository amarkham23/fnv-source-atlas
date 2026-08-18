"""Candidate-only observations from address-bearing C/C++ SDK sources.

The SDK is useful research evidence, not an authority which can create atlas
functions or accepted mappings.  This module keeps four distinct concepts:

* source-authored address-to-declaration observations;
* direct engine-call targets, whose enclosing wrapper is context rather than a
  name assertion for the target;
* global-data addresses (``AddressPtr`` and ``NIRTTI_ADDRESS``), which never
  participate in function-entry classification; and
* explicit boundary-review candidates derived from ``CREATE_OBJECT`` targets
  which are executable but absent from a supplied canonical inventory.

All extractors are read-only, deterministic, dependency-free, and retain raw
file hashes and source locations.  They never create functions, names, match
claims, confidence values, or review decisions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Iterable, Iterator


SOURCE_SUFFIXES = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl"}
)

_ADDRESS_COMMENT_RE = re.compile(
    r"^\s*//\s*(?P<variant>GAME|GECK)\s*-\s*(?P<body>.*)$",
    re.IGNORECASE,
)
_HEX_ADDRESS_RE = re.compile(
    r"(?<![0-9A-Za-z_])0x(?P<digits>[0-9A-Fa-f]{1,8})(?![0-9A-Za-z_])"
)
_CREATE_OBJECT_RE = re.compile(
    r"^\s*CREATE_OBJECT\s*\(\s*"
    r"(?P<class_name>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*,\s*"
    r"0x(?P<address>[0-9A-Fa-f]{1,8})\s*\)\s*;?\s*(?://.*)?$"
)
_HELPER_CALL_RE = re.compile(
    r"\b(?P<helper>ThisCall|CdeclCall|StdCall|FastCall)"
    r"(?:\s*<(?P<return_type>[^;{}]*?)>)?\s*"
    r"\(\s*0x(?P<address>[0-9A-Fa-f]{1,8})",
    re.IGNORECASE,
)
_TYPED_CALL_RE = re.compile(
    r"\(\(\s*(?P<return_type>[^()]+?)\s*"
    r"\(\s*(?P<calling_convention>__(?:thiscall|cdecl|stdcall|fastcall))"
    r"\s*\*\s*\)\s*"
    r"\((?P<parameter_types>[^()]*)\)\s*\)\s*"
    r"0x(?P<address>[0-9A-Fa-f]{1,8})\s*\)\s*\(",
    re.IGNORECASE,
)
_ADDRESS_PTR_RE = re.compile(
    r"\bAddressPtr\s*<(?P<declared_type>.+),\s*"
    r"0x(?P<address>[0-9A-Fa-f]{1,8})\s*>\s*"
    r"(?P<member_name>[A-Za-z_]\w*)\s*;?\s*(?://.*)?$",
    re.IGNORECASE,
)
_NIRTTI_RE = re.compile(
    r"^\s*NIRTTI_ADDRESS\s*\(\s*0x(?P<address>[0-9A-Fa-f]{1,8})\s*\)\s*;?",
    re.IGNORECASE,
)
_DECLARED_NAME_RE = re.compile(
    r"(?P<name>"
    r"(?:(?:~?[A-Za-z_]\w*|[A-Za-z_]\w*<[^(){};]*>)::)*"
    r"(?:~?[A-Za-z_]\w*|operator(?:\s+(?:new|delete)(?:\[\])?|"
    r"\s+[A-Za-z_]\w*|\[\]|\(\)|[^\s(]+))"
    r")\s*\("
)
_CLASS_OPEN_RE = re.compile(
    r"\b(?:class|struct)\s+"
    r"(?:alignas\s*\([^)]*\)\s*)?"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:final\s*)?"
    r"(?::[^{};]*)?\{"
)
_NON_FUNCTION_PAREN_NAMES = frozenset(
    {
        "alignas",
        "catch",
        "decltype",
        "for",
        "if",
        "noexcept",
        "requires",
        "sizeof",
        "static_assert",
        "switch",
        "while",
    }
)
_HELPER_CALLING_CONVENTIONS = {
    "thiscall": "__thiscall",
    "cdeclcall": "__cdecl",
    "stdcall": "__stdcall",
    "fastcall": "__fastcall",
}


@dataclass(frozen=True, slots=True)
class SdkSourceFile:
    """Portable identity of one scanned SDK source file."""

    relative_path: str
    sha256: str
    byte_length: int

    def __post_init__(self) -> None:
        parsed_path = PurePosixPath(self.relative_path)
        if (
            not self.relative_path
            or "\\" in self.relative_path
            or self.relative_path.startswith("/")
            or parsed_path.as_posix() != self.relative_path
            or any(part in {"", ".", ".."} for part in parsed_path.parts)
            or (parsed_path.parts and ":" in parsed_path.parts[0])
        ):
            raise ValueError(
                "SDK source paths must be normalized relative POSIX paths"
            )
        if (
            len(self.sha256) != 64
            or self.sha256 != self.sha256.lower()
            or any(character not in "0123456789abcdef" for character in self.sha256)
        ):
            raise ValueError("SDK source file SHA-256 must be lowercase hexadecimal")
        if self.byte_length < 0:
            raise ValueError("SDK source file byte length cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _source_tree_sha256(files: Iterable[SdkSourceFile]) -> str:
    digest = hashlib.sha256()
    ordered = tuple(sorted(files, key=lambda item: item.relative_path.casefold()))
    folded_paths: set[str] = set()
    for item in ordered:
        folded = item.relative_path.casefold()
        if folded in folded_paths:
            raise ValueError(
                f"SDK source manifest has a case-colliding path {item.relative_path!r}"
            )
        folded_paths.add(folded)
        path_bytes = item.relative_path.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(item.byte_length.to_bytes(8, "big"))
        digest.update(bytes.fromhex(item.sha256))
    return f"sha256:{digest.hexdigest()}"


@dataclass(frozen=True, slots=True)
class SdkPrototypeObservation:
    """One source-authored address-to-declaration observation."""

    program_variant: str
    address: int
    declared_name: str
    signature: str
    evidence_kind: str
    source_path: str
    source_file_sha256: str
    address_line: int
    declaration_line: int
    source_text: str
    address_ordinal: int = 0
    declaration_text: str | None = None

    @property
    def observation_id(self) -> str:
        fields = (
            self.program_variant,
            f"{self.address:08x}",
            self.declared_name,
            self.signature,
            self.evidence_kind,
            self.source_path,
            self.source_file_sha256,
            str(self.address_line),
            str(self.declaration_line),
            str(self.address_ordinal),
        )
        digest = hashlib.sha256("\0".join(fields).encode("utf-8")).hexdigest()
        return f"sdk-prototype:sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["observation_id"] = self.observation_id
        result["address_hex"] = f"0x{self.address:08X}"
        return result


@dataclass(frozen=True, slots=True)
class SdkCallTargetObservation:
    """A literal call target; enclosing declaration fields are context only."""

    program_variant: str
    address: int
    invocation_kind: str
    helper_name: str | None
    calling_convention: str | None
    rendered_return_type: str | None
    parameter_types: tuple[str, ...] | None
    rendered_target_type: str | None
    argument_expressions: tuple[str, ...]
    enclosing_declared_name: str | None
    enclosing_owner_hint: str | None
    enclosing_signature: str | None
    declaration_text: str | None
    source_path: str
    source_file_sha256: str
    call_line: int
    declaration_line: int | None
    source_text: str
    address_ordinal: int = 0

    @property
    def observation_id(self) -> str:
        fields = (
            self.program_variant,
            f"{self.address:08x}",
            self.invocation_kind,
            self.helper_name or "",
            self.calling_convention or "",
            self.rendered_return_type or "",
            "\x1f".join(self.parameter_types or ()),
            self.rendered_target_type or "",
            "\x1f".join(self.argument_expressions),
            self.enclosing_declared_name or "",
            self.enclosing_owner_hint or "",
            self.enclosing_signature or "",
            self.declaration_text or "",
            self.source_path,
            self.source_file_sha256,
            str(self.call_line),
            str(self.declaration_line or 0),
            str(self.address_ordinal),
        )
        digest = hashlib.sha256("\0".join(fields).encode("utf-8")).hexdigest()
        return f"sdk-call-target:sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["parameter_types"] = (
            list(self.parameter_types) if self.parameter_types is not None else None
        )
        result["argument_expressions"] = list(self.argument_expressions)
        result["observation_id"] = self.observation_id
        result["address_hex"] = f"0x{self.address:08X}"
        return result


@dataclass(frozen=True, slots=True)
class SdkDataAddressObservation:
    """A typed global-data address, explicitly separate from code entries."""

    program_variant: str
    address: int
    data_kind: str
    declared_name: str
    member_name: str
    declared_type: str
    owner_name: str | None
    owner_basis: str | None
    declaration_text: str
    source_path: str
    source_file_sha256: str
    declaration_line: int

    @property
    def observation_id(self) -> str:
        fields = (
            self.program_variant,
            f"{self.address:08x}",
            self.data_kind,
            self.declared_name,
            self.member_name,
            self.declared_type,
            self.owner_name or "",
            self.owner_basis or "",
            self.declaration_text,
            self.source_path,
            self.source_file_sha256,
            str(self.declaration_line),
        )
        digest = hashlib.sha256("\0".join(fields).encode("utf-8")).hexdigest()
        return f"sdk-data-address:sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["observation_id"] = self.observation_id
        result["address_hex"] = f"0x{self.address:08X}"
        return result


@dataclass(frozen=True, slots=True)
class SdkPrototypeDiagnostic:
    code: str
    source_path: str
    line: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SdkPrototypeExtraction:
    """One extraction run; ``root`` is diagnostic-only and not serialized."""

    root: str
    files_scanned: int
    observations: tuple[SdkPrototypeObservation, ...]
    diagnostics: tuple[SdkPrototypeDiagnostic, ...]
    call_targets: tuple[SdkCallTargetObservation, ...] = ()
    data_addresses: tuple[SdkDataAddressObservation, ...] = ()
    source_files: tuple[SdkSourceFile, ...] = ()

    def __post_init__(self) -> None:
        if self.files_scanned < 0:
            raise ValueError("files_scanned cannot be negative")
        if self.source_files and len(self.source_files) != self.files_scanned:
            raise ValueError("source-file manifest count does not match files_scanned")
        manifest = {item.relative_path: item.sha256 for item in self.source_files}
        if len(manifest) != len(self.source_files):
            raise ValueError("source-file manifest paths must be unique")
        if manifest:
            for observation in (
                *self.observations,
                *self.call_targets,
                *self.data_addresses,
            ):
                if manifest.get(observation.source_path) != observation.source_file_sha256:
                    raise ValueError(
                        "SDK observation source identity disagrees with source manifest"
                    )

    @property
    def source_tree_sha256(self) -> str:
        """Content identity of every scanned source file, excluding root path."""

        return _source_tree_sha256(self.source_files)

    @property
    def unique_addresses(self) -> frozenset[int]:
        """Unique declaration-observation addresses (legacy-compatible view)."""

        return frozenset(item.address for item in self.observations)

    @property
    def game_addresses(self) -> frozenset[int]:
        return frozenset(
            item.address
            for item in self.observations
            if item.program_variant == "game"
        )

    @property
    def geck_addresses(self) -> frozenset[int]:
        return frozenset(
            item.address
            for item in self.observations
            if item.program_variant == "geck"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "observation_count": len(self.observations),
            "unique_address_count": len(self.unique_addresses),
            "game_address_count": len(self.game_addresses),
            "geck_address_count": len(self.geck_addresses),
            "call_target_count": len(self.call_targets),
            "data_address_count": len(self.data_addresses),
            "source_tree_sha256": self.source_tree_sha256,
            "source_files": [item.to_dict() for item in self.source_files],
            "observations": [item.to_dict() for item in self.observations],
            "call_targets": [item.to_dict() for item in self.call_targets],
            "data_addresses": [item.to_dict() for item in self.data_addresses],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True, slots=True)
class SdkPrototypeClassification:
    """One declaration observation joined to an externally supplied inventory."""

    observation: SdkPrototypeObservation
    classification: str

    def to_dict(self) -> dict[str, Any]:
        result = self.observation.to_dict()
        result["pc_inventory_classification"] = self.classification
        return result


@dataclass(frozen=True, slots=True)
class SdkBoundaryCandidate:
    """A review candidate, never a new or promoted canonical function."""

    source_observation: SdkPrototypeObservation
    inventory_classification: str
    candidate_reason: str
    containing_function_entries: tuple[int, ...]

    @property
    def candidate_id(self) -> str:
        fields = (
            self.source_observation.observation_id,
            self.inventory_classification,
            self.candidate_reason,
            ",".join(f"{entry:08x}" for entry in self.containing_function_entries),
        )
        digest = hashlib.sha256("\0".join(fields).encode("utf-8")).hexdigest()
        return f"sdk-boundary-candidate:sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source_observation_id": self.source_observation.observation_id,
            "source_observation": self.source_observation.to_dict(),
            "address": self.source_observation.address,
            "address_hex": f"0x{self.source_observation.address:08X}",
            "declared_name": self.source_observation.declared_name,
            "inventory_classification": self.inventory_classification,
            "candidate_reason": self.candidate_reason,
            "containing_function_entries": list(self.containing_function_entries),
        }


@dataclass(frozen=True, slots=True)
class _DeclarationContext:
    declared_name: str
    owner_hint: str | None
    signature: str
    declaration_text: str
    declaration_line: int


def _normalise_cpp(fragment: str) -> str:
    return " ".join(fragment.split())


def _declared_name(signature: str) -> str | None:
    candidate = re.sub(r"^\s*template\s*<[^;{}]*?>\s*", "", signature)
    for match in _DECLARED_NAME_RE.finditer(candidate):
        name = " ".join(match.group("name").split())
        name = re.sub(r"\s*::\s*", "::", name)
        name = re.sub(r"\s*([<>,])\s*", r"\1", name)
        if name not in _NON_FUNCTION_PAREN_NAMES and not name.startswith("__declspec"):
            return name
    return None


def _declaration_after(
    lines: list[str], start: int, *, max_physical_lines: int = 40
) -> tuple[int, str, str, str] | None:
    fragments: list[str] = []
    raw_fragments: list[str] = []
    declaration_line: int | None = None
    for index in range(start, min(len(lines), start + max_physical_lines)):
        stripped = lines[index].strip()
        if not stripped:
            continue
        if _ADDRESS_COMMENT_RE.match(lines[index]):
            continue
        if (
            stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
        ):
            continue
        if stripped.startswith("#") and not fragments:
            continue
        if declaration_line is None:
            declaration_line = index + 1
        fragments.append(stripped)
        raw_fragments.append(lines[index].rstrip())
        joined = _normalise_cpp(" ".join(fragments))
        terminators = [
            position
            for token in ("{", ";")
            if (position := joined.find(token)) >= 0
        ]
        if not terminators:
            continue
        header = joined[: min(terminators)].strip()
        name = _declared_name(header)
        if name is None:
            return None
        declaration_text = "\n".join(raw_fragments)
        raw_terminators = [
            position
            for token in ("{", ";")
            if (position := declaration_text.find(token)) >= 0
        ]
        if raw_terminators:
            declaration_text = declaration_text[: min(raw_terminators)].rstrip()
        return declaration_line, header, name, declaration_text
    return None


def _mask_cpp_lines(lines: list[str]) -> list[str]:
    """Mask comments and strings while retaining source columns and braces."""

    masked: list[str] = []
    in_block_comment = False
    for line in lines:
        result = list(line)
        index = 0
        quote: str | None = None
        escaped = False
        while index < len(line):
            if in_block_comment:
                result[index] = " "
                if line.startswith("*/", index):
                    result[index : index + 2] = [" ", " "]
                    in_block_comment = False
                    index += 2
                else:
                    index += 1
                continue
            if quote is not None:
                result[index] = " "
                if escaped:
                    escaped = False
                elif line[index] == "\\":
                    escaped = True
                elif line[index] == quote:
                    quote = None
                index += 1
                continue
            if line.startswith("//", index):
                result[index:] = [" "] * (len(line) - index)
                break
            if line.startswith("/*", index):
                result[index : index + 2] = [" ", " "]
                in_block_comment = True
                index += 2
                continue
            if line[index] in {'"', "'"}:
                quote = line[index]
                result[index] = " "
            index += 1
        masked.append("".join(result))
    return masked


def _lexical_class_owners(masked_lines: list[str]) -> tuple[str | None, ...]:
    depth = 0
    stack: list[tuple[str, int]] = []
    owners: list[str | None] = []
    for code in masked_lines:
        while stack and depth < stack[-1][1]:
            stack.pop()
        match = _CLASS_OPEN_RE.search(code)
        if match is not None:
            prefix = code[: match.end()]
            body_depth = depth + prefix.count("{") - prefix.count("}")
            local_name = match.group("name")
            qualified_name = (
                f"{stack[-1][0]}::{local_name}" if stack else local_name
            )
            stack.append((qualified_name, body_depth))
        owners.append(stack[-1][0] if stack else None)
        depth += code.count("{") - code.count("}")
        while stack and depth < stack[-1][1]:
            stack.pop()
    return tuple(owners)


def _preprocessor_variants(
    lines: list[str], source_path: str
) -> tuple[tuple[str, ...], tuple[SdkPrototypeDiagnostic, ...]]:
    current = "unspecified_pc"
    frames: list[tuple[str, bool]] = []
    variants: list[str] = []
    diagnostics: list[SdkPrototypeDiagnostic] = []
    for line_number, line in enumerate(lines, 1):
        variants.append(current)
        stripped = line.strip()
        if re.match(r"^#\s*(?:if|ifdef)\s+GAME\b", stripped):
            frames.append((current, True))
            current = "game"
        elif re.match(r"^#\s*ifndef\s+GAME\b", stripped):
            frames.append((current, True))
            current = "geck"
        elif re.match(r"^#\s*if\s+defined\s*\(\s*GAME\s*\)", stripped):
            frames.append((current, True))
            current = "game"
        elif re.match(r"^#\s*if\s*!\s*defined\s*\(\s*GAME\s*\)", stripped):
            frames.append((current, True))
            current = "geck"
        elif re.match(r"^#\s*(?:if|ifdef|ifndef)\b", stripped):
            frames.append((current, False))
        elif re.match(r"^#\s*else\b", stripped):
            if not frames:
                diagnostics.append(
                    SdkPrototypeDiagnostic(
                        "unbalanced_preprocessor_else",
                        source_path,
                        line_number,
                        "#else has no matching conditional",
                    )
                )
            elif frames[-1][1]:
                current = "geck" if current == "game" else "game"
        elif re.match(r"^#\s*endif\b", stripped):
            if not frames:
                diagnostics.append(
                    SdkPrototypeDiagnostic(
                        "unbalanced_preprocessor_endif",
                        source_path,
                        line_number,
                        "#endif has no matching conditional",
                    )
                )
            else:
                current = frames.pop()[0]
    if frames:
        diagnostics.append(
            SdkPrototypeDiagnostic(
                "unterminated_preprocessor_conditional",
                source_path,
                len(lines),
                f"{len(frames)} conditional block(s) remain open",
            )
        )
    return tuple(variants), tuple(diagnostics)


def _split_cpp_list(text: str) -> tuple[str, ...]:
    if not text.strip():
        return ()
    items: list[str] = []
    start = 0
    round_depth = square_depth = brace_depth = angle_depth = 0
    quote: str | None = None
    escaped = False
    for index, character in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "(":
            round_depth += 1
        elif character == ")":
            round_depth = max(0, round_depth - 1)
        elif character == "[":
            square_depth += 1
        elif character == "]":
            square_depth = max(0, square_depth - 1)
        elif character == "{":
            brace_depth += 1
        elif character == "}":
            brace_depth = max(0, brace_depth - 1)
        elif character == "<":
            angle_depth += 1
        elif character == ">":
            angle_depth = max(0, angle_depth - 1)
        elif (
            character == ","
            and round_depth == square_depth == brace_depth == angle_depth == 0
        ):
            items.append(_normalise_cpp(text[start:index]))
            start = index + 1
    items.append(_normalise_cpp(text[start:]))
    return tuple(item for item in items if item)


def _parenthesized_text(line: str, opening: int) -> tuple[str, int] | None:
    if opening < 0 or opening >= len(line) or line[opening] != "(":
        return None
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(line)):
        character = line[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return line[opening + 1 : index], index
    return None


def _brace_active_at(
    masked_lines: list[str], opening_line: int, opening_column: int, target_line: int,
    target_column: int,
) -> bool:
    depth = 1
    for line_index in range(opening_line, target_line + 1):
        start = opening_column + 1 if line_index == opening_line else 0
        end = target_column if line_index == target_line else len(masked_lines[line_index])
        segment = masked_lines[line_index][start:end]
        depth += segment.count("{") - segment.count("}")
        if depth <= 0:
            return False
    return depth > 0


def _header_before_brace(
    lines: list[str], masked_lines: list[str], brace_line: int, brace_column: int,
    owners: tuple[str | None, ...], *, max_header_lines: int = 16,
) -> _DeclarationContext | None:
    for start in range(brace_line, max(-1, brace_line - max_header_lines), -1):
        final_raw = lines[brace_line][:brace_column]
        raw_parts = lines[start:brace_line] + [final_raw]
        declaration_text = "\n".join(raw_parts).strip()
        signature = _normalise_cpp(declaration_text)
        name = _declared_name(signature)
        if name is not None:
            return _DeclarationContext(
                declared_name=name,
                owner_hint=owners[brace_line],
                signature=signature,
                declaration_text=declaration_text,
                declaration_line=start + 1,
            )
        if start < brace_line and any(
            token in masked_lines[start] for token in (";", "{", "}")
        ):
            break
    return None


def _enclosing_declaration(
    lines: list[str], masked_lines: list[str], owners: tuple[str | None, ...],
    target_line: int, target_column: int,
) -> _DeclarationContext | None:
    for line_index in range(target_line, -1, -1):
        limit = target_column if line_index == target_line else len(masked_lines[line_index])
        for brace_column in range(limit - 1, -1, -1):
            if masked_lines[line_index][brace_column] != "{":
                continue
            if not _brace_active_at(
                masked_lines,
                line_index,
                brace_column,
                target_line,
                target_column,
            ):
                continue
            context = _header_before_brace(
                lines, masked_lines, line_index, brace_column, owners
            )
            if context is not None:
                return context
    return None


def _relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_link_or_reparse_point(path: Path) -> bool:
    """Return whether *path* can redirect traversal away from its parent tree."""

    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect SDK source path {path}: {exc}") from exc
    is_junction = getattr(path, "is_junction", None)
    return (
        path.is_symlink()
        or (is_junction is not None and is_junction())
        or bool(
            getattr(file_stat, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    )


def _resolve_source_path(path: Path) -> Path:
    return path.resolve(strict=True)


def _validated_source_path(path: Path, root: Path) -> Path:
    """Resolve a non-link SDK path and prove that it stays below *root*."""

    if _is_link_or_reparse_point(path):
        raise ValueError(
            f"SDK source tree contains a symlink, junction, or reparse point: {path}"
        )
    try:
        resolved = _resolve_source_path(path)
    except OSError as exc:
        raise ValueError(f"cannot resolve SDK source path {path}: {exc}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"SDK source path resolves outside the SDK root: {path} -> {resolved}"
        ) from exc
    return resolved


def _validated_source_root(root: str | Path) -> Path:
    requested_root = Path(root)
    if not requested_root.is_dir():
        raise ValueError(f"SDK root is not a directory: {requested_root.resolve()}")
    if _is_link_or_reparse_point(requested_root):
        raise ValueError(
            "SDK root cannot be a symlink, junction, or reparse point: "
            f"{requested_root}"
        )
    return _resolve_source_path(requested_root)


def _iter_source_files(root: Path) -> Iterator[Path]:
    directories = [root]
    source_files: list[Path] = []
    while directories:
        directory = directories.pop()
        try:
            children = sorted(
                directory.iterdir(),
                key=lambda item: item.name.casefold(),
                reverse=True,
            )
        except OSError as exc:
            raise ValueError(
                f"cannot enumerate SDK source path {directory}: {exc}"
            ) from exc
        for child in children:
            resolved = _validated_source_path(child, root)
            if resolved.is_dir():
                if child.name != ".git":
                    directories.append(resolved)
            elif resolved.is_file() and resolved.suffix.lower() in SOURCE_SUFFIXES:
                source_files.append(resolved)
    yield from sorted(
        source_files,
        key=lambda item: item.relative_to(root).as_posix().casefold(),
    )


def _read_source_bytes(path: Path, root: Path) -> bytes:
    """Revalidate a discovered source immediately before reading it."""

    return _validated_source_path(path, root).read_bytes()


def sdk_source_manifest(root: str | Path) -> tuple[SdkSourceFile, ...]:
    """Hash every scanned C/C++ file without exposing an absolute root path."""

    source_root = _validated_source_root(root)
    records = []
    for path in _iter_source_files(source_root):
        payload = _read_source_bytes(path, source_root)
        records.append(
            SdkSourceFile(
                relative_path=_relative_path(path, source_root),
                sha256=hashlib.sha256(payload).hexdigest(),
                byte_length=len(payload),
            )
        )
    # Computing the tree ID also rejects portable case collisions.
    _source_tree_sha256(records)
    return tuple(records)


def sdk_source_manifest_bytes(root: str | Path) -> bytes:
    """Canonical content addressed by an atlas input manifest entry."""

    records = sdk_source_manifest(root)
    document = {
        "format": "fnv-sdk-source-manifest-v1",
        "source_tree_sha256": _source_tree_sha256(records),
        "files": [item.to_dict() for item in records],
    }
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def extract_sdk_prototypes(root: str | Path) -> SdkPrototypeExtraction:
    """Extract candidate-only declarations, call targets, and data addresses."""

    source_root = _validated_source_root(root)

    observations: list[SdkPrototypeObservation] = []
    call_targets: list[SdkCallTargetObservation] = []
    data_addresses: list[SdkDataAddressObservation] = []
    diagnostics: list[SdkPrototypeDiagnostic] = []
    source_files = tuple(_iter_source_files(source_root))
    source_file_manifest: list[SdkSourceFile] = []
    for path in source_files:
        relative = _relative_path(path, source_root)
        source_bytes = _read_source_bytes(path, source_root)
        source_file_sha256 = hashlib.sha256(source_bytes).hexdigest()
        source_file_manifest.append(
            SdkSourceFile(
                relative_path=relative,
                sha256=source_file_sha256,
                byte_length=len(source_bytes),
            )
        )
        lines = source_bytes.decode("utf-8-sig").splitlines()
        masked_lines = _mask_cpp_lines(lines)
        owners = _lexical_class_owners(masked_lines)
        variants, variant_diagnostics = _preprocessor_variants(lines, relative)
        diagnostics.extend(variant_diagnostics)
        declaration_cache: dict[tuple[int, int], _DeclarationContext | None] = {}

        for index, line in enumerate(lines):
            comment = _ADDRESS_COMMENT_RE.match(line)
            if comment is not None:
                addresses = tuple(
                    int(match.group("digits"), 16)
                    for match in _HEX_ADDRESS_RE.finditer(comment.group("body"))
                )
                if not addresses:
                    diagnostics.append(
                        SdkPrototypeDiagnostic(
                            "address_comment_without_address",
                            relative,
                            index + 1,
                            "variant address comment contains no hexadecimal address",
                        )
                    )
                else:
                    declaration = _declaration_after(lines, index + 1)
                    if declaration is None:
                        diagnostics.append(
                            SdkPrototypeDiagnostic(
                                "address_comment_without_declaration",
                                relative,
                                index + 1,
                                "no nearby function declaration matched the conservative grammar",
                            )
                        )
                    else:
                        declaration_line, signature, name, declaration_text = declaration
                        for ordinal, address in enumerate(addresses):
                            observations.append(
                                SdkPrototypeObservation(
                                    comment.group("variant").lower(),
                                    address,
                                    name,
                                    signature,
                                    "variant_address_comment",
                                    relative,
                                    source_file_sha256,
                                    index + 1,
                                    declaration_line,
                                    line.strip(),
                                    ordinal,
                                    declaration_text,
                                )
                            )

            macro = _CREATE_OBJECT_RE.match(line)
            if macro is not None and not line.lstrip().startswith("#"):
                class_name = macro.group("class_name")
                qualified_name = f"{class_name}::CreateObject"
                observations.append(
                    SdkPrototypeObservation(
                        variants[index],
                        int(macro.group("address"), 16),
                        qualified_name,
                        f"static {class_name}* {qualified_name}()",
                        "create_object_macro",
                        relative,
                        source_file_sha256,
                        index + 1,
                        index + 1,
                        line.strip(),
                        declaration_text=line.strip(),
                    )
                )

            for ordinal, match in enumerate(_HELPER_CALL_RE.finditer(line)):
                opening = line.find("(", match.start())
                invocation = _parenthesized_text(line, opening)
                if invocation is None:
                    diagnostics.append(
                        SdkPrototypeDiagnostic(
                            "unterminated_helper_call",
                            relative,
                            index + 1,
                            "helper call is not contained on one source line",
                        )
                    )
                    continue
                arguments = _split_cpp_list(invocation[0])
                if not arguments or not _HEX_ADDRESS_RE.fullmatch(arguments[0]):
                    diagnostics.append(
                        SdkPrototypeDiagnostic(
                            "helper_call_address_not_first_argument",
                            relative,
                            index + 1,
                            "literal address was not the complete first helper argument",
                        )
                    )
                    continue
                cache_key = (index, match.start())
                context = declaration_cache.setdefault(
                    cache_key,
                    _enclosing_declaration(
                        lines, masked_lines, owners, index, match.start()
                    ),
                )
                if context is None:
                    diagnostics.append(
                        SdkPrototypeDiagnostic(
                            "call_target_without_enclosing_declaration",
                            relative,
                            index + 1,
                            "helper target retained without an enclosing declaration",
                        )
                    )
                helper_name = match.group("helper")
                return_type = match.group("return_type")
                call_targets.append(
                    SdkCallTargetObservation(
                        variants[index],
                        int(match.group("address"), 16),
                        "helper_call",
                        helper_name,
                        _HELPER_CALLING_CONVENTIONS[helper_name.lower()],
                        _normalise_cpp(return_type) if return_type else None,
                        None,
                        None,
                        arguments[1:],
                        context.declared_name if context else None,
                        context.owner_hint if context else None,
                        context.signature if context else None,
                        context.declaration_text if context else None,
                        relative,
                        source_file_sha256,
                        index + 1,
                        context.declaration_line if context else None,
                        line.strip(),
                        ordinal,
                    )
                )

            for ordinal, match in enumerate(_TYPED_CALL_RE.finditer(line)):
                opening = match.end() - 1
                invocation = _parenthesized_text(line, opening)
                if invocation is None:
                    diagnostics.append(
                        SdkPrototypeDiagnostic(
                            "unterminated_typed_call",
                            relative,
                            index + 1,
                            "typed function-pointer call is not contained on one line",
                        )
                    )
                    continue
                context = _enclosing_declaration(
                    lines, masked_lines, owners, index, match.start()
                )
                if context is None:
                    diagnostics.append(
                        SdkPrototypeDiagnostic(
                            "call_target_without_enclosing_declaration",
                            relative,
                            index + 1,
                            "typed target retained without an enclosing declaration",
                        )
                    )
                return_type = _normalise_cpp(match.group("return_type"))
                calling_convention = match.group("calling_convention").lower()
                parameter_types = _split_cpp_list(match.group("parameter_types"))
                rendered_target_type = (
                    f"{return_type} ({calling_convention}*)"
                    f"({', '.join(parameter_types)})"
                )
                call_targets.append(
                    SdkCallTargetObservation(
                        variants[index],
                        int(match.group("address"), 16),
                        "typed_function_pointer_call",
                        None,
                        calling_convention,
                        return_type,
                        parameter_types,
                        rendered_target_type,
                        _split_cpp_list(invocation[0]),
                        context.declared_name if context else None,
                        context.owner_hint if context else None,
                        context.signature if context else None,
                        context.declaration_text if context else None,
                        relative,
                        source_file_sha256,
                        index + 1,
                        context.declaration_line if context else None,
                        line.strip(),
                        ordinal,
                    )
                )

            address_ptr = _ADDRESS_PTR_RE.search(line)
            if address_ptr is not None:
                owner = owners[index]
                if owner is None:
                    diagnostics.append(
                        SdkPrototypeDiagnostic(
                            "data_address_without_class_owner",
                            relative,
                            index + 1,
                            "AddressPtr member has no resolvable lexical class owner",
                        )
                    )
                member_name = address_ptr.group("member_name")
                data_addresses.append(
                    SdkDataAddressObservation(
                        variants[index],
                        int(address_ptr.group("address"), 16),
                        "address_ptr",
                        f"{owner}::{member_name}" if owner else member_name,
                        member_name,
                        _normalise_cpp(address_ptr.group("declared_type")),
                        owner,
                        "lexical_class_scope" if owner else None,
                        line.strip(),
                        relative,
                        source_file_sha256,
                        index + 1,
                    )
                )

            nirtti = _NIRTTI_RE.match(line)
            if nirtti is not None:
                owner = owners[index]
                if owner is None:
                    diagnostics.append(
                        SdkPrototypeDiagnostic(
                            "data_address_without_class_owner",
                            relative,
                            index + 1,
                            "NIRTTI_ADDRESS has no resolvable lexical class owner",
                        )
                    )
                member_name = "ms_RTTI"
                data_addresses.append(
                    SdkDataAddressObservation(
                        variants[index],
                        int(nirtti.group("address"), 16),
                        "ni_rtti",
                        f"{owner}::{member_name}" if owner else member_name,
                        member_name,
                        "NiRTTI",
                        owner,
                        "lexical_class_scope" if owner else None,
                        line.strip(),
                        relative,
                        source_file_sha256,
                        index + 1,
                    )
                )

    observations.sort(
        key=lambda item: (
            item.source_path.casefold(),
            item.address_line,
            item.evidence_kind,
            item.program_variant,
            item.address,
            item.address_ordinal,
        )
    )
    call_targets.sort(
        key=lambda item: (
            item.source_path.casefold(),
            item.call_line,
            item.invocation_kind,
            item.program_variant,
            item.address,
            item.address_ordinal,
        )
    )
    data_addresses.sort(
        key=lambda item: (
            item.source_path.casefold(),
            item.declaration_line,
            item.data_kind,
            item.program_variant,
            item.address,
        )
    )
    concrete_declaration_variants: dict[tuple[str, int, str], set[str]] = {}
    for observation in observations:
        if observation.program_variant not in {"game", "geck"}:
            continue
        key = (
            observation.source_path,
            observation.address,
            observation.declared_name,
        )
        concrete_declaration_variants.setdefault(key, set()).add(
            observation.program_variant
        )
    for call_target in call_targets:
        if call_target.program_variant not in {"game", "geck"}:
            continue
        if call_target.enclosing_declared_name is None:
            continue
        key = (
            call_target.source_path,
            call_target.address,
            call_target.enclosing_declared_name,
        )
        labeled_variants = concrete_declaration_variants.get(key, set())
        if labeled_variants and call_target.program_variant not in labeled_variants:
            diagnostics.append(
                SdkPrototypeDiagnostic(
                    "variant_label_disagreement",
                    call_target.source_path,
                    call_target.call_line,
                    f"call branch is {call_target.program_variant}, but address "
                    f"0x{call_target.address:08X} is labeled as "
                    f"{', '.join(sorted(labeled_variants))} for the same declaration",
                )
            )
    diagnostics.sort(key=lambda item: (item.source_path.casefold(), item.line, item.code))
    return SdkPrototypeExtraction(
        root=str(source_root),
        files_scanned=len(source_files),
        observations=tuple(observations),
        diagnostics=tuple(diagnostics),
        call_targets=tuple(call_targets),
        data_addresses=tuple(data_addresses),
        source_files=tuple(source_file_manifest),
    )


def classify_sdk_prototypes(
    observations: Iterable[SdkPrototypeObservation],
    *,
    pc_function_entries: set[int] | frozenset[int],
    executable_ranges: tuple[tuple[int, int], ...] = (),
) -> tuple[SdkPrototypeClassification, ...]:
    """Classify declarations without converting them into canonical functions."""

    entries = frozenset(int(address) for address in pc_function_entries)
    ranges = tuple(sorted((int(start), int(end)) for start, end in executable_ranges))
    if any(start < 0 or end <= start for start, end in ranges):
        raise ValueError("executable ranges must be non-negative, increasing pairs")

    results: list[SdkPrototypeClassification] = []
    for observation in observations:
        if observation.address in entries:
            classification = "pc_function_entry"
        elif not ranges:
            classification = "unresolved_non_entry"
        elif any(start <= observation.address < end for start, end in ranges):
            classification = "executable_non_entry"
        else:
            classification = "outside_executable_ranges"
        results.append(SdkPrototypeClassification(observation, classification))
    return tuple(results)


def select_sdk_boundary_candidates(
    classifications: Iterable[SdkPrototypeClassification],
    *,
    function_extents: Iterable[tuple[int, int]] = (),
) -> tuple[SdkBoundaryCandidate, ...]:
    """Select review-only ``CREATE_OBJECT`` executable non-entry candidates."""

    extents = tuple(sorted((int(start), int(end)) for start, end in function_extents))
    if any(start < 0 or end <= start for start, end in extents):
        raise ValueError("function extents must be non-negative, increasing pairs")
    candidates: list[SdkBoundaryCandidate] = []
    for classified in classifications:
        observation = classified.observation
        if observation.evidence_kind != "create_object_macro":
            continue
        if classified.classification != "executable_non_entry":
            continue
        containing = tuple(
            start for start, end in extents if start <= observation.address < end
        )
        candidates.append(
            SdkBoundaryCandidate(
                source_observation=observation,
                inventory_classification=classified.classification,
                candidate_reason="sdk_create_object_target_is_executable_non_entry",
                containing_function_entries=containing,
            )
        )
    candidates.sort(
        key=lambda item: (
            item.source_observation.address,
            item.source_observation.source_path.casefold(),
            item.source_observation.address_line,
        )
    )
    return tuple(candidates)


__all__ = [
    "SOURCE_SUFFIXES",
    "SdkBoundaryCandidate",
    "SdkCallTargetObservation",
    "SdkDataAddressObservation",
    "SdkPrototypeClassification",
    "SdkPrototypeDiagnostic",
    "SdkPrototypeExtraction",
    "SdkPrototypeObservation",
    "classify_sdk_prototypes",
    "extract_sdk_prototypes",
    "select_sdk_boundary_candidates",
]
