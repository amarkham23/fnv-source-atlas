"""Lossless CodeView function signatures from a PDB TPI stream.

Procedure symbols carry a nonzero CodeView type index.  This module resolves
that index without using a function's display name as identity and without
discarding raw indices when readable rendering is incomplete.  Both ordinary
``LF_PROCEDURE`` and member ``LF_MFUNCTION`` records are supported, including
their ordered ``LF_ARGLIST`` records and a terminal ``T_NOTYPE`` vararg marker.

The high-level :func:`resolve_function_signatures` API accepts an explicit PDB
path and preserves input order and multiplicity.  A PDB may contain procedure
symbols whose indices do not name a function record in its global TPI stream
(notably third-party/type-server objects); those are returned as explicit
unresolved results rather than coerced or silently omitted.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
import struct
from typing import Any

from .pdb_symbols import PdbFormatError, _MsfReader


LF_MODIFIER = 0x1001
LF_POINTER = 0x1002
LF_PROCEDURE = 0x1008
LF_MFUNCTION = 0x1009
LF_ARGLIST = 0x1201
LF_ARRAY = 0x1503
LF_CLASS = 0x1504
LF_STRUCTURE = 0x1505
LF_UNION = 0x1506
LF_ENUM = 0x1507
LF_ALIAS = 0x150A

T_NOTYPE = 0x0000
TPI_STREAM_INDEX = 2


LEAF_NAMES = {
    LF_MODIFIER: "LF_MODIFIER",
    LF_POINTER: "LF_POINTER",
    LF_PROCEDURE: "LF_PROCEDURE",
    LF_MFUNCTION: "LF_MFUNCTION",
    LF_ARGLIST: "LF_ARGLIST",
    LF_ARRAY: "LF_ARRAY",
    LF_CLASS: "LF_CLASS",
    LF_STRUCTURE: "LF_STRUCTURE",
    LF_UNION: "LF_UNION",
    LF_ENUM: "LF_ENUM",
    LF_ALIAS: "LF_ALIAS",
}


CALLING_CONVENTIONS = {
    0x00: "near_c",
    0x01: "far_c",
    0x02: "near_pascal",
    0x03: "far_pascal",
    0x04: "near_fastcall",
    0x05: "far_fastcall",
    0x07: "near_stdcall",
    0x08: "far_stdcall",
    0x09: "near_syscall",
    0x0A: "far_syscall",
    0x0B: "thiscall",
    0x0C: "mips_call",
    0x0D: "generic",
    0x0E: "alpha_call",
    0x0F: "ppc_call",
    0x10: "sh_call",
    0x11: "arm_call",
    0x12: "am33_call",
    0x13: "tri_call",
    0x14: "sh5_call",
    0x15: "m32r_call",
    0x16: "clr_call",
    0x17: "inline",
    0x18: "near_vector",
}


_CALLING_CONVENTION_RENDER = {
    0x00: "__cdecl",
    0x04: "__fastcall",
    0x07: "__stdcall",
    0x0B: "__thiscall",
    0x0F: "__ppccall",
    0x18: "__vectorcall",
}


_PRIMITIVE_NAMES = {
    0x00: "<no type>",
    0x03: "void",
    0x08: "HRESULT",
    0x10: "signed char",
    0x11: "short",
    0x12: "long",
    0x13: "__int64",
    0x20: "unsigned char",
    0x21: "unsigned short",
    0x22: "unsigned long",
    0x23: "unsigned __int64",
    0x30: "bool",
    0x40: "float",
    0x41: "double",
    0x42: "long double",
    0x68: "__int8",
    0x69: "unsigned __int8",
    0x70: "char",
    0x71: "wchar_t",
    0x74: "int",
    0x75: "unsigned int",
    0x76: "__int64",
    0x77: "unsigned __int64",
}


class TpiFormatError(PdbFormatError):
    """The TPI stream or one of its records is structurally malformed."""


class TypeResolutionError(ValueError):
    """A requested type index cannot be resolved as a function signature."""

    def __init__(self, type_index: int, code: str, message: str):
        super().__init__(message)
        self.type_index = type_index
        self.code = code


@dataclass(frozen=True, slots=True)
class TpiHeader:
    version: int
    header_size: int
    type_index_begin: int
    type_index_end: int
    type_record_bytes: int

    @property
    def type_record_count(self) -> int:
        return self.type_index_end - self.type_index_begin


@dataclass(frozen=True, slots=True)
class TpiRecord:
    type_index: int
    leaf_kind: int
    record_length: int
    body: bytes

    @property
    def leaf_name(self) -> str:
        return LEAF_NAMES.get(self.leaf_kind, f"LF_0x{self.leaf_kind:04X}")


@dataclass(frozen=True, slots=True)
class FunctionSignature:
    """Exact function-type fields plus best-effort readable decoration."""

    type_index: int
    leaf_kind: int
    leaf_name: str
    return_type_index: int
    class_type_index: int | None
    this_type_index: int | None
    calling_convention: int
    calling_convention_name: str
    attributes: int
    this_adjustment: int | None
    parameter_count: int
    argument_list_type_index: int
    argument_list_count: int
    argument_type_indices: tuple[int, ...]
    is_variadic: bool
    rendered_return_type: str
    rendered_class_type: str | None
    rendered_this_type: str | None
    rendered_argument_types: tuple[str, ...]
    rendered_signature: str

    @property
    def is_member_function(self) -> bool:
        return self.leaf_kind == LF_MFUNCTION

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["argument_type_indices"] = list(self.argument_type_indices)
        result["rendered_argument_types"] = list(self.rendered_argument_types)
        return result


@dataclass(frozen=True, slots=True)
class SignatureResult:
    """One requested occurrence, including an explicit unresolved reason."""

    type_index: int
    signature: FunctionSignature | None
    error_code: str | None = None
    error_message: str | None = None
    actual_leaf_kind: int | None = None
    actual_leaf_name: str | None = None

    @property
    def resolved(self) -> bool:
        return self.signature is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type_index": self.type_index,
            "resolved": self.resolved,
            "signature": self.signature.to_dict() if self.signature else None,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "actual_leaf_kind": self.actual_leaf_kind,
            "actual_leaf_name": self.actual_leaf_name,
        }


@dataclass(frozen=True, slots=True)
class SignatureResolution:
    """Ordered, multiplicity-preserving results for an iterable of indices."""

    results: tuple[SignatureResult, ...]

    @property
    def requested_count(self) -> int:
        return len(self.results)

    @property
    def resolved_count(self) -> int:
        return sum(result.resolved for result in self.results)

    @property
    def unresolved_count(self) -> int:
        return self.requested_count - self.resolved_count

    @property
    def unique_requested_count(self) -> int:
        return len({result.type_index for result in self.results})

    @property
    def unique_resolved_count(self) -> int:
        return len(
            {result.type_index for result in self.results if result.signature is not None}
        )

    @property
    def error_counts(self) -> dict[str, int]:
        return dict(
            Counter(
                result.error_code
                for result in self.results
                if result.error_code is not None
            )
        )

    def signatures_by_index(self) -> dict[int, FunctionSignature]:
        """Return unique resolved types; input occurrences remain in ``results``."""

        return {
            result.type_index: result.signature
            for result in self.results
            if result.signature is not None
        }


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _cstring(data: bytes, offset: int) -> str | None:
    end = data.find(b"\0", offset)
    if end < 0:
        return None
    return data[offset:end].decode("latin-1")


def _numeric_end(data: bytes, offset: int) -> int | None:
    """Return the end of a CodeView numeric leaf, without interpreting it."""

    if offset + 2 > len(data):
        return None
    leaf = _u16(data, offset)
    if leaf < 0x8000:
        return offset + 2
    sizes = {
        0x8000: 1,  # LF_CHAR
        0x8001: 2,  # LF_SHORT
        0x8002: 2,  # LF_USHORT
        0x8003: 4,  # LF_LONG
        0x8004: 4,  # LF_ULONG
        0x8005: 4,  # LF_REAL32
        0x8006: 8,  # LF_REAL64
        0x8009: 8,  # LF_QUADWORD
        0x800A: 8,  # LF_UQUADWORD
        0x8017: 16,  # LF_OCTWORD
        0x8018: 16,  # LF_UOCTWORD
    }
    payload_size = sizes.get(leaf)
    if payload_size is None or offset + 2 + payload_size > len(data):
        return None
    return offset + 2 + payload_size


class TpiTypeResolver:
    """Indexed, read-only view of one CodeView TPI stream."""

    def __init__(self, stream: bytes):
        if len(stream) < 20:
            raise TpiFormatError("TPI stream is shorter than its fixed header fields")
        version, header_size, begin, end, record_bytes = struct.unpack_from(
            "<5I", stream, 0
        )
        if header_size < 20 or header_size > len(stream):
            raise TpiFormatError(f"invalid TPI header size {header_size}")
        if end < begin:
            raise TpiFormatError(
                f"TPI type-index range is reversed: 0x{begin:X}..0x{end:X}"
            )
        records_end = header_size + record_bytes
        if records_end > len(stream):
            raise TpiFormatError(
                f"TPI declares {record_bytes} record bytes past stream end"
            )
        self.header = TpiHeader(version, header_size, begin, end, record_bytes)
        self._records: dict[int, TpiRecord] = {}
        cursor = header_size
        for type_index in range(begin, end):
            if cursor + 4 > records_end:
                raise TpiFormatError(
                    f"missing TPI record for type index 0x{type_index:X}"
                )
            record_length = _u16(stream, cursor)
            if record_length < 2:
                raise TpiFormatError(
                    f"TPI record 0x{type_index:X} has length {record_length}"
                )
            record_end = cursor + 2 + record_length
            if record_end > records_end:
                raise TpiFormatError(
                    f"TPI record 0x{type_index:X} extends past record region"
                )
            leaf_kind = _u16(stream, cursor + 2)
            self._records[type_index] = TpiRecord(
                type_index=type_index,
                leaf_kind=leaf_kind,
                record_length=record_length,
                body=stream[cursor + 4 : record_end],
            )
            cursor = record_end
        if cursor != records_end:
            raise TpiFormatError(
                f"TPI type range consumed {cursor - header_size} bytes, "
                f"but header declares {record_bytes}"
            )
        self._render_cache: dict[int, str] = {}
        self._signature_cache: dict[int, FunctionSignature] = {}

    @classmethod
    def from_pdb(cls, pdb_path: str | Path) -> "TpiTypeResolver":
        """Read stream 2 from an explicitly named MSF 7.0 PDB."""

        return cls(_MsfReader(pdb_path).read_stream(TPI_STREAM_INDEX))

    @property
    def record_count(self) -> int:
        return len(self._records)

    def record(self, type_index: int) -> TpiRecord | None:
        return self._records.get(type_index)

    def iter_records(self) -> Iterator[TpiRecord]:
        return iter(self._records.values())

    def _argument_types(self, function_type_index: int, arglist_index: int) -> tuple[int, ...]:
        record = self._records.get(arglist_index)
        if record is None:
            raise TypeResolutionError(
                function_type_index,
                "missing_argument_list",
                f"function type 0x{function_type_index:X} references missing "
                f"argument list 0x{arglist_index:X}",
            )
        if record.leaf_kind != LF_ARGLIST:
            raise TypeResolutionError(
                function_type_index,
                "wrong_argument_list_leaf",
                f"function type 0x{function_type_index:X} references "
                f"{record.leaf_name} at 0x{arglist_index:X}, not LF_ARGLIST",
            )
        if len(record.body) < 4:
            raise TypeResolutionError(
                function_type_index,
                "malformed_argument_list",
                f"LF_ARGLIST 0x{arglist_index:X} has no count",
            )
        count = _u32(record.body, 0)
        required = 4 + count * 4
        if required > len(record.body):
            raise TypeResolutionError(
                function_type_index,
                "malformed_argument_list",
                f"LF_ARGLIST 0x{arglist_index:X} declares {count} arguments "
                f"but has only {len(record.body) - 4} payload bytes",
            )
        return (
            struct.unpack_from(f"<{count}I", record.body, 4)
            if count
            else ()
        )

    def resolve(self, type_index: int) -> FunctionSignature:
        """Resolve one exact LF_PROCEDURE/LF_MFUNCTION type index."""

        if type_index in self._signature_cache:
            return self._signature_cache[type_index]
        if type_index < self.header.type_index_begin:
            raise TypeResolutionError(
                type_index,
                "primitive_or_zero_type",
                f"type index 0x{type_index:X} is not a TPI function record",
            )
        record = self._records.get(type_index)
        if record is None:
            raise TypeResolutionError(
                type_index,
                "missing_type",
                f"type index 0x{type_index:X} is outside the TPI record map",
            )
        body = record.body
        if record.leaf_kind == LF_PROCEDURE:
            if len(body) < 12:
                raise TypeResolutionError(
                    type_index,
                    "malformed_function",
                    f"LF_PROCEDURE 0x{type_index:X} is shorter than 12 bytes",
                )
            (
                return_type,
                calling_convention,
                attributes,
                parameter_count,
                arglist_index,
            ) = struct.unpack_from("<IBBHI", body, 0)
            class_type = None
            this_type = None
            this_adjustment = None
        elif record.leaf_kind == LF_MFUNCTION:
            if len(body) < 24:
                raise TypeResolutionError(
                    type_index,
                    "malformed_function",
                    f"LF_MFUNCTION 0x{type_index:X} is shorter than 24 bytes",
                )
            (
                return_type,
                class_type,
                this_type,
                calling_convention,
                attributes,
                parameter_count,
                arglist_index,
                this_adjustment,
            ) = struct.unpack_from("<IIIBBHIi", body, 0)
        else:
            raise TypeResolutionError(
                type_index,
                "not_function_type",
                f"type index 0x{type_index:X} is {record.leaf_name}, not a "
                "function-type record",
            )

        argument_types = self._argument_types(type_index, arglist_index)
        rendered_return = self.render_type(return_type)
        rendered_class = self.render_type(class_type) if class_type is not None else None
        rendered_this = self.render_type(this_type) if this_type is not None else None
        rendered_arguments = tuple(
            "..." if argument == T_NOTYPE else self.render_type(argument)
            for argument in argument_types
        )
        call_name = CALLING_CONVENTIONS.get(
            calling_convention, f"call_0x{calling_convention:02X}"
        )
        call_render = _CALLING_CONVENTION_RENDER.get(
            calling_convention, call_name
        )
        owner = f" {rendered_class}::*" if rendered_class is not None else " "
        rendered_signature = (
            f"{rendered_return} {call_render}{owner}"
            f"({', '.join(rendered_arguments)})"
        )
        signature = FunctionSignature(
            type_index=type_index,
            leaf_kind=record.leaf_kind,
            leaf_name=record.leaf_name,
            return_type_index=return_type,
            class_type_index=class_type,
            this_type_index=this_type,
            calling_convention=calling_convention,
            calling_convention_name=call_name,
            attributes=attributes,
            this_adjustment=this_adjustment,
            parameter_count=parameter_count,
            argument_list_type_index=arglist_index,
            argument_list_count=len(argument_types),
            argument_type_indices=argument_types,
            is_variadic=bool(argument_types and argument_types[-1] == T_NOTYPE),
            rendered_return_type=rendered_return,
            rendered_class_type=rendered_class,
            rendered_this_type=rendered_this,
            rendered_argument_types=rendered_arguments,
            rendered_signature=rendered_signature,
        )
        self._signature_cache[type_index] = signature
        return signature

    def resolve_many(
        self, type_indices: Iterable[int], *, strict: bool = False
    ) -> SignatureResolution:
        """Resolve indices in order, preserving duplicate requested occurrences."""

        cached_results: dict[int, SignatureResult] = {}
        results: list[SignatureResult] = []
        for raw_index in type_indices:
            type_index = int(raw_index)
            result = cached_results.get(type_index)
            if result is None:
                try:
                    signature = self.resolve(type_index)
                    result = SignatureResult(type_index, signature)
                except TypeResolutionError as exc:
                    if strict:
                        raise
                    record = self._records.get(type_index)
                    result = SignatureResult(
                        type_index=type_index,
                        signature=None,
                        error_code=exc.code,
                        error_message=str(exc),
                        actual_leaf_kind=record.leaf_kind if record else None,
                        actual_leaf_name=record.leaf_name if record else None,
                    )
                cached_results[type_index] = result
            results.append(result)
        return SignatureResolution(tuple(results))

    def render_type(self, type_index: int, *, _depth: int = 0) -> str:
        """Best-effort type spelling; never used as an identity or join key."""

        if type_index in self._render_cache:
            return self._render_cache[type_index]
        if _depth > 12:
            return f"type_0x{type_index:X}<recursive>"
        if type_index < self.header.type_index_begin:
            base = _PRIMITIVE_NAMES.get(
                type_index & 0xFF, f"primitive_0x{type_index & 0xFF:02X}"
            )
            mode = (type_index >> 8) & 0x0F
            suffix = {
                0: "",
                1: "*",  # near pointer
                2: "*",  # far pointer
                3: "*",  # huge pointer
                4: "*",  # 32-bit pointer
                5: "*",  # 32-bit far pointer
                6: "*",  # 64-bit pointer
                7: "*",  # 128-bit pointer
            }.get(mode, f"<mode-{mode}>")
            return base + suffix
        record = self._records.get(type_index)
        if record is None:
            return f"type_0x{type_index:X}<missing>"
        body = record.body
        rendered = f"type_0x{type_index:X}<{record.leaf_name}>"
        try:
            if record.leaf_kind == LF_POINTER and len(body) >= 8:
                referent = _u32(body, 0)
                attributes = _u32(body, 4)
                pointer_mode = (attributes >> 5) & 0x07
                suffix = {0: "*", 1: "&", 4: "&&"}.get(pointer_mode, "*")
                rendered = self.render_type(referent, _depth=_depth + 1) + suffix
            elif record.leaf_kind == LF_MODIFIER and len(body) >= 6:
                modified = _u32(body, 0)
                modifiers = _u16(body, 4)
                prefix = " ".join(
                    word
                    for bit, word in ((1, "const"), (2, "volatile"), (4, "unaligned"))
                    if modifiers & bit
                )
                target = self.render_type(modified, _depth=_depth + 1)
                rendered = f"{prefix} {target}".strip()
            elif record.leaf_kind in (LF_CLASS, LF_STRUCTURE) and len(body) >= 18:
                name_offset = _numeric_end(body, 16)
                name = _cstring(body, name_offset) if name_offset is not None else None
                if name:
                    rendered = name
            elif record.leaf_kind == LF_UNION and len(body) >= 10:
                name_offset = _numeric_end(body, 8)
                name = _cstring(body, name_offset) if name_offset is not None else None
                if name:
                    rendered = name
            elif record.leaf_kind == LF_ENUM and len(body) >= 12:
                name = _cstring(body, 12)
                if name:
                    rendered = name
            elif record.leaf_kind == LF_ALIAS and len(body) >= 5:
                name = _cstring(body, 4)
                if name:
                    rendered = name
            elif record.leaf_kind in (LF_PROCEDURE, LF_MFUNCTION):
                rendered = self.resolve(type_index).rendered_signature
        except (IndexError, struct.error, TypeResolutionError):
            # Readability is explicitly best-effort; the exact indices and
            # structured signature fields above remain intact.
            pass
        self._render_cache[type_index] = rendered
        return rendered


def resolve_function_signatures(
    pdb_path: str | Path,
    type_indices: Iterable[int],
    *,
    strict: bool = False,
) -> SignatureResolution:
    """Resolve an iterable of procedure type indices from an explicit PDB."""

    return TpiTypeResolver.from_pdb(pdb_path).resolve_many(
        type_indices, strict=strict
    )


__all__ = [
    "CALLING_CONVENTIONS",
    "FunctionSignature",
    "LEAF_NAMES",
    "LF_ARGLIST",
    "LF_MFUNCTION",
    "LF_PROCEDURE",
    "SignatureResolution",
    "SignatureResult",
    "TPI_STREAM_INDEX",
    "T_NOTYPE",
    "TpiFormatError",
    "TpiHeader",
    "TpiRecord",
    "TpiTypeResolver",
    "TypeResolutionError",
    "resolve_function_signatures",
]

