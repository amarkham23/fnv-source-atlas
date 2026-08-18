from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.tpi_layouts import (  # noqa: E402
    CV_PROP_FORWARD_REFERENCE,
    CV_PROP_HAS_UNIQUE_NAME,
    LF_BCLASS,
    LF_CLASS,
    LF_FIELDLIST,
    LF_MEMBER,
    LF_METHOD,
    LF_METHODLIST,
    LF_ONEMETHOD,
    extract_type_records_from_resolver,
    extract_type_layouts_from_resolver,
)
from fnv_atlas.tpi_signatures import LF_ARGLIST, LF_MFUNCTION, TpiTypeResolver  # noqa: E402


def _padding(length: int) -> bytes:
    count = (-length) % 4
    return bytes(0xF0 + value for value in range(count, 0, -1))


def _type_record(leaf: int, body: bytes) -> bytes:
    payload = struct.pack("<H", leaf) + body
    payload += _padding(2 + len(payload))
    return struct.pack("<H", len(payload)) + payload


def _member_record(leaf: int, body: bytes) -> bytes:
    payload = struct.pack("<H", leaf) + body
    return payload + _padding(len(payload))


def _tpi_stream(*records: bytes, begin: int = 0x1000) -> bytes:
    record_data = b"".join(records)
    header = struct.pack(
        "<IIIIIHHIIIIIIII",
        20040203,
        56,
        begin,
        begin + len(records),
        len(record_data),
        0xFFFF,
        0xFFFF,
        4,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    return header + record_data


def _class_record(
    name: str,
    unique_name: str,
    *,
    field_list: int,
    size: int,
    properties: int = CV_PROP_HAS_UNIQUE_NAME,
    member_count: int = 0,
) -> bytes:
    return _type_record(
        LF_CLASS,
        struct.pack(
            "<HHIIIH",
            member_count,
            properties,
            field_list,
            0,
            0,
            size,
        )
        + name.encode("latin-1")
        + b"\0"
        + unique_name.encode("latin-1")
        + b"\0",
    )


class TpiLayoutTests(unittest.TestCase):
    def test_preserves_duplicate_tags_fields_bases_and_exact_method_types(self) -> None:
        # 1000: arglist, 1001: member-function type, 1002: method list,
        # 1003: field list, 1004/1005: duplicate display-name definitions,
        # 1006: forward declaration of the first unique identity.
        arglist = _type_record(LF_ARGLIST, struct.pack("<I", 0))
        method_type = _type_record(
            LF_MFUNCTION,
            struct.pack(
                "<IIIBBHIi",
                0x0003,
                0x1004,
                0x0403,
                0x0B,
                0,
                0,
                0x1000,
                0,
            ),
        )
        public_vanilla = 3
        public_intro = 3 | (4 << 2)
        method_list = _type_record(
            LF_METHODLIST,
            struct.pack("<HHI", public_vanilla, 0, 0x1001)
            + struct.pack("<HHIi", public_intro, 0, 0x1001, 8),
        )
        field_list = _type_record(
            LF_FIELDLIST,
            _member_record(
                LF_BCLASS,
                struct.pack("<HIH", 3, 0x1005, 0),
            )
            + _member_record(
                LF_MEMBER,
                struct.pack("<HIH", 3, 0x0074, 4) + b"value\0",
            )
            + _member_record(
                LF_METHOD,
                struct.pack("<HI", 2, 0x1002) + b"Tick\0",
            )
            + _member_record(
                LF_ONEMETHOD,
                struct.pack("<HIi", public_intro, 0x1001, 12) + b"Run\0",
            ),
        )
        stream = _tpi_stream(
            arglist,
            method_type,
            method_list,
            field_list,
            _class_record(
                "Duplicate",
                ".?AVDuplicate@One@@",
                field_list=0x1003,
                size=16,
                member_count=5,
            ),
            _class_record(
                "Duplicate",
                ".?AVDuplicate@Two@@",
                field_list=0,
                size=4,
            ),
            _class_record(
                "Duplicate",
                ".?AVDuplicate@One@@",
                field_list=0,
                size=0,
                properties=CV_PROP_HAS_UNIQUE_NAME | CV_PROP_FORWARD_REFERENCE,
            ),
        )
        extraction = extract_type_layouts_from_resolver(TpiTypeResolver(stream))

        self.assertEqual(extraction.record_count, 3)
        self.assertEqual(extraction.definition_count, 2)
        self.assertEqual(extraction.forward_reference_count, 1)
        self.assertEqual(extraction.duplicate_display_name_count, 1)
        definitions = extraction.definitions_by_identity_name()
        self.assertEqual(set(definitions), {".?AVDuplicate@One@@", ".?AVDuplicate@Two@@"})

        first = definitions[".?AVDuplicate@One@@"][0]
        self.assertEqual(first.type_index, 0x1004)
        self.assertEqual(first.size, 16)
        self.assertEqual(len(first.members), 4)
        self.assertEqual(first.decoded_member_count, 5)
        base, field, group, direct = first.members
        self.assertEqual((base.member_kind, base.base_type_index, base.offset), ("base_class", 0x1005, 0))
        self.assertEqual((field.member_kind, field.name, field.type_index, field.offset), ("data_member", "value", 0x74, 4))
        self.assertEqual(group.name, "Tick")
        self.assertEqual(group.method_list_type_index, 0x1002)
        self.assertEqual([item.type_index for item in group.overloads], [0x1001, 0x1001])
        self.assertEqual([item.vtable_offset for item in group.overloads], [None, 8])
        self.assertEqual((direct.name, direct.type_index, direct.vtable_offset), ("Run", 0x1001, 12))
        self.assertEqual(first.diagnostics, ())

    def test_unknown_field_member_is_explicit_and_retains_remaining_bytes(self) -> None:
        unknown = _type_record(LF_FIELDLIST, struct.pack("<H", 0x1337) + b"opaque")
        stream = _tpi_stream(
            unknown,
            _class_record(
                "Broken",
                ".?AVBroken@@",
                field_list=0x1000,
                size=4,
            ),
        )
        result = extract_type_layouts_from_resolver(TpiTypeResolver(stream)).records[0]
        self.assertEqual(result.members, ())
        self.assertEqual(len(result.diagnostics), 1)
        self.assertEqual(result.diagnostics[0].code, "unknown_field_member")
        self.assertTrue(result.diagnostics[0].remaining_hex.startswith("3713"))

    def test_serialization_is_stable_and_includes_raw_identity_fields(self) -> None:
        stream = _tpi_stream(
            _class_record(
                "Thing",
                ".?AVThing@@",
                field_list=0,
                size=8,
            )
        )
        extraction = extract_type_layouts_from_resolver(TpiTypeResolver(stream))
        left = extraction.to_dict()
        right = extract_type_layouts_from_resolver(TpiTypeResolver(stream)).to_dict()
        self.assertEqual(left, right)
        record = left["records"][0]
        self.assertEqual(record["type_index"], 0x1000)
        self.assertEqual(record["unique_name"], ".?AVThing@@")
        self.assertEqual(len(record["record_sha256"]), 64)

        raw = extract_type_records_from_resolver(TpiTypeResolver(stream))
        self.assertEqual(raw.record_count, 1)
        self.assertEqual(raw.body_bytes, len(raw.records[0].body))
        raw_dict = raw.to_dict()["records"][0]
        self.assertEqual(bytes.fromhex(raw_dict["body_hex"]), raw.records[0].body)
        self.assertEqual(len(raw_dict["body_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
