from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from fnv_atlas.pdb_globals import (
    S_GDATA32,
    S_LDATA32,
    build_data_address_groups,
    extract_data_module_streams,
    parse_module_data_symbols,
    write_data_jsonl,
)
from fnv_atlas.pdb_symbols import PdbFormatError


CV_SIGNATURE = b"\x04\x00\x00\x00"
S_UDT = 0x1108


def _data_record(
    *,
    kind: int,
    name: bytes,
    section: int = 1,
    section_offset: int = 0x1234,
    type_index: int = 0x1001,
    terminate_name: bool = True,
) -> bytes:
    body = struct.pack("<IIH", type_index, section_offset, section) + name
    if terminate_name:
        body += b"\0"
    payload = struct.pack("<H", kind) + body
    record = struct.pack("<H", len(payload)) + payload
    return record + b"\0" * ((-len(record)) % 4)


def _unknown_record(payload: bytes = b"ignored\0") -> bytes:
    body = struct.pack("<H", S_UDT) + payload
    record = struct.pack("<H", len(body)) + body
    return record + b"\0" * ((-len(record)) % 4)


class PdbGlobalTests(unittest.TestCase):
    def test_parse_preserves_shared_address_records_and_all_fields(self):
        first = _data_record(
            kind=S_GDATA32,
            name=b"?globalA@@3HA",
            type_index=0x44556677,
        )
        second = _data_record(
            kind=S_LDATA32,
            name=b"localAlias",
            type_index=0x8899AABB,
        )
        third = _data_record(
            kind=S_GDATA32,
            name=b"separate",
            section=2,
            section_offset=0x40,
        )
        blob = CV_SIGNATURE + first + _unknown_record() + second + third

        records = parse_module_data_symbols(
            blob,
            module_index=7,
            module_name=r"obj\xbox\example.obj",
            symbol_stream=42,
            section_bases=(0x82000000, 0x83000000),
            symbol_bytes=len(blob),
        )

        self.assertEqual(len(records), 3)
        self.assertEqual(
            [record.raw_name for record in records],
            ["?globalA@@3HA", "localAlias", "separate"],
        )
        self.assertEqual(
            records[0].record_id, "x360-data:m0007:s0042:o00000004"
        )
        self.assertEqual(records[0].record_kind, "S_GDATA32")
        self.assertEqual(records[1].record_kind, "S_LDATA32")
        self.assertEqual(records[0].record_kind_code, S_GDATA32)
        self.assertEqual(records[0].va, 0x82001234)
        self.assertEqual(records[1].va, 0x82001234)
        self.assertEqual(records[2].va, 0x83000040)
        self.assertEqual(records[0].section, 1)
        self.assertEqual(records[0].section_offset, 0x1234)
        self.assertEqual(records[0].type_index, 0x44556677)
        self.assertEqual(records[1].type_index, 0x8899AABB)
        self.assertEqual(records[0].module_index, 7)
        self.assertEqual(records[0].module_name, r"obj\xbox\example.obj")
        self.assertEqual(records[0].symbol_stream, 42)

        groups = build_data_address_groups(records)
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0].group_id, "x360-data-address:82001234")
        self.assertEqual(groups[0].count, 2)
        self.assertEqual(
            groups[0].record_ids,
            (records[0].record_id, records[1].record_id),
        )
        self.assertEqual(
            groups[0].raw_names, ("?globalA@@3HA", "localAlias")
        )

    def test_symbol_byte_limit_excludes_c13_lookalike(self):
        actual = _data_record(kind=S_GDATA32, name=b"actual")
        fake_c13 = _data_record(kind=S_GDATA32, name=b"not-a-symbol")
        blob = CV_SIGNATURE + actual + fake_c13

        records = parse_module_data_symbols(
            blob,
            module_index=1,
            module_name="module.obj",
            symbol_stream=8,
            section_bases=(0x82000000,),
            symbol_bytes=len(CV_SIGNATURE + actual),
        )

        self.assertEqual([record.raw_name for record in records], ["actual"])

    def test_extract_is_order_independent_and_groups_across_modules(self):
        stream_10 = CV_SIGNATURE + _data_record(
            kind=S_GDATA32, name=b"global-name", section_offset=0x20
        )
        stream_11 = CV_SIGNATURE + _data_record(
            kind=S_LDATA32, name=b"local-alias", section_offset=0x20
        )
        streams = {10: stream_10, 11: stream_11}
        modules = [
            {
                "index": 9,
                "name": "later.obj",
                "sym_stream": 11,
                "sym_bytes": len(stream_11),
            },
            {
                "index": 2,
                "name": "earlier.obj",
                "sym_stream": 10,
                "sym_bytes": len(stream_10),
            },
            {"index": 3, "name": "no-symbols.obj", "sym_stream": None},
        ]

        result = extract_data_module_streams(
            modules=modules,
            section_bases=(0x82000000,),
            read_stream=streams.__getitem__,
            stream_count=12,
        )

        self.assertEqual(
            [record.module_index for record in result.records], [2, 9]
        )
        self.assertEqual(result.record_count, 2)
        self.assertEqual(result.unique_va_count, 1)
        self.assertEqual(result.unresolved_va_count, 0)
        self.assertEqual(len(result.address_groups), 1)
        self.assertEqual(
            result.address_groups[0].raw_names,
            ("global-name", "local-alias"),
        )

    def test_invalid_section_is_retained_without_an_address_group(self):
        blob = CV_SIGNATURE + _data_record(
            kind=S_GDATA32, name=b"bad-section", section=7
        )
        records = parse_module_data_symbols(
            blob,
            module_index=0,
            module_name="bad.obj",
            symbol_stream=5,
            section_bases=(0x82000000,),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].section, 7)
        self.assertIsNone(records[0].va)
        self.assertEqual(build_data_address_groups(records), ())

    def test_empty_names_are_records_but_malformed_records_raise(self):
        empty = CV_SIGNATURE + _data_record(kind=S_GDATA32, name=b"")
        records = parse_module_data_symbols(
            empty,
            module_index=0,
            module_name="empty.obj",
            symbol_stream=5,
            section_bases=(0x82000000,),
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].raw_name, "")

        malformed = _data_record(
            kind=S_GDATA32,
            name=b"unterminated",
            terminate_name=False,
        ).rstrip(b"\0")
        with self.assertRaisesRegex(
            PdbFormatError, "unterminated data-symbol name"
        ):
            parse_module_data_symbols(
                CV_SIGNATURE + malformed,
                module_index=0,
                module_name="bad.obj",
                symbol_stream=5,
                section_bases=(0x82000000,),
            )

    def test_invalid_stream_metadata_is_rejected(self):
        with self.assertRaisesRegex(PdbFormatError, "missing symbol stream"):
            extract_data_module_streams(
                modules=[{"index": 1, "sym_stream": 9}],
                section_bases=(0x82000000,),
                read_stream=lambda _index: CV_SIGNATURE,
                stream_count=3,
            )

        with self.assertRaisesRegex(ValueError, "cannot be negative"):
            parse_module_data_symbols(
                CV_SIGNATURE,
                module_index=1,
                module_name="bad.obj",
                symbol_stream=2,
                section_bases=(0x82000000,),
                symbol_bytes=-1,
            )

    def test_raw_name_round_trips_and_jsonl_is_deterministic(self):
        raw_name = b"raw-\x80-name"
        blob = CV_SIGNATURE + _data_record(
            kind=S_GDATA32, name=raw_name
        )
        records = parse_module_data_symbols(
            blob,
            module_index=0,
            module_name="bytes.obj",
            symbol_stream=5,
            section_bases=(0x82000000,),
        )
        self.assertEqual(records[0].raw_name.encode("latin-1"), raw_name)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "globals.jsonl"
            write_data_jsonl(reversed(records), output)
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_bytes = output.read_bytes()
        self.assertEqual(payload["record_id"], records[0].record_id)
        self.assertEqual(payload["raw_name"].encode("latin-1"), raw_name)
        self.assertTrue(output_bytes.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
