from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from fnv_atlas.pdb_symbols import (
    PdbFormatError,
    S_GPROC32,
    S_LPROC32,
    build_alias_groups,
    extract_module_streams,
    parse_module_procedures,
    write_jsonl,
)


CV_SIGNATURE = b"\x04\x00\x00\x00"


def _procedure_record(
    *,
    kind: int,
    name: bytes,
    section: int = 1,
    section_offset: int = 0x1234,
    size: int = 0x80,
    type_index: int = 0x1001,
    flags: int = 0,
    parent_offset: int = 0,
    end_offset: int = 0,
    next_offset: int = 0,
    debug_start: int = 0,
    debug_end: int = 0,
    terminate_name: bool = True,
) -> bytes:
    body = struct.pack(
        "<8IHB",
        parent_offset,
        end_offset,
        next_offset,
        size,
        debug_start,
        debug_end,
        type_index,
        section_offset,
        section,
        flags,
    )
    body += name
    if terminate_name:
        body += b"\0"
    payload = struct.pack("<H", kind) + body
    record = struct.pack("<H", len(payload)) + payload
    return record + b"\0" * ((-len(record)) % 4)


class PdbSymbolTests(unittest.TestCase):
    def test_parse_preserves_duplicate_va_records_and_all_proc_fields(self):
        first = _procedure_record(
            kind=S_GPROC32,
            name=b"?FoldedA@@YAXXZ",
            size=0x91,
            type_index=0x44556677,
            flags=0xA5,
            parent_offset=1,
            end_offset=2,
            next_offset=3,
            debug_start=4,
            debug_end=5,
        )
        second = _procedure_record(
            kind=S_LPROC32,
            name=b"?FoldedB@@YAXXZ",
            size=0x91,
            type_index=0x8899AABB,
            section_offset=0x1234,
            flags=0x02,
        )
        third = _procedure_record(
            kind=S_GPROC32,
            name=b"separate",
            section=2,
            section_offset=0x40,
        )
        blob = CV_SIGNATURE + first + second + third

        records = parse_module_procedures(
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
            ["?FoldedA@@YAXXZ", "?FoldedB@@YAXXZ", "separate"],
        )
        self.assertEqual(
            records[0].record_id, "x360-proc:m0007:s0042:o00000004"
        )
        self.assertEqual(records[1].record_offset, 4 + len(first))
        self.assertEqual(records[0].record_kind, "S_GPROC32")
        self.assertEqual(records[1].record_kind, "S_LPROC32")
        self.assertEqual(records[0].record_kind_code, S_GPROC32)
        self.assertEqual(records[0].va, 0x82001234)
        self.assertEqual(records[1].va, 0x82001234)
        self.assertEqual(records[2].va, 0x83000040)
        self.assertEqual(records[0].section, 1)
        self.assertEqual(records[0].section_offset, 0x1234)
        self.assertEqual(records[0].size, 0x91)
        # This specifically guards the CodeView type-index at body + 24.
        self.assertEqual(records[0].type_index, 0x44556677)
        self.assertEqual(records[1].type_index, 0x8899AABB)
        self.assertEqual(records[0].flags, 0xA5)
        self.assertEqual(records[0].module_index, 7)
        self.assertEqual(records[0].module_name, r"obj\xbox\example.obj")
        self.assertEqual(records[0].symbol_stream, 42)
        self.assertEqual(records[0].parent_offset, 1)
        self.assertEqual(records[0].end_offset, 2)
        self.assertEqual(records[0].next_offset, 3)
        self.assertEqual(records[0].debug_start, 4)
        self.assertEqual(records[0].debug_end, 5)

        groups = build_alias_groups(records)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].group_id, "x360-fold:82001234")
        self.assertEqual(
            groups[0].record_ids,
            (records[0].record_id, records[1].record_id),
        )
        self.assertEqual(
            groups[0].raw_names,
            ("?FoldedA@@YAXXZ", "?FoldedB@@YAXXZ"),
        )

    def test_symbol_byte_limit_prevents_line_data_from_becoming_symbols(self):
        actual = _procedure_record(kind=S_GPROC32, name=b"actual")
        fake_c13 = _procedure_record(kind=S_GPROC32, name=b"not-a-symbol")
        blob = CV_SIGNATURE + actual + fake_c13

        records = parse_module_procedures(
            blob,
            module_index=1,
            module_name="module.obj",
            symbol_stream=8,
            section_bases=(0x82000000,),
            symbol_bytes=len(CV_SIGNATURE + actual),
        )

        self.assertEqual([record.raw_name for record in records], ["actual"])

    def test_extract_is_order_independent_and_groups_across_modules(self):
        stream_10 = CV_SIGNATURE + _procedure_record(
            kind=S_GPROC32, name=b"global-name", section_offset=0x20
        )
        stream_11 = CV_SIGNATURE + _procedure_record(
            kind=S_LPROC32, name=b"local-alias", section_offset=0x20
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

        result = extract_module_streams(
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
        self.assertEqual(len(result.alias_groups), 1)
        self.assertEqual(
            result.alias_groups[0].raw_names,
            ("global-name", "local-alias"),
        )

    def test_invalid_section_is_retained_with_unresolved_va(self):
        blob = CV_SIGNATURE + _procedure_record(
            kind=S_GPROC32, name=b"bad-section", section=7
        )
        records = parse_module_procedures(
            blob,
            module_index=0,
            module_name="bad.obj",
            symbol_stream=5,
            section_bases=(0x82000000,),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].section, 7)
        self.assertIsNone(records[0].va)
        self.assertEqual(build_alias_groups(records), ())

    def test_malformed_procedure_record_is_never_silently_dropped(self):
        malformed = _procedure_record(
            kind=S_GPROC32,
            name=b"unterminated",
            terminate_name=False,
        )
        # Remove alignment zeroes too, otherwise one can be mistaken for NUL.
        malformed = malformed.rstrip(b"\0")
        blob = CV_SIGNATURE + malformed

        with self.assertRaisesRegex(
            PdbFormatError, "unterminated procedure name"
        ):
            parse_module_procedures(
                blob,
                module_index=0,
                module_name="bad.obj",
                symbol_stream=5,
                section_bases=(0x82000000,),
            )

    def test_raw_name_round_trips_and_jsonl_is_deterministic(self):
        raw_name = b"raw-\x80-name"
        blob = CV_SIGNATURE + _procedure_record(
            kind=S_GPROC32, name=raw_name
        )
        records = parse_module_procedures(
            blob,
            module_index=0,
            module_name="bytes.obj",
            symbol_stream=5,
            section_bases=(0x82000000,),
        )
        self.assertEqual(records[0].raw_name.encode("latin-1"), raw_name)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "procedures.jsonl"
            write_jsonl(reversed(records), output)
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_bytes = output.read_bytes()
        self.assertEqual(payload["record_id"], records[0].record_id)
        self.assertEqual(payload["raw_name"].encode("latin-1"), raw_name)
        self.assertTrue(output_bytes.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
