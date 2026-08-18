from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from fnv_atlas.pdb_symbols import PdbFormatError
from fnv_atlas.pdb_vftables import (
    PeImage,
    PeSection,
    S_PUB32,
    parse_dbi_symbol_stream_reference,
    parse_vftable_name,
    parse_vftable_symbol_records,
    scan_vftable_pointer_runs,
    write_pointer_runs_jsonl,
    write_vftable_symbols_jsonl,
)


def _record(kind: int, body: bytes) -> bytes:
    record = struct.pack("<HH", 2 + len(body), kind) + body
    return record + b"\0" * ((-len(record)) % 4)


def _public(name: str, *, offset: int, section: int = 1, flags: int = 0) -> bytes:
    body = struct.pack("<IIH", flags, offset, section)
    body += name.encode("latin-1") + b"\0"
    return _record(S_PUB32, body)


class VftableSymbolTests(unittest.TestCase):
    def test_dbi_reference_points_at_shared_physical_record_stream(self):
        blob = bytearray(64)
        struct.pack_into("<6H", blob, 12, 5, 0, 6, 0, 7, 0)

        result = parse_dbi_symbol_stream_reference(bytes(blob))

        self.assertEqual(result.dbi_stream, 3)
        self.assertEqual(result.global_symbol_hash_stream, 5)
        self.assertEqual(result.public_symbol_hash_stream, 6)
        self.assertEqual(result.symbol_record_stream, 7)

    def test_missing_or_truncated_dbi_record_stream_is_rejected(self):
        with self.assertRaisesRegex(PdbFormatError, "64-byte"):
            parse_dbi_symbol_stream_reference(b"short")
        blob = bytearray(64)
        struct.pack_into("<6H", blob, 12, 5, 0, 6, 0, 0xFFFF, 0)
        with self.assertRaisesRegex(PdbFormatError, "no symbol-record"):
            parse_dbi_symbol_stream_reference(bytes(blob))

    def test_parser_preserves_every_physical_alias_and_exact_record(self):
        first_name = "??_7?$Bag@H@@6B@"
        second_name = "??_7?$Bag@H@@6BBase@@@"
        same_name_elsewhere = first_name
        first = _public(first_name, offset=0x20, flags=8)
        second = _public(second_name, offset=0x20)
        third = _public(same_name_elsewhere, offset=0x40)
        ignored = _record(0x1125, b"ignored")
        blob = ignored + first + second + third

        result = parse_vftable_symbol_records(
            blob, symbol_record_stream=7, section_bases=(0x82000000,)
        )

        self.assertEqual(result.record_count, 3)
        self.assertEqual(result.unique_va_count, 2)
        records = result.records
        self.assertEqual(records[0].decorated_name, first_name)
        self.assertEqual(records[0].raw_record, first.rstrip(b"\0") + b"\0")
        self.assertEqual(records[0].public_flags, 8)
        self.assertEqual(records[0].va, 0x82000020)
        self.assertNotEqual(records[0].record_id, records[1].record_id)
        self.assertEqual(
            records[0].canonical_name_id, records[2].canonical_name_id
        )
        shared = next(group for group in result.address_groups if group.count == 2)
        self.assertEqual(shared.decorated_names, (first_name, second_name))
        self.assertEqual(shared.record_ids[:], tuple(r.record_id for r in records[:2]))
        self.assertIn(":g", shared.group_id)

    def test_name_parser_keeps_template_owner_and_qualified_role_separate(self):
        owner_template = parse_vftable_name(
            "??_7?$BSSimpleArrayRefCounted@VPathingAvoidNode@@$0EAA@@@"
            "6BNiRefObject@@@"
        )
        qualifier_template = parse_vftable_name(
            "??_7TESWeather@@6B?$TESImageSpaceModifiableCountForm@$05@@@"
        )

        self.assertTrue(owner_template.is_template_owner)
        self.assertFalse(owner_template.is_template_qualifier)
        self.assertEqual(
            owner_template.qualifier_encoding, "NiRefObject@@"
        )
        self.assertEqual(
            owner_template.role_encoding, "qualified_vfptr_symbol"
        )
        self.assertFalse(qualifier_template.is_template_owner)
        self.assertTrue(qualifier_template.is_template_qualifier)
        self.assertEqual(
            qualifier_template.qualifier_encoding,
            "?$TESImageSpaceModifiableCountForm@$05@@",
        )

    def test_unusual_local_class_name_is_retained_with_diagnostic(self):
        name = (
            "??_7Local@?1??Function@Scope@@SAXXZ@6B@"
        )
        result = parse_vftable_symbol_records(
            _public(name, offset=0),
            symbol_record_stream=7,
            section_bases=(0x82000000,),
        )

        self.assertEqual(result.records[0].decorated_name, name)
        self.assertEqual(
            result.records[0].name_parts.parse_status,
            "unrecognized_msvc_vftable_form",
        )
        self.assertEqual(
            [diagnostic.code for diagnostic in result.diagnostics],
            ["vftable_name_form_unparsed"],
        )

    def test_unresolved_section_is_retained_instead_of_dropped(self):
        result = parse_vftable_symbol_records(
            _public("??_7Lost@@6B@", offset=4, section=3),
            symbol_record_stream=7,
            section_bases=(0x82000000,),
        )

        self.assertEqual(result.record_count, 1)
        self.assertIsNone(result.records[0].va)
        self.assertEqual(result.unresolved_va_count, 1)
        self.assertEqual(result.diagnostics[0].code, "unresolved_pe_section")

    def test_malformed_public_records_are_never_silently_skipped(self):
        truncated = _record(S_PUB32, b"tiny")
        with self.assertRaisesRegex(PdbFormatError, "truncated S_PUB32"):
            parse_vftable_symbol_records(
                truncated, symbol_record_stream=7, section_bases=()
            )

        body = struct.pack("<IIH", 0, 0, 1) + b"??_7NoTerminator@@6B@"
        unterminated = struct.pack("<HH", 2 + len(body), S_PUB32) + body
        with self.assertRaisesRegex(PdbFormatError, "unterminated S_PUB32"):
            parse_vftable_symbol_records(
                unterminated, symbol_record_stream=7, section_bases=(0,)
            )


class PointerRunTests(unittest.TestCase):
    @staticmethod
    def _fixture():
        # Three uninterrupted big-endian text pointers begin at 0x82001000.
        # A second known vftable begins at the third pointer, so the raw run
        # crosses a symbol boundary.  Neither observation is selected as an
        # authoritative class-table extent.
        data = bytearray(0x200)
        struct.pack_into(">4I", data, 0, 0x82002000, 0x82002004, 0x82002008, 0)
        image = PeImage(
            image_base=0x82000000,
            sections=(
                PeSection(
                    index=1,
                    name=".rdata",
                    va=0x82001000,
                    virtual_size=0x100,
                    raw_offset=0,
                    raw_size=0x100,
                    characteristics=0,
                ),
                PeSection(
                    index=2,
                    name=".text",
                    va=0x82002000,
                    virtual_size=0x100,
                    raw_offset=0x100,
                    raw_size=0x100,
                    characteristics=0x20000000,
                ),
            ),
            data=bytes(data),
        )
        records = parse_vftable_symbol_records(
            _public("??_7First@@6B@", offset=0)
            + _public("??_7FirstAlias@@6B@", offset=0)
            + _public("??_7Second@@6B@", offset=8),
            symbol_record_stream=7,
            section_bases=image.section_bases,
        )
        return image, records

    def test_raw_pointer_run_and_known_symbol_boundary_both_survive(self):
        image, symbols = self._fixture()

        result = scan_vftable_pointer_runs(image, symbols.address_groups)

        self.assertEqual(result.run_count, 2)
        first, second = result.runs
        self.assertEqual(len(first.symbol_record_ids), 2)
        self.assertEqual(first.observed_pointer_count, 3)
        self.assertEqual(
            [slot.target_va for slot in first.slots],
            [0x82002000, 0x82002004, 0x82002008],
        )
        self.assertEqual(first.known_boundary_slot_index, 2)
        self.assertEqual(
            first.boundary_relation, "next_vftable_inside_pointer_run"
        )
        self.assertIn(
            "pointer_run_crosses_known_vftable_symbol",
            [diagnostic.code for diagnostic in first.diagnostics],
        )
        self.assertEqual(first.termination_kind, "first_non_text_pointer")
        self.assertEqual(first.termination_word_hex, "00000000")
        self.assertEqual(second.observed_pointer_count, 1)
        self.assertEqual(second.boundary_relation, "no_later_vftable_symbol")

    def test_cap_and_empty_run_are_explicit_diagnostics(self):
        image, symbols = self._fixture()
        capped = scan_vftable_pointer_runs(
            image, symbols.address_groups, max_slots=1
        )
        self.assertEqual(capped.runs[0].termination_kind, "max_slots_reached")
        self.assertIn(
            "max_slots_reached",
            [item.code for item in capped.runs[0].diagnostics],
        )

        data = bytearray(image.data)
        struct.pack_into(">I", data, 0, 0)
        empty = scan_vftable_pointer_runs(
            PeImage(image.image_base, image.sections, bytes(data)),
            symbols.address_groups,
        )
        self.assertEqual(empty.runs[0].observed_pointer_count, 0)
        self.assertIn(
            "no_leading_text_pointer",
            [item.code for item in empty.runs[0].diagnostics],
        )

    def test_known_boundary_can_follow_the_observed_pointer_prefix(self):
        image, symbols = self._fixture()
        data = bytearray(image.data)
        struct.pack_into(">I", data, 4, 0)

        result = scan_vftable_pointer_runs(
            PeImage(image.image_base, image.sections, bytes(data)),
            symbols.address_groups,
        )

        first = result.runs[0]
        self.assertEqual(first.observed_pointer_count, 1)
        self.assertEqual(first.known_boundary_slot_index, 2)
        self.assertEqual(
            first.next_vftable_va - first.table_va,
            first.known_boundary_slot_index * 4,
        )
        self.assertEqual(
            first.boundary_relation, "next_vftable_after_pointer_run"
        )

    def test_jsonl_outputs_are_deterministic_and_keep_raw_observations(self):
        image, symbols = self._fixture()
        runs = scan_vftable_pointer_runs(image, symbols.address_groups)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            symbol_path = root / "symbols.jsonl"
            run_path = root / "runs.jsonl"
            write_vftable_symbols_jsonl(
                reversed(symbols.records), symbol_path
            )
            write_pointer_runs_jsonl(reversed(runs.runs), run_path)
            symbol_rows = [
                json.loads(line)
                for line in symbol_path.read_text(encoding="utf-8").splitlines()
            ]
            run_rows = [
                json.loads(line)
                for line in run_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(
            [row["record_offset"] for row in symbol_rows],
            sorted(row["record_offset"] for row in symbol_rows),
        )
        self.assertIn("raw_record_hex", symbol_rows[0])
        self.assertEqual(run_rows[0]["observed_pointer_count"], 3)
        self.assertEqual(
            run_rows[0]["boundary_relation"],
            "next_vftable_inside_pointer_run",
        )


if __name__ == "__main__":
    unittest.main()
