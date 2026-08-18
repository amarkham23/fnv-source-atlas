from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from fnv_atlas.vtables import (
    load_pc_vtables,
    load_xbox_vtables,
    parse_pc_vtables,
    parse_xbox_vftable_symbol,
    parse_xbox_vtables,
)


class VtableLoaderTests(unittest.TestCase):
    def test_pc_loader_retains_every_table_col_role_and_slot_occurrence(self):
        document = {
            "source": "FalloutNV.exe",
            "imagebase": "0x00400000",
            "class_count": 1,
            "vtable_count": 2,
            "total_slots": 4,
            "classes": {
                "Derived": [
                    {
                        "rtti_name": ".?AVDerived@@",
                        "vtable_va": 0x01001000,
                        "col_va": 0x01101000,
                        "offset": 0,
                        "slot_count": 2,
                        "slots": ["0x00401000", "0x00401000"],
                    },
                    {
                        "rtti_name": ".?AVDerived@@",
                        "vtable_va": 0x01002000,
                        "col_va": 0x01102000,
                        "offset": 16,
                        "slot_count": 2,
                        "slots": ["0x00402000", "0x00402010"],
                    },
                ]
            },
        }

        result = parse_pc_vtables(document)

        self.assertEqual(result.platform, "pc")
        self.assertEqual(result.class_count, 1)
        self.assertEqual(result.table_count, 2)
        self.assertEqual(result.slot_count, 4)
        primary, secondary = result.tables
        self.assertNotEqual(primary.vtable_id, secondary.vtable_id)
        self.assertEqual(primary.vfptr_role, "primary")
        self.assertEqual(primary.subobject_offset, 0)
        self.assertEqual(secondary.vfptr_role, "secondary")
        self.assertEqual(secondary.subobject_offset, 16)
        self.assertEqual(secondary.col_address, 0x01102000)
        self.assertEqual(secondary.rtti_name, ".?AVDerived@@")
        self.assertEqual(secondary.raw_table_identity, ".?AVDerived@@")
        self.assertEqual(
            [slot.slot_index for slot in primary.slots], [0, 1]
        )
        # Repeated target addresses remain two independent slot occurrences.
        self.assertEqual(
            [slot.target_address for slot in primary.slots],
            [0x00401000, 0x00401000],
        )
        self.assertNotEqual(primary.slots[0].slot_id, primary.slots[1].slot_id)
        self.assertEqual(primary.extent.status, "unassessed_same_platform_declaration_unavailable")
        self.assertFalse(primary.extent.extent_suspect)
        self.assertIsNone(primary.extent.reference_slot_count)

    def test_xbox_loader_resolves_roles_from_same_platform_tpi_only(self):
        types = {
            "Root": {
                "bases": [],
                "virtuals": [
                    {"name": "a", "kind": "intro", "slot": 0},
                    {"name": "b", "kind": "intro", "slot": 1},
                ],
            },
            "Secondary": {
                "bases": [],
                "virtuals": [
                    {"name": "s", "kind": "intro", "slot": 0}
                ],
            },
            "Derived": {
                "bases": [
                    {"name": "Root", "offset": 0},
                    {"name": "Secondary", "offset": 16},
                ],
                "virtuals": [
                    {"name": "c", "kind": "intro", "slot": 2}
                ],
            },
        }
        document = {
            "Derived": [
                {
                    "symbol": "??_7Derived@@6BRoot@@@",
                    "vtable_va": "0x82001000",
                    "slot_count": 3,
                    "slots": [
                        {"va": "0x82600000", "name": "?a@Root@@UAAXXZ"},
                        {"va": "0x82600010", "name": "?b@Root@@UAAXXZ"},
                        {"va": "0x82600020", "name": "?c@Derived@@UAAXXZ"},
                    ],
                },
                {
                    "symbol": "??_7Derived@@6BSecondary@@@",
                    "vtable_va": "0x82002000",
                    "slot_count": 2,
                    "slots": [
                        {
                            "va": "0x82600100",
                            "name": "?s@Secondary@@UAAXXZ",
                        },
                        {
                            "va": "0x82600110",
                            "name": "?next_table@Other@@UAAXXZ",
                        },
                    ],
                },
            ]
        }

        result = parse_xbox_vtables(document, types=types)

        self.assertEqual(result.platform, "xbox360")
        self.assertEqual(result.table_count, 2)
        self.assertEqual(result.slot_count, 5)
        primary, secondary = result.tables
        self.assertEqual(primary.qualifier, "Root")
        self.assertEqual(primary.raw_qualifier, "Root@@")
        self.assertEqual(primary.vfptr_role, "primary")
        self.assertEqual(primary.subobject_offset, 0)
        self.assertEqual(primary.extent.reference_class, "Derived")
        self.assertEqual(primary.extent.reference_slot_count, 3)
        self.assertEqual(
            primary.extent.status, "matches_hole_free_xbox_tpi_map"
        )

        self.assertEqual(secondary.vfptr_role, "secondary")
        self.assertEqual(secondary.subobject_offset, 16)
        self.assertEqual(secondary.subobject_offset_candidates, (16,))
        self.assertEqual(secondary.extent.reference_class, "Secondary")
        self.assertEqual(secondary.extent.reference_slot_count, 1)
        self.assertTrue(secondary.extent.extent_suspect)
        self.assertEqual(secondary.extent.excess_slot_count, 1)
        self.assertEqual(
            secondary.extent.status,
            "pointer_run_exceeds_hole_free_xbox_tpi_map",
        )
        # The address-derived symbol survives only as an explicitly ambiguous
        # observation; it does not become the slot or function identity.
        observation = secondary.slots[0].name_observations[0]
        self.assertEqual(observation.raw_name, "?s@Secondary@@UAAXXZ")
        self.assertEqual(observation.observation_kind, "address_derived_symbol")
        self.assertEqual(
            observation.ambiguity, "address_may_have_multiple_symbol_aliases"
        )

    def test_unqualified_and_complex_symbols_are_preserved_without_guessing(self):
        unqualified = parse_xbox_vftable_symbol("??_7Root@@6B@")
        self.assertTrue(unqualified.is_unqualified)
        self.assertIsNone(unqualified.raw_qualifier)

        complex_symbol = "??_7Voice@Audio@@6BBase@1@@"
        complex_parts = parse_xbox_vftable_symbol(complex_symbol)
        self.assertEqual(complex_parts.raw_symbol, complex_symbol)
        self.assertEqual(complex_parts.raw_qualifier, "Base@1@")
        self.assertIsNone(complex_parts.simple_qualifier)
        self.assertEqual(complex_parts.parse_status, "complex_qualifier")

        result = parse_xbox_vtables(
            {
                "Audio::Voice": [
                    {
                        "symbol": complex_symbol,
                        "vtable_va": "0x82003000",
                        "slot_count": 1,
                        "slots": [
                            {"va": "0x82600200", "name": "raw_name"}
                        ],
                    }
                ]
            },
            types={},
        )
        table = result.tables[0]
        self.assertEqual(table.raw_table_identity, complex_symbol)
        self.assertEqual(table.raw_qualifier, "Base@1@")
        self.assertEqual(table.vfptr_role, "unknown")
        self.assertIsNone(table.subobject_offset)
        self.assertEqual(table.extent.status, "unassessed_no_hole_free_xbox_tpi_map")

    def test_reported_count_mismatch_is_metadata_not_data_loss(self):
        result = parse_pc_vtables(
            {
                "classes": {
                    "Mismatch": [
                        {
                            "rtti_name": ".?AVMismatch@@",
                            "vtable_va": 0x01004000,
                            "col_va": 0x01104000,
                            "offset": 0,
                            "slot_count": 99,
                            "slots": ["0x00404000"],
                        }
                    ]
                }
            }
        )
        table = result.tables[0]
        self.assertEqual(table.slot_count, 1)
        self.assertEqual(table.extent.reported_slot_count, 99)
        self.assertFalse(table.extent.reported_count_matches_payload)
        self.assertTrue(table.extent.extent_suspect)
        self.assertIn(
            "source_reported_slot_count_differs_from_payload",
            table.extent.reasons,
        )

    def test_shorter_than_same_platform_tpi_extent_is_suspect(self):
        result = parse_xbox_vtables(
            {
                "Short": [
                    {
                        "symbol": "??_7Short@@6B@",
                        "vtable_va": "0x82004000",
                        "slot_count": 1,
                        "slots": [{"va": "0x82604000", "name": "first"}],
                    }
                ]
            },
            types={
                "Short": {
                    "bases": [],
                    "virtuals": [
                        {"name": "first", "kind": "intro", "slot": 0},
                        {"name": "second", "kind": "intro", "slot": 1},
                    ],
                }
            },
        )
        extent = result.tables[0].extent
        self.assertEqual(extent.status, "shorter_than_hole_free_xbox_tpi_map")
        self.assertTrue(extent.extent_suspect)
        self.assertIn(extent.status, extent.reasons)

    def test_explicit_path_loaders_accept_current_json_shapes(self):
        pc_document = {
            "source": "FalloutNV.exe",
            "classes": {
                "Root": [
                    {
                        "rtti_name": ".?AVRoot@@",
                        "vtable_va": 0x01005000,
                        "col_va": 0x01105000,
                        "offset": 0,
                        "slot_count": 1,
                        "slots": ["0x00405000"],
                    }
                ]
            },
        }
        xbox_document = {
            "Root": [
                {
                    "symbol": "??_7Root@@6B@",
                    "vtable_va": "0x82005000",
                    "slot_count": 1,
                    "slots": [{"va": "0x82605000", "name": "root"}],
                }
            ]
        }
        types_document = {
            "Root": {
                "bases": [],
                "virtuals": [
                    {"name": "root", "kind": "intro", "slot": 0}
                ],
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pc_path = root / "pc_classes.json"
            xbox_path = root / "vtables_360.json"
            types_path = root / "types_360.json"
            pc_path.write_text(json.dumps(pc_document), encoding="utf-8")
            xbox_path.write_text(json.dumps(xbox_document), encoding="utf-8")
            types_path.write_text(json.dumps(types_document), encoding="utf-8")

            pc = load_pc_vtables(pc_path)
            xbox = load_xbox_vtables(xbox_path, types_path=types_path)

        self.assertEqual(pc.table_count, 1)
        self.assertEqual(xbox.table_count, 1)
        self.assertEqual(xbox.tables[0].extent.reference_slot_count, 1)


if __name__ == "__main__":
    unittest.main()
