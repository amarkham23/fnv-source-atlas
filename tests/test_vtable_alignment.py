from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.vtable_alignment import (  # noqa: E402
    VtableAlignmentError,
    propose_vtable_alignments,
)
from fnv_atlas.vtables import (  # noqa: E402
    VtableDataset,
    parse_pc_vtables,
    parse_xbox_vtables,
)


def _pc_table(address: int, offset: int, targets: list[int]) -> dict[str, object]:
    return {
        "rtti_name": ".?AVDerived@@",
        "vtable_va": address,
        "col_va": address + 0x100000,
        "offset": offset,
        "slot_count": len(targets),
        "slots": targets,
    }


def _xbox_table(
    address: int, symbol: str, targets: list[int]
) -> dict[str, object]:
    return {
        "symbol": symbol,
        "vtable_va": address,
        "slot_count": len(targets),
        "slots": [
            {"va": target, "name": f"slot_name_{index}"}
            for index, target in enumerate(targets)
        ],
    }


_TYPES = {
    "Root": {"bases": [], "virtuals": [{"slot": 0}]},
    "Secondary": {"bases": [], "virtuals": [{"slot": 0}]},
    "Derived": {
        "bases": [
            {"name": "Root", "offset": 0},
            {"name": "Secondary", "offset": 16},
        ],
        "virtuals": [{"slot": 1}],
    },
}


class VtableAlignmentTests(unittest.TestCase):
    def test_pairs_unique_roles_not_source_list_order_or_largest_table(self) -> None:
        pc = parse_pc_vtables(
            {
                "classes": {
                    "Derived": [
                        # Secondary comes first in PC source order.
                        _pc_table(0x1000200, 16, [0x402000, 0x402010]),
                        # Primary is larger than the Xbox primary.
                        _pc_table(
                            0x1000100, 0, [0x401000, 0x401010, 0x401020]
                        ),
                    ]
                }
            }
        )
        xbox = parse_xbox_vtables(
            {
                "Derived": [
                    # Primary comes first on Xbox.
                    _xbox_table(
                        0x82000100,
                        "??_7Derived@@6B@",
                        [0x82601000, 0x82601010],
                    ),
                    # This is the largest table, but remains the secondary.
                    _xbox_table(
                        0x82000200,
                        "??_7Derived@@6BSecondary@@@",
                        [0x82602000, 0x82602010, 0x82602020, 0x82602030],
                    ),
                ]
            },
            types=_TYPES,
        )

        result = propose_vtable_alignments(pc, xbox)

        self.assertEqual(result.exact_class_overlap_count, 1)
        self.assertEqual(result.candidate_count, 2)
        primary, secondary = result.candidates
        self.assertEqual(primary.vfptr_role, "primary")
        self.assertEqual(primary.subobject_offset, 0)
        self.assertEqual(primary.pc_address, 0x1000100)
        self.assertEqual(primary.xbox_address, 0x82000100)
        self.assertEqual(primary.pc_observed_slot_count, 3)
        self.assertEqual(primary.xbox_observed_slot_count, 2)
        self.assertEqual(primary.shared_prefix_slot_count, 2)
        self.assertEqual(primary.pc_unpaired_tail_count, 1)
        self.assertEqual(primary.xbox_unpaired_tail_count, 0)
        self.assertEqual([pair.slot_index for pair in primary.slot_pairs], [0, 1])
        self.assertEqual(primary.pc_extent.observed_slot_count, 3)
        self.assertEqual(primary.xbox_extent.observed_slot_count, 2)

        self.assertEqual(secondary.vfptr_role, "secondary")
        self.assertEqual(secondary.subobject_offset, 16)
        self.assertEqual(secondary.pc_address, 0x1000200)
        self.assertEqual(secondary.xbox_address, 0x82000200)
        self.assertEqual(secondary.shared_prefix_slot_count, 2)
        self.assertEqual(secondary.xbox_unpaired_tail_count, 2)

        serialized = result.to_dict()
        self.assertNotIn("confidence", serialized["candidates"][0])
        self.assertNotIn("accepted", serialized["candidates"][0])

    def test_primary_ambiguity_and_unmatched_secondary_offsets_are_issues(self) -> None:
        pc = parse_pc_vtables(
            {
                "classes": {
                    "Derived": [
                        _pc_table(0x1001000, 0, [0x401000]),
                        _pc_table(0x1001100, 0, [0x401100]),
                        _pc_table(0x1001200, 16, [0x401200]),
                    ]
                }
            }
        )
        xbox = parse_xbox_vtables(
            {
                "Derived": [
                    _xbox_table(0x82001000, "??_7Derived@@6B@", [0x82601000]),
                    # A different exact subobject offset; it must not be paired
                    # merely because it is the only secondary table.
                    _xbox_table(
                        0x82001200,
                        "??_7Derived@@6BOtherBase@@@",
                        [0x82601200],
                    ),
                    # Complex qualifier remains structurally unresolved.
                    _xbox_table(
                        0x82001300,
                        "??_7Voice@Audio@@6BBase@1@@",
                        [0x82601300],
                    ),
                ]
            },
            types={
                **_TYPES,
                "Derived": {
                    "bases": [
                        {"name": "Root", "offset": 0},
                        {"name": "Secondary", "offset": 16},
                        {"name": "OtherBase", "offset": 20},
                    ],
                    "virtuals": [{"slot": 0}],
                },
            },
        )

        result = propose_vtable_alignments(pc, xbox)

        self.assertEqual(result.candidate_count, 0)
        kinds = {issue.issue_kind for issue in result.issues}
        self.assertIn("primary_role_ambiguous", kinds)
        self.assertIn("secondary_offset_missing_on_xbox", kinds)
        self.assertIn("secondary_offset_missing_on_pc", kinds)
        self.assertIn("xbox_role_or_offset_unresolved", kinds)
        ambiguity = next(
            issue for issue in result.issues if issue.issue_kind == "primary_role_ambiguous"
        )
        self.assertEqual(len(ambiguity.pc_vtable_ids), 2)
        self.assertEqual(len(ambiguity.xbox_vtable_ids), 1)

    def test_duplicate_secondary_offset_is_not_selected(self) -> None:
        pc = parse_pc_vtables(
            {
                "classes": {
                    "Derived": [
                        _pc_table(0x1002000, 0, [0x402000]),
                        _pc_table(0x1002100, 16, [0x402100]),
                    ]
                }
            }
        )
        xbox = parse_xbox_vtables(
            {
                "Derived": [
                    _xbox_table(0x82002000, "??_7Derived@@6B@", [0x82602000]),
                    _xbox_table(
                        0x82002100,
                        "??_7Derived@@6BSecondary@@@",
                        [0x82602100],
                    ),
                    _xbox_table(
                        0x82002200,
                        "??_7Derived@@6BSecondary@@@",
                        [0x82602200],
                    ),
                ]
            },
            types=_TYPES,
        )
        result = propose_vtable_alignments(pc, xbox)

        self.assertEqual(result.candidate_count, 1)
        self.assertEqual(result.candidates[0].vfptr_role, "primary")
        issue = next(
            item
            for item in result.issues
            if item.issue_kind == "secondary_offset_ambiguous"
        )
        self.assertEqual(issue.subobject_offset, 16)
        self.assertEqual(len(issue.xbox_vtable_ids), 2)

    def test_class_names_are_exact_and_unmatched_classes_remain_issues(self) -> None:
        pc = parse_pc_vtables(
            {"classes": {"CaseSensitive": [_pc_table(0x1003000, 0, [0x403000])]}}
        )
        xbox = parse_xbox_vtables(
            {
                "casesensitive": [
                    _xbox_table(
                        0x82003000,
                        "??_7casesensitive@@6B@",
                        [0x82603000],
                    )
                ]
            }
        )
        result = propose_vtable_alignments(pc, xbox)

        self.assertEqual(result.exact_class_overlap_count, 0)
        self.assertEqual(result.candidate_count, 0)
        self.assertEqual(result.pc_only_class_count, 1)
        self.assertEqual(result.xbox_only_class_count, 1)
        self.assertEqual(
            {issue.issue_kind for issue in result.issues},
            {"class_missing_on_pc", "class_missing_on_xbox"},
        )

    def test_table_and_slot_tuple_order_do_not_change_output(self) -> None:
        pc = parse_pc_vtables(
            {
                "classes": {
                    "Derived": [
                        _pc_table(0x1004000, 0, [0x404000, 0x404010]),
                        _pc_table(0x1004100, 16, [0x404100, 0x404110]),
                    ]
                }
            }
        )
        xbox = parse_xbox_vtables(
            {
                "Derived": [
                    _xbox_table(
                        0x82004000,
                        "??_7Derived@@6B@",
                        [0x82604000, 0x82604010],
                    ),
                    _xbox_table(
                        0x82004100,
                        "??_7Derived@@6BSecondary@@@",
                        [0x82604100, 0x82604110],
                    ),
                ]
            },
            types=_TYPES,
        )
        original = propose_vtable_alignments(pc, xbox)

        reversed_pc_tables = tuple(
            replace(table, slots=tuple(reversed(table.slots)))
            for table in reversed(pc.tables)
        )
        reordered_pc = VtableDataset("pc", reversed_pc_tables)
        reordered_xbox = VtableDataset("xbox360", tuple(reversed(xbox.tables)))
        reordered = propose_vtable_alignments(reordered_pc, reordered_xbox)

        self.assertEqual(original.to_dict(), reordered.to_dict())

    def test_dataset_platforms_are_explicit(self) -> None:
        empty_pc = VtableDataset("pc", ())
        empty_xbox = VtableDataset("xbox360", ())
        with self.assertRaises(VtableAlignmentError):
            propose_vtable_alignments(empty_xbox, empty_pc)


if __name__ == "__main__":
    unittest.main()

