from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.pc_inventory import PCFunction, PCInventory  # noqa: E402
from fnv_atlas.pdb_symbols import (  # noqa: E402
    ProcedureExtraction,
    ProcedureRecord,
    S_GPROC32,
    build_alias_groups,
    make_record_id,
)
from fnv_atlas.vtable_alignment import propose_vtable_alignments  # noqa: E402
from fnv_atlas.vtable_hypotheses import (  # noqa: E402
    VtableHypothesisError,
    materialize_vtable_hypotheses,
)
from fnv_atlas.vtables import parse_pc_vtables, parse_xbox_vtables  # noqa: E402


def _procedure(va: int, ordinal: int, name: str) -> ProcedureRecord:
    module_index = ordinal // 100 + 1
    symbol_stream = ordinal // 20 + 10
    record_offset = ordinal * 48 + 4
    return ProcedureRecord(
        record_id=make_record_id(module_index, symbol_stream, record_offset),
        module_index=module_index,
        module_name=f"module_{module_index}.obj",
        symbol_stream=symbol_stream,
        record_offset=record_offset,
        record_length=42,
        record_kind="S_GPROC32",
        record_kind_code=S_GPROC32,
        va=va,
        section=1,
        section_offset=va - 0x82000000,
        size=16,
        type_index=0x1000 + ordinal,
        flags=0,
        raw_name=name,
        parent_offset=0,
        end_offset=0,
        next_offset=0,
        debug_start=0,
        debug_end=16,
    )


def _inventory(*addresses: int) -> PCInventory:
    return PCInventory(
        image_base=0x400000,
        functions=tuple(
            PCFunction(
                function_id=f"pc:ram:{address:08x}",
                address=address,
                address_space="ram",
                name=f"FUN_{address:08x}",
                size=16,
                thunk=False,
                in_executable_range=True,
                callees=(),
            )
            for address in addresses
        ),
    )


def _alignment(
    pc_targets: list[int], xbox_targets: list[int], *, with_issue: bool = False
):
    pc_classes: dict[str, object] = {
        "Mapped": [
            {
                "rtti_name": ".?AVMapped@@",
                "vtable_va": 0x1010000,
                "col_va": 0x1110000,
                "offset": 0,
                "slot_count": len(pc_targets),
                "slots": pc_targets,
            }
        ]
    }
    if with_issue:
        pc_classes["PCOnly"] = [
            {
                "rtti_name": ".?AVPCOnly@@",
                "vtable_va": 0x1020000,
                "col_va": 0x1120000,
                "offset": 0,
                "slot_count": 1,
                "slots": [0x404000],
            }
        ]
    pc = parse_pc_vtables({"classes": pc_classes})
    xbox = parse_xbox_vtables(
        {
            "Mapped": [
                {
                    "symbol": "??_7Mapped@@6B@",
                    "vtable_va": 0x82010000,
                    "slot_count": len(xbox_targets),
                    "slots": [
                        {"va": address, "name": f"observed_slot_{index}"}
                        for index, address in enumerate(xbox_targets)
                    ],
                }
            ]
        }
    )
    return propose_vtable_alignments(pc, xbox)


class VtableHypothesisTests(unittest.TestCase):
    def test_classifies_endpoints_without_losing_slot_occurrences(self) -> None:
        alignment = _alignment(
            [0x401000, 0x401100, 0x401000, 0x401200],
            [0x82001000, 0x82002000, 0x82001000, 0x82003000],
            with_issue=True,
        )
        records = (
            _procedure(0x82001000, 1, "?Exact@@YAXXZ"),
            _procedure(0x82002000, 2, "?FoldA@@YAXXZ"),
            _procedure(0x82002000, 3, "?FoldB@@YAXXZ"),
        )
        extraction = ProcedureExtraction(
            records=records,
            alias_groups=build_alias_groups(records),
        )

        result = materialize_vtable_hypotheses(
            alignment,
            _inventory(0x401000, 0x401200),
            extraction,
        )

        self.assertEqual(result.table_alignment_count, 1)
        self.assertEqual(result.hypothesis_set_count, 4)
        self.assertEqual(result.alternative_count, 4)
        self.assertEqual(result.issue_count, 1)
        self.assertEqual(result.issues[0].issue_kind, "class_missing_on_xbox")
        self.assertEqual(result.pc_exact_count, 3)
        self.assertEqual(result.pc_unresolved_count, 1)
        self.assertEqual(result.xbox_exact_count, 2)
        self.assertEqual(result.xbox_fold_group_count, 1)
        self.assertEqual(result.xbox_unresolved_count, 1)

        by_slot = {item.slot_index: item for item in result.hypothesis_sets}
        self.assertEqual(by_slot[0].pc_subject.endpoint_kind, "exact_function")
        self.assertEqual(by_slot[0].pc_subject.address_space, "ram")
        self.assertEqual(
            by_slot[0].xbox_alternative.function_id, records[0].record_id
        )
        self.assertEqual(by_slot[1].pc_subject.endpoint_kind, "unresolved_address")
        self.assertEqual(by_slot[1].xbox_alternative.endpoint_kind, "fold_group")
        self.assertEqual(by_slot[1].xbox_alternative.fold_member_count, 2)
        self.assertEqual(
            by_slot[1].xbox_alternative.fold_group_id,
            extraction.alias_groups[0].group_id,
        )
        self.assertEqual(
            by_slot[3].xbox_alternative.endpoint_kind, "unresolved_address"
        )

        # Repeated endpoint pairs reuse one semantic identity, but their
        # structural slot occurrences remain two independent hypothesis sets.
        self.assertNotEqual(
            by_slot[0].hypothesis_set_id, by_slot[2].hypothesis_set_id
        )
        self.assertEqual(by_slot[0].semantic_pair_id, by_slot[2].semantic_pair_id)
        self.assertEqual(result.scalar_or_unresolved_pair_count, 2)
        self.assertEqual(result.fold_pair_count, 1)
        self.assertEqual(result.supporting_evidence_count, 4)
        self.assertEqual(result.context_evidence_count, 0)

        serialized = by_slot[1].to_dict()
        self.assertEqual(serialized["status"], "candidate")
        self.assertEqual(serialized["scoring_status"], "unscored")
        self.assertEqual(serialized["pc_unpaired_tail_count"], 0)
        self.assertEqual(serialized["xbox_unpaired_tail_count"], 0)
        self.assertEqual(serialized["vfptr_role"], "primary")
        self.assertEqual(
            serialized["xbox_name_observations_context_only"][0]["raw_name"],
            "observed_slot_1",
        )
        self.assertNotIn("confidence", serialized)
        self.assertNotIn("accepted", serialized)

    def test_extent_overflow_is_context_while_safe_prefix_supports(self) -> None:
        alignment = _alignment(
            [0x401000, 0x401010, 0x401020],
            [0x82008000, 0x82008010, 0x82008020],
        )
        candidate = alignment.candidates[0]
        suspect_extent = replace(
            candidate.xbox_extent,
            status="pointer_run_exceeds_hole_free_xbox_tpi_map",
            extent_suspect=True,
            reference_kind="xbox_tpi_declared_primary_vfptr",
            reference_class="Mapped",
            reference_slot_count=2,
            reference_hole_free=True,
            excess_slot_count=1,
            reasons=("pointer_run_exceeds_hole_free_xbox_tpi_map",),
        )
        alignment = replace(
            alignment,
            candidates=(replace(candidate, xbox_extent=suspect_extent),),
        )
        records = tuple(
            _procedure(address, ordinal, f"?Slot{ordinal}@@YAXXZ")
            for ordinal, address in enumerate(
                [0x82008000, 0x82008010, 0x82008020], start=1
            )
        )

        result = materialize_vtable_hypotheses(
            alignment,
            _inventory(0x401000, 0x401010, 0x401020),
            ProcedureExtraction(records, build_alias_groups(records)),
        )
        by_slot = {item.slot_index: item for item in result.hypothesis_sets}

        self.assertEqual(result.supporting_evidence_count, 2)
        self.assertEqual(result.context_evidence_count, 1)
        self.assertEqual(by_slot[0].evidence_effect, "supports")
        self.assertEqual(
            by_slot[0].evidence_reason,
            "equal_index_within_declared_hole_free_tpi_extent",
        )
        self.assertEqual(by_slot[2].evidence_effect, "context")
        self.assertEqual(
            by_slot[2].evidence_reason,
            "slot_at_or_beyond_declared_hole_free_tpi_extent",
        )

    def test_shorter_extent_supports_with_diagnostic(self) -> None:
        alignment = _alignment([0x401000], [0x82009000])
        candidate = alignment.candidates[0]
        short_extent = replace(
            candidate.xbox_extent,
            status="shorter_than_hole_free_xbox_tpi_map",
            extent_suspect=True,
            reference_kind="xbox_tpi_declared_primary_vfptr",
            reference_class="Mapped",
            reference_slot_count=2,
            reference_hole_free=True,
            excess_slot_count=None,
            reasons=("shorter_than_hole_free_xbox_tpi_map",),
        )
        alignment = replace(
            alignment,
            candidates=(replace(candidate, xbox_extent=short_extent),),
        )
        record = _procedure(0x82009000, 1, "?Short@@YAXXZ")

        result = materialize_vtable_hypotheses(
            alignment,
            _inventory(0x401000),
            ProcedureExtraction((record,), ()),
        )
        item = result.hypothesis_sets[0]

        self.assertEqual(item.evidence_effect, "supports")
        self.assertEqual(
            item.evidence_reason, "equal_index_in_shorter_observed_pointer_run"
        )
        self.assertIn(
            "xbox_observed_pointer_run_shorter_than_hole_free_tpi_extent",
            item.evidence_diagnostics,
        )

    def test_large_fold_is_one_bundle_not_member_alternatives(self) -> None:
        alignment = _alignment([0x401000], [0x82004000])
        records = tuple(
            _procedure(0x82004000, ordinal, f"?Fold{ordinal}@@YAXXZ")
            for ordinal in range(1, 1106)
        )
        extraction = ProcedureExtraction(
            records=records,
            alias_groups=build_alias_groups(records),
        )

        result = materialize_vtable_hypotheses(
            alignment, _inventory(0x401000), extraction
        )

        self.assertEqual(result.hypothesis_set_count, 1)
        self.assertEqual(result.alternative_count, 1)
        alternative = result.hypothesis_sets[0].xbox_alternative
        self.assertEqual(alternative.endpoint_kind, "fold_group")
        self.assertEqual(alternative.fold_member_count, 1105)
        self.assertIsNone(alternative.function_id)

    def test_rejects_missing_or_lossy_fold_description(self) -> None:
        alignment = _alignment([0x401000], [0x82005000])
        records = (
            _procedure(0x82005000, 1, "?A@@YAXXZ"),
            _procedure(0x82005000, 2, "?B@@YAXXZ"),
        )
        extraction = ProcedureExtraction(records=records, alias_groups=())

        with self.assertRaisesRegex(VtableHypothesisError, "no lossless fold group"):
            materialize_vtable_hypotheses(
                alignment, _inventory(0x401000), extraction
            )

    def test_input_order_does_not_change_materialization(self) -> None:
        alignment = _alignment([0x401000, 0x401100], [0x82006000, 0x82007000])
        records = (
            _procedure(0x82006000, 1, "?One@@YAXXZ"),
            _procedure(0x82007000, 2, "?Two@@YAXXZ"),
        )
        forward = ProcedureExtraction(
            records=records,
            alias_groups=build_alias_groups(records),
        )
        reversed_extraction = replace(forward, records=tuple(reversed(records)))

        first = materialize_vtable_hypotheses(
            alignment, _inventory(0x401000, 0x401100), forward
        )
        second = materialize_vtable_hypotheses(
            alignment,
            PCInventory(
                image_base=0x400000,
                functions=tuple(reversed(_inventory(0x401000, 0x401100).functions)),
            ),
            reversed_extraction,
        )

        self.assertEqual(first.to_dict(), second.to_dict())

    def test_wrong_address_space_does_not_resolve_same_numeric_address(self) -> None:
        alignment = _alignment([0x401000], [0x82006000])
        candidate = alignment.candidates[0]
        pair = candidate.slot_pairs[0]
        wrong_pc_slot = replace(pair.pc_slot, target_address_space="file-offset")
        wrong_xbox_slot = replace(
            pair.xbox_slot, target_address_space="section-relative"
        )
        alignment = replace(
            alignment,
            candidates=(
                replace(
                    candidate,
                    slot_pairs=(
                        replace(
                            pair,
                            pc_slot=wrong_pc_slot,
                            xbox_slot=wrong_xbox_slot,
                        ),
                    ),
                ),
            ),
        )
        record = _procedure(0x82006000, 1, "?SameNumber@@YAXXZ")

        result = materialize_vtable_hypotheses(
            alignment,
            _inventory(0x401000),
            ProcedureExtraction((record,), ()),
        )
        item = result.hypothesis_sets[0]

        self.assertEqual(item.pc_subject.endpoint_kind, "unresolved_address")
        self.assertEqual(item.pc_subject.address_space, "file-offset")
        self.assertEqual(
            item.xbox_alternative.endpoint_kind, "unresolved_address"
        )
        self.assertEqual(
            item.xbox_alternative.address_space, "section-relative"
        )


if __name__ == "__main__":
    unittest.main()
