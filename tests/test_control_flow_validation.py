from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import AtlasDatabase  # noqa: E402
from fnv_atlas.ppc_control_flow import (  # noqa: E402
    ExecutableImage,
    ExecutableSection,
    IMAGE_FILE_MACHINE_POWERPCBE,
    ProcedureExtent,
    extract_ppc_control_flow,
)
from fnv_atlas.validation import (  # noqa: E402
    semantic_validation_counts,
    semantic_validation_ok,
)


def _immediate_branch(address: int, target: int, *, link: bool = False) -> int:
    return 0x48000000 | ((target - address) & 0x03FFFFFC) | int(link)


def _control_flow_fixture():
    start = 0x1000
    data = bytearray(0x400)
    words = {
        0x1000: _immediate_branch(0x1000, 0x1100, link=True),
        0x1004: _immediate_branch(0x1004, 0x1200),
        0x1008: _immediate_branch(0x1008, 0x1300, link=True),
        0x100C: 0x4E800421,
        0x1100: 0x4E800020,
        0x1200: 0x4E800020,
    }
    for address, word in words.items():
        struct.pack_into(">I", data, address - start, word)
    image = ExecutableImage(
        data=bytes(data),
        machine=IMAGE_FILE_MACHINE_POWERPCBE,
        image_base=0,
        sections=(
            ExecutableSection(
                ".text", start, len(data), 0, len(data), 0x60000020
            ),
        ),
    )
    return extract_ppc_control_flow(
        image,
        (
            ProcedureExtent("caller", 0x1000, 0x10),
            ProcedureExtent("unique", 0x1100, 4),
            ProcedureExtent("fold-a", 0x1200, 4),
            ProcedureExtent("fold-b", 0x1200, 4),
        ),
    )


class ControlFlowSemanticValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("xbox", platform="xbox360", name="Xbox")
        self.symbol_provenance = self.db.upsert_provenance(
            kind="extraction", producer="fixture.symbols"
        )
        self.control_flow_provenance = self.db.upsert_provenance(
            kind="extraction", producer="fnv_atlas.ppc_control_flow"
        )
        for record_id, address in (
            ("caller", 0x1000),
            ("unique", 0x1100),
            ("fold-a", 0x1200),
            ("fold-b", 0x1200),
        ):
            address_group = self.db.upsert_address_group(
                program_id="xbox",
                address_space="xbox-va",
                address=address,
            )
            self.db.upsert_function(
                function_id=record_id,
                address_group_id=address_group,
                identity_key=record_id,
                provenance_id=self.symbol_provenance,
            )
            self.db.add_function_name(
                record_id,
                f"fixture::{record_id}",
                name_kind="fixture",
                provenance_id=self.symbol_provenance,
            )
        self.fold_group = self.db.upsert_fold_group(
            "x360-fold:00001200",
            program_id="xbox",
            provenance_id=self.symbol_provenance,
        )
        self.db.add_fold_member(self.fold_group, "fold-a")
        self.db.add_fold_member(self.fold_group, "fold-b")
        self.extraction = _control_flow_fixture()
        self.result = self.db.persist_control_flow_extraction(
            self.extraction,
            program_id="xbox",
            provenance_id=self.control_flow_provenance,
        )

    def tearDown(self) -> None:
        self.db.close()

    def _counts(self) -> dict[str, int]:
        return semantic_validation_counts(self.db.connection)

    def _drop_triggers(self, *trigger_names: str) -> None:
        for trigger_name in trigger_names:
            self.db.connection.execute(f"DROP TRIGGER {trigger_name}")

    def test_valid_control_flow_extraction_has_zero_semantic_violations(self) -> None:
        counts = self._counts()
        self.assertTrue(semantic_validation_ok(counts))
        self.assertTrue(
            all(
                count == 0
                for name, count in counts.items()
                if name.startswith("control_flow_")
            )
        )

    def test_detects_metadata_policy_and_orphan_relationships(self) -> None:
        uses = {
            row["site_address"]: row
            for row in self.db.iter_control_flow_uses(
                extraction_id=self.result.extraction_id
            )
        }
        self._drop_triggers(
            "reject_control_flow_site_assertion_delete",
            "reject_control_flow_use_assertion_update",
            "reject_control_flow_use_assertion_delete",
            "reject_control_flow_use_update",
            "reject_control_flow_scan_delete",
        )
        self.db.connection.execute(
            "UPDATE control_flow_use_assertions SET role = 'local_branch' "
            "WHERE assertion_id = ?",
            (uses[0x1000]["assertion_id"],),
        )
        self.db.connection.execute(
            "DELETE FROM control_flow_site_assertions "
            "WHERE extraction_id = ? AND raw_site_va = ?",
            (self.result.extraction_id, 0x1004),
        )
        self.db.connection.execute(
            "DELETE FROM control_flow_use_assertions WHERE assertion_id = ?",
            (uses[0x1008]["assertion_id"],),
        )
        self.db.connection.execute(
            "UPDATE control_flow_uses SET procedure_record_id = 'missing-record' "
            "WHERE use_id = ?",
            (uses[0x100C]["use_id"],),
        )
        self.db.connection.execute(
            "DELETE FROM control_flow_scans "
            "WHERE extraction_id = ? AND procedure_record_id = 'unique'",
            (self.result.extraction_id,),
        )

        counts = self._counts()
        for check_name in (
            "control_flow_metadata_row_count_mismatch",
            "control_flow_policy_trigger_count_mismatch",
            "control_flow_sites_without_policy_trigger_use",
            "control_flow_sites_without_any_use",
            "control_flow_uses_without_site_assertion",
            "control_flow_uses_without_matching_scan",
            "control_flow_canonical_sites_without_assertions",
            "control_flow_canonical_uses_without_assertions",
            "control_flow_scan_use_count_mismatch",
            "control_flow_scan_total_mismatch",
        ):
            self.assertGreater(counts[check_name], 0, check_name)

    def test_detects_extent_and_full_scan_count_tampering(self) -> None:
        self._drop_triggers("reject_control_flow_scan_update")
        self.db.connection.execute(
            """
            UPDATE control_flow_scans
            SET scanned_size = 4,
                unscanned_byte_count = declared_size - 4,
                source_branch_use_count = source_branch_use_count + 1,
                persisted_branch_use_count = persisted_branch_use_count - 1
            WHERE extraction_id = ? AND procedure_record_id = 'caller'
            """,
            (self.result.extraction_id,),
        )

        counts = self._counts()
        self.assertEqual(counts["control_flow_use_outside_scan_extent"], 3)
        self.assertEqual(counts["control_flow_scan_use_count_mismatch"], 1)
        self.assertEqual(counts["control_flow_scan_total_mismatch"], 1)
        self.assertEqual(counts["control_flow_metadata_row_count_mismatch"], 0)

    def test_detects_endpoint_cardinality_addressing_and_raw_mismatches(self) -> None:
        for function_id, address in (
            ("extra-unique", 0x1100),
            ("extra-fold", 0x1200),
            ("hidden-entry", 0x1300),
        ):
            address_group = self.db.upsert_address_group(
                program_id="xbox",
                address_space="xbox-va",
                address=address,
            )
            self.db.upsert_function(
                function_id=function_id,
                address_group_id=address_group,
                identity_key=function_id,
                provenance_id=self.symbol_provenance,
            )
        rogue_address = self.db.upsert_address_group(
            program_id="xbox", address_space="ram", address=0x1400
        )
        self.db.upsert_control_flow_site(
            "rogue-non-xbox-site", address_group_id=rogue_address
        )
        self._drop_triggers(
            "reject_control_flow_site_assertion_update",
            "reject_control_flow_scan_update",
        )
        self.db.connection.execute(
            """
            UPDATE control_flow_site_assertions SET raw_target_va = 57005
            WHERE extraction_id = ? AND raw_site_va = 4096
            """,
            (self.result.extraction_id,),
        )
        non_entry_address = self.db.connection.execute(
            """
            SELECT address_group_id FROM address_groups
            WHERE program_id = 'xbox' AND address_space = 'xbox-va'
              AND address = 4864
            """
        ).fetchone()[0]
        self.db.connection.execute(
            """
            UPDATE control_flow_scans SET scan_address_group_id = ?
            WHERE extraction_id = ? AND procedure_record_id = 'unique'
            """,
            (non_entry_address, self.result.extraction_id),
        )

        counts = self._counts()
        self.assertEqual(
            counts["control_flow_unique_endpoint_cardinality_mismatch"], 1
        )
        self.assertEqual(
            counts["control_flow_fold_endpoint_cardinality_mismatch"], 1
        )
        self.assertEqual(
            counts["control_flow_non_entry_endpoint_cardinality_mismatch"], 1
        )
        self.assertEqual(counts["control_flow_raw_endpoint_mismatch"], 1)
        self.assertEqual(counts["control_flow_scan_endpoint_mismatch"], 1)
        self.assertGreater(counts["control_flow_non_xbox_addressing"], 0)

    def test_detects_control_flow_provenance_leaking_into_mapping_facts(self) -> None:
        leaked_group = self.db.upsert_address_group(
            program_id="xbox", address_space="xbox-va", address=0x1500
        )
        leaked_function = self.db.upsert_function(
            function_id="leaked-function",
            address_group_id=leaked_group,
            identity_key="leaked-function",
            provenance_id=self.control_flow_provenance,
        )
        self.db.add_function_name(
            leaked_function,
            "leaked::name",
            name_kind="fixture",
            provenance_id=self.control_flow_provenance,
        )
        pc_group = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x401000
        )
        pc_function = self.db.upsert_function(
            function_id="pc-function",
            address_group_id=pc_group,
            identity_key="pc-function",
            provenance_id=self.symbol_provenance,
        )
        claim = self.db.upsert_match_claim(
            pc_function_id=pc_function,
            xbox_function_id="unique",
            provenance_id=self.control_flow_provenance,
        )
        self.db.add_claim_evidence(
            claim,
            effect="context",
            evidence_kind="fixture-leak",
            independence_group="fixture-leak",
            provenance_id=self.control_flow_provenance,
        )

        counts = self._counts()
        self.assertGreater(
            counts["control_flow_provenance_created_function_or_name"], 0
        )
        self.assertGreater(
            counts["control_flow_provenance_created_match_state"], 0
        )


if __name__ == "__main__":
    unittest.main()
