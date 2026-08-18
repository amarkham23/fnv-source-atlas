from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sqlite3
import struct
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import (  # noqa: E402
    AtlasDatabase,
    AtlasError,
    IdentityConflictError,
)
from fnv_atlas.ppc_control_flow import (  # noqa: E402
    ControlFlowExtraction,
    ExecutableImage,
    ExecutableSection,
    IMAGE_FILE_MACHINE_POWERPCBE,
    ProcedureExtent,
    ProcedureScan,
    extract_ppc_control_flow,
)


def _immediate_branch(address: int, target: int, *, link: bool = False) -> int:
    return 0x48000000 | ((target - address) & 0x03FFFFFC) | int(link)


def _conditional_branch(address: int, target: int) -> int:
    return 0x40000000 | (20 << 21) | ((target - address) & 0xFFFC)


def _fixture_extraction() -> ControlFlowExtraction:
    start = 0x1000
    size = 0x400
    data = bytearray(size)
    words = {
        0x1000: _immediate_branch(0x1000, 0x1100, link=True),
        0x1004: _conditional_branch(0x1004, 0x100C),
        0x1008: 0x4E800421,  # bctrl / indirect call
        0x100C: _immediate_branch(0x100C, 0x1200),  # folded tail target
        0x1010: _immediate_branch(0x1010, 0x1014, link=True),  # LR setup
        0x1014: _immediate_branch(0x1014, 0x1300, link=True),  # non-entry
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
                name=".text",
                start=start,
                virtual_size=size,
                raw_offset=0,
                raw_size=size,
                characteristics=0x60000020,
            ),
        ),
    )
    return extract_ppc_control_flow(
        image,
        (
            ProcedureExtent("caller", 0x1000, 0x18),
            ProcedureExtent("unique", 0x1100, 4),
            ProcedureExtent("fold-a", 0x1200, 4),
            ProcedureExtent("fold-b", 0x1200, 4),
        ),
    )


class ControlFlowDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("x360", platform="xbox360", name="Xbox")
        self.provenance = self.db.upsert_provenance(
            kind="control-flow", producer="control-flow-db-tests", producer_version="1"
        )
        self.second_provenance = self.db.upsert_provenance(
            kind="control-flow", producer="control-flow-db-tests", producer_version="2"
        )
        for record_id, address in (
            ("caller", 0x1000),
            ("unique", 0x1100),
            ("fold-a", 0x1200),
            ("fold-b", 0x1200),
        ):
            address_group = self.db.upsert_address_group(
                program_id="x360", address_space="xbox-va", address=address
            )
            self.db.upsert_function(
                function_id=record_id,
                address_group_id=address_group,
                identity_key=record_id,
            )
            self.db.add_function_name(
                record_id,
                f"name-for-{record_id}",
                name_kind="test",
                provenance_id=self.provenance,
            )
        self.fold_group = self.db.upsert_fold_group(
            "x360-fold:00001200",
            program_id="x360",
            provenance_id=self.provenance,
        )
        self.db.add_fold_member(self.fold_group, "fold-a")
        self.db.add_fold_member(self.fold_group, "fold-b")
        self.extraction = _fixture_extraction()

    def tearDown(self) -> None:
        self.db.close()

    def test_call_relevant_policy_is_identity_safe_and_non_destructive(self) -> None:
        prior_target_address = self.db.upsert_address_group(
            program_id="x360",
            address_space="xbox-va",
            address=0x1300,
            kind="prior-address-kind",
            details={"producer": "prior"},
        )
        functions_before = self.db.connection.execute(
            "SELECT COUNT(*) FROM functions"
        ).fetchone()[0]
        names_before = self.db.connection.execute(
            "SELECT COUNT(*) FROM function_names"
        ).fetchone()[0]
        result = self.db.persist_control_flow_extraction(
            self.extraction,
            program_id="x360",
            provenance_id=self.provenance,
        )

        self.assertEqual(result.source_physical_sites, 8)
        self.assertEqual(result.source_logical_uses, 9)
        self.assertEqual(result.persisted_physical_sites, 4)
        self.assertEqual(result.persisted_logical_uses, 4)
        self.assertEqual(result.triggering_logical_uses, 4)
        self.assertEqual(result.procedure_scans, 4)
        self.assertTrue(self.db.validate_control_flow_extraction(result.extraction_id))

        stored = self.db.get_control_flow_extraction(result.extraction_id)
        assert stored is not None
        self.assertEqual(stored["persistence_policy"], "call_relevant_v1")
        self.assertEqual(stored["source_physical_site_count"], 8)
        self.assertEqual(stored["persisted_physical_site_count"], 4)
        self.assertTrue(
            stored["details"]["all_memberships_of_selected_sites_retained"]
        )

        sites = {
            row["raw_site_va"]: row
            for row in self.db.iter_control_flow_sites(
                extraction_id=result.extraction_id
            )
        }
        self.assertEqual(set(sites), {0x1000, 0x1008, 0x100C, 0x1014})
        self.assertEqual(sites[0x1000]["target_function_id"], "unique")
        self.assertEqual(sites[0x100C]["target_kind"], "fold_group")
        self.assertEqual(
            sites[0x100C]["target_fold_group_id"], "x360-fold:00001200"
        )
        self.assertIsNone(sites[0x100C]["target_function_id"])
        self.assertEqual(sites[0x100C]["target_record_count"], 2)
        self.assertEqual(sites[0x1008]["target_kind"], "indirect")
        self.assertIsNone(sites[0x1008]["target_address_group_id"])
        self.assertEqual(sites[0x1014]["target_kind"], "executable_non_entry")
        self.assertEqual(sites[0x1014]["raw_target_va"], 0x1300)
        self.assertEqual(
            self.db.functions_at("x360", "xbox-va", 0x1300), []
        )

        uses = list(
            self.db.iter_control_flow_uses(extraction_id=result.extraction_id)
        )
        self.assertEqual({row["procedure_record_id"] for row in uses}, {"caller"})
        self.assertEqual(
            {row["role"] for row in uses},
            {"direct_call", "tail_transfer", "indirect_call"},
        )
        scans = {
            row["procedure_record_id"]: row
            for row in self.db.iter_control_flow_scans(result.extraction_id)
        }
        self.assertEqual(len(scans), 4)
        self.assertEqual(scans["caller"]["source_branch_use_count"], 6)
        self.assertEqual(scans["caller"]["persisted_branch_use_count"], 4)
        self.assertEqual(scans["fold-a"]["persisted_branch_use_count"], 0)

        self.assertEqual(
            self.db.connection.execute("SELECT COUNT(*) FROM functions").fetchone()[0],
            functions_before,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM function_names"
            ).fetchone()[0],
            names_before,
        )
        self.assertEqual(
            self.db.connection.execute("SELECT COUNT(*) FROM match_claims").fetchone()[0],
            0,
        )
        prior_address = self.db.connection.execute(
            """
            SELECT kind, details_json FROM address_groups
            WHERE address_group_id = ?
            """,
            (prior_target_address,),
        ).fetchone()
        self.assertEqual(prior_address["kind"], "prior-address-kind")
        self.assertEqual(prior_address["details_json"], '{"producer":"prior"}')

        # Exact replay is idempotent and does not duplicate producer assertions.
        replay = self.db.persist_control_flow_extraction(
            self.extraction,
            program_id="x360",
            provenance_id=self.provenance,
        )
        self.assertEqual(replay.extraction_id, result.extraction_id)
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM control_flow_site_assertions"
            ).fetchone()[0],
            4,
        )

    def test_multi_producer_assertions_share_physical_and_logical_identity(self) -> None:
        first = self.db.persist_control_flow_extraction(
            self.extraction,
            program_id="x360",
            provenance_id=self.provenance,
        )
        second = self.db.persist_control_flow_extraction(
            self.extraction,
            program_id="x360",
            provenance_id=self.second_provenance,
        )
        self.assertNotEqual(first.extraction_id, second.extraction_id)
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM control_flow_sites"
            ).fetchone()[0],
            4,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM control_flow_uses"
            ).fetchone()[0],
            4,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM control_flow_site_assertions"
            ).fetchone()[0],
            8,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM control_flow_use_assertions"
            ).fetchone()[0],
            8,
        )
        site = self.db.get_control_flow_site("x360-ppc-branch:xbox-va:00001000")
        assert site is not None
        self.assertEqual(len(site["assertions"]), 2)
        self.assertEqual(len(site["uses"]), 2)

        assertion_id = site["assertions"][0]["assertion_id"]
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                UPDATE control_flow_site_assertions SET instruction_word = 0
                WHERE assertion_id = ?
                """,
                (assertion_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "DELETE FROM control_flow_site_assertions WHERE assertion_id = ?",
                (assertion_id,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "physical sites"):
            self.db.connection.execute(
                """
                UPDATE control_flow_sites SET address_group_id = ?
                WHERE site_id = ?
                """,
                (
                    self.db.connection.execute(
                        """
                        SELECT address_group_id FROM functions
                        WHERE function_id = 'unique'
                        """
                    ).fetchone()[0],
                    "x360-ppc-branch:xbox-va:00001000",
                ),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "logical uses"):
            self.db.connection.execute(
                """
                UPDATE control_flow_uses SET procedure_record_id = 'moved-record'
                WHERE use_id = (
                    SELECT use_id FROM control_flow_uses ORDER BY use_id LIMIT 1
                )
                """
            )

    def test_all_branches_policy_and_unresolved_scan_coverage(self) -> None:
        all_result = self.db.persist_control_flow_extraction(
            self.extraction,
            program_id="x360",
            provenance_id=self.provenance,
            policy="all_branches_v1",
        )
        self.assertEqual(all_result.persisted_physical_sites, 8)
        self.assertEqual(all_result.persisted_logical_uses, 9)
        self.assertEqual(all_result.triggering_logical_uses, 9)
        self.assertTrue(self.db.validate_control_flow_extraction(all_result.extraction_id))

        unresolved_target = self.db.upsert_unresolved_target(
            target_id="unresolved-record-target",
            program_id="x360",
            target_kind="pdb-procedure-without-va",
            name_hint="record-without-va",
            provenance_id=self.provenance,
        )
        no_va = ControlFlowExtraction(
            sites=(),
            uses=(),
            scans=(
                ProcedureScan(
                    record_id="record-without-va",
                    va=None,
                    declared_size=12,
                    scanned_size=0,
                    unscanned_byte_count=12,
                    status="unresolved_va",
                    branch_use_count=0,
                ),
            ),
        )
        unresolved_result = self.db.persist_control_flow_extraction(
            no_va,
            program_id="x360",
            provenance_id=self.provenance,
            unresolved_target_ids={"record-without-va": unresolved_target},
        )
        scan = next(self.db.iter_control_flow_scans(unresolved_result.extraction_id))
        self.assertEqual(scan["unresolved_target_id"], unresolved_target)
        self.assertIsNone(scan["scan_address_group_id"])

    def test_policy_endpoint_extent_and_platform_guards(self) -> None:
        with self.assertRaises(IdentityConflictError):
            self.db.persist_control_flow_extraction(
                self.extraction,
                program_id="pc",
                provenance_id=self.provenance,
            )

        broken_use = replace(self.extraction.uses[0], site_va=0x2000)
        malformed = replace(
            self.extraction,
            uses=(broken_use, *self.extraction.uses[1:]),
        )
        with self.assertRaisesRegex(ValueError, "physical site VA"):
            self.db.persist_control_flow_extraction(
                malformed,
                program_id="x360",
                provenance_id=self.provenance,
            )

        result = self.db.persist_control_flow_extraction(
            self.extraction,
            program_id="x360",
            provenance_id=self.provenance,
        )
        wrong_target = self.db.upsert_address_group(
            program_id="x360", address_space="xbox-va", address=0x1400
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.add_control_flow_site_assertion(
                result.extraction_id,
                "x360-ppc-branch:xbox-va:00001000",
                assertion_id="wrong-endpoint",
                raw_site_va=0x1000,
                instruction_word=_immediate_branch(0x1000, 0x1100, link=True),
                branch_kind="branch_immediate",
                raw_target_va=0x1100,
                target_address_group_id=wrong_target,
                target_function_id="unique",
                target_kind="unique_procedure",
                target_record_count=1,
                link=True,
                absolute=False,
                conditional=False,
                indirect=False,
            )

    def test_selected_site_retains_nontriggering_membership(self) -> None:
        data = bytearray(0x40)
        struct.pack_into(">I", data, 0, _immediate_branch(0x2000, 0x2010))
        image = ExecutableImage(
            data=bytes(data),
            machine=IMAGE_FILE_MACHINE_POWERPCBE,
            image_base=0,
            sections=(
                ExecutableSection(
                    ".text", 0x2000, 0x40, 0, 0x40, 0x60000020
                ),
            ),
        )
        overlapping = extract_ppc_control_flow(
            image,
            (
                ProcedureExtent("narrow", 0x2000, 4),
                ProcedureExtent("wide", 0x2000, 0x20),
            ),
        )
        address = self.db.upsert_address_group(
            program_id="x360", address_space="xbox-va", address=0x2000
        )
        self.db.upsert_function(
            function_id="canonical-overlap",
            address_group_id=address,
            identity_key="canonical-overlap",
        )
        result = self.db.persist_control_flow_extraction(
            overlapping,
            program_id="x360",
            provenance_id=self.provenance,
            procedure_function_ids={
                "narrow": "canonical-overlap",
                "wide": "canonical-overlap",
            },
        )
        self.assertEqual(result.persisted_physical_sites, 1)
        self.assertEqual(result.persisted_logical_uses, 2)
        self.assertEqual(result.triggering_logical_uses, 1)
        self.assertEqual(
            {
                row["role"]
                for row in self.db.iter_control_flow_uses(
                    extraction_id=result.extraction_id
                )
            },
            {"tail_transfer", "local_branch"},
        )
        self.assertEqual(
            {
                row["procedure_record_id"]
                for row in self.db.iter_control_flow_uses(
                    extraction_id=result.extraction_id
                )
            },
            {"narrow", "wide"},
        )

    def test_unique_target_requires_exactly_one_function_at_address(self) -> None:
        target_address = self.db.upsert_address_group(
            program_id="x360", address_space="xbox-va", address=0x1100
        )
        self.db.upsert_function(
            function_id="unreported-unique-alias",
            address_group_id=target_address,
            identity_key="unreported-unique-alias",
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "not unique"):
            self.db.persist_control_flow_extraction(
                self.extraction,
                program_id="x360",
                provenance_id=self.provenance,
            )

    def test_fold_target_must_cover_every_function_at_address(self) -> None:
        target_address = self.db.upsert_address_group(
            program_id="x360", address_space="xbox-va", address=0x1200
        )
        self.db.upsert_function(
            function_id="unreported-fold-alias",
            address_group_id=target_address,
            identity_key="unreported-fold-alias",
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "fold target"):
            self.db.persist_control_flow_extraction(
                self.extraction,
                program_id="x360",
                provenance_id=self.provenance,
            )

    def test_non_entry_target_requires_zero_functions_at_address(self) -> None:
        target_address = self.db.upsert_address_group(
            program_id="x360", address_space="xbox-va", address=0x1300
        )
        self.db.upsert_function(
            function_id="hidden-entry",
            address_group_id=target_address,
            identity_key="hidden-entry",
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "has a function"):
            self.db.persist_control_flow_extraction(
                self.extraction,
                program_id="x360",
                provenance_id=self.provenance,
            )

    def test_procedure_record_mapping_applies_to_uses_scans_and_targets(self) -> None:
        data = bytearray(0x200)
        struct.pack_into(
            ">I", data, 0, _immediate_branch(0x3000, 0x3100, link=True)
        )
        struct.pack_into(">I", data, 0x100, 0x4E800020)
        image = ExecutableImage(
            data=bytes(data),
            machine=IMAGE_FILE_MACHINE_POWERPCBE,
            image_base=0,
            sections=(
                ExecutableSection(
                    ".text", 0x3000, 0x200, 0, 0x200, 0x60000020
                ),
            ),
        )
        extraction = extract_ppc_control_flow(
            image,
            (
                ProcedureExtent("pdb-caller", 0x3000, 4),
                ProcedureExtent("pdb-target", 0x3100, 4),
            ),
        )
        for function_id, address in (
            ("canonical-caller", 0x3000),
            ("canonical-target", 0x3100),
        ):
            address_group = self.db.upsert_address_group(
                program_id="x360", address_space="xbox-va", address=address
            )
            self.db.upsert_function(
                function_id=function_id,
                address_group_id=address_group,
                identity_key=function_id,
            )

        result = self.db.persist_control_flow_extraction(
            extraction,
            program_id="x360",
            provenance_id=self.provenance,
            procedure_function_ids={
                "pdb-caller": "canonical-caller",
                "pdb-target": "canonical-target",
            },
        )
        site = next(
            self.db.iter_control_flow_sites(extraction_id=result.extraction_id)
        )
        self.assertEqual(site["target_function_id"], "canonical-target")
        use = next(
            self.db.iter_control_flow_uses(extraction_id=result.extraction_id)
        )
        self.assertEqual(use["procedure_record_id"], "pdb-caller")
        self.assertEqual(use["function_id"], "canonical-caller")
        scans = {
            scan["procedure_record_id"]: scan
            for scan in self.db.iter_control_flow_scans(result.extraction_id)
        }
        self.assertEqual(scans["pdb-caller"]["function_id"], "canonical-caller")
        self.assertEqual(scans["pdb-target"]["function_id"], "canonical-target")

    def test_validator_rejects_call_policy_site_without_triggering_role(self) -> None:
        extraction_id = self.db.upsert_control_flow_extraction(
            extraction_id="manual-incomplete-extraction",
            program_id="x360",
            persistence_policy="call_relevant_v1",
            source_physical_site_count=1,
            source_logical_use_count=1,
            persisted_physical_site_count=1,
            persisted_logical_use_count=1,
            triggering_logical_use_count=0,
            procedure_scan_count=1,
            provenance_id=self.provenance,
        )
        address = self.db.upsert_address_group(
            program_id="x360", address_space="xbox-va", address=0x1100
        )
        self.db.upsert_control_flow_site("manual-return-site", address_group_id=address)
        self.db.upsert_control_flow_use(
            "manual-return-use",
            procedure_record_id="unique",
            function_id="unique",
            site_id="manual-return-site",
        )
        self.db.add_control_flow_use_assertion(
            extraction_id,
            "manual-return-use",
            role="return_or_indirect_branch",
        )
        self.db.add_control_flow_site_assertion(
            extraction_id,
            "manual-return-site",
            raw_site_va=0x1100,
            instruction_word=0x4E800020,
            branch_kind="branch_to_link_register",
            raw_target_va=None,
            target_kind="indirect",
            target_record_count=0,
            link=False,
            absolute=False,
            conditional=True,
            indirect=True,
            bo=20,
            bi=0,
        )
        self.db.add_control_flow_scan(
            extraction_id,
            procedure_record_id="unique",
            function_id="unique",
            scan_address_group_id=address,
            declared_size=4,
            scanned_size=4,
            unscanned_byte_count=0,
            status="ok",
            source_branch_use_count=1,
            persisted_branch_use_count=1,
        )
        with self.assertRaisesRegex(AtlasError, "policy-triggering"):
            self.db.validate_control_flow_extraction(extraction_id)


if __name__ == "__main__":
    unittest.main()
