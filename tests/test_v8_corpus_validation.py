from __future__ import annotations

from pathlib import Path
import sys
import time
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import AtlasDatabase  # noqa: E402
from fnv_atlas.validation import (  # noqa: E402
    semantic_validation_counts,
    semantic_validation_ok,
)
from tests.test_sdk_database import _extract_and_join  # noqa: E402
from tests.test_vftable_database import _corpus  # noqa: E402


V8_PREFIXES = ("xbox_vftable_", "sdk_")


class V8CorpusSemanticValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory, self.sdk_extraction, self.sdk_join = _extract_and_join()
        self.db = AtlasDatabase.create(":memory:")
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("xbox", platform="xbox360", name="Xbox")
        self.symbol_provenance = self.db.upsert_provenance(
            kind="test", producer="v8-validation-symbol-fixture"
        )
        pc_address = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x401000
        )
        self.pc_function = self.db.upsert_function(
            function_id="pc:ram:00401000",
            address_group_id=pc_address,
            identity_key="inventory",
            provenance_id=self.symbol_provenance,
        )
        self.vftable_provenance = self.db.upsert_provenance(
            kind="extraction", producer="v8-validation-vftable-fixture"
        )
        self.sdk_provenance = self.db.upsert_provenance(
            kind="extraction", producer="v8-validation-sdk-fixture"
        )
        self.db.persist_vftable_corpus(
            "vftable-v8",
            _corpus(),
            program_id="xbox",
            provenance_id=self.vftable_provenance,
        )
        self.db.persist_sdk_extraction(
            "sdk-v8",
            self.sdk_extraction,
            self.sdk_join,
            pc_program_id="pc",
            provenance_id=self.sdk_provenance,
        )

    def tearDown(self) -> None:
        self.db.close()
        self.directory.cleanup()

    def _counts(self) -> dict[str, int]:
        return semantic_validation_counts(self.db.connection)

    def _drop_triggers_for(self, table_prefix: str, *extra_names: str) -> None:
        trigger_names = {
            row[0]
            for row in self.db.connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'trigger' AND tbl_name LIKE ?
                """,
                (table_prefix + "%",),
            )
        }
        trigger_names.update(extra_names)
        existing = {
            row[0]
            for row in self.db.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        for trigger_name in sorted(trigger_names & existing):
            self.db.connection.execute(f'DROP TRIGGER "{trigger_name}"')

    def _disable_foreign_keys(self) -> None:
        self.db.connection.commit()
        self.db.connection.execute("PRAGMA foreign_keys = OFF")
        self.assertEqual(
            self.db.connection.execute("PRAGMA foreign_keys").fetchone()[0], 0
        )

    def test_complete_v8_corpora_are_semantically_valid(self) -> None:
        counts = self._counts()
        relevant = {
            name: count
            for name, count in counts.items()
            if name.startswith(V8_PREFIXES)
        }
        self.assertEqual(len(relevant), 22)
        self.assertTrue(all(count == 0 for count in relevant.values()), relevant)
        self.assertTrue(semantic_validation_ok(counts), counts)

    def test_real_vftable_boundary_contract_is_semantically_valid(self) -> None:
        with AtlasDatabase.create(":memory:") as database:
            database.upsert_program("xbox", platform="xbox360", name="Xbox")
            provenance = database.upsert_provenance(
                kind="extraction", producer="real-vftable-boundary-contract"
            )
            database.persist_vftable_corpus(
                "vftable-boundary-after-prefix",
                _corpus(second_table_offset=16),
                program_id="xbox",
                provenance_id=provenance,
            )
            counts = semantic_validation_counts(database.connection)
        relevant = {
            name: count
            for name, count in counts.items()
            if name.startswith("xbox_vftable_")
        }
        self.assertTrue(all(count == 0 for count in relevant.values()), relevant)

    def test_detects_vftable_summary_raw_membership_boundary_and_domain_tampering(
        self,
    ) -> None:
        self._drop_triggers_for(
            "xbox_vftable_", "protect_vftable_address_identity_update"
        )
        self._disable_foreign_keys()

        self.db.connection.execute(
            """
            UPDATE xbox_vftable_extractions
            SET physical_record_count = physical_record_count + 1,
                unresolved_record_count = unresolved_record_count + 1
            WHERE extraction_id = 'vftable-v8'
            """
        )
        self.db.connection.execute(
            """
            UPDATE xbox_vftable_name_identities SET decorated_name_bytes = x'01'
            WHERE canonical_name_id = (
                SELECT canonical_name_id FROM xbox_vftable_name_identities LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE xbox_vftable_symbol_records SET raw_record_sha256 = ?
            WHERE vftable_record_id = (
                SELECT vftable_record_id FROM xbox_vftable_symbol_records LIMIT 1
            )
            """,
            ("0" * 64,),
        )
        self.db.connection.execute(
            """
            DELETE FROM xbox_vftable_symbol_assertions
            WHERE assertion_id = (
                SELECT assertion_id FROM xbox_vftable_symbol_assertions
                WHERE resolved_va IS NULL LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE xbox_vftable_symbol_assertions SET program_id = 'pc'
            WHERE assertion_id = (
                SELECT assertion_id FROM xbox_vftable_symbol_assertions LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            DELETE FROM xbox_vftable_address_members
            WHERE membership_id = (
                SELECT membership_id FROM xbox_vftable_address_members LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            DELETE FROM xbox_vftable_pointer_run_symbols
            WHERE run_symbol_id = (
                SELECT run_symbol_id FROM xbox_vftable_pointer_run_symbols
                WHERE membership_role = 'next' LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE xbox_vftable_pointer_runs
            SET observed_pointer_count = observed_pointer_count + 1
            WHERE pointer_run_id = (
                SELECT pointer_run_id FROM xbox_vftable_pointer_runs LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE address_groups SET address_space = 'ram'
            WHERE address_group_id = (
                SELECT table_address_group_id FROM xbox_vftable_pointer_runs LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE xbox_vftable_diagnostics SET source_ordinal = 99
            WHERE diagnostic_id = (
                SELECT diagnostic_id FROM xbox_vftable_diagnostics LIMIT 1
            )
            """
        )
        self.db.add_function_name(
            self.pc_function,
            "VftableProducerLeak",
            name_kind="vftable-producer-leak",
            provenance_id=self.vftable_provenance,
        )

        counts = self._counts()
        for name in (
            "xbox_vftable_extraction_summary_mismatch",
            "xbox_vftable_name_identity_mismatch",
            "xbox_vftable_record_integrity_mismatch",
            "xbox_vftable_records_without_assertions",
            "xbox_vftable_symbol_assertion_identity_mismatch",
            "xbox_vftable_address_membership_mismatch",
            "xbox_vftable_pointer_run_membership_mismatch",
            "xbox_vftable_pointer_run_observation_mismatch",
            "xbox_vftable_non_xbox_addressing",
            "xbox_vftable_diagnostic_identity_mismatch",
            "xbox_vftable_provenance_leakage",
        ):
            self.assertGreater(counts[name], 0, name)

    def test_detects_sdk_tree_join_variant_boundary_and_provenance_tampering(
        self,
    ) -> None:
        self._drop_triggers_for(
            "sdk_",
            "protect_sdk_program_platform_update",
            "protect_sdk_linked_function_endpoint_update",
            "protect_sdk_address_identity_update",
        )
        self._disable_foreign_keys()

        self.db.connection.execute(
            """
            UPDATE sdk_extractions SET prototype_count = prototype_count + 1
            WHERE extraction_id = 'sdk-v8'
            """
        )
        self.db.connection.execute(
            """
            UPDATE sdk_source_tree_files SET byte_length = byte_length + 1
            WHERE source_file_id = (
                SELECT source_file_id FROM sdk_source_tree_files LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE sdk_prototype_observations SET source_file_sha256 = ?
            WHERE prototype_observation_id = (
                SELECT prototype_observation_id
                FROM sdk_prototype_observations LIMIT 1
            )
            """,
            ("0" * 64,),
        )
        self.db.connection.execute(
            """
            DELETE FROM sdk_data_extraction_assertions
            WHERE assertion_id = (
                SELECT assertion_id FROM sdk_data_extraction_assertions LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE sdk_call_argument_expressions SET ordinal = 99
            WHERE argument_expression_id = (
                SELECT argument_expression_id
                FROM sdk_call_argument_expressions LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE sdk_code_inventory_joins SET address = address + 1
            WHERE code_join_id = (
                SELECT code_join_id FROM sdk_code_inventory_joins LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE sdk_code_inventory_joins
            SET classification = 'pc_executable_non_entry'
            WHERE code_join_id = (
                SELECT link.code_join_id FROM sdk_game_exact_entry_links link
                JOIN sdk_code_inventory_joins joined USING (code_join_id)
                WHERE joined.program_variant = 'game' LIMIT 1
            )
            """
        )
        geck_join = self.db.connection.execute(
            """
            SELECT code_join_id FROM sdk_code_inventory_joins
            WHERE program_variant = 'geck' LIMIT 1
            """
        ).fetchone()[0]
        self.db.connection.execute(
            """
            INSERT INTO sdk_game_exact_entry_links(code_join_id, function_id)
            VALUES (?, ?)
            """,
            (geck_join, self.pc_function),
        )
        self.db.connection.execute(
            """
            UPDATE sdk_data_inventory_joins SET classification = 'non_game_variant'
            WHERE data_join_id = (
                SELECT data_join_id FROM sdk_data_inventory_joins
                WHERE program_variant = 'game' LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            """
            UPDATE sdk_boundary_candidates SET candidate_reason = 'tampered'
            WHERE boundary_candidate_id = (
                SELECT boundary_candidate_id FROM sdk_boundary_candidates LIMIT 1
            )
            """
        )
        self.db.connection.execute(
            "UPDATE programs SET platform = 'xbox360' WHERE program_id = 'pc'"
        )
        self.db.add_function_name(
            self.pc_function,
            "SdkProducerLeak",
            name_kind="sdk-producer-leak",
            provenance_id=self.sdk_provenance,
        )
        self.db.connection.execute(
            """
            INSERT INTO review_releases(
                review_release_id, release_key, label, provenance_id
            ) VALUES ('sdk-leak-release', 'sdk-leak-release',
                      'SDK provenance leak', ?)
            """,
            (self.sdk_provenance,),
        )

        counts = self._counts()
        for name in (
            "sdk_extraction_summary_mismatch",
            "sdk_source_tree_integrity_mismatch",
            "sdk_source_observation_file_mismatch",
            "sdk_observations_without_memberships",
            "sdk_call_sequence_mismatch",
            "sdk_observation_join_mismatch",
            "sdk_code_variant_link_mismatch",
            "sdk_data_variant_classification_mismatch",
            "sdk_boundary_candidate_mismatch",
            "sdk_non_pc_addressing",
            "sdk_provenance_leakage",
        ):
            self.assertGreater(counts[name], 0, name)

    def test_set_based_checks_remain_fast_across_replayed_extractions(self) -> None:
        for index in range(1, 21):
            self.db.persist_vftable_corpus(
                f"vftable-v8-{index}",
                _corpus(),
                program_id="xbox",
                provenance_id=self.vftable_provenance,
            )
            self.db.persist_sdk_extraction(
                f"sdk-v8-{index}",
                self.sdk_extraction,
                self.sdk_join,
                pc_program_id="pc",
                provenance_id=self.sdk_provenance,
            )

        started = time.perf_counter()
        counts = self._counts()
        elapsed = time.perf_counter() - started
        relevant = {
            name: count
            for name, count in counts.items()
            if name.startswith(V8_PREFIXES)
        }
        self.assertTrue(all(count == 0 for count in relevant.values()), relevant)
        self.assertLess(elapsed, 5.0, f"v8 semantic checks took {elapsed:.3f}s")


if __name__ == "__main__":
    unittest.main()
