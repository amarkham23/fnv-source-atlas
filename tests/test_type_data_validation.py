from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import AtlasDatabase  # noqa: E402
from fnv_atlas.pdb_globals import (  # noqa: E402
    DataSymbolExtraction,
    build_data_address_groups,
)
from fnv_atlas.validation import (  # noqa: E402
    semantic_validation_counts,
    semantic_validation_ok,
)
from tests.test_type_data_database import (  # noqa: E402
    _data_record,
    _tpi_fixture,
)


class TypeDataSemanticValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("x360", platform="xbox360", name="Xbox")
        self.provenance = self.db.upsert_provenance(
            kind="test", producer="type-data-validation-tests"
        )
        self.tpi = self.db.persist_tpi_layout_corpus(
            _tpi_fixture(),
            program_id="x360",
            provenance_id=self.provenance,
        )
        records = (
            _data_record(
                1,
                4,
                va=0x82001000,
                name="first",
                type_index=0x74,
            ),
            _data_record(
                1,
                32,
                va=0x82001000,
                name="alias",
                type_index=0xBEEF,
            ),
            _data_record(
                2,
                4,
                va=None,
                name="unresolved",
                type_index=0xDEAD,
            ),
        )
        self.data = self.db.persist_data_symbol_extraction(
            DataSymbolExtraction(records, build_data_address_groups(records)),
            program_id="x360",
            provenance_id=self.provenance,
        )

    def tearDown(self) -> None:
        self.db.close()

    def _disable_foreign_keys(self) -> None:
        self.db.connection.commit()
        self.db.connection.execute("PRAGMA foreign_keys = OFF")
        self.assertEqual(
            self.db.connection.execute("PRAGMA foreign_keys").fetchone()[0],
            0,
        )

    def test_complete_type_and_data_extractions_are_semantically_valid(self) -> None:
        counts = semantic_validation_counts(self.db.connection)
        relevant = {
            name: count
            for name, count in counts.items()
            if name.startswith(("codeview_", "data_symbol_", "type_data_"))
        }
        self.assertGreaterEqual(len(relevant), 18)
        self.assertTrue(all(count == 0 for count in relevant.values()), relevant)
        self.assertTrue(semantic_validation_ok(counts))

    def test_detects_type_summary_hash_assertion_and_layout_corruption(self) -> None:
        for trigger in (
            "reject_codeview_type_extraction_update",
            "reject_codeview_type_record_update",
            "reject_codeview_type_record_assertion_update",
            "reject_codeview_type_record_assertion_delete",
            "reject_codeview_tag_member_use_delete",
            "reject_codeview_method_overload_update",
            "reject_codeview_layout_diagnostic_update",
        ):
            self.db.connection.execute(f'DROP TRIGGER "{trigger}"')
        self._disable_foreign_keys()

        self.db.connection.execute(
            """
            UPDATE codeview_type_extractions
            SET raw_type_record_count = raw_type_record_count + 1
            WHERE extraction_id = ?
            """,
            (self.tpi.extraction_id,),
        )
        self.db.connection.execute(
            """
            UPDATE codeview_type_records
            SET raw_body_sha256 = ?
            WHERE program_id = 'x360' AND type_index = 4352
            """,
            ("0" * 64,),
        )
        self.db.connection.execute(
            """
            DELETE FROM codeview_type_record_assertions
            WHERE extraction_id = ? AND type_record_id = (
                SELECT type_record_id FROM codeview_type_records
                WHERE program_id = 'x360' AND type_index = 4864
            )
            """,
            (self.tpi.extraction_id,),
        )
        self.db.connection.execute(
            """
            UPDATE codeview_type_record_assertions
            SET program_id = 'pc'
            WHERE extraction_id = ? AND type_record_id = (
                SELECT type_record_id FROM codeview_type_records
                WHERE program_id = 'x360' AND type_index = 4865
            )
            """,
            (self.tpi.extraction_id,),
        )
        self.db.connection.execute(
            """
            DELETE FROM codeview_tag_member_uses
            WHERE extraction_id = ? AND field_member_id = (
                SELECT field_member_id FROM codeview_field_members
                WHERE extraction_id = ? AND source_record_offset = 0
            )
            """,
            (self.tpi.extraction_id, self.tpi.extraction_id),
        )
        self.db.connection.execute(
            """
            UPDATE codeview_method_overloads SET ordinal = 9
            WHERE extraction_id = ? AND ordinal = 1
            """,
            (self.tpi.extraction_id,),
        )
        self.db.connection.execute(
            """
            UPDATE codeview_layout_diagnostics SET ordinal = 3
            WHERE extraction_id = ?
            """,
            (self.tpi.extraction_id,),
        )

        counts = semantic_validation_counts(self.db.connection)
        for name in (
            "codeview_type_extraction_summary_mismatch",
            "codeview_type_record_integrity_mismatch",
            "codeview_type_records_without_assertions",
            "codeview_type_assertion_identity_mismatch",
            "codeview_tag_record_identity_mismatch",
            "codeview_tag_member_shape_mismatch",
            "codeview_field_member_identity_mismatch",
            "codeview_method_overload_identity_mismatch",
            "codeview_layout_diagnostic_identity_mismatch",
            "codeview_type_non_xbox_identity",
        ):
            self.assertGreater(counts[name], 0, name)
        self.assertFalse(semantic_validation_ok(counts))

    def test_detects_data_summary_physical_identity_and_address_corruption(self) -> None:
        for trigger in (
            "reject_data_symbol_extraction_update",
            "reject_data_symbol_record_update",
            "reject_data_symbol_record_assertion_update",
            "reject_data_symbol_record_assertion_delete",
        ):
            self.db.connection.execute(f'DROP TRIGGER "{trigger}"')
        self._disable_foreign_keys()

        self.db.connection.execute(
            """
            UPDATE data_symbol_extractions
            SET record_count = record_count + 1,
                unresolved_record_count = unresolved_record_count + 1
            WHERE extraction_id = ?
            """,
            (self.data.extraction_id,),
        )
        self.db.connection.execute(
            """
            UPDATE data_symbol_records SET source_record_id = 'bad-physical-id'
            WHERE data_record_id = (
                SELECT data_record_id FROM data_symbol_record_assertions
                WHERE extraction_id = ? AND raw_name = 'first'
            )
            """,
            (self.data.extraction_id,),
        )
        self.db.connection.execute(
            """
            DELETE FROM data_symbol_record_assertions
            WHERE extraction_id = ? AND raw_name = 'unresolved'
            """,
            (self.data.extraction_id,),
        )
        self.db.connection.execute(
            """
            UPDATE data_symbol_record_assertions
            SET resolved_va = resolved_va + 4
            WHERE extraction_id = ? AND raw_name = 'first'
            """,
            (self.data.extraction_id,),
        )
        self.db.connection.execute(
            """
            UPDATE data_symbol_record_assertions SET program_id = 'pc'
            WHERE extraction_id = ? AND raw_name = 'alias'
            """,
            (self.data.extraction_id,),
        )

        counts = semantic_validation_counts(self.db.connection)
        for name in (
            "data_symbol_extraction_summary_mismatch",
            "data_symbol_records_without_assertions",
            "data_symbol_record_identity_mismatch",
            "data_symbol_assertion_identity_mismatch",
            "data_symbol_non_xbox_addressing",
        ):
            self.assertGreater(counts[name], 0, name)
        self.assertFalse(semantic_validation_ok(counts))

    def test_detects_type_data_producer_function_name_and_match_leakage(self) -> None:
        pc_address = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x401000
        )
        pc_function = self.db.upsert_function(
            address_group_id=pc_address,
            identity_key="leaked-pc",
            provenance_id=self.provenance,
        )
        xbox_address = self.db.upsert_address_group(
            program_id="x360", address_space="xbox-va", address=0x82002000
        )
        xbox_function = self.db.upsert_function(
            address_group_id=xbox_address,
            identity_key="leaked-xbox",
            provenance_id=self.provenance,
        )
        self.db.add_function_name(
            pc_function,
            "LeakedName",
            name_kind="fixture",
            provenance_id=self.provenance,
        )
        claim = self.db.upsert_match_claim(
            pc_function_id=pc_function,
            xbox_function_id=xbox_function,
            provenance_id=self.provenance,
        )
        self.db.add_claim_evidence(
            claim,
            effect="supports",
            evidence_kind="fixture",
            independence_group="fixture",
            provenance_id=self.provenance,
        )

        counts = semantic_validation_counts(self.db.connection)
        self.assertGreater(
            counts["type_data_provenance_created_function_or_name"], 0
        )
        self.assertGreater(
            counts["type_data_provenance_created_match_state"], 0
        )
        self.assertFalse(semantic_validation_ok(counts))


if __name__ == "__main__":
    unittest.main()
