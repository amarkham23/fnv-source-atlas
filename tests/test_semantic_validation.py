from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import AtlasDatabase  # noqa: E402
from fnv_atlas.tpi_signatures import (  # noqa: E402
    FunctionSignature,
    LF_PROCEDURE,
    SignatureResult,
)
from fnv_atlas.validation import (  # noqa: E402
    semantic_validation_counts,
    semantic_validation_ok,
)


class SemanticValidationTests(unittest.TestCase):
    def test_empty_current_schema_has_no_semantic_violations(self):
        with AtlasDatabase.create() as db:
            counts = semantic_validation_counts(db.connection)
        self.assertTrue(semantic_validation_ok(counts))

    def test_detects_deleted_signature_argument_and_claim_evidence(self):
        with AtlasDatabase.create() as db:
            db.upsert_program("pc", platform="pc", name="PC")
            db.upsert_program("xbox", platform="xbox360", name="Xbox")
            provenance = db.upsert_provenance(
                kind="test", producer="test_semantic_validation"
            )
            pc_group = db.upsert_address_group(
                program_id="pc", address_space="ram", address=0x401000
            )
            pc_function = db.upsert_function(
                function_id="pc:f",
                address_group_id=pc_group,
                identity_key="pc:f",
                provenance_id=provenance,
            )
            xbox_group = db.upsert_address_group(
                program_id="xbox", address_space="xbox-va", address=0x82001000
            )
            xbox_function = db.upsert_function(
                function_id="xbox:f",
                address_group_id=xbox_group,
                identity_key="xbox:f",
                type_index=0x2000,
                provenance_id=provenance,
            )
            signature = FunctionSignature(
                type_index=0x2000,
                leaf_kind=LF_PROCEDURE,
                leaf_name="LF_PROCEDURE",
                return_type_index=3,
                class_type_index=None,
                this_type_index=None,
                calling_convention=0,
                calling_convention_name="near_c",
                attributes=0,
                this_adjustment=None,
                parameter_count=1,
                argument_list_type_index=0x2100,
                argument_list_count=1,
                argument_type_indices=(0x74,),
                is_variadic=False,
                rendered_return_type="void",
                rendered_class_type=None,
                rendered_this_type=None,
                rendered_argument_types=("int",),
                rendered_signature="void __cdecl (int)",
            )
            db.upsert_signature_result(
                xbox_function,
                SignatureResult(0x2000, signature),
                provenance_id=provenance,
            )
            claim = db.upsert_match_claim(
                pc_function_id=pc_function,
                xbox_function_id=xbox_function,
                provenance_id=provenance,
            )
            db.add_claim_evidence(
                claim,
                effect="supports",
                evidence_kind="fixture",
                independence_group="fixture",
                provenance_id=provenance,
            )

            db.connection.execute(
                "DELETE FROM function_signature_arguments WHERE function_id = ?",
                (xbox_function,),
            )
            # The row shape permits a producer to claim variadic while its
            # ordered argument records fail to retain the terminal marker;
            # completed-build semantic validation must catch that mismatch.
            db.connection.execute(
                "UPDATE function_signatures SET is_variadic = 1 WHERE function_id = ?",
                (xbox_function,),
            )
            db.connection.execute(
                "DELETE FROM claim_evidence WHERE claim_id = ?", (claim,)
            )
            db.connection.execute(
                "DELETE FROM function_assertions WHERE function_id = ?",
                (pc_function,),
            )
            counts = semantic_validation_counts(db.connection)

        self.assertEqual(counts["functions_without_assertions"], 1)
        self.assertEqual(
            counts["function_projection_without_matching_assertion"], 1
        )
        self.assertEqual(counts["signature_argument_count_mismatch"], 1)
        self.assertEqual(counts["variadic_signature_marker_mismatch"], 1)
        self.assertEqual(counts["match_claims_without_evidence"], 1)
        self.assertFalse(semantic_validation_ok(counts))

    def test_detects_incomplete_hypothesis_and_noncontiguous_vtable(self):
        with AtlasDatabase.create() as db:
            db.upsert_program("pc", platform="pc", name="PC")
            provenance = db.upsert_provenance(
                kind="test", producer="test_semantic_validation"
            )
            function_group = db.upsert_address_group(
                program_id="pc", address_space="ram", address=0x401000
            )
            function = db.upsert_function(
                function_id="pc:f",
                address_group_id=function_group,
                identity_key="pc:f",
                provenance_id=provenance,
            )
            db.upsert_match_hypothesis_set(
                hypothesis_set_id="hypothesis:incomplete",
                identity_key="fixture:incomplete",
                pc_function_id=function,
                provenance_id=provenance,
            )

            class_id = db.upsert_class(
                "pc:class",
                program_id="pc",
                identity_key="fixture-class",
            )
            db.upsert_vtable(
                "pc:vtable",
                program_id="pc",
                class_id=class_id,
                address_space="ram",
                address=0x501000,
                vfptr_role="primary",
                subobject_offset=0,
                provenance_id=provenance,
                details={"observed_slot_count": 1},
            )
            # One stored slot agrees with the observed count, but index 1
            # proves the physical occurrence sequence has a hole at index 0.
            db.upsert_vtable_slot(
                "pc:vtable",
                1,
                target_address_group_id=function_group,
                provenance_id=provenance,
            )
            db.connection.execute(
                "DELETE FROM vtable_slot_assertions WHERE vtable_id = ?",
                ("pc:vtable",),
            )

            counts = semantic_validation_counts(db.connection)

        self.assertEqual(counts["hypothesis_sets_without_alternatives"], 1)
        self.assertEqual(counts["hypothesis_sets_without_evidence"], 1)
        self.assertEqual(counts["vtable_observed_slot_count_mismatch"], 0)
        self.assertEqual(counts["vtable_slot_indices_noncontiguous"], 1)
        self.assertEqual(counts["vtable_slots_without_assertions"], 1)
        self.assertEqual(
            counts["vtable_slot_projection_without_matching_assertion"], 1
        )
        self.assertFalse(semantic_validation_ok(counts))


if __name__ == "__main__":
    unittest.main()
