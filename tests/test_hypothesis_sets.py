from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import AtlasDatabase  # noqa: E402


class HypothesisSetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("x360", platform="xbox360", name="Xbox")
        self.provenance = self.db.upsert_provenance(
            kind="test", producer="hypothesis-test"
        )
        self.pc_first = self._function("pc", 0x401000, "pc:first")
        self.pc_second = self._function("pc", 0x402000, "pc:second")
        self.xbox_first = self._function("x360", 0x82001000, "xbox:first")
        self.xbox_fold_first = self._function(
            "x360", 0x82002000, "xbox:fold:first"
        )
        self.xbox_fold_second = self._function(
            "x360", 0x82002000, "xbox:fold:second"
        )

    def tearDown(self) -> None:
        self.db.close()

    def _function(self, program: str, address: int, identity: str) -> str:
        group = self.db.upsert_address_group(
            program_id=program,
            address_space="ram" if program == "pc" else "xbox-va",
            address=address,
        )
        return self.db.upsert_function(
            function_id=identity,
            address_group_id=group,
            identity_key=identity,
        )

    def _claim(self, pc_function: str, xbox_function: str) -> str:
        return self.db.upsert_match_claim(
            pc_function_id=pc_function,
            xbox_function_id=xbox_function,
            provenance_id=self.provenance,
        )

    def test_set_keeps_n_unordered_scalar_and_fold_bundle_alternatives(self) -> None:
        scalar_claim = self._claim(self.pc_first, self.xbox_first)
        fold_group = self.db.upsert_fold_group(
            "xbox:fold", program_id="x360", provenance_id=self.provenance
        )
        self.db.add_fold_member(fold_group, self.xbox_fold_first)
        self.db.add_fold_member(fold_group, self.xbox_fold_second)

        hypothesis = self.db.upsert_match_hypothesis_set(
            pc_function_id=self.pc_first,
            provenance_id=self.provenance,
            identity_key="slot-occurrence:42",
            details={"origin": "vtable-slot"},
        )
        scalar = self.db.add_match_hypothesis_alternative(
            hypothesis, claim_id=scalar_claim
        )
        bundle = self.db.add_match_hypothesis_alternative(
            hypothesis,
            xbox_fold_group_id=fold_group,
            details={"member_count_at_extraction": 2},
        )
        # Identical membership is idempotent and does not enumerate fold members.
        self.assertEqual(
            self.db.add_match_hypothesis_alternative(
                hypothesis, xbox_fold_group_id=fold_group
            ),
            bundle,
        )
        evidence = self.db.add_match_hypothesis_evidence(
            hypothesis,
            effect="supports",
            evidence_kind="exact_slot_index",
            independence_group="vtable-structure",
            provenance_id=self.provenance,
            details={"slot": 42},
        )

        stored = self.db.get_match_hypothesis_set(hypothesis)
        assert stored is not None
        self.assertEqual(stored["status"], "candidate")
        self.assertEqual(
            {row["alternative_id"] for row in stored["alternatives"]},
            {scalar, bundle},
        )
        self.assertEqual(len(stored["alternatives"]), 2)
        self.assertEqual(stored["evidence"][0]["evidence_id"], evidence)
        self.assertNotIn("confidence_value", stored)
        self.assertEqual(
            self.db.connection.execute(
                """
                SELECT COUNT(*) FROM match_hypothesis_alternatives
                WHERE xbox_fold_group_id = ?
                """,
                (fold_group,),
            ).fetchone()[0],
            1,
        )

    def test_subject_platform_and_membership_guards_survive_direct_sql(self) -> None:
        with self.assertRaises(ValueError):
            self.db.upsert_match_hypothesis_set(
                provenance_id=self.provenance,
                pc_function_id=self.pc_first,
                pc_target_id="also-present",
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_match_hypothesis_set(
                provenance_id=self.provenance,
                pc_function_id=self.xbox_first,
            )

        hypothesis = self.db.upsert_match_hypothesis_set(
            provenance_id=self.provenance,
            pc_function_id=self.pc_first,
            identity_key="guarded",
        )
        wrong_subject_claim = self._claim(self.pc_second, self.xbox_first)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.add_match_hypothesis_alternative(
                hypothesis, claim_id=wrong_subject_claim
            )

        right_claim = self._claim(self.pc_first, self.xbox_first)
        self.db.add_match_hypothesis_alternative(hypothesis, claim_id=right_claim)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                UPDATE match_claims SET pc_function_id = ? WHERE claim_id = ?
                """,
                (self.pc_second, right_claim),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                UPDATE match_hypothesis_sets SET pc_function_id = ?
                WHERE hypothesis_set_id = ?
                """,
                (self.pc_second, hypothesis),
            )

        pc_fold = self.db.upsert_fold_group(
            "pc:fold", program_id="pc", provenance_id=self.provenance
        )
        self.db.add_fold_member(pc_fold, self.pc_first)
        self.db.add_fold_member(pc_fold, self.pc_second)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.add_match_hypothesis_alternative(
                hypothesis, xbox_fold_group_id=pc_fold
            )

    def test_set_evidence_strength_is_part_of_assertion_identity(self) -> None:
        hypothesis = self.db.upsert_match_hypothesis_set(
            provenance_id=self.provenance,
            pc_function_id=self.pc_first,
            identity_key="strength-identity",
        )
        weak = self.db.add_match_hypothesis_evidence(
            hypothesis,
            effect="supports",
            evidence_kind="manual-review",
            independence_group="manual-review",
            provenance_id=self.provenance,
            asserted_strength="weak",
        )
        strong = self.db.add_match_hypothesis_evidence(
            hypothesis,
            effect="supports",
            evidence_kind="manual-review",
            independence_group="manual-review",
            provenance_id=self.provenance,
            asserted_strength="strong",
        )

        self.assertNotEqual(weak, strong)
        stored = self.db.get_match_hypothesis_set(hypothesis)
        assert stored is not None
        self.assertEqual(
            {item["asserted_strength"] for item in stored["evidence"]},
            {"weak", "strong"},
        )

    def test_unresolved_subject_and_unresolved_xbox_claim_are_first_class(self) -> None:
        pc_group = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x403000
        )
        pc_target = self.db.upsert_unresolved_target(
            address_group_id=pc_group,
            target_kind="slot-target",
            provenance_id=self.provenance,
        )
        xbox_group = self.db.upsert_address_group(
            program_id="x360", address_space="xbox-va", address=0x82003000
        )
        xbox_target = self.db.upsert_unresolved_target(
            address_group_id=xbox_group,
            target_kind="slot-target",
            provenance_id=self.provenance,
        )
        claim = self.db.upsert_match_claim(
            pc_target_id=pc_target,
            xbox_target_id=xbox_target,
            provenance_id=self.provenance,
        )
        hypothesis = self.db.upsert_match_hypothesis_set(
            pc_target_id=pc_target,
            provenance_id=self.provenance,
            identity_key="unresolved-slot",
        )
        self.db.add_match_hypothesis_alternative(hypothesis, claim_id=claim)
        stored = self.db.get_match_hypothesis_set(hypothesis)
        assert stored is not None
        self.assertEqual(stored["pc_target_id"], pc_target)
        self.assertEqual(stored["alternatives"][0]["claim_id"], claim)


class VtableAlignmentPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("x360", platform="xbox360", name="Xbox")
        self.provenance = self.db.upsert_provenance(
            kind="test", producer="vtable-alignment-test"
        )
        self.pc_function, self.pc_vtable = self._platform_fixture("pc", 0x401000)
        self.xbox_function, self.xbox_vtable = self._platform_fixture(
            "x360", 0x82001000
        )

    def tearDown(self) -> None:
        self.db.close()

    def _platform_fixture(self, program: str, target_address: int) -> tuple[str, str]:
        address_space = "ram" if program == "pc" else "xbox-va"
        target_group = self.db.upsert_address_group(
            program_id=program,
            address_space=address_space,
            address=target_address,
        )
        function = self.db.upsert_function(
            function_id=f"{program}:function",
            address_group_id=target_group,
            identity_key="slot-target",
        )
        class_id = self.db.upsert_class(
            f"{program}:class", program_id=program, identity_key="Fixture"
        )
        vtable = self.db.upsert_vtable(
            f"{program}:vtable",
            program_id=program,
            class_id=class_id,
            address_space=address_space,
            address=target_address + 0x1000,
            vfptr_role="primary",
            provenance_id=self.provenance,
        )
        self.db.upsert_vtable_slot(
            vtable,
            0,
            target_address_group_id=target_group,
            provenance_id=self.provenance,
        )
        return function, vtable

    def test_alignment_slot_occurrence_hypothesis_and_issue_round_trip(self) -> None:
        claim = self.db.upsert_match_claim(
            pc_function_id=self.pc_function,
            xbox_function_id=self.xbox_function,
            provenance_id=self.provenance,
        )
        hypothesis = self.db.upsert_match_hypothesis_set(
            pc_function_id=self.pc_function,
            provenance_id=self.provenance,
            identity_key="pc:vtable:slot:0",
        )
        self.db.add_match_hypothesis_alternative(hypothesis, claim_id=claim)
        alignment = self.db.upsert_vtable_alignment_candidate(
            "alignment:fixture",
            pc_vtable_id=self.pc_vtable,
            xbox_vtable_id=self.xbox_vtable,
            class_name="Fixture",
            vfptr_role="primary",
            subobject_offset=0,
            provenance_id=self.provenance,
            details={"shared_prefix_slot_count": 1, "pc_tail": 0, "xbox_tail": 0},
        )
        slot = self.db.upsert_vtable_slot_alignment(
            alignment_id=alignment,
            pc_slot_index=0,
            xbox_slot_index=0,
            hypothesis_set_id=hypothesis,
            provenance_id=self.provenance,
            details={"pairing": "equal-index-shared-prefix"},
        )
        issue = self.db.upsert_vtable_alignment_issue(
            "issue:fixture",
            issue_kind="unmatched-secondary-offset",
            class_name="Fixture",
            vfptr_role="secondary",
            subobject_offset=8,
            message="Xbox table has no unique PC peer",
            provenance_id=self.provenance,
            details={"pc_vtable_ids": [], "xbox_vtable_ids": [self.xbox_vtable]},
        )

        candidates = list(self.db.iter_vtable_alignment_candidates())
        slots = list(self.db.iter_vtable_slot_alignments(alignment_id=alignment))
        issues = list(self.db.iter_vtable_alignment_issues())
        self.assertEqual(candidates[0]["status"], "candidate")
        self.assertEqual(slots[0]["slot_alignment_id"], slot)
        self.assertEqual(slots[0]["hypothesis_set_id"], hypothesis)
        self.assertEqual(issues[0]["issue_id"], issue)
        self.assertEqual(issues[0]["details"]["xbox_vtable_ids"], [self.xbox_vtable])

    def test_alignment_platform_slot_and_candidate_only_constraints(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_vtable_alignment_candidate(
                "alignment:reversed",
                pc_vtable_id=self.xbox_vtable,
                xbox_vtable_id=self.pc_vtable,
                class_name="Fixture",
                vfptr_role="primary",
                subobject_offset=0,
                provenance_id=self.provenance,
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_vtable_alignment_candidate(
                "alignment:accepted",
                pc_vtable_id=self.pc_vtable,
                xbox_vtable_id=self.xbox_vtable,
                class_name="Fixture",
                vfptr_role="primary",
                subobject_offset=0,
                provenance_id=self.provenance,
                status="accepted",
            )

        claim = self.db.upsert_match_claim(
            pc_function_id=self.pc_function,
            xbox_function_id=self.xbox_function,
            provenance_id=self.provenance,
        )
        hypothesis = self.db.upsert_match_hypothesis_set(
            pc_function_id=self.pc_function,
            provenance_id=self.provenance,
            identity_key="slot",
        )
        self.db.add_match_hypothesis_alternative(hypothesis, claim_id=claim)
        alignment = self.db.upsert_vtable_alignment_candidate(
            "alignment:valid",
            pc_vtable_id=self.pc_vtable,
            xbox_vtable_id=self.xbox_vtable,
            class_name="Fixture",
            vfptr_role="primary",
            subobject_offset=0,
            provenance_id=self.provenance,
        )
        wrong_xbox_group = self.db.upsert_address_group(
            program_id="x360", address_space="xbox-va", address=0x82009000
        )
        wrong_xbox_function = self.db.upsert_function(
            function_id="x360:wrong-slot-function",
            address_group_id=wrong_xbox_group,
            identity_key="wrong-slot-function",
        )
        wrong_claim = self.db.upsert_match_claim(
            pc_function_id=self.pc_function,
            xbox_function_id=wrong_xbox_function,
            provenance_id=self.provenance,
        )
        wrong_hypothesis = self.db.upsert_match_hypothesis_set(
            pc_function_id=self.pc_function,
            provenance_id=self.provenance,
            identity_key="wrong-xbox-endpoint",
        )
        self.db.add_match_hypothesis_alternative(
            wrong_hypothesis, claim_id=wrong_claim
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_vtable_slot_alignment(
                alignment_id=alignment,
                pc_slot_index=0,
                xbox_slot_index=0,
                hypothesis_set_id=wrong_hypothesis,
                provenance_id=self.provenance,
            )
        pc_group = self.db.connection.execute(
            "SELECT address_group_id FROM functions WHERE function_id = ?",
            (self.pc_function,),
        ).fetchone()[0]
        xbox_group = self.db.connection.execute(
            "SELECT address_group_id FROM functions WHERE function_id = ?",
            (self.xbox_function,),
        ).fetchone()[0]
        self.db.upsert_vtable_slot(
            self.pc_vtable,
            1,
            target_address_group_id=pc_group,
            provenance_id=self.provenance,
        )
        self.db.upsert_vtable_slot(
            self.xbox_vtable,
            1,
            target_address_group_id=xbox_group,
            provenance_id=self.provenance,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_vtable_slot_alignment(
                alignment_id=alignment,
                pc_slot_index=0,
                xbox_slot_index=1,
                hypothesis_set_id=hypothesis,
                provenance_id=self.provenance,
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_vtable_slot_alignment(
                alignment_id=alignment,
                pc_slot_index=0,
                xbox_slot_index=0,
                hypothesis_set_id=hypothesis,
                provenance_id=self.provenance,
                status="accepted",
            )
        self.db.upsert_vtable_slot_alignment(
            alignment_id=alignment,
            pc_slot_index=0,
            xbox_slot_index=0,
            hypothesis_set_id=hypothesis,
            provenance_id=self.provenance,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_vtable_slot_alignment(
                alignment_id=alignment,
                pc_slot_index=1,
                xbox_slot_index=1,
                hypothesis_set_id=hypothesis,
                provenance_id=self.provenance,
            )

    def test_slot_alignment_accepts_one_fold_bundle_without_member_expansion(self) -> None:
        xbox_group = self.db.connection.execute(
            "SELECT address_group_id FROM functions WHERE function_id = ?",
            (self.xbox_function,),
        ).fetchone()[0]
        folded_alias = self.db.upsert_function(
            function_id="x360:function:folded-alias",
            address_group_id=xbox_group,
            identity_key="folded-alias",
        )
        fold_group = self.db.upsert_fold_group(
            "x360:slot-fold", program_id="x360", provenance_id=self.provenance
        )
        self.db.add_fold_member(fold_group, self.xbox_function)
        self.db.add_fold_member(fold_group, folded_alias)

        hypothesis = self.db.upsert_match_hypothesis_set(
            pc_function_id=self.pc_function,
            provenance_id=self.provenance,
            identity_key="folded-slot",
        )
        self.db.add_match_hypothesis_alternative(
            hypothesis, xbox_fold_group_id=fold_group
        )
        alignment = self.db.upsert_vtable_alignment_candidate(
            "alignment:folded",
            pc_vtable_id=self.pc_vtable,
            xbox_vtable_id=self.xbox_vtable,
            class_name="Fixture",
            vfptr_role="primary",
            subobject_offset=0,
            provenance_id=self.provenance,
        )
        self.db.upsert_vtable_slot_alignment(
            alignment_id=alignment,
            pc_slot_index=0,
            xbox_slot_index=0,
            hypothesis_set_id=hypothesis,
            provenance_id=self.provenance,
        )
        self.assertEqual(
            self.db.connection.execute(
                """
                SELECT COUNT(*) FROM match_hypothesis_alternatives
                WHERE hypothesis_set_id = ?
                """,
                (hypothesis,),
            ).fetchone()[0],
            1,
        )


if __name__ == "__main__":
    unittest.main()
