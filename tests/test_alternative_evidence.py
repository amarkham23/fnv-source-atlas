from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import (  # noqa: E402
    AtlasDatabase,
    IdentityConflictError,
)


class AlternativeEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("x360", platform="xbox360", name="Xbox")
        self.provenance = self.db.upsert_provenance(
            kind="test", producer="alternative-evidence-tests"
        )
        self.pc = self._function("pc", 0x401000)
        self.xbox_a = self._function("x360", 0x82001000)
        self.xbox_b = self._function("x360", 0x82002000)
        self.hypothesis = self.db.upsert_match_hypothesis_set(
            pc_function_id=self.pc,
            provenance_id=self.provenance,
            identity_key="one-of-two",
        )
        self.first_alternative = self.db.add_match_hypothesis_alternative(
            self.hypothesis,
            claim_id=self.db.upsert_match_claim(
                pc_function_id=self.pc,
                xbox_function_id=self.xbox_a,
                provenance_id=self.provenance,
            ),
        )
        self.second_alternative = self.db.add_match_hypothesis_alternative(
            self.hypothesis,
            claim_id=self.db.upsert_match_claim(
                pc_function_id=self.pc,
                xbox_function_id=self.xbox_b,
                provenance_id=self.provenance,
            ),
        )

    def tearDown(self) -> None:
        self.db.close()

    def _function(self, program_id: str, address: int) -> str:
        address_group = self.db.upsert_address_group(
            program_id=program_id,
            address_space="ram" if program_id == "pc" else "xbox-va",
            address=address,
        )
        return self.db.upsert_function(
            address_group_id=address_group,
            identity_key=f"{program_id}:{address:x}",
        )

    def test_evidence_remains_specific_to_one_alternative(self) -> None:
        evidence_id = self.db.add_match_hypothesis_alternative_evidence(
            self.first_alternative,
            effect="supports",
            evidence_kind="closed_control_flow_square",
            independence_group="control-flow:anchor-1",
            provenance_id=self.provenance,
            asserted_strength="conditional",
            details={"dependency": "anchor-1"},
        )
        self.assertEqual(
            self.db.add_match_hypothesis_alternative_evidence(
                self.first_alternative,
                effect="supports",
                evidence_kind="closed_control_flow_square",
                independence_group="control-flow:anchor-1",
                provenance_id=self.provenance,
                asserted_strength="conditional",
                details={"dependency": "anchor-1"},
            ),
            evidence_id,
        )

        stored = self.db.get_match_hypothesis_set(self.hypothesis)
        assert stored is not None
        self.assertEqual(stored["evidence"], [])
        by_id = {row["alternative_id"]: row for row in stored["alternatives"]}
        self.assertEqual(
            by_id[self.first_alternative]["evidence"][0]["evidence_id"],
            evidence_id,
        )
        self.assertEqual(by_id[self.second_alternative]["evidence"], [])

        evidence = self.db.get_match_hypothesis_alternative_evidence(evidence_id)
        assert evidence is not None
        self.assertEqual(evidence["hypothesis_set_id"], self.hypothesis)
        self.assertEqual(evidence["details"], {"dependency": "anchor-1"})
        self.assertEqual(
            [row["evidence_id"] for row in
             self.db.iter_match_hypothesis_alternative_evidence(
                 hypothesis_set_id=self.hypothesis,
                 effect="supports",
             )],
            [evidence_id],
        )

    def test_strength_and_details_are_immutable_assertion_identity(self) -> None:
        weak = self.db.add_match_hypothesis_alternative_evidence(
            self.first_alternative,
            effect="supports",
            evidence_kind="manual",
            independence_group="review",
            provenance_id=self.provenance,
            asserted_strength="weak",
        )
        strong = self.db.add_match_hypothesis_alternative_evidence(
            self.first_alternative,
            effect="supports",
            evidence_kind="manual",
            independence_group="review",
            provenance_id=self.provenance,
            asserted_strength="strong",
        )
        self.assertNotEqual(weak, strong)
        with self.assertRaises(IdentityConflictError):
            self.db.add_match_hypothesis_alternative_evidence(
                self.second_alternative,
                evidence_id=weak,
                effect="contradicts",
                evidence_kind="manual",
                independence_group="review",
                provenance_id=self.provenance,
            )

    def test_direct_sql_constraints_and_append_only_triggers(self) -> None:
        evidence_id = self.db.add_match_hypothesis_alternative_evidence(
            self.first_alternative,
            effect="context",
            evidence_kind="dependency-lineage",
            independence_group="anchor",
            provenance_id=self.provenance,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE match_hypothesis_alternative_evidence "
                "SET effect = 'supports' WHERE evidence_id = ?",
                (evidence_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "DELETE FROM match_hypothesis_alternative_evidence "
                "WHERE evidence_id = ?",
                (evidence_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                INSERT INTO match_hypothesis_alternative_evidence(
                    evidence_id, alternative_id, effect, evidence_kind,
                    independence_group, provenance_id
                ) VALUES ('bad-effect', ?, 'accepted', 'kind', 'group', ?)
                """,
                (self.first_alternative, self.provenance),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                INSERT INTO match_hypothesis_alternative_evidence(
                    evidence_id, alternative_id, effect, evidence_kind,
                    independence_group, provenance_id
                ) VALUES ('bad-alternative', 'missing', 'supports', 'kind',
                          'group', ?)
                """,
                (self.provenance,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "DELETE FROM match_hypothesis_alternatives WHERE alternative_id = ?",
                (self.first_alternative,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE match_hypothesis_alternatives "
                "SET hypothesis_set_id = hypothesis_set_id WHERE alternative_id = ?",
                (self.first_alternative,),
            )
        claim_id = self.db.connection.execute(
            "SELECT claim_id FROM match_hypothesis_alternatives "
            "WHERE alternative_id = ?",
            (self.first_alternative,),
        ).fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE match_claims SET xbox_function_id = xbox_function_id "
                "WHERE claim_id = ?",
                (claim_id,),
            )

    def test_evidenced_fold_alternative_freezes_bundle_membership(self) -> None:
        fold_group = self.db.upsert_fold_group(
            "x360:fold", program_id="x360", provenance_id=self.provenance
        )
        self.db.add_fold_member(fold_group, self.xbox_a)
        self.db.add_fold_member(fold_group, self.xbox_b)
        alternative = self.db.add_match_hypothesis_alternative(
            self.hypothesis, xbox_fold_group_id=fold_group
        )
        evidence = self.db.add_match_hypothesis_alternative_evidence(
            alternative,
            effect="supports",
            evidence_kind="fold-preserving-relation",
            independence_group="control-flow",
            provenance_id=self.provenance,
        )
        self.assertEqual(
            self.db.get_match_hypothesis_alternative_evidence(evidence)[
                "alternative_id"
            ],
            alternative,
        )
        third = self._function("x360", 0x82003000)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.add_fold_member(fold_group, third)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "DELETE FROM fold_group_members "
                "WHERE fold_group_id = ? AND function_id = ?",
                (fold_group, self.xbox_a),
            )


if __name__ == "__main__":
    unittest.main()
