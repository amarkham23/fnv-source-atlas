from __future__ import annotations

from datetime import datetime, timezone
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


class ReviewHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("x360", platform="xbox360", name="Xbox")
        self.provenance = self.db.upsert_provenance(
            kind="human-review", producer="review-history-tests"
        )
        self.pc_function = self._function("pc", 0x401000, "pc:function")
        self.xbox_function = self._function(
            "x360", 0x82001000, "xbox:function"
        )
        self.xbox_fold_first = self._function(
            "x360", 0x82002000, "xbox:fold:first"
        )
        self.xbox_fold_second = self._function(
            "x360", 0x82002000, "xbox:fold:second"
        )
        self.claim = self.db.upsert_match_claim(
            pc_function_id=self.pc_function,
            xbox_function_id=self.xbox_function,
            provenance_id=self.provenance,
        )
        self.hypothesis = self.db.upsert_match_hypothesis_set(
            pc_function_id=self.pc_function,
            provenance_id=self.provenance,
            identity_key="reviewed-slot-occurrence",
        )
        self.scalar_alternative = self.db.add_match_hypothesis_alternative(
            self.hypothesis, claim_id=self.claim
        )
        self.fold_group = self.db.upsert_fold_group(
            "xbox:review-fold", program_id="x360", provenance_id=self.provenance
        )
        self.db.add_fold_member(self.fold_group, self.xbox_fold_first)
        self.db.add_fold_member(self.fold_group, self.xbox_fold_second)
        self.fold_alternative = self.db.add_match_hypothesis_alternative(
            self.hypothesis,
            xbox_fold_group_id=self.fold_group,
            details={"member_count_at_extraction": 2},
        )
        self.alice = self.db.upsert_reviewer(
            identity_kind="person",
            identity_key="alice@example.invalid",
            display_name="Alice",
        )
        self.bob = self.db.upsert_reviewer(
            identity_kind="person",
            identity_key="bob@example.invalid",
            display_name="Bob",
        )
        self.first_release = self.db.upsert_review_release(
            release_key="atlas-test-r1",
            label="Atlas test release 1",
            version="1",
            source_revision="abc123",
            provenance_id=self.provenance,
        )
        self.second_release = self.db.upsert_review_release(
            release_key="atlas-test-r2",
            label="Atlas test release 2",
            version="2",
            source_revision="def456",
            provenance_id=self.provenance,
        )

    def tearDown(self) -> None:
        self.db.close()

    def _function(self, program_id: str, address: int, identity: str) -> str:
        address_group = self.db.upsert_address_group(
            program_id=program_id,
            address_space="va",
            address=address,
        )
        return self.db.upsert_function(
            function_id=identity,
            address_group_id=address_group,
            identity_key=identity,
        )

    def _decision(
        self,
        *,
        reviewer_id: str,
        action: str,
        decided_at: str | datetime,
        rationale: str,
        previous_decision_id: str | None = None,
        review_release_id: str | None = None,
        hypothesis_set_id: str | None = None,
        alternative_id: str | None = None,
        claim_id: str | None = None,
    ) -> str:
        return self.db.add_review_decision(
            reviewer_id=reviewer_id,
            action=action,
            decided_at=decided_at,
            rationale=rationale,
            provenance_id=self.provenance,
            review_release_id=review_release_id or self.first_release,
            previous_decision_id=previous_decision_id,
            hypothesis_set_id=hypothesis_set_id,
            alternative_id=alternative_id,
            claim_id=claim_id,
        )

    def test_set_and_fold_alternative_acceptance_are_distinct(self) -> None:
        set_decision = self._decision(
            reviewer_id=self.alice,
            action="accept",
            decided_at="2026-08-17T12:00:00-04:00",
            rationale="The set-level ambiguity is real and should be retained.",
            hypothesis_set_id=self.hypothesis,
        )
        fold_decision = self._decision(
            reviewer_id=self.alice,
            action="accept",
            decided_at="2026-08-17T16:01:00Z",
            rationale="This exact folded-address bundle is viable.",
            alternative_id=self.fold_alternative,
        )

        set_state = self.db.get_current_review_state(
            hypothesis_set_id=self.hypothesis
        )
        fold_state = self.db.get_current_review_state(
            alternative_id=self.fold_alternative
        )
        claim_state = self.db.get_current_review_state(claim_id=self.claim)
        self.assertEqual(set_state["status_counts"], {"accepted": 1})
        self.assertEqual(fold_state["status_counts"], {"accepted": 1})
        self.assertEqual(claim_state["status_counts"], {})
        self.assertEqual(
            set_state["current_by_reviewer"][0]["decision_id"], set_decision
        )
        self.assertEqual(
            fold_state["current_by_reviewer"][0]["decision_id"], fold_decision
        )
        self.assertNotIn("consensus", set_state)
        self.assertNotIn("status", set_state)

        # Human review never mutates the producer-owned candidate projections.
        self.assertEqual(
            self.db.connection.execute(
                "SELECT status FROM match_hypothesis_sets WHERE hypothesis_set_id = ?",
                (self.hypothesis,),
            ).fetchone()[0],
            "candidate",
        )
        self.assertEqual(self.db.get_claim(self.claim)["status"], "candidate")
        alternative = self.db.connection.execute(
            """
            SELECT claim_id, xbox_fold_group_id
            FROM match_hypothesis_alternatives WHERE alternative_id = ?
            """,
            (self.fold_alternative,),
        ).fetchone()
        self.assertIsNone(alternative["claim_id"])
        self.assertEqual(alternative["xbox_fold_group_id"], self.fold_group)

    def test_history_is_append_only_idempotent_and_per_reviewer(self) -> None:
        rejected = self._decision(
            reviewer_id=self.alice,
            action="reject",
            decided_at="2026-08-17T17:00:00Z",
            rationale="The endpoint pairing is not supported.",
            claim_id=self.claim,
        )
        reopened = self._decision(
            reviewer_id=self.alice,
            action="reopen",
            decided_at="2026-08-17T17:00:00Z",  # Equal timestamps are valid.
            rationale="New evidence warrants another look.",
            previous_decision_id=rejected,
            claim_id=self.claim,
        )
        superseded = self._decision(
            reviewer_id=self.alice,
            action="supersede",
            decided_at="2026-08-17T18:00:00Z",
            rationale="Withdraw this stance in favor of the replacement mapping.",
            previous_decision_id=reopened,
            review_release_id=self.second_release,
            claim_id=self.claim,
        )
        accepted = self._decision(
            reviewer_id=self.bob,
            action="accept",
            decided_at="2026-08-17T18:30:00Z",
            rationale="Independent review supports the pairing.",
            review_release_id=self.second_release,
            claim_id=self.claim,
        )

        # An exact replay is idempotent even though decisions are immutable.
        self.assertEqual(
            self._decision(
                reviewer_id=self.alice,
                action="supersede",
                decided_at="2026-08-17T18:00:00Z",
                rationale="Withdraw this stance in favor of the replacement mapping.",
                previous_decision_id=reopened,
                review_release_id=self.second_release,
                claim_id=self.claim,
            ),
            superseded,
        )
        history = list(self.db.iter_review_history(claim_id=self.claim))
        self.assertEqual(len(history), 4)
        self.assertEqual(
            {row["decision_id"] for row in history},
            {rejected, reopened, superseded, accepted},
        )
        alice_history = list(
            self.db.iter_review_history(claim_id=self.claim, reviewer_id=self.alice)
        )
        self.assertEqual(
            [row["decision_id"] for row in alice_history],
            [rejected, reopened, superseded],
        )
        self.assertEqual([row["chain_depth"] for row in alice_history], [0, 1, 2])

        state = self.db.get_current_review_state(claim_id=self.claim)
        self.assertEqual(
            state["status_counts"], {"accepted": 1, "superseded": 1}
        )
        self.assertEqual(
            {row["reviewer_id"] for row in state["current_by_reviewer"]},
            {self.alice, self.bob},
        )
        self.assertNotIn("consensus", state)

        # Superseding withdraws a stance; it does not delete earlier review rows.
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM review_decisions WHERE reviewer_id = ?",
                (self.alice,),
            ).fetchone()[0],
            3,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE review_decisions SET rationale = 'rewritten' WHERE decision_id = ?",
                (rejected,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "DELETE FROM review_decisions WHERE decision_id = ?", (rejected,)
            )

    def test_successor_target_reviewer_time_and_release_guards(self) -> None:
        first = self._decision(
            reviewer_id=self.alice,
            action="defer",
            decided_at=datetime(2026, 8, 17, 19, tzinfo=timezone.utc),
            rationale="Defer pending another artifact.",
            claim_id=self.claim,
        )
        # A chain may deliberately cross release contexts.
        second = self._decision(
            reviewer_id=self.alice,
            action="accept",
            decided_at="2026-08-17T19:00:00Z",
            rationale="The second release supplies the missing artifact.",
            previous_decision_id=first,
            review_release_id=self.second_release,
            claim_id=self.claim,
        )
        self.assertEqual(
            self.db.get_current_review_state(claim_id=self.claim)[
                "current_by_reviewer"
            ][0]["decision_id"],
            second,
        )

        with self.assertRaises(ValueError):
            self._decision(
                reviewer_id=self.alice,
                action="reject",
                decided_at="2026-08-17T18:59:59Z",
                rationale="This timestamp moves backward.",
                previous_decision_id=second,
                claim_id=self.claim,
            )
        with self.assertRaises(IdentityConflictError):
            self._decision(
                reviewer_id=self.bob,
                action="reject",
                decided_at="2026-08-17T20:00:00Z",
                rationale="A reviewer cannot continue another reviewer's chain.",
                previous_decision_id=second,
                claim_id=self.claim,
            )
        with self.assertRaises(IdentityConflictError):
            self._decision(
                reviewer_id=self.alice,
                action="reject",
                decided_at="2026-08-17T20:00:00Z",
                rationale="A successor cannot move to a different exact target.",
                previous_decision_id=second,
                hypothesis_set_id=self.hypothesis,
            )
        with self.assertRaises(ValueError):
            self._decision(
                reviewer_id=self.bob,
                action="reopen",
                decided_at="2026-08-17T20:00:00Z",
                rationale="There is no prior Bob decision to reopen.",
                claim_id=self.claim,
            )
        with self.assertRaises(ValueError):
            self._decision(
                reviewer_id=self.bob,
                action="defer",
                decided_at="2026-08-17T20:00:00",
                rationale="A naive timestamp is not durable.",
                claim_id=self.claim,
            )

        # A second unchained root for one reviewer and exact target is forbidden.
        with self.assertRaises(sqlite3.IntegrityError):
            self._decision(
                reviewer_id=self.alice,
                action="accept",
                decided_at="2026-08-17T21:00:00Z",
                rationale="This incorrectly starts a second Alice chain.",
                claim_id=self.claim,
            )

    def test_direct_sql_cannot_bypass_target_xor_or_chronology(self) -> None:
        carol = self.db.upsert_reviewer(
            identity_kind="person",
            identity_key="carol@example.invalid",
            display_name="Carol",
        )
        first = self._decision(
            reviewer_id=carol,
            action="defer",
            decided_at="2026-08-17T22:00:00Z",
            rationale="Hold for manual analysis.",
            claim_id=self.claim,
        )
        base = (
            carol,
            "accept",
            "2026-08-17T21:59:59.000000Z",
            "Backdated successor.",
            self.provenance,
            self.first_release,
            first,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                INSERT INTO review_decisions
                    (decision_id, claim_id, reviewer_id, action, decided_at,
                     rationale, provenance_id, review_release_id,
                     previous_decision_id)
                VALUES ('backdated', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self.claim, *base),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                INSERT INTO review_decisions
                    (decision_id, hypothesis_set_id, claim_id, reviewer_id,
                     action, decided_at, rationale, provenance_id,
                     review_release_id)
                VALUES ('two-targets', ?, ?, ?, 'defer',
                        '2026-08-17T23:00:00.000000Z', 'Ambiguous target.', ?, ?)
                """,
                (
                    self.hypothesis,
                    self.claim,
                    carol,
                    self.provenance,
                    self.first_release,
                ),
            )

    def test_release_identity_is_idempotent_and_immutable(self) -> None:
        self.assertEqual(
            self.db.upsert_review_release(
                release_key="atlas-test-r1",
                label="Atlas test release 1",
                version="1",
                source_revision="abc123",
                provenance_id=self.provenance,
            ),
            self.first_release,
        )
        with self.assertRaises(IdentityConflictError):
            self.db.upsert_review_release(
                release_key="atlas-test-r1",
                label="Retconned release label",
                version="1",
                source_revision="abc123",
                provenance_id=self.provenance,
            )

        self._decision(
            reviewer_id=self.alice,
            action="defer",
            decided_at="2026-08-17T23:30:00Z",
            rationale="Create a durable reference to reviewer and release context.",
            review_release_id=self.first_release,
            claim_id=self.claim,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE review_releases SET label = 'rewritten' WHERE review_release_id = ?",
                (self.first_release,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE reviewers SET identity_key = 'someone-else' WHERE reviewer_id = ?",
                (self.alice,),
            )


if __name__ == "__main__":
    unittest.main()
