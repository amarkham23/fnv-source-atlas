from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import AtlasDatabase  # noqa: E402
from fnv_atlas.review_queue import (  # noqa: E402
    DECISION_STATES,
    TRIAGE_BUCKETS,
    build_review_queue_page,
    build_review_release_snapshot,
    evaluate_producers,
)


class ReviewQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary.name) / "atlas.sqlite"
        self.db = AtlasDatabase.create(self.database_path)
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("xbox", platform="xbox360", name="Xbox")
        self.alpha = self.db.upsert_provenance(
            provenance_id="provenance:alpha",
            kind="matcher",
            producer="producer-alpha",
            producer_version="1",
            parameters={"fixture": "alpha"},
        )
        self.beta = self.db.upsert_provenance(
            provenance_id="provenance:beta",
            kind="matcher",
            producer="producer-beta",
            producer_version="2",
        )
        self.alice = self.db.upsert_reviewer(
            reviewer_id="reviewer:alice",
            identity_kind="person",
            identity_key="alice@example.invalid",
            display_name="Alice",
        )
        self.bob = self.db.upsert_reviewer(
            reviewer_id="reviewer:bob",
            identity_kind="person",
            identity_key="bob@example.invalid",
            display_name="Bob",
        )
        self.charlie = self.db.upsert_reviewer(
            reviewer_id="reviewer:charlie",
            identity_kind="person",
            identity_key="charlie@example.invalid",
            display_name="Charlie",
        )
        self.release_one = self.db.upsert_review_release(
            review_release_id="review-release:r1",
            release_key="r1",
            label="Release 1",
            version="1",
            source_revision="abc",
            provenance_id=self.alpha,
        )
        self.release_two = self.db.upsert_review_release(
            review_release_id="review-release:r2",
            release_key="r2",
            label="Release 2",
            version="2",
            source_revision="def",
            provenance_id=self.alpha,
        )
        self._pc_index = 0
        self._xbox_index = 0
        self._time_index = 0
        self.fixture = self._build_triage_fixture()
        self._add_reviews()

    def tearDown(self) -> None:
        self.db.close()
        self.temporary.cleanup()

    def _function(self, program_id: str) -> str:
        if program_id == "pc":
            self._pc_index += 1
            index = self._pc_index
            address = 0x400000 + index * 0x10
            address_space = "ram"
        else:
            self._xbox_index += 1
            index = self._xbox_index
            address = 0x82000000 + index * 0x10
            address_space = "xbox-va"
        function_id = f"{program_id}:function:{index:03d}"
        group = self.db.upsert_address_group(
            program_id=program_id,
            address_space=address_space,
            address=address,
        )
        self.db.upsert_function(
            function_id=function_id,
            address_group_id=group,
            identity_key=function_id,
        )
        self.db.add_function_name(
            function_id,
            f"name::{function_id}",
            name_kind="fixture",
            is_primary=True,
            provenance_id=self.alpha,
        )
        return function_id

    def _target(self, program_id: str) -> str:
        if program_id == "pc":
            address = 0x500000
            address_space = "ram"
        else:
            address = 0x83000000
            address_space = "xbox-va"
        group = self.db.upsert_address_group(
            program_id=program_id,
            address_space=address_space,
            address=address,
        )
        return self.db.upsert_unresolved_target(
            target_id=f"{program_id}:target",
            address_group_id=group,
            target_kind="candidate-entry",
            provenance_id=self.alpha,
        )

    def _scalar_set(
        self,
        name: str,
        *,
        producer: str | None = None,
        pc_target: str | None = None,
        xbox_target: str | None = None,
        add_support: bool = False,
    ) -> tuple[str, str, str]:
        producer = producer or self.alpha
        pc_function = None if pc_target is not None else self._function("pc")
        xbox_function = None if xbox_target is not None else self._function("xbox")
        claim = self.db.upsert_match_claim(
            claim_id=f"claim:{name}",
            pc_function_id=pc_function,
            pc_target_id=pc_target,
            xbox_function_id=xbox_function,
            xbox_target_id=xbox_target,
            provenance_id=producer,
        )
        hypothesis = self.db.upsert_match_hypothesis_set(
            hypothesis_set_id=f"set:{name}",
            pc_function_id=pc_function,
            pc_target_id=pc_target,
            identity_key=name,
            provenance_id=self.alpha,
        )
        alternative = self.db.add_match_hypothesis_alternative(
            hypothesis,
            alternative_id=f"alternative:{name}",
            claim_id=claim,
        )
        if add_support:
            self.db.add_match_hypothesis_alternative_evidence(
                alternative,
                evidence_id=f"evidence:{name}:alternative",
                effect="supports",
                evidence_kind="fixture-edge",
                independence_group="flow",
                provenance_id=self.alpha,
                details={"name": name},
            )
        return hypothesis, alternative, claim

    def _build_triage_fixture(self) -> dict[str, dict[str, str]]:
        fixture: dict[str, dict[str, str]] = {}
        contradicted = self._scalar_set("contradicted", add_support=True)
        self.db.add_match_hypothesis_evidence(
            contradicted[0],
            evidence_id="evidence:contradiction",
            effect="contradicts",
            evidence_kind="fixture-conflict",
            independence_group="manual-check",
            provenance_id=self.beta,
        )
        fixture["contradicted"] = dict(
            zip(("set", "alternative", "claim"), contradicted, strict=True)
        )

        incomplete = self._scalar_set("incomplete")
        fixture["incomplete"] = dict(
            zip(("set", "alternative", "claim"), incomplete, strict=True)
        )

        ambiguous = self._scalar_set("ambiguous", add_support=True)
        second_pc = self.db.connection.execute(
            "SELECT pc_function_id FROM match_claims WHERE claim_id = ?",
            (ambiguous[2],),
        ).fetchone()[0]
        second_claim = self.db.upsert_match_claim(
            claim_id="claim:ambiguous:second",
            pc_function_id=second_pc,
            xbox_function_id=self._function("xbox"),
            provenance_id=self.beta,
        )
        self.db.add_match_hypothesis_alternative(
            ambiguous[0],
            alternative_id="alternative:ambiguous:second",
            claim_id=second_claim,
        )
        fixture["ambiguous"] = dict(
            zip(("set", "alternative", "claim"), ambiguous, strict=True)
        )

        fold_pc = self._function("pc")
        fold_set = self.db.upsert_match_hypothesis_set(
            hypothesis_set_id="set:fold",
            pc_function_id=fold_pc,
            identity_key="fold",
            provenance_id=self.alpha,
        )
        fold_id = self.db.upsert_fold_group(
            "fold:large",
            program_id="xbox",
            provenance_id=self.alpha,
        )
        for _ in range(11):
            self.db.add_fold_member(fold_id, self._function("xbox"))
        fold_alternative = self.db.add_match_hypothesis_alternative(
            fold_set,
            alternative_id="alternative:fold",
            xbox_fold_group_id=fold_id,
        )
        self.db.add_match_hypothesis_evidence(
            fold_set,
            evidence_id="evidence:fold",
            effect="supports",
            evidence_kind="fixture-fold",
            independence_group="vtable-structure",
            provenance_id=self.alpha,
        )
        fixture["fold"] = {
            "set": fold_set,
            "alternative": fold_alternative,
            "fold": fold_id,
        }

        unresolved = self._scalar_set(
            "unresolved",
            pc_target=self._target("pc"),
            xbox_target=self._target("xbox"),
            add_support=True,
        )
        fixture["unresolved"] = dict(
            zip(("set", "alternative", "claim"), unresolved, strict=True)
        )

        exact = self._scalar_set("exact", add_support=True)
        self.db.add_claim_evidence(
            exact[2],
            evidence_id="evidence:exact:claim",
            effect="context",
            evidence_kind="name-shape",
            independence_group="names",
            provenance_id=self.beta,
        )
        fixture["exact"] = dict(
            zip(("set", "alternative", "claim"), exact, strict=True)
        )
        return fixture

    def _decision(
        self,
        *,
        reviewer: str,
        action: str,
        release: str,
        alternative: str | None = None,
        claim: str | None = None,
        hypothesis: str | None = None,
    ) -> str:
        self._time_index += 1
        return self.db.add_review_decision(
            reviewer_id=reviewer,
            action=action,
            decided_at=f"2026-08-17T12:00:{self._time_index:02d}.000000Z",
            rationale=f"Fixture {action} decision.",
            provenance_id=self.alpha,
            review_release_id=release,
            alternative_id=alternative,
            claim_id=claim,
            hypothesis_set_id=hypothesis,
        )

    def _add_reviews(self) -> None:
        exact_alternative = self.fixture["exact"]["alternative"]
        self._decision(
            reviewer=self.alice,
            action="accept",
            release=self.release_one,
            alternative=exact_alternative,
        )
        self._decision(
            reviewer=self.bob,
            action="reject",
            release=self.release_one,
            alternative=exact_alternative,
        )
        self._decision(
            reviewer=self.alice,
            action="reject",
            release=self.release_one,
            claim=self.fixture["contradicted"]["claim"],
        )
        self._decision(
            reviewer=self.alice,
            action="defer",
            release=self.release_one,
            alternative=self.fixture["fold"]["alternative"],
        )
        # This remains visible as Alice's current leaf but is open in r1.
        self._decision(
            reviewer=self.alice,
            action="accept",
            release=self.release_two,
            hypothesis=self.fixture["ambiguous"]["set"],
        )

    def test_explicit_triage_evidence_fold_bounds_and_review_conflict(self) -> None:
        queue = build_review_queue_page(
            self.db.connection,
            reviewer_id=self.alice,
            review_release_id=self.release_one,
            limit=100,
            fold_sample_limit=3,
        )
        document = queue.to_dict()
        self.assertEqual(
            [item["triage_bucket"] for item in document["items"]],
            list(TRIAGE_BUCKETS),
        )
        by_bucket = {item["triage_bucket"]: item for item in document["items"]}

        contradicted = by_bucket["contradicted"]
        effects = [item["effect"] for item in contradicted["evidence"]]
        self.assertIn("contradicts", effects)
        self.assertEqual(
            {
                group["independence_group"]
                for group in contradicted["independence_groups"]
            },
            {"flow", "manual-check"},
        )
        self.assertEqual(len(by_bucket["ambiguous"]["alternatives"]), 2)

        unresolved = by_bucket["unresolved"]
        self.assertEqual(unresolved["pc_subject"]["endpoint_kind"], "unresolved_target")
        self.assertEqual(
            unresolved["alternatives"][0]["claim"]["xbox_endpoint"][
                "endpoint_kind"
            ],
            "unresolved_target",
        )

        fold = by_bucket["fold"]["alternatives"][0]["fold_bundle"]
        self.assertEqual(fold["member_count"], 11)
        self.assertEqual(len(fold["member_sample"]), 3)
        self.assertTrue(fold["member_sample_truncated"])
        self.assertNotIn("members", fold)

        exact = by_bucket["exact"]
        self.assertEqual(
            {group["independence_group"] for group in exact["independence_groups"]},
            {"flow", "names"},
        )
        self.assertEqual(
            exact["alternatives"][0]["evidence"][0]["scope"], "alternative"
        )
        self.assertEqual(
            exact["alternatives"][0]["claim"]["evidence"][0]["scope"],
            "claim",
        )
        exact_review = exact["alternatives"][0]["review"]
        self.assertEqual(
            exact_review["selected_reviewer"]["state"], "accepted"
        )
        self.assertEqual(
            exact_review["literal_leaf_summary"]["distinct_actions"],
            ["accept", "reject"],
        )
        self.assertTrue(
            exact_review["literal_leaf_summary"]["has_action_disagreement"]
        )
        stale = by_bucket["ambiguous"]["review"]["selected_reviewer"]
        self.assertEqual(stale["state"], "open")
        self.assertEqual(stale["basis"], "current_leaf_from_another_release")
        self.assertEqual(stale["current_leaf"]["review_release_id"], self.release_two)
        self.assertFalse(document["policy"]["consensus_inferred"])
        self.assertFalse(document["policy"]["confidence_inferred"])

    def test_queue_is_deterministic_immutable_and_pages_stably(self) -> None:
        first_page = build_review_queue_page(
            self.database_path,
            reviewer_id=self.alice,
            review_release_id=self.release_one,
            limit=2,
            fold_sample_limit=2,
        )
        repeated = build_review_queue_page(
            self.database_path,
            reviewer_id=self.alice,
            review_release_id=self.release_one,
            limit=2,
            fold_sample_limit=2,
        )
        self.assertEqual(first_page.to_json(), repeated.to_json())
        self.assertEqual(first_page.page_sha256, repeated.page_sha256)

        first = first_page.to_dict()
        self.assertEqual(first["returned_count"], 2)
        self.assertEqual(first["total_count"], 6)
        second = build_review_queue_page(
            self.database_path,
            reviewer_id=self.alice,
            review_release_id=self.release_one,
            limit=2,
            after=first["next_cursor"],
            fold_sample_limit=2,
        ).to_dict()
        third = build_review_queue_page(
            self.database_path,
            reviewer_id=self.alice,
            review_release_id=self.release_one,
            limit=2,
            after=second["next_cursor"],
            fold_sample_limit=2,
        ).to_dict()
        whole = build_review_queue_page(
            self.database_path,
            reviewer_id=self.alice,
            review_release_id=self.release_one,
            limit=6,
            fold_sample_limit=2,
        ).to_dict()
        paged = first["items"] + second["items"] + third["items"]
        self.assertEqual(paged, whole["items"])
        self.assertIsNone(third["next_cursor"])
        with self.assertRaises(ValueError):
            build_review_queue_page(
                self.database_path,
                reviewer_id=self.charlie,
                review_release_id=self.release_one,
                limit=1,
                after=first["next_cursor"],
                fold_sample_limit=2,
            )

        self.db.add_match_hypothesis_evidence(
            self.fixture["exact"]["set"],
            evidence_id="evidence:late-bucket-change",
            effect="contradicts",
            evidence_kind="late-review-input",
            independence_group="late-input",
            provenance_id=self.alpha,
        )
        with self.assertRaisesRegex(ValueError, "queue changed"):
            build_review_queue_page(
                self.db.connection,
                reviewer_id=self.alice,
                review_release_id=self.release_one,
                limit=2,
                after=first["next_cursor"],
                fold_sample_limit=2,
            )

        detached = first_page.to_dict()
        detached["items"].clear()
        self.assertEqual(len(first_page.to_dict()["items"]), 2)

    def test_all_database_work_succeeds_when_sqlite_denies_writes(self) -> None:
        denied = {
            sqlite3.SQLITE_INSERT,
            sqlite3.SQLITE_UPDATE,
            sqlite3.SQLITE_DELETE,
            sqlite3.SQLITE_CREATE_INDEX,
            sqlite3.SQLITE_CREATE_TABLE,
            sqlite3.SQLITE_CREATE_TEMP_INDEX,
            sqlite3.SQLITE_CREATE_TEMP_TABLE,
            sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
            sqlite3.SQLITE_CREATE_TEMP_VIEW,
            sqlite3.SQLITE_CREATE_TRIGGER,
            sqlite3.SQLITE_CREATE_VIEW,
            sqlite3.SQLITE_DROP_INDEX,
            sqlite3.SQLITE_DROP_TABLE,
            sqlite3.SQLITE_DROP_TEMP_INDEX,
            sqlite3.SQLITE_DROP_TEMP_TABLE,
            sqlite3.SQLITE_DROP_TEMP_TRIGGER,
            sqlite3.SQLITE_DROP_TEMP_VIEW,
            sqlite3.SQLITE_DROP_TRIGGER,
            sqlite3.SQLITE_DROP_VIEW,
            sqlite3.SQLITE_ALTER_TABLE,
        }

        def authorizer(action: int, *_: object) -> int:
            return sqlite3.SQLITE_DENY if action in denied else sqlite3.SQLITE_OK

        before_changes = self.db.connection.total_changes
        self.db.connection.set_authorizer(authorizer)
        try:
            queue = build_review_queue_page(
                self.db.connection,
                reviewer_id=self.alice,
                review_release_id=self.release_one,
            )
            snapshot = build_review_release_snapshot(
                self.db.connection,
                reviewer_id=self.alice,
                review_release_id=self.release_one,
            )
        finally:
            self.db.connection.set_authorizer(None)
        self.assertEqual(len(queue.to_dict()["items"]), 6)
        self.assertGreater(len(snapshot.to_dict()["targets"]), 0)
        self.assertEqual(self.db.connection.total_changes, before_changes)

    def test_snapshot_evaluation_keeps_target_scopes_distinct(self) -> None:
        snapshot = build_review_release_snapshot(
            self.db.connection,
            reviewer_id=self.alice,
            review_release_id=self.release_one,
            fold_sample_limit=2,
        )
        document = snapshot.to_dict()
        self.assertEqual(document["reviewer"]["reviewer_id"], self.alice)
        self.assertEqual(
            document["review_release"]["review_release_id"], self.release_one
        )
        self.assertEqual(
            set(document["counts"]["by_target_kind"]),
            {"claim", "hypothesis_set", "alternative"},
        )
        self.assertEqual(
            document["counts"]["all_targets"]["total"],
            len(document["targets"]),
        )
        exact_claim = next(
            target
            for target in document["targets"]
            if target["target_id"] == self.fixture["exact"]["claim"]
        )
        endpoint_ref = exact_claim["candidate"]["pc_endpoint_ref"]
        self.assertIn(endpoint_ref, document["catalogs"]["endpoints"])
        self.assertNotIn("pc_endpoint", exact_claim["candidate"])
        self.assertIn(
            exact_claim["producer_provenance_id"],
            document["catalogs"]["provenance"],
        )
        self.assertEqual(snapshot.to_json(), snapshot.to_json())

        evaluation = evaluate_producers(snapshot).to_dict()
        by_producer = {row["producer"]: row for row in evaluation["producers"]}
        alpha = by_producer["producer-alpha"]
        self.assertGreaterEqual(alpha["counts"]["accepted"], 1)
        self.assertGreaterEqual(alpha["counts"]["rejected"], 1)
        self.assertGreaterEqual(alpha["counts"]["deferred"], 1)
        self.assertGreaterEqual(alpha["counts"]["open"], 1)
        self.assertEqual(
            alpha["by_target_kind"]["alternative"]["accepted"], 1
        )
        self.assertEqual(
            alpha["by_target_kind"]["claim"]["rejected"], 1
        )
        self.assertFalse(evaluation["policy"]["precision_calculated"])
        self.assertFalse(evaluation["policy"]["accuracy_calculated"])
        self.assertNotIn("precision", alpha)

    def test_zero_review_snapshot_reports_open_counts_not_fake_precision(self) -> None:
        snapshot = build_review_release_snapshot(
            self.db.connection,
            reviewer_id=self.charlie,
            review_release_id=self.release_one,
        )
        document = snapshot.to_dict()
        counts = document["counts"]["all_targets"]
        self.assertEqual(counts["open"], counts["total"])
        for state in ("accepted", "rejected", "deferred"):
            self.assertEqual(counts[state], 0)
        evaluation = evaluate_producers(snapshot).to_dict()
        for producer in evaluation["producers"]:
            self.assertEqual(producer["counts"]["open"], producer["counts"]["total"])
            for state in DECISION_STATES[:-1]:
                self.assertEqual(producer["counts"][state], 0)
        serialized = evaluation["policy"]
        self.assertEqual(serialized["metrics"], "counts_only")
        self.assertFalse(serialized["precision_calculated"])


if __name__ == "__main__":
    unittest.main()
