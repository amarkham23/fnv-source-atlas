from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.control_flow_matching import (  # noqa: E402
    Endpoint,
    MappingAlternative,
    PcCallEdge,
    XboxFlowOccurrence,
    analyze_control_flow_candidates,
)
from fnv_atlas.control_flow_matching_persistence import (  # noqa: E402
    persist_control_flow_matching_result,
)
from fnv_atlas.database import AtlasDatabase  # noqa: E402
from fnv_atlas.validation import (  # noqa: E402
    semantic_validation_counts,
    semantic_validation_ok,
)


PC = "program:pc:matcher-validation"
XBOX = "program:xbox:matcher-validation"
CHECK_PREFIX = "control_flow_matching_"


def _flow(ordinal: int, caller: str, target: Endpoint) -> XboxFlowOccurrence:
    return XboxFlowOccurrence(
        occurrence_id=f"flow:{ordinal}",
        extraction_id="flow-extraction:matcher-validation",
        use_id=f"use:{ordinal}",
        use_assertion_id=f"use-assertion:{ordinal}",
        site_id=f"site:{ordinal}",
        site_assertion_id=f"site-assertion:{ordinal}",
        caller_function_id=caller,
        procedure_record_id=caller,
        role="direct_call",
        target_endpoint=target,
        site_address_space="xbox-va",
        site_address=0x82010000 + ordinal * 4,
    )


def _mapping(ordinal: str, pc: str, xbox: str) -> MappingAlternative:
    return MappingAlternative(
        hypothesis_set_id=f"source-set:{ordinal}",
        alternative_id=f"source-alternative:{ordinal}",
        claim_id=f"source-claim:{ordinal}",
        pc_endpoint=Endpoint("pc", "function", pc),
        xbox_endpoint=Endpoint("xbox360", "function", xbox),
        provenance_id="source-provenance:matcher-validation",
        producer="fixture",
    )


class ControlFlowMatchingSemanticValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create(":memory:")
        self.addCleanup(self.db.close)
        self.db.upsert_program(PC, platform="pc", name="PC")
        self.db.upsert_program(XBOX, platform="xbox360", name="Xbox")
        self.symbol_provenance = self.db.upsert_provenance(
            kind="test", producer="matcher-validation-symbol-fixture"
        )
        self.matcher_provenance = self.db.upsert_provenance(
            kind="analysis", producer="fnv_atlas.control_flow_matching"
        )
        for index, identity in enumerate(("pc:A", "pc:B", "pc:C")):
            self._function(PC, identity, 0x401000 + index * 0x100)
        for index, identity in enumerate(("x:A", "x:B", "x:C")):
            self._function(XBOX, identity, 0x82001000 + index * 0x100)
        address_only_group = self.db.upsert_address_group(
            program_id=XBOX,
            address_space="xbox-va",
            address=0x8200A000,
            kind="control-flow-target",
        )
        address_only_endpoint = Endpoint(
            "xbox360",
            "address_only",
            address_only_group,
            address_group_id=address_only_group,
            address_space="xbox-va",
            address=0x8200A000,
            classification="executable_non_entry",
        )

        result = analyze_control_flow_candidates(
            (
                _mapping("caller", "pc:A", "x:A"),
                _mapping("closed", "pc:B", "x:B"),
            ),
            (
                PcCallEdge(
                    "edge:closed", "pc:A", Endpoint("pc", "function", "pc:B")
                ),
                PcCallEdge(
                    "edge:residual",
                    "pc:A",
                    Endpoint("pc", "function", "pc:C"),
                ),
            ),
            (
                _flow(1, "x:A", Endpoint("xbox360", "function", "x:B")),
                _flow(2, "x:A", address_only_endpoint),
                _flow(3, "x:A", address_only_endpoint),
            ),
        )
        persist_control_flow_matching_result(
            self.db, result, provenance_id=self.matcher_provenance
        )
        rows = list(
            self.db.connection.execute(
                """
                SELECT hypothesis_set_id,
                       json_extract(details_json, '$.kind') AS set_kind
                FROM match_hypothesis_sets
                WHERE provenance_id = ? ORDER BY hypothesis_set_id
                """,
                (self.matcher_provenance,),
            )
        )
        self.closed_set = next(
            row["hypothesis_set_id"]
            for row in rows
            if row["set_kind"] == "closed_call_square_relation"
        )
        self.proposal_set = next(
            row["hypothesis_set_id"]
            for row in rows
            if row["set_kind"] == "unique_residual_call_proposal"
        )

    def _function(self, program: str, identity: str, address: int) -> str:
        address_group = self.db.upsert_address_group(
            program_id=program,
            address_space="ram" if program == PC else "xbox-va",
            address=address,
        )
        return self.db.upsert_function(
            function_id=identity,
            address_group_id=address_group,
            identity_key=identity,
            provenance_id=self.symbol_provenance,
        )

    def _counts(self) -> dict[str, int]:
        return semantic_validation_counts(self.db.connection)

    def test_matcher_output_is_candidate_only_and_globally_valid(self) -> None:
        self.assertEqual(
            self.db.connection.execute(
                """
                SELECT COUNT(*) FROM unresolved_targets
                WHERE provenance_id = ?
                  AND target_kind = 'control_flow_address_only'
                """,
                (self.matcher_provenance,),
            ).fetchone()[0],
            1,
        )
        counts = self._counts()
        relevant = {
            name: count
            for name, count in counts.items()
            if name.startswith(CHECK_PREFIX)
        }
        self.assertEqual(len(relevant), 5)
        self.assertTrue(all(count == 0 for count in relevant.values()), relevant)
        self.assertTrue(semantic_validation_ok(counts), counts)

    def test_detects_state_evidence_scope_completeness_and_disjunction_tampering(
        self,
    ) -> None:
        claim_id = self.db.connection.execute(
            """
            SELECT claim.claim_id
            FROM match_claims claim
            WHERE claim.provenance_id = ? ORDER BY claim.claim_id LIMIT 1
            """,
            (self.matcher_provenance,),
        ).fetchone()[0]
        evidence_rows = list(
            self.db.connection.execute(
                """
                SELECT evidence_id, alternative_id
                FROM match_hypothesis_alternative_evidence
                WHERE provenance_id = ? ORDER BY evidence_id
                """,
                (self.matcher_provenance,),
            )
        )
        self.assertGreaterEqual(len(evidence_rows), 2)

        self.db.connection.execute(
            "UPDATE match_hypothesis_sets SET status = 'accepted' "
            "WHERE hypothesis_set_id = ?",
            (self.closed_set,),
        )
        self.db.connection.execute(
            "UPDATE match_claims SET confidence_label = 'high' WHERE claim_id = ?",
            (claim_id,),
        )
        self.db.add_claim_evidence(
            claim_id,
            effect="supports",
            evidence_kind="invalid-matcher-claim-scope",
            independence_group="invalid-matcher-claim-scope",
            provenance_id=self.matcher_provenance,
        )
        self.db.add_match_hypothesis_evidence(
            self.closed_set,
            effect="supports",
            evidence_kind="invalid-matcher-set-scope",
            independence_group="invalid-matcher-set-scope",
            provenance_id=self.matcher_provenance,
        )
        self.db.connection.execute(
            "DROP TRIGGER reject_match_hypothesis_alternative_evidence_update"
        )
        self.db.connection.execute(
            "DROP TRIGGER reject_match_hypothesis_alternative_evidence_delete"
        )
        self.db.connection.execute(
            """
            UPDATE match_hypothesis_alternative_evidence
            SET effect = 'contradicts',
                details_json = json_set(
                    details_json,
                    '$.conditional_evidence', json('false'),
                    '$.independent_confirmation', json('true'),
                    '$.acceptance_effect', 'accept'
                )
            WHERE evidence_id = ?
            """,
            (evidence_rows[0]["evidence_id"],),
        )
        self.db.connection.execute(
            """
            DELETE FROM match_hypothesis_alternative_evidence
            WHERE alternative_id = ?
            """,
            (evidence_rows[1]["alternative_id"],),
        )
        self.db.connection.execute(
            """
            UPDATE match_hypothesis_sets
            SET details_json = json_set(
                details_json,
                '$.proposal_set.alternative_ids',
                json_array('missing-alternative-a', 'missing-alternative-b')
            )
            WHERE hypothesis_set_id = ?
            """,
            (self.proposal_set,),
        )

        counts = self._counts()
        for name in (
            "control_flow_matching_candidate_state_mismatch",
            "control_flow_matching_evidence_scope_mismatch",
            "control_flow_matching_incomplete_alternatives",
            "control_flow_matching_disjunction_mismatch",
        ):
            self.assertGreater(counts[name], 0, name)

    def test_detects_orphan_matcher_address_only_target(self) -> None:
        address_group = self.db.upsert_address_group(
            program_id=XBOX,
            address_space="xbox-va",
            address=0x8200B000,
            kind="control-flow-target",
        )
        self.db.upsert_unresolved_target(
            target_id="orphan-matcher-address-only-target",
            address_group_id=address_group,
            target_kind="control_flow_address_only",
            reason="Orphan tamper fixture",
            provenance_id=self.matcher_provenance,
            details={
                "candidate_only": True,
                "classification": "executable_non_entry",
                "function_creation": "forbidden",
            },
        )

        counts = self._counts()
        self.assertGreater(
            counts["control_flow_matching_candidate_state_mismatch"], 0
        )

    def test_detects_function_name_class_vtable_and_review_leakage(self) -> None:
        leaked_function = self._function(PC, "pc:leaked", 0x404000)
        # Add a forbidden matcher-attributed assertion to the canonical row.
        self.db.upsert_function(
            function_id=leaked_function,
            address_group_id=self.db.connection.execute(
                "SELECT address_group_id FROM functions WHERE function_id = ?",
                (leaked_function,),
            ).fetchone()[0],
            identity_key=leaked_function,
            provenance_id=self.matcher_provenance,
        )
        self.db.add_function_name(
            leaked_function,
            "MatcherLeakedFunction",
            name_kind="matcher-leak",
            provenance_id=self.matcher_provenance,
        )
        self.db.upsert_class(
            "matcher-leaked-class",
            program_id=PC,
            identity_key="matcher-leaked-class",
        )
        self.db.add_class_name(
            "matcher-leaked-class",
            "MatcherLeakedClass",
            name_kind="matcher-leak",
            provenance_id=self.matcher_provenance,
        )
        self.db.upsert_fold_group(
            "matcher-leaked-fold",
            program_id=XBOX,
            provenance_id=self.matcher_provenance,
        )
        self.db.upsert_vtable(
            "matcher-leaked-vtable",
            program_id=PC,
            class_id="matcher-leaked-class",
            address_space="ram",
            address=0x500000,
            vfptr_role="primary",
            provenance_id=self.matcher_provenance,
        )
        target_address_group = self.db.connection.execute(
            "SELECT address_group_id FROM functions WHERE function_id = ?",
            (leaked_function,),
        ).fetchone()[0]
        self.db.upsert_vtable_slot(
            "matcher-leaked-vtable",
            0,
            target_address_group_id=target_address_group,
            provenance_id=self.matcher_provenance,
        )
        release = self.db.upsert_review_release(
            release_key="matcher-leaked-review",
            label="Matcher leaked review",
            provenance_id=self.matcher_provenance,
        )
        reviewer = self.db.upsert_reviewer(
            identity_kind="fixture",
            identity_key="matcher-leaked-reviewer",
            display_name="Matcher leaked reviewer",
        )
        self.db.add_review_decision(
            reviewer_id=reviewer,
            action="defer",
            decided_at="2026-08-17T00:00:00.000000Z",
            rationale="Tamper fixture",
            provenance_id=self.matcher_provenance,
            review_release_id=release,
            hypothesis_set_id=self.closed_set,
        )

        counts = self._counts()
        self.assertGreaterEqual(
            counts["control_flow_matching_provenance_leakage"], 11
        )


if __name__ == "__main__":
    unittest.main()
