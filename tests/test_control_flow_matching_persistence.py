from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))


from fnv_atlas.control_flow_matching import (
    Endpoint,
    FoldMembership,
    MappingAlternative,
    PcCallEdge,
    XboxFlowOccurrence,
    analyze_control_flow_candidates,
)
from fnv_atlas.control_flow_matching_persistence import (
    persist_control_flow_matching_result,
)
from fnv_atlas.database import AtlasDatabase


PC = "program:pc:fixture"
XBOX = "program:xbox:fixture"


def _flow(ordinal: int, caller: str, target: Endpoint) -> XboxFlowOccurrence:
    return XboxFlowOccurrence(
        occurrence_id=f"flow:{ordinal}",
        extraction_id="flow-extraction:fixture",
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


class ControlFlowMatchingPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.addCleanup(self.db.close)
        self.db.upsert_program(PC, platform="pc", name="PC")
        self.db.upsert_program(XBOX, platform="xbox360", name="Xbox")
        self.provenance = self.db.upsert_provenance(
            kind="analysis",
            producer="fnv_atlas.control_flow_matching",
        )

    def function(self, program: str, identity: str, address: int) -> str:
        space = "ram" if program == PC else "xbox-va"
        group = self.db.upsert_address_group(
            program_id=program,
            address_space=space,
            address=address,
        )
        return self.db.upsert_function(
            function_id=identity,
            address_group_id=group,
            identity_key=identity,
        )

    @staticmethod
    def alternative(
        ordinal: str, pc: str, xbox: str
    ) -> MappingAlternative:
        return MappingAlternative(
            hypothesis_set_id=f"source-set:{ordinal}",
            alternative_id=f"source-alternative:{ordinal}",
            claim_id=f"source-claim:{ordinal}",
            pc_endpoint=Endpoint("pc", "function", pc),
            xbox_endpoint=Endpoint("xbox360", "function", xbox),
            provenance_id="source-provenance:fixture",
            producer="fixture",
        )

    def test_closed_and_residual_candidates_are_append_only_and_replay_safe(self) -> None:
        for index, identity in enumerate(("pc:A", "pc:B", "pc:C")):
            self.function(PC, identity, 0x401000 + index * 0x100)
        for index, identity in enumerate(("x:A", "x:B", "x:C")):
            self.function(XBOX, identity, 0x82001000 + index * 0x100)

        result = analyze_control_flow_candidates(
            (
                self.alternative("caller", "pc:A", "x:A"),
                self.alternative("closed", "pc:B", "x:B"),
            ),
            (
                PcCallEdge(
                    "edge:closed", "pc:A", Endpoint("pc", "function", "pc:B")
                ),
                PcCallEdge(
                    "edge:residual", "pc:A", Endpoint("pc", "function", "pc:C")
                ),
            ),
            (
                _flow(1, "x:A", Endpoint("xbox360", "function", "x:B")),
                _flow(2, "x:A", Endpoint("xbox360", "function", "x:C")),
                _flow(3, "x:A", Endpoint("xbox360", "function", "x:C")),
            ),
        )
        before = tuple(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM functions UNION ALL "
                "SELECT COUNT(*) FROM function_names"
            ).fetchall()
        )
        counts = persist_control_flow_matching_result(
            self.db, result, provenance_id=self.provenance
        )
        replay = persist_control_flow_matching_result(
            self.db, result, provenance_id=self.provenance
        )

        self.assertEqual(counts, replay)
        self.assertEqual(counts.closed_relations, 1)
        self.assertEqual(counts.proposal_sets, 1)
        self.assertEqual(counts.proposal_alternatives, 1)
        self.assertEqual(counts.scalar_claims, 2)
        self.assertEqual(counts.fold_bundle_alternatives, 0)
        self.assertEqual(counts.supporting_evidence, 3)
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM match_hypothesis_sets"
            ).fetchone()[0],
            2,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM match_hypothesis_alternative_evidence"
            ).fetchone()[0],
            3,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM match_hypothesis_evidence"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM match_claims WHERE status <> 'candidate' "
                "OR confidence_label IS NOT NULL OR confidence_value IS NOT NULL"
            ).fetchone()[0],
            0,
        )
        after = tuple(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM functions UNION ALL "
                "SELECT COUNT(*) FROM function_names"
            ).fetchall()
        )
        self.assertEqual(before, after)

    def test_fold_and_address_only_targets_are_not_fabricated_as_functions(self) -> None:
        for index, identity in enumerate(("pc:A", "pc:B", "pc:C", "pc:D")):
            self.function(PC, identity, 0x401000 + index * 0x100)
        for index, identity in enumerate(
            ("x:A", "x:B", "x:D", "x:member1", "x:member2")
        ):
            address = 0x82001000 + index * 0x100
            if identity.startswith("x:member"):
                address = 0x82009000
            self.function(XBOX, identity, address)
        fold = "fold:fixture"
        self.db.upsert_fold_group(fold, program_id=XBOX)
        self.db.add_fold_member(fold, "x:member1")
        self.db.add_fold_member(fold, "x:member2")
        address_group = self.db.upsert_address_group(
            program_id=XBOX,
            address_space="xbox-va",
            address=0x8200A000,
            kind="control-flow-target",
        )

        mappings = (
            self.alternative("caller", "pc:A", "x:A"),
            self.alternative("closed", "pc:B", "x:B"),
        )
        # Two independent caller neighborhoods derive two proposals: one fold
        # bundle and one executable address without a procedure entry.
        mappings += (self.alternative("caller2", "pc:D", "x:D"),)
        result = analyze_control_flow_candidates(
            mappings,
            (
                PcCallEdge("edge:1", "pc:A", Endpoint("pc", "function", "pc:B")),
                PcCallEdge("edge:2", "pc:A", Endpoint("pc", "function", "pc:C")),
                PcCallEdge("edge:3", "pc:D", Endpoint("pc", "function", "pc:B")),
                PcCallEdge("edge:4", "pc:D", Endpoint("pc", "function", "pc:C")),
            ),
            (
                _flow(1, "x:A", Endpoint("xbox360", "function", "x:B")),
                _flow(2, "x:A", Endpoint("xbox360", "fold_group", fold)),
                _flow(3, "x:D", Endpoint("xbox360", "function", "x:B")),
                _flow(
                    4,
                    "x:D",
                    Endpoint(
                        "xbox360",
                        "address_only",
                        address_group,
                        address_group_id=address_group,
                        address_space="xbox-va",
                        address=0x8200A000,
                        classification="executable_non_entry",
                    ),
                ),
            ),
            (
                FoldMembership(fold, "x:member1"),
                FoldMembership(fold, "x:member2"),
            ),
        )
        functions_before = self.db.connection.execute(
            "SELECT COUNT(*) FROM functions"
        ).fetchone()[0]
        counts = persist_control_flow_matching_result(
            self.db, result, provenance_id=self.provenance
        )

        self.assertGreaterEqual(counts.fold_bundle_alternatives, 1)
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM functions"
            ).fetchone()[0],
            functions_before,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM match_hypothesis_alternatives "
                "WHERE xbox_fold_group_id = ?",
                (fold,),
            ).fetchone()[0],
            1,
        )
        target = self.db.connection.execute(
            "SELECT target_kind, address_group_id FROM unresolved_targets "
            "WHERE target_kind = 'control_flow_address_only'"
        ).fetchone()
        self.assertIsNotNone(target)
        self.assertEqual(target["address_group_id"], address_group)


if __name__ == "__main__":
    unittest.main()
