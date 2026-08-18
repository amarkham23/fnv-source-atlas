from __future__ import annotations

from dataclasses import fields
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


def _pc_function(identity: str) -> Endpoint:
    return Endpoint("pc", "function", identity)


def _pc_unresolved(identity: str) -> Endpoint:
    return Endpoint("pc", "unresolved_target", identity)


def _xbox_function(identity: str) -> Endpoint:
    return Endpoint("xbox360", "function", identity)


def _xbox_unresolved(identity: str, address_group: str) -> Endpoint:
    return Endpoint(
        "xbox360",
        "unresolved_target",
        identity,
        address_group_id=address_group,
    )


def _xbox_fold(identity: str) -> Endpoint:
    return Endpoint("xbox360", "fold_group", identity)


def _xbox_address(identity: str, address: int) -> Endpoint:
    return Endpoint(
        "xbox360",
        "address_only",
        identity,
        address_group_id=identity,
        address_space="xbox-va",
        address=address,
        classification="executable_non_entry",
    )


def _xbox_indirect(identity: str) -> Endpoint:
    return Endpoint("xbox360", "indirect", identity)


def _alternative(
    ordinal: str,
    pc: Endpoint,
    xbox: Endpoint,
    *,
    status: str = "candidate",
) -> MappingAlternative:
    return MappingAlternative(
        hypothesis_set_id=f"set:{ordinal}",
        alternative_id=f"alternative:{ordinal}",
        claim_id=f"claim:{ordinal}" if xbox.kind != "fold_group" else None,
        pc_endpoint=pc,
        xbox_endpoint=xbox,
        provenance_id=f"provenance:{ordinal}",
        producer="fixture",
        status=status,
    )


def _edge(ordinal: str, caller: str, callee: Endpoint) -> PcCallEdge:
    return PcCallEdge(
        edge_id=f"edge:{ordinal}",
        caller_function_id=caller,
        callee_endpoint=callee,
    )


def _flow(
    ordinal: str,
    caller: str,
    target: Endpoint,
    *,
    role: str = "direct_call",
) -> XboxFlowOccurrence:
    return XboxFlowOccurrence(
        occurrence_id=f"flow:{ordinal}",
        extraction_id="extraction:fixture",
        use_id=f"use:{ordinal}",
        use_assertion_id=f"use-assertion:{ordinal}",
        site_id=f"site:{ordinal}",
        site_assertion_id=f"site-assertion:{ordinal}",
        caller_function_id=caller,
        procedure_record_id=caller,
        role=role,
        target_endpoint=target,
        site_address_space="xbox-va",
        site_address=0x82000000 + int(ordinal.strip("abcdefghijklmnopqrstuvwxyz") or 0),
    )


class ControlFlowMatchingTests(unittest.TestCase):
    def test_closed_square_unique_residual_is_deterministic_and_conditional(self) -> None:
        mappings = [
            _alternative("caller-a", _pc_function("pc:A"), _xbox_function("x:A")),
            _alternative("caller-b", _pc_function("pc:A"), _xbox_function("x:A")),
            _alternative("closed-a", _pc_function("pc:B"), _xbox_function("x:B")),
            _alternative("closed-b", _pc_function("pc:B"), _xbox_function("x:B")),
            _alternative(
                "rejected", _pc_function("pc:Z"), _xbox_function("x:Z"), status="rejected"
            ),
        ]
        edges = [
            _edge("closed", "pc:A", _pc_function("pc:B")),
            _edge("residual", "pc:A", _pc_function("pc:C")),
        ]
        flows = [
            _flow("1", "x:A", _xbox_function("x:B")),
            _flow("2", "x:A", _xbox_function("x:C")),
            _flow("3", "x:A", _xbox_function("x:C")),
            _flow("4", "x:A", _xbox_function("x:T"), role="tail_transfer"),
            _flow("5", "x:A", _xbox_indirect("indirect:5"), role="indirect_call"),
        ]

        result = analyze_control_flow_candidates(mappings, edges, flows)
        reversed_result = analyze_control_flow_candidates(
            reversed(mappings), reversed(edges), reversed(flows)
        )

        self.assertEqual(result, reversed_result)
        self.assertEqual(result.summary.source_mapping_alternatives, 5)
        self.assertEqual(result.summary.excluded_mapping_status_counts, (("rejected", 1),))
        self.assertEqual(result.summary.semantic_mapping_bundles, 2)
        self.assertEqual(result.summary.closed_square_derivations, 1)
        self.assertEqual(result.summary.closed_square_evidence_occurrences, 1)
        self.assertEqual(result.summary.residual_proposal_derivations, 1)
        self.assertEqual(result.summary.proposal_sets, 1)
        self.assertEqual(result.summary.proposal_alternatives, 1)
        self.assertEqual(result.summary.proposal_evidence_occurrences, 2)
        self.assertEqual(
            result.summary.excluded_xbox_occurrence_counts,
            (
                ("indirect_target", 1),
                ("tail_transfer_not_pc_call_equivalent", 1),
            ),
        )
        self.assertEqual(
            result.summary.excluded_xbox_role_counts,
            (("indirect_call", 1), ("tail_transfer", 1)),
        )

        caller_bundle = next(
            bundle for bundle in result.mapping_bundles if bundle.pc_endpoint.identity == "pc:A"
        )
        closed_bundle = next(
            bundle for bundle in result.mapping_bundles if bundle.pc_endpoint.identity == "pc:B"
        )
        self.assertEqual(len(caller_bundle.lineages), 2)
        self.assertEqual(len(closed_bundle.lineages), 2)
        self.assertFalse(caller_bundle.accepted_truth)

        proposal = result.proposals[0]
        self.assertEqual(proposal.pc_endpoint.identity, "pc:C")
        self.assertEqual(proposal.xbox_endpoint.identity, "x:C")
        self.assertEqual(proposal.status, "candidate")
        self.assertIsNone(proposal.confidence_value)
        self.assertFalse(proposal.applies_name)
        derivation = result.proposal_derivations[0]
        self.assertEqual(
            set(derivation.conditional_on_mapping_bundle_ids),
            {caller_bundle.bundle_id, closed_bundle.bundle_id},
        )
        self.assertEqual(
            set(proposal.conditional_on_mapping_bundle_ids),
            {caller_bundle.bundle_id, closed_bundle.bundle_id},
        )
        self.assertEqual(
            set(result.proposal_sets[0].conditional_on_mapping_bundle_ids),
            {caller_bundle.bundle_id, closed_bundle.bundle_id},
        )
        self.assertFalse(derivation.confirms_dependency_anchors)
        proposal_evidence = [
            item
            for item in result.evidence
            if item.evidence_kind == "unique_residual_call_pair"
        ]
        self.assertEqual(len(proposal_evidence), 2)
        self.assertTrue(
            all(item.independence_group == caller_bundle.bundle_id for item in proposal_evidence)
        )
        self.assertTrue(
            all(not item.confirms_dependency_anchors for item in result.evidence)
        )
        self.assertNotIn(
            "name", {field.name for field in fields(type(proposal))}
        )

    def test_scalar_fold_member_blocks_without_expansion_or_selection(self) -> None:
        mappings = [
            _alternative("caller", _pc_function("pc:A"), _xbox_function("x:A")),
            _alternative("member", _pc_function("pc:B"), _xbox_function("x:member")),
            _alternative("bundle", _pc_function("pc:B"), _xbox_fold("fold:G")),
        ]
        edges = [
            _edge("blocked", "pc:A", _pc_function("pc:B")),
            _edge("unmatched", "pc:A", _pc_function("pc:C")),
        ]
        flows = [
            _flow("1", "x:A", _xbox_fold("fold:G")),
            _flow("2", "x:A", _xbox_function("x:C")),
        ]

        result = analyze_control_flow_candidates(
            mappings,
            edges,
            flows,
            [FoldMembership("fold:G", "x:member")],
        )

        self.assertEqual(result.summary.blocked_neighborhoods, 1)
        self.assertEqual(result.summary.fold_member_blocked_neighborhoods, 1)
        self.assertEqual(result.summary.closed_square_derivations, 0)
        self.assertEqual(result.summary.proposal_alternatives, 0)
        blocked = next(
            item for item in result.neighborhoods if item.outcome.startswith("blocked")
        )
        self.assertEqual(len(blocked.blocked_relations), 1)
        self.assertEqual(
            blocked.blocked_relations[0].relation_kinds,
            ("exact", "fold_member_blocker"),
        )
        self.assertEqual(
            blocked.blocked_relations[0].xbox_endpoint,
            _xbox_fold("fold:G"),
        )

    def test_unique_residual_fold_stays_one_bundle_alternative(self) -> None:
        mappings = [
            _alternative("caller", _pc_function("pc:A"), _xbox_function("x:A")),
            _alternative("closed", _pc_function("pc:B"), _xbox_function("x:B")),
        ]
        edges = [
            _edge("closed", "pc:A", _pc_function("pc:B")),
            _edge("fold", "pc:A", _pc_function("pc:C")),
        ]
        flows = [
            _flow("1", "x:A", _xbox_function("x:B")),
            _flow("2", "x:A", _xbox_fold("fold:G")),
        ]
        memberships = [
            FoldMembership("fold:G", "x:m1"),
            FoldMembership("fold:G", "x:m2"),
            FoldMembership("fold:G", "x:m3"),
        ]

        result = analyze_control_flow_candidates(mappings, edges, flows, memberships)

        self.assertEqual(result.summary.proposal_alternatives, 1)
        self.assertEqual(result.proposals[0].xbox_endpoint, _xbox_fold("fold:G"))
        self.assertEqual(result.proposals[0].xbox_endpoint.kind, "fold_group")
        self.assertNotIn(
            result.proposals[0].xbox_endpoint.identity,
            {membership.function_id for membership in memberships},
        )

    def test_unresolved_pc_and_address_only_xbox_endpoints_are_retained(self) -> None:
        mappings = [
            _alternative("caller", _pc_function("pc:A"), _xbox_function("x:A")),
            _alternative(
                "closed-address",
                _pc_function("pc:B"),
                _xbox_unresolved("x:target:known", "x-ag:known"),
            ),
        ]
        edges = [
            _edge("closed", "pc:A", _pc_function("pc:B")),
            _edge("residual", "pc:A", _pc_unresolved("pc:target:missing")),
        ]
        flows = [
            _flow("1", "x:A", _xbox_address("x-ag:known", 0x82001000)),
            _flow("2", "x:A", _xbox_address("x-ag:new", 0x82002000)),
        ]

        result = analyze_control_flow_candidates(mappings, edges, flows)

        self.assertEqual(result.summary.closed_square_derivations, 1)
        self.assertEqual(result.summary.proposal_alternatives, 1)
        proposal = result.proposals[0]
        self.assertEqual(proposal.pc_endpoint.kind, "unresolved_target")
        self.assertEqual(proposal.pc_endpoint.identity, "pc:target:missing")
        self.assertEqual(proposal.xbox_endpoint.kind, "address_only")
        self.assertEqual(proposal.xbox_endpoint.address_group_id, "x-ag:new")
        self.assertEqual(proposal.xbox_endpoint.address, 0x82002000)

    def test_ambiguous_existing_relations_block_residual_inference(self) -> None:
        mappings = [
            _alternative("caller", _pc_function("pc:A"), _xbox_function("x:A")),
            _alternative("b-one", _pc_function("pc:B"), _xbox_function("x:B1")),
            _alternative("b-two", _pc_function("pc:B"), _xbox_function("x:B2")),
        ]
        edges = [
            _edge("ambiguous", "pc:A", _pc_function("pc:B")),
            _edge("residual", "pc:A", _pc_function("pc:C")),
        ]
        flows = [
            _flow("1", "x:A", _xbox_function("x:B1")),
            _flow("2", "x:A", _xbox_function("x:B2")),
            _flow("3", "x:A", _xbox_function("x:C")),
        ]

        result = analyze_control_flow_candidates(mappings, edges, flows)

        self.assertEqual(result.summary.blocked_neighborhoods, 1)
        self.assertEqual(result.summary.proposal_alternatives, 0)
        blocked = next(
            item for item in result.neighborhoods if item.outcome.startswith("blocked")
        )
        self.assertEqual(len(blocked.blocked_relations), 2)
        self.assertTrue(all(item.relation_kinds == ("exact",) for item in blocked.blocked_relations))

    def test_conflicting_duplicate_source_ids_are_rejected(self) -> None:
        left = _edge("same", "pc:A", _pc_function("pc:B"))
        right = _edge("same", "pc:A", _pc_function("pc:C"))
        with self.assertRaisesRegex(ValueError, "conflicting PcCallEdge"):
            analyze_control_flow_candidates([], [left, right], [])


if __name__ == "__main__":
    unittest.main()
