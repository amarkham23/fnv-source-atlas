"""Persist conditional control-flow mapping candidates without promoting them.

The pure matcher deliberately has no database dependency.  This module is the
small write boundary that records its output as ordinary candidate hypothesis
sets.  Closed-square relations become one-alternative derived hypotheses;
unique-residual proposals retain their original disjunctions and attach each
evidence occurrence to the exact alternative it supports.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Iterable, Mapping

from .control_flow_matching import (
    CANDIDATE_STATUS,
    CandidateRelation,
    ControlFlowMatchingResult,
    Endpoint,
    EvidenceOccurrence,
    MappingBundle,
    ProposalAlternative,
    ProposalSet,
)
from .database import AtlasDatabase, stable_id


POLICY = "closed_square_unique_residual_v1"


@dataclass(frozen=True, slots=True)
class ControlFlowMatchingPersistenceResult:
    """Counts for one candidate-only matcher materialization."""

    mapping_bundles_observed: int
    closed_relations: int
    closed_relation_sets: int
    proposal_sets: int
    proposal_alternatives: int
    scalar_claims: int
    fold_bundle_alternatives: int
    supporting_evidence: int


def _endpoint_dict(endpoint: Endpoint) -> dict[str, object]:
    return asdict(endpoint)


def _bundle_dict(bundle: MappingBundle) -> dict[str, object]:
    return {
        "bundle_id": bundle.bundle_id,
        "pc_endpoint": _endpoint_dict(bundle.pc_endpoint),
        "xbox_endpoint": _endpoint_dict(bundle.xbox_endpoint),
        "lineages": [asdict(lineage) for lineage in bundle.lineages],
        "status": bundle.status,
        "accepted_truth": bundle.accepted_truth,
    }


def _pc_subject(endpoint: Endpoint) -> tuple[str | None, str | None]:
    if endpoint.platform != "pc":
        raise ValueError("control-flow proposal subject must be a PC endpoint")
    if endpoint.kind == "function":
        return endpoint.identity, None
    if endpoint.kind == "unresolved_target":
        return None, endpoint.identity
    raise ValueError(
        "control-flow proposal PC endpoint must be function or unresolved_target"
    )


def _address_only_target(
    db: AtlasDatabase,
    endpoint: Endpoint,
    *,
    provenance_id: str,
) -> str:
    if endpoint.platform != "xbox360" or endpoint.kind != "address_only":
        raise ValueError("address-only target must be an Xbox endpoint")
    if endpoint.address_group_id is None:
        raise ValueError("address-only target lacks its address group")
    return db.upsert_unresolved_target(
        target_id=stable_id(
            "control-flow-address-only-target",
            endpoint.address_group_id,
            endpoint.classification,
        ),
        address_group_id=endpoint.address_group_id,
        target_kind="control_flow_address_only",
        reason=(
            "Static Xbox call target has no unique canonical procedure entry; "
            "retained as an address-specific candidate endpoint"
        ),
        provenance_id=provenance_id,
        details={
            "candidate_only": True,
            "classification": endpoint.classification,
            "source_endpoint": _endpoint_dict(endpoint),
            "function_creation": "forbidden",
        },
    )


def _scalar_claim(
    db: AtlasDatabase,
    *,
    subject_kind: str,
    subject_id: str,
    pc_endpoint: Endpoint,
    xbox_endpoint: Endpoint,
    provenance_id: str,
    details: Mapping[str, object],
) -> str:
    pc_function_id, pc_target_id = _pc_subject(pc_endpoint)
    xbox_function_id: str | None = None
    xbox_target_id: str | None = None
    if xbox_endpoint.platform != "xbox360":
        raise ValueError("control-flow proposal target must be an Xbox endpoint")
    if xbox_endpoint.kind == "function":
        xbox_function_id = xbox_endpoint.identity
    elif xbox_endpoint.kind == "unresolved_target":
        xbox_target_id = xbox_endpoint.identity
    elif xbox_endpoint.kind == "address_only":
        xbox_target_id = _address_only_target(
            db, xbox_endpoint, provenance_id=provenance_id
        )
    else:
        raise ValueError("fold and indirect endpoints are not scalar claims")
    return db.upsert_match_claim(
        claim_id=stable_id(
            "control-flow-derived-claim",
            subject_kind,
            subject_id,
            pc_endpoint.identity_payload(),
            xbox_endpoint.identity_payload(),
        ),
        pc_function_id=pc_function_id,
        pc_target_id=pc_target_id,
        xbox_function_id=xbox_function_id,
        xbox_target_id=xbox_target_id,
        provenance_id=provenance_id,
        status=CANDIDATE_STATUS,
        rationale=(
            "Conditional cross-platform control-flow candidate; dependency "
            "anchors are candidates and this row does not confirm them"
        ),
        details={
            **dict(details),
            "candidate_only": True,
            "confidence": None,
            "name_transfer": "forbidden",
            "pc_endpoint": _endpoint_dict(pc_endpoint),
            "xbox_endpoint": _endpoint_dict(xbox_endpoint),
        },
    )


def _add_alternative(
    db: AtlasDatabase,
    *,
    hypothesis_set_id: str,
    alternative_id: str,
    subject_kind: str,
    subject_id: str,
    pc_endpoint: Endpoint,
    xbox_endpoint: Endpoint,
    provenance_id: str,
    details: Mapping[str, object],
) -> tuple[str, bool]:
    if xbox_endpoint.kind == "fold_group":
        result = db.add_match_hypothesis_alternative(
            hypothesis_set_id,
            alternative_id=alternative_id,
            xbox_fold_group_id=xbox_endpoint.identity,
            details={
                **dict(details),
                "candidate_only": True,
                "fold_bundle_not_expanded": True,
                "xbox_endpoint": _endpoint_dict(xbox_endpoint),
            },
        )
        return result, True
    if xbox_endpoint.kind == "indirect":
        raise ValueError("indirect endpoints cannot become mapping alternatives")
    claim_id = _scalar_claim(
        db,
        subject_kind=subject_kind,
        subject_id=subject_id,
        pc_endpoint=pc_endpoint,
        xbox_endpoint=xbox_endpoint,
        provenance_id=provenance_id,
        details=details,
    )
    result = db.add_match_hypothesis_alternative(
        hypothesis_set_id,
        alternative_id=alternative_id,
        claim_id=claim_id,
        details={
            **dict(details),
            "candidate_only": True,
            "semantic_claim_id": claim_id,
            "xbox_endpoint": _endpoint_dict(xbox_endpoint),
        },
    )
    return result, False


def _evidence_details(
    evidence: EvidenceOccurrence,
    *,
    derivation: object,
) -> dict[str, object]:
    return {
        **asdict(evidence),
        "derivation": asdict(derivation),
        "conditional_evidence": True,
        "independent_confirmation": False,
        "acceptance_effect": "none",
    }


def _index_unique(items: Iterable[object], attribute: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for item in items:
        identity = str(getattr(item, attribute))
        previous = result.get(identity)
        if previous is not None and previous != item:
            raise ValueError(f"conflicting matcher rows share {attribute} {identity!r}")
        result[identity] = item
    return result


def persist_control_flow_matching_result(
    db: AtlasDatabase,
    result: ControlFlowMatchingResult,
    *,
    provenance_id: str,
) -> ControlFlowMatchingPersistenceResult:
    """Persist one deterministic matcher result as unscored candidates.

    This routine never creates functions or names and never mutates source
    hypothesis sets.  Exact fold groups remain one bundle alternative.
    """

    if result.policy != POLICY:
        raise ValueError(f"unsupported control-flow matching policy {result.policy!r}")

    bundles = _index_unique(result.mapping_bundles, "bundle_id")
    relations = _index_unique(result.candidate_relations, "relation_id")
    closed_derivations = _index_unique(
        result.closed_square_derivations, "derivation_id"
    )
    proposal_sets = _index_unique(result.proposal_sets, "proposal_set_id")
    proposals = _index_unique(result.proposals, "proposal_id")
    proposal_derivations = _index_unique(
        result.proposal_derivations, "derivation_id"
    )

    evidence_by_subject: dict[tuple[str, str], list[EvidenceOccurrence]] = defaultdict(list)
    for evidence in result.evidence:
        if not evidence.candidate_only or evidence.confirms_dependency_anchors:
            raise ValueError("matcher evidence must remain conditional and candidate-only")
        evidence_by_subject[(evidence.subject_kind, evidence.subject_id)].append(evidence)
    for rows in evidence_by_subject.values():
        rows.sort(key=lambda item: item.evidence_id)

    functions_before = int(
        db.connection.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
    )
    names_before = int(
        db.connection.execute("SELECT COUNT(*) FROM function_names").fetchone()[0]
    )
    scalar_claims = fold_alternatives = supporting_evidence = 0

    with db.batch():
        for relation_id in sorted(relations):
            relation = relations[relation_id]
            assert isinstance(relation, CandidateRelation)
            dependency_bundles = []
            for bundle_id in relation.mapping_bundle_ids:
                bundle = bundles.get(bundle_id)
                if bundle is None:
                    raise ValueError(
                        f"relation {relation_id!r} references unknown bundle {bundle_id!r}"
                    )
                dependency_bundles.append(_bundle_dict(bundle))
            pc_function_id, pc_target_id = _pc_subject(relation.pc_endpoint)
            set_id = stable_id("control-flow-relation-set", relation_id)
            db.upsert_match_hypothesis_set(
                hypothesis_set_id=set_id,
                identity_key=relation_id,
                pc_function_id=pc_function_id,
                pc_target_id=pc_target_id,
                provenance_id=provenance_id,
                status=CANDIDATE_STATUS,
                rationale=(
                    "Existing semantic candidate pair observed in at least one "
                    "closed call square; evidence remains conditional on candidates"
                ),
                details={
                    "kind": "closed_call_square_relation",
                    "policy": result.policy,
                    "relation": asdict(relation),
                    "conditional_mapping_bundles": dependency_bundles,
                    "candidate_only": True,
                    "confidence": None,
                },
            )
            alternative_id, is_fold = _add_alternative(
                db,
                hypothesis_set_id=set_id,
                alternative_id=stable_id(
                    "control-flow-relation-alternative", relation_id
                ),
                subject_kind="candidate_relation",
                subject_id=relation_id,
                pc_endpoint=relation.pc_endpoint,
                xbox_endpoint=relation.xbox_endpoint,
                provenance_id=provenance_id,
                details={
                    "kind": "closed_call_square_relation",
                    "relation_id": relation_id,
                    "conditional_mapping_bundle_ids": list(
                        relation.mapping_bundle_ids
                    ),
                },
            )
            fold_alternatives += int(is_fold)
            scalar_claims += int(not is_fold)
            for evidence in evidence_by_subject.pop(
                ("candidate_relation", relation_id), []
            ):
                derivation = closed_derivations.get(evidence.derivation_id)
                if derivation is None:
                    raise ValueError(
                        f"evidence {evidence.evidence_id!r} has no closed derivation"
                    )
                db.add_match_hypothesis_alternative_evidence(
                    alternative_id,
                    evidence_id=stable_id(
                        "control-flow-alternative-evidence",
                        alternative_id,
                        evidence.evidence_id,
                    ),
                    effect=evidence.effect,
                    evidence_kind=evidence.evidence_kind,
                    independence_group=evidence.independence_group,
                    provenance_id=provenance_id,
                    details=_evidence_details(evidence, derivation=derivation),
                )
                supporting_evidence += 1

        proposals_by_set: dict[str, list[ProposalAlternative]] = defaultdict(list)
        for proposal in proposals.values():
            assert isinstance(proposal, ProposalAlternative)
            proposals_by_set[proposal.proposal_set_id].append(proposal)
        for rows in proposals_by_set.values():
            rows.sort(key=lambda item: item.proposal_id)

        for proposal_set_id in sorted(proposal_sets):
            proposal_set = proposal_sets[proposal_set_id]
            assert isinstance(proposal_set, ProposalSet)
            rows = proposals_by_set.pop(proposal_set_id, [])
            if tuple(row.proposal_id for row in rows) != proposal_set.alternative_ids:
                raise ValueError(
                    f"proposal set {proposal_set_id!r} alternatives do not match"
                )
            pc_function_id, pc_target_id = _pc_subject(proposal_set.pc_endpoint)
            dependency_bundles = []
            for bundle_id in proposal_set.conditional_on_mapping_bundle_ids:
                bundle = bundles.get(bundle_id)
                if bundle is None:
                    raise ValueError(
                        f"proposal set references unknown bundle {bundle_id!r}"
                    )
                dependency_bundles.append(_bundle_dict(bundle))
            db.upsert_match_hypothesis_set(
                hypothesis_set_id=proposal_set_id,
                identity_key=proposal_set_id,
                pc_function_id=pc_function_id,
                pc_target_id=pc_target_id,
                provenance_id=provenance_id,
                status=CANDIDATE_STATUS,
                rationale=(
                    "Unique residual call-neighborhood proposal; alternatives "
                    "remain an explicit unscored disjunction"
                ),
                details={
                    "kind": "unique_residual_call_proposal",
                    "policy": result.policy,
                    "proposal_set": asdict(proposal_set),
                    "conditional_mapping_bundles": dependency_bundles,
                    "candidate_only": True,
                    "confidence": None,
                },
            )
            for proposal in rows:
                if (
                    proposal.status != CANDIDATE_STATUS
                    or proposal.confidence_label is not None
                    or proposal.confidence_value is not None
                    or proposal.applies_name
                ):
                    raise ValueError("proposal attempts to score, accept, or apply a name")
                alternative_id, is_fold = _add_alternative(
                    db,
                    hypothesis_set_id=proposal_set_id,
                    alternative_id=proposal.proposal_id,
                    subject_kind="candidate_proposal",
                    subject_id=proposal.proposal_id,
                    pc_endpoint=proposal.pc_endpoint,
                    xbox_endpoint=proposal.xbox_endpoint,
                    provenance_id=provenance_id,
                    details={
                        "kind": "unique_residual_call_proposal",
                        "proposal": asdict(proposal),
                    },
                )
                fold_alternatives += int(is_fold)
                scalar_claims += int(not is_fold)
                for evidence in evidence_by_subject.pop(
                    ("candidate_proposal", proposal.proposal_id), []
                ):
                    derivation = proposal_derivations.get(evidence.derivation_id)
                    if derivation is None:
                        raise ValueError(
                            f"evidence {evidence.evidence_id!r} has no proposal derivation"
                        )
                    db.add_match_hypothesis_alternative_evidence(
                        alternative_id,
                        evidence_id=stable_id(
                            "control-flow-alternative-evidence",
                            alternative_id,
                            evidence.evidence_id,
                        ),
                        effect=evidence.effect,
                        evidence_kind=evidence.evidence_kind,
                        independence_group=evidence.independence_group,
                        provenance_id=provenance_id,
                        details=_evidence_details(evidence, derivation=derivation),
                    )
                    supporting_evidence += 1

    if proposals_by_set:
        raise ValueError("one or more proposals reference an unknown proposal set")
    if evidence_by_subject:
        raise ValueError("one or more matcher evidence rows reference unknown subjects")
    functions_after = int(
        db.connection.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
    )
    names_after = int(
        db.connection.execute("SELECT COUNT(*) FROM function_names").fetchone()[0]
    )
    if (functions_after, names_after) != (functions_before, names_before):
        raise RuntimeError("control-flow matching persistence created functions or names")

    return ControlFlowMatchingPersistenceResult(
        mapping_bundles_observed=len(bundles),
        closed_relations=len(relations),
        closed_relation_sets=len(relations),
        proposal_sets=len(proposal_sets),
        proposal_alternatives=len(proposals),
        scalar_claims=scalar_claims,
        fold_bundle_alternatives=fold_alternatives,
        supporting_evidence=supporting_evidence,
    )
