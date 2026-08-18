"""Pure, candidate-only cross-platform control-flow proposals.

This module deliberately knows nothing about SQLite or atlas write APIs.  It
compares already-normalized PC call adjacency, persisted Xbox logical branch
occurrences, and pre-existing mapping *candidates*.  Those candidates are
conditional anchors, never accepted truth.  Every derived row records that
dependency and cannot be counted as independent confirmation of its anchor.

The conservative proposal rule is a closed square followed by one unique
residual pair.  It never compares names, expands a fold group, infers a score,
accepts a mapping, or applies a name.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
from typing import Iterable, Literal, Mapping, Sequence


PC_PLATFORM = "pc"
XBOX_PLATFORM = "xbox360"
ELIGIBLE_XBOX_CALL_ROLES = frozenset({"direct_call", "local_direct_call"})
CANDIDATE_STATUS = "candidate"

EndpointKind = Literal[
    "function", "unresolved_target", "fold_group", "address_only", "indirect"
]


def _stable_id(namespace: str, *components: object) -> str:
    payload = json.dumps(
        {"namespace": namespace, "components": components},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"{namespace}:sha256:{hashlib.sha256(payload).hexdigest()}"


def _nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One identity-bearing endpoint; names are intentionally absent."""

    platform: str
    kind: EndpointKind
    identity: str
    address_group_id: str | None = None
    address_space: str | None = None
    address: int | None = None
    classification: str | None = None

    def __post_init__(self) -> None:
        _nonempty(self.platform, "endpoint platform")
        _nonempty(self.identity, "endpoint identity")
        if self.kind not in {
            "function",
            "unresolved_target",
            "fold_group",
            "address_only",
            "indirect",
        }:
            raise ValueError(f"unsupported endpoint kind {self.kind!r}")
        if self.address is not None and self.address < 0:
            raise ValueError("endpoint address cannot be negative")
        if self.kind == "address_only" and self.address_group_id is None:
            raise ValueError("address-only endpoints require address_group_id")

    @property
    def semantic_key(self) -> tuple[str, str, str]:
        return (self.platform, self.kind, self.identity)

    @property
    def sort_key(self) -> tuple[object, ...]:
        return (
            self.platform,
            self.kind,
            self.identity,
            self.address_group_id or "",
            self.address_space or "",
            -1 if self.address is None else self.address,
            self.classification or "",
        )

    def identity_payload(self) -> tuple[object, ...]:
        return self.sort_key


@dataclass(frozen=True, slots=True)
class MappingAlternative:
    """One source hypothesis alternative before semantic bundling."""

    hypothesis_set_id: str
    alternative_id: str
    pc_endpoint: Endpoint
    xbox_endpoint: Endpoint
    claim_id: str | None = None
    provenance_id: str | None = None
    producer: str | None = None
    status: str = CANDIDATE_STATUS

    def __post_init__(self) -> None:
        _nonempty(self.hypothesis_set_id, "hypothesis_set_id")
        _nonempty(self.alternative_id, "alternative_id")
        if self.pc_endpoint.platform != PC_PLATFORM:
            raise ValueError("mapping PC endpoint must use platform 'pc'")
        if self.pc_endpoint.kind not in {"function", "unresolved_target"}:
            raise ValueError("mapping PC endpoint must be function or unresolved_target")
        if self.xbox_endpoint.platform != XBOX_PLATFORM:
            raise ValueError("mapping Xbox endpoint must use platform 'xbox360'")
        if self.xbox_endpoint.kind not in {
            "function",
            "unresolved_target",
            "fold_group",
        }:
            raise ValueError(
                "mapping Xbox endpoint must be function, unresolved_target, or fold_group"
            )


@dataclass(frozen=True, slots=True)
class MappingLineage:
    hypothesis_set_id: str
    alternative_id: str
    claim_id: str | None
    provenance_id: str | None
    producer: str | None
    source_status: str


@dataclass(frozen=True, slots=True)
class MappingBundle:
    """All candidate occurrences asserting one semantic endpoint pair."""

    bundle_id: str
    pc_endpoint: Endpoint
    xbox_endpoint: Endpoint
    lineages: tuple[MappingLineage, ...]
    status: str = CANDIDATE_STATUS
    accepted_truth: bool = False


@dataclass(frozen=True, slots=True)
class PcCallEdge:
    edge_id: str
    caller_function_id: str
    callee_endpoint: Endpoint
    edge_kind: str = "ghidra_call"
    provenance_id: str | None = None

    def __post_init__(self) -> None:
        _nonempty(self.edge_id, "edge_id")
        _nonempty(self.caller_function_id, "caller_function_id")
        if self.callee_endpoint.platform != PC_PLATFORM:
            raise ValueError("PC call callee endpoint must use platform 'pc'")
        if self.callee_endpoint.kind not in {"function", "unresolved_target"}:
            raise ValueError("PC call callee must be function or unresolved_target")


@dataclass(frozen=True, slots=True)
class XboxFlowOccurrence:
    """One same-extraction logical-use plus physical-site assertion pair."""

    occurrence_id: str
    extraction_id: str
    use_id: str
    use_assertion_id: str
    site_id: str
    site_assertion_id: str
    caller_function_id: str
    procedure_record_id: str
    role: str
    target_endpoint: Endpoint
    site_address_space: str | None = None
    site_address: int | None = None
    provenance_id: str | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "occurrence_id",
            "extraction_id",
            "use_id",
            "use_assertion_id",
            "site_id",
            "site_assertion_id",
            "caller_function_id",
            "procedure_record_id",
            "role",
        ):
            _nonempty(getattr(self, field_name), field_name)
        if self.target_endpoint.platform != XBOX_PLATFORM:
            raise ValueError("Xbox flow target must use platform 'xbox360'")
        if self.site_address is not None and self.site_address < 0:
            raise ValueError("site_address cannot be negative")


@dataclass(frozen=True, slots=True)
class FoldMembership:
    fold_group_id: str
    function_id: str

    def __post_init__(self) -> None:
        _nonempty(self.fold_group_id, "fold_group_id")
        _nonempty(self.function_id, "function_id")


@dataclass(frozen=True, slots=True)
class CandidateRelation:
    relation_id: str
    pc_endpoint: Endpoint
    xbox_endpoint: Endpoint
    mapping_bundle_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BlockedRelation:
    pc_endpoint: Endpoint
    xbox_endpoint: Endpoint
    relation_kinds: tuple[str, ...]
    mapping_bundle_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ClosedSquareDerivation:
    derivation_id: str
    relation_id: str
    neighborhood_id: str
    conditional_on_caller_bundle_id: str
    target_mapping_bundle_ids: tuple[str, ...]
    candidate_only: bool = True
    confirms_caller_anchor: bool = False


@dataclass(frozen=True, slots=True)
class ProposalAlternative:
    proposal_id: str
    proposal_set_id: str
    pc_endpoint: Endpoint
    xbox_endpoint: Endpoint
    derivation_ids: tuple[str, ...]
    conditional_on_mapping_bundle_ids: tuple[str, ...]
    status: str = CANDIDATE_STATUS
    confidence_label: None = None
    confidence_value: None = None
    applies_name: bool = False


@dataclass(frozen=True, slots=True)
class ProposalSet:
    proposal_set_id: str
    pc_endpoint: Endpoint
    alternative_ids: tuple[str, ...]
    conditional_on_mapping_bundle_ids: tuple[str, ...]
    status: str = CANDIDATE_STATUS


@dataclass(frozen=True, slots=True)
class ProposalDerivation:
    derivation_id: str
    proposal_id: str
    neighborhood_id: str
    conditional_on_mapping_bundle_ids: tuple[str, ...]
    supporting_closed_square_derivation_ids: tuple[str, ...]
    candidate_only: bool = True
    confirms_dependency_anchors: bool = False


@dataclass(frozen=True, slots=True)
class EvidenceOccurrence:
    evidence_id: str
    evidence_kind: Literal["closed_call_square", "unique_residual_call_pair"]
    effect: Literal["supports"]
    subject_kind: Literal["candidate_relation", "candidate_proposal"]
    subject_id: str
    derivation_id: str
    independence_group: str
    conditional_on_mapping_bundle_ids: tuple[str, ...]
    pc_edge_id: str
    xbox_occurrence_id: str
    xbox_extraction_id: str
    xbox_use_id: str
    xbox_use_assertion_id: str
    xbox_site_id: str
    xbox_site_assertion_id: str
    xbox_role: str
    candidate_only: bool = True
    confirms_dependency_anchors: bool = False


@dataclass(frozen=True, slots=True)
class NeighborhoodDiagnostic:
    neighborhood_id: str
    caller_mapping_bundle_id: str
    outcome: str
    pc_endpoint_count: int
    eligible_xbox_endpoint_count: int
    closed_square_derivation_ids: tuple[str, ...]
    blocked_relations: tuple[BlockedRelation, ...]
    unmatched_pc_endpoints: tuple[Endpoint, ...]
    unmatched_xbox_endpoints: tuple[Endpoint, ...]
    excluded_xbox_occurrence_ids: tuple[str, ...]
    proposal_derivation_ids: tuple[str, ...]
    conditional_on_candidate_anchor: bool = True
    confirms_caller_anchor: bool = False


@dataclass(frozen=True, slots=True)
class MatchingSummary:
    source_mapping_alternatives: int
    excluded_mapping_status_counts: tuple[tuple[str, int], ...]
    semantic_mapping_bundles: int
    caller_anchor_bundles: int
    caller_anchor_neighborhoods_with_both_graph_sides: int
    closed_square_derivations: int
    closed_square_evidence_occurrences: int
    blocked_neighborhoods: int
    fold_member_blocked_neighborhoods: int
    residual_proposal_derivations: int
    proposal_sets: int
    proposal_alternatives: int
    proposal_evidence_occurrences: int
    source_xbox_occurrences: int
    eligible_xbox_occurrences: int
    excluded_xbox_occurrence_counts: tuple[tuple[str, int], ...]
    excluded_xbox_role_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class ControlFlowMatchingResult:
    mapping_bundles: tuple[MappingBundle, ...]
    candidate_relations: tuple[CandidateRelation, ...]
    closed_square_derivations: tuple[ClosedSquareDerivation, ...]
    proposal_sets: tuple[ProposalSet, ...]
    proposals: tuple[ProposalAlternative, ...]
    proposal_derivations: tuple[ProposalDerivation, ...]
    evidence: tuple[EvidenceOccurrence, ...]
    neighborhoods: tuple[NeighborhoodDiagnostic, ...]
    summary: MatchingSummary
    policy: str = "closed_square_unique_residual_v1"


def _unique_records(records: Iterable[object], field_name: str) -> list[object]:
    indexed: dict[str, object] = {}
    for record in records:
        identity = getattr(record, field_name)
        previous = indexed.get(identity)
        if previous is not None and previous != record:
            raise ValueError(
                f"conflicting {type(record).__name__} rows share {field_name} "
                f"{identity!r}"
            )
        indexed[identity] = record
    return [indexed[key] for key in sorted(indexed)]


def _bundle_mappings(
    alternatives: Sequence[MappingAlternative],
) -> tuple[MappingBundle, ...]:
    grouped: dict[
        tuple[tuple[str, str, str], tuple[str, str, str]],
        list[MappingAlternative],
    ] = defaultdict(list)
    for alternative in alternatives:
        if alternative.status == CANDIDATE_STATUS:
            grouped[
                (
                    alternative.pc_endpoint.semantic_key,
                    alternative.xbox_endpoint.semantic_key,
                )
            ].append(alternative)

    bundles: list[MappingBundle] = []
    for key in sorted(grouped):
        rows = sorted(grouped[key], key=lambda item: item.alternative_id)
        pc_endpoint = rows[0].pc_endpoint
        xbox_endpoint = rows[0].xbox_endpoint
        for row in rows[1:]:
            if row.pc_endpoint != pc_endpoint or row.xbox_endpoint != xbox_endpoint:
                raise ValueError(
                    "one semantic mapping pair has conflicting endpoint metadata"
                )
        lineages = tuple(
            MappingLineage(
                hypothesis_set_id=row.hypothesis_set_id,
                alternative_id=row.alternative_id,
                claim_id=row.claim_id,
                provenance_id=row.provenance_id,
                producer=row.producer,
                source_status=row.status,
            )
            for row in rows
        )
        bundle_id = _stable_id(
            "control-flow-mapping-bundle",
            pc_endpoint.identity_payload(),
            xbox_endpoint.identity_payload(),
        )
        bundles.append(
            MappingBundle(
                bundle_id=bundle_id,
                pc_endpoint=pc_endpoint,
                xbox_endpoint=xbox_endpoint,
                lineages=lineages,
            )
        )
    return tuple(sorted(bundles, key=lambda item: item.bundle_id))


def _exclusion_reason(occurrence: XboxFlowOccurrence) -> str | None:
    if occurrence.role in ELIGIBLE_XBOX_CALL_ROLES:
        if occurrence.target_endpoint.kind == "indirect":
            return "indirect_target"
        return None
    if occurrence.role == "tail_transfer":
        return "tail_transfer_not_pc_call_equivalent"
    if occurrence.role.startswith("indirect_") or occurrence.target_endpoint.kind == "indirect":
        return "indirect_target"
    return "role_not_pc_call_equivalent"


def _relation_kind(
    mapping_xbox: Endpoint,
    flow_xbox: Endpoint,
    member_groups: Mapping[str, frozenset[str]],
) -> str | None:
    if flow_xbox.kind == "function":
        if mapping_xbox.kind == "function" and mapping_xbox.identity == flow_xbox.identity:
            return "exact"
        return None
    if flow_xbox.kind == "fold_group":
        if (
            mapping_xbox.kind == "fold_group"
            and mapping_xbox.identity == flow_xbox.identity
        ):
            return "exact"
        if (
            mapping_xbox.kind == "function"
            and flow_xbox.identity
            in member_groups.get(mapping_xbox.identity, frozenset())
        ):
            return "fold_member_blocker"
        return None
    if flow_xbox.kind == "address_only":
        if (
            mapping_xbox.kind == "unresolved_target"
            and mapping_xbox.address_group_id is not None
            and mapping_xbox.address_group_id == flow_xbox.address_group_id
        ):
            return "exact"
    return None


def analyze_control_flow_candidates(
    mapping_alternatives: Iterable[MappingAlternative],
    pc_call_edges: Iterable[PcCallEdge],
    xbox_flow_occurrences: Iterable[XboxFlowOccurrence],
    fold_memberships: Iterable[FoldMembership] = (),
) -> ControlFlowMatchingResult:
    """Return deterministic conditional evidence and candidate proposals.

    The seed collection is frozen for the entire invocation.  Newly generated
    proposals are never fed back as anchors, so one run cannot amplify itself.
    """

    alternatives = tuple(
        _unique_records(mapping_alternatives, "alternative_id")
    )
    pc_edges = tuple(_unique_records(pc_call_edges, "edge_id"))
    xbox_occurrences = tuple(
        _unique_records(xbox_flow_occurrences, "occurrence_id")
    )
    memberships = {
        (item.fold_group_id, item.function_id)
        for item in fold_memberships
    }
    member_groups_mutable: dict[str, set[str]] = defaultdict(set)
    for fold_group_id, function_id in memberships:
        member_groups_mutable[function_id].add(fold_group_id)
    member_groups = {
        function_id: frozenset(groups)
        for function_id, groups in member_groups_mutable.items()
    }

    bundles = _bundle_mappings(alternatives)
    bundles_by_pc: dict[tuple[str, str, str], list[MappingBundle]] = defaultdict(list)
    caller_bundles: list[MappingBundle] = []
    for bundle in bundles:
        bundles_by_pc[bundle.pc_endpoint.semantic_key].append(bundle)
        if (
            bundle.pc_endpoint.kind == "function"
            and bundle.xbox_endpoint.kind == "function"
        ):
            caller_bundles.append(bundle)
    for rows in bundles_by_pc.values():
        rows.sort(key=lambda item: item.bundle_id)
    caller_bundles.sort(key=lambda item: item.bundle_id)

    pc_by_caller: dict[str, list[PcCallEdge]] = defaultdict(list)
    for edge in pc_edges:
        pc_by_caller[edge.caller_function_id].append(edge)
    for rows in pc_by_caller.values():
        rows.sort(key=lambda item: item.edge_id)

    xbox_by_caller: dict[str, list[XboxFlowOccurrence]] = defaultdict(list)
    excluded_counts: Counter[str] = Counter()
    excluded_role_counts: Counter[str] = Counter()
    eligible_count = 0
    for occurrence in xbox_occurrences:
        xbox_by_caller[occurrence.caller_function_id].append(occurrence)
        reason = _exclusion_reason(occurrence)
        if reason is None:
            eligible_count += 1
        else:
            excluded_counts[reason] += 1
            excluded_role_counts[occurrence.role] += 1
    for rows in xbox_by_caller.values():
        rows.sort(key=lambda item: item.occurrence_id)

    relations: dict[str, CandidateRelation] = {}
    closed_derivations: list[ClosedSquareDerivation] = []
    proposal_derivations: list[ProposalDerivation] = []
    evidence: list[EvidenceOccurrence] = []
    neighborhoods: list[NeighborhoodDiagnostic] = []
    proposal_derivations_by_pair: dict[
        tuple[tuple[str, str, str], tuple[str, str, str]],
        list[ProposalDerivation],
    ] = defaultdict(list)
    proposal_endpoints: dict[
        tuple[tuple[str, str, str], tuple[str, str, str]],
        tuple[Endpoint, Endpoint],
    ] = {}
    with_both = blocked_count = fold_blocked_count = 0

    for caller_bundle in caller_bundles:
        pc_rows = pc_by_caller.get(caller_bundle.pc_endpoint.identity, [])
        all_xbox_rows = xbox_by_caller.get(caller_bundle.xbox_endpoint.identity, [])
        eligible_xbox_rows = [
            row for row in all_xbox_rows if _exclusion_reason(row) is None
        ]
        excluded_ids = tuple(
            row.occurrence_id
            for row in all_xbox_rows
            if _exclusion_reason(row) is not None
        )
        neighborhood_id = _stable_id(
            "control-flow-neighborhood", caller_bundle.bundle_id
        )

        pc_endpoint_rows: dict[tuple[str, str, str], list[PcCallEdge]] = defaultdict(list)
        pc_endpoints: dict[tuple[str, str, str], Endpoint] = {}
        for edge in pc_rows:
            key = edge.callee_endpoint.semantic_key
            pc_endpoint_rows[key].append(edge)
            pc_endpoints[key] = edge.callee_endpoint
        xbox_endpoint_rows: dict[
            tuple[str, str, str], list[XboxFlowOccurrence]
        ] = defaultdict(list)
        xbox_endpoints: dict[tuple[str, str, str], Endpoint] = {}
        for occurrence in eligible_xbox_rows:
            key = occurrence.target_endpoint.semantic_key
            xbox_endpoint_rows[key].append(occurrence)
            xbox_endpoints[key] = occurrence.target_endpoint

        if pc_endpoint_rows and xbox_endpoint_rows:
            with_both += 1

        pc_adjacency: dict[
            tuple[str, str, str], set[tuple[str, str, str]]
        ] = defaultdict(set)
        xbox_adjacency: dict[
            tuple[str, str, str], set[tuple[str, str, str]]
        ] = defaultdict(set)
        relation_kinds: dict[
            tuple[tuple[str, str, str], tuple[str, str, str]], set[str]
        ] = defaultdict(set)
        relation_bundle_ids: dict[
            tuple[tuple[str, str, str], tuple[str, str, str]], set[str]
        ] = defaultdict(set)
        for pc_key in pc_endpoint_rows:
            for mapping_bundle in bundles_by_pc.get(pc_key, []):
                for xbox_key, xbox_endpoint in xbox_endpoints.items():
                    kind = _relation_kind(
                        mapping_bundle.xbox_endpoint,
                        xbox_endpoint,
                        member_groups,
                    )
                    if kind is None:
                        continue
                    pair = (pc_key, xbox_key)
                    pc_adjacency[pc_key].add(xbox_key)
                    xbox_adjacency[xbox_key].add(pc_key)
                    relation_kinds[pair].add(kind)
                    relation_bundle_ids[pair].add(mapping_bundle.bundle_id)

        mutual_pairs: set[
            tuple[tuple[str, str, str], tuple[str, str, str]]
        ] = set()
        for pc_key, xbox_keys in pc_adjacency.items():
            if len(xbox_keys) != 1:
                continue
            xbox_key = next(iter(xbox_keys))
            pair = (pc_key, xbox_key)
            if (
                len(xbox_adjacency[xbox_key]) == 1
                and relation_kinds[pair] == {"exact"}
            ):
                mutual_pairs.add(pair)

        blocked_pc = {
            key
            for key in pc_endpoint_rows
            if pc_adjacency.get(key)
            and not any(pc_key == key for pc_key, _ in mutual_pairs)
        }
        blocked_xbox = {
            key
            for key in xbox_endpoint_rows
            if xbox_adjacency.get(key)
            and not any(xbox_key == key for _, xbox_key in mutual_pairs)
        }
        blocked_relations: list[BlockedRelation] = []
        for pair in sorted(relation_kinds):
            pc_key, xbox_key = pair
            if pc_key not in blocked_pc and xbox_key not in blocked_xbox:
                continue
            blocked_relations.append(
                BlockedRelation(
                    pc_endpoint=pc_endpoints[pc_key],
                    xbox_endpoint=xbox_endpoints[xbox_key],
                    relation_kinds=tuple(sorted(relation_kinds[pair])),
                    mapping_bundle_ids=tuple(sorted(relation_bundle_ids[pair])),
                )
            )
        if blocked_relations:
            blocked_count += 1
            if any(
                "fold_member_blocker" in relation.relation_kinds
                for relation in blocked_relations
            ):
                fold_blocked_count += 1

        neighborhood_closed: list[ClosedSquareDerivation] = []
        for pc_key, xbox_key in sorted(mutual_pairs):
            mapping_bundle_ids = tuple(
                sorted(relation_bundle_ids[(pc_key, xbox_key)])
            )
            relation_id = _stable_id(
                "control-flow-candidate-relation",
                pc_endpoints[pc_key].identity_payload(),
                xbox_endpoints[xbox_key].identity_payload(),
                mapping_bundle_ids,
            )
            relations.setdefault(
                relation_id,
                CandidateRelation(
                    relation_id=relation_id,
                    pc_endpoint=pc_endpoints[pc_key],
                    xbox_endpoint=xbox_endpoints[xbox_key],
                    mapping_bundle_ids=mapping_bundle_ids,
                ),
            )
            derivation_id = _stable_id(
                "control-flow-closed-square",
                neighborhood_id,
                relation_id,
            )
            derivation = ClosedSquareDerivation(
                derivation_id=derivation_id,
                relation_id=relation_id,
                neighborhood_id=neighborhood_id,
                conditional_on_caller_bundle_id=caller_bundle.bundle_id,
                target_mapping_bundle_ids=mapping_bundle_ids,
            )
            closed_derivations.append(derivation)
            neighborhood_closed.append(derivation)
            for edge in pc_endpoint_rows[pc_key]:
                for occurrence in xbox_endpoint_rows[xbox_key]:
                    evidence_id = _stable_id(
                        "control-flow-evidence",
                        "closed_call_square",
                        derivation_id,
                        edge.edge_id,
                        occurrence.occurrence_id,
                    )
                    evidence.append(
                        EvidenceOccurrence(
                            evidence_id=evidence_id,
                            evidence_kind="closed_call_square",
                            effect="supports",
                            subject_kind="candidate_relation",
                            subject_id=relation_id,
                            derivation_id=derivation_id,
                            independence_group=caller_bundle.bundle_id,
                            conditional_on_mapping_bundle_ids=(
                                caller_bundle.bundle_id,
                            ),
                            pc_edge_id=edge.edge_id,
                            xbox_occurrence_id=occurrence.occurrence_id,
                            xbox_extraction_id=occurrence.extraction_id,
                            xbox_use_id=occurrence.use_id,
                            xbox_use_assertion_id=occurrence.use_assertion_id,
                            xbox_site_id=occurrence.site_id,
                            xbox_site_assertion_id=occurrence.site_assertion_id,
                            xbox_role=occurrence.role,
                        )
                    )

        unmatched_pc_keys = sorted(
            key for key in pc_endpoint_rows if not pc_adjacency.get(key)
        )
        unmatched_xbox_keys = sorted(
            key for key in xbox_endpoint_rows if not xbox_adjacency.get(key)
        )
        neighborhood_proposals: list[ProposalDerivation] = []
        if (
            not blocked_relations
            and len(unmatched_pc_keys) == 1
            and len(unmatched_xbox_keys) == 1
            and neighborhood_closed
        ):
            pc_key = unmatched_pc_keys[0]
            xbox_key = unmatched_xbox_keys[0]
            pair_key = (pc_key, xbox_key)
            pc_endpoint = pc_endpoints[pc_key]
            xbox_endpoint = xbox_endpoints[xbox_key]
            proposal_id = _stable_id(
                "control-flow-proposal",
                pc_endpoint.identity_payload(),
                xbox_endpoint.identity_payload(),
            )
            dependency_bundle_ids = tuple(
                sorted(
                    {caller_bundle.bundle_id}
                    | {
                        bundle_id
                        for closed in neighborhood_closed
                        for bundle_id in closed.target_mapping_bundle_ids
                    }
                )
            )
            derivation_id = _stable_id(
                "control-flow-proposal-derivation",
                proposal_id,
                neighborhood_id,
                tuple(item.derivation_id for item in neighborhood_closed),
            )
            derivation = ProposalDerivation(
                derivation_id=derivation_id,
                proposal_id=proposal_id,
                neighborhood_id=neighborhood_id,
                conditional_on_mapping_bundle_ids=dependency_bundle_ids,
                supporting_closed_square_derivation_ids=tuple(
                    item.derivation_id for item in neighborhood_closed
                ),
            )
            proposal_derivations.append(derivation)
            neighborhood_proposals.append(derivation)
            proposal_derivations_by_pair[pair_key].append(derivation)
            proposal_endpoints[pair_key] = (pc_endpoint, xbox_endpoint)
            for edge in pc_endpoint_rows[pc_key]:
                for occurrence in xbox_endpoint_rows[xbox_key]:
                    evidence_id = _stable_id(
                        "control-flow-evidence",
                        "unique_residual_call_pair",
                        derivation_id,
                        edge.edge_id,
                        occurrence.occurrence_id,
                    )
                    evidence.append(
                        EvidenceOccurrence(
                            evidence_id=evidence_id,
                            evidence_kind="unique_residual_call_pair",
                            effect="supports",
                            subject_kind="candidate_proposal",
                            subject_id=proposal_id,
                            derivation_id=derivation_id,
                            independence_group=caller_bundle.bundle_id,
                            conditional_on_mapping_bundle_ids=dependency_bundle_ids,
                            pc_edge_id=edge.edge_id,
                            xbox_occurrence_id=occurrence.occurrence_id,
                            xbox_extraction_id=occurrence.extraction_id,
                            xbox_use_id=occurrence.use_id,
                            xbox_use_assertion_id=occurrence.use_assertion_id,
                            xbox_site_id=occurrence.site_id,
                            xbox_site_assertion_id=occurrence.site_assertion_id,
                            xbox_role=occurrence.role,
                        )
                    )

        if not pc_endpoint_rows:
            outcome = "missing_pc_calls"
        elif not xbox_endpoint_rows:
            outcome = "missing_eligible_xbox_calls"
        elif blocked_relations:
            outcome = "blocked_ambiguous_existing_relations"
        elif neighborhood_proposals:
            outcome = "unique_residual_proposal"
        elif not unmatched_pc_keys and not unmatched_xbox_keys:
            outcome = "closed_squares_only"
        else:
            outcome = "no_unique_residual"
        neighborhoods.append(
            NeighborhoodDiagnostic(
                neighborhood_id=neighborhood_id,
                caller_mapping_bundle_id=caller_bundle.bundle_id,
                outcome=outcome,
                pc_endpoint_count=len(pc_endpoint_rows),
                eligible_xbox_endpoint_count=len(xbox_endpoint_rows),
                closed_square_derivation_ids=tuple(
                    item.derivation_id for item in neighborhood_closed
                ),
                blocked_relations=tuple(blocked_relations),
                unmatched_pc_endpoints=tuple(
                    pc_endpoints[key] for key in unmatched_pc_keys
                ),
                unmatched_xbox_endpoints=tuple(
                    xbox_endpoints[key] for key in unmatched_xbox_keys
                ),
                excluded_xbox_occurrence_ids=excluded_ids,
                proposal_derivation_ids=tuple(
                    item.derivation_id for item in neighborhood_proposals
                ),
            )
        )

    proposals: list[ProposalAlternative] = []
    proposal_ids_by_pc: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    proposal_dependencies_by_pc: dict[
        tuple[str, str, str], set[str]
    ] = defaultdict(set)
    proposal_endpoint_by_pc: dict[tuple[str, str, str], Endpoint] = {}
    for pair_key in sorted(proposal_derivations_by_pair):
        pc_endpoint, xbox_endpoint = proposal_endpoints[pair_key]
        proposal_set_id = _stable_id(
            "control-flow-proposal-set", pc_endpoint.identity_payload()
        )
        proposal_id = _stable_id(
            "control-flow-proposal",
            pc_endpoint.identity_payload(),
            xbox_endpoint.identity_payload(),
        )
        derivation_ids = tuple(
            sorted(
                item.derivation_id
                for item in proposal_derivations_by_pair[pair_key]
            )
        )
        dependency_ids = tuple(
            sorted(
                {
                    bundle_id
                    for item in proposal_derivations_by_pair[pair_key]
                    for bundle_id in item.conditional_on_mapping_bundle_ids
                }
            )
        )
        proposals.append(
            ProposalAlternative(
                proposal_id=proposal_id,
                proposal_set_id=proposal_set_id,
                pc_endpoint=pc_endpoint,
                xbox_endpoint=xbox_endpoint,
                derivation_ids=derivation_ids,
                conditional_on_mapping_bundle_ids=dependency_ids,
            )
        )
        proposal_ids_by_pc[pc_endpoint.semantic_key].append(proposal_id)
        proposal_dependencies_by_pc[pc_endpoint.semantic_key].update(dependency_ids)
        proposal_endpoint_by_pc[pc_endpoint.semantic_key] = pc_endpoint
    proposal_sets = tuple(
        ProposalSet(
            proposal_set_id=_stable_id(
                "control-flow-proposal-set",
                proposal_endpoint_by_pc[key].identity_payload(),
            ),
            pc_endpoint=proposal_endpoint_by_pc[key],
            alternative_ids=tuple(sorted(proposal_ids_by_pc[key])),
            conditional_on_mapping_bundle_ids=tuple(
                sorted(proposal_dependencies_by_pc[key])
            ),
        )
        for key in sorted(proposal_ids_by_pc)
    )

    excluded_statuses = Counter(
        item.status for item in alternatives if item.status != CANDIDATE_STATUS
    )
    proposal_evidence_count = sum(
        item.evidence_kind == "unique_residual_call_pair" for item in evidence
    )
    closed_evidence_count = len(evidence) - proposal_evidence_count
    summary = MatchingSummary(
        source_mapping_alternatives=len(alternatives),
        excluded_mapping_status_counts=tuple(sorted(excluded_statuses.items())),
        semantic_mapping_bundles=len(bundles),
        caller_anchor_bundles=len(caller_bundles),
        caller_anchor_neighborhoods_with_both_graph_sides=with_both,
        closed_square_derivations=len(closed_derivations),
        closed_square_evidence_occurrences=closed_evidence_count,
        blocked_neighborhoods=blocked_count,
        fold_member_blocked_neighborhoods=fold_blocked_count,
        residual_proposal_derivations=len(proposal_derivations),
        proposal_sets=len(proposal_sets),
        proposal_alternatives=len(proposals),
        proposal_evidence_occurrences=proposal_evidence_count,
        source_xbox_occurrences=len(xbox_occurrences),
        eligible_xbox_occurrences=eligible_count,
        excluded_xbox_occurrence_counts=tuple(sorted(excluded_counts.items())),
        excluded_xbox_role_counts=tuple(sorted(excluded_role_counts.items())),
    )
    return ControlFlowMatchingResult(
        mapping_bundles=bundles,
        candidate_relations=tuple(
            relations[key] for key in sorted(relations)
        ),
        closed_square_derivations=tuple(
            sorted(closed_derivations, key=lambda item: item.derivation_id)
        ),
        proposal_sets=proposal_sets,
        proposals=tuple(sorted(proposals, key=lambda item: item.proposal_id)),
        proposal_derivations=tuple(
            sorted(proposal_derivations, key=lambda item: item.derivation_id)
        ),
        evidence=tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        neighborhoods=tuple(
            sorted(neighborhoods, key=lambda item: item.neighborhood_id)
        ),
        summary=summary,
    )


__all__ = [
    "CANDIDATE_STATUS",
    "ELIGIBLE_XBOX_CALL_ROLES",
    "PC_PLATFORM",
    "XBOX_PLATFORM",
    "BlockedRelation",
    "CandidateRelation",
    "ClosedSquareDerivation",
    "ControlFlowMatchingResult",
    "Endpoint",
    "EvidenceOccurrence",
    "FoldMembership",
    "MappingAlternative",
    "MappingBundle",
    "MappingLineage",
    "MatchingSummary",
    "NeighborhoodDiagnostic",
    "PcCallEdge",
    "ProposalAlternative",
    "ProposalDerivation",
    "ProposalSet",
    "XboxFlowOccurrence",
    "analyze_control_flow_candidates",
]
