"""Import legacy name maps as claims and evidence, never as ground truth."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from .pc_inventory import parse_address, stable_pc_function_id


# Channels in the same independence group are related observations.  In
# particular, both vtable channels depend on the same cross-build slot-alignment
# assumption and must not be counted as independent proof.
INDEPENDENCE_GROUPS = {
    "vtable": "class_slot_alignment",
    "vtable_recon": "class_slot_alignment",
    "graph": "call_graph",
    # PGM is derived from the same call graph.  Keeping both channels is useful
    # provenance, but they are not independent confirmations.
    "pgm": "call_graph",
    "strmatch": "string_reference",
    "public": "public_reference_context",
    "source": "source_file_context",
    "seed": "legacy_seed_unknown",
    "agent": "decompiler_agent_review",
    "assign": "legacy_composite_structural",
    "vmatch": "class_slot_alignment",
    # The retained fingerprint and callee-alignment experiments combine seed,
    # call-graph, CFG, size, vcall, and/or assignment inputs.  Treating either
    # as an independent channel would double-count their parents.
    "fingerprint": "legacy_composite_structural",
    "calleealign": "legacy_composite_structural",
    "wrappers": "public_wrapper_consensus",
    "constmatch": "constant_reference",
}


def _load_object(path: str | Path | None) -> dict[str, object]:
    if path is None:
        return {}
    source = Path(path)
    if not source.exists():
        return {}
    with source.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{source}: expected a JSON object")
    return value


def _claim_id(address: int, name: str) -> str:
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
    return f"legacy:pc:ram:{address:08x}:{digest}"


@dataclass(frozen=True, slots=True)
class LegacyEvidence:
    channel: str
    kind: str
    effect: str
    independence_group: str
    artifact: str
    details: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["details"] = dict(self.details)
        return result


@dataclass(frozen=True, slots=True)
class LegacyClaim:
    claim_id: str
    pc_address: int
    pc_function_id: str | None
    proposed_name: str
    resolution: str
    legacy_tier: str | None
    evidence: tuple[LegacyEvidence, ...]

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["evidence"] = [item.to_dict() for item in self.evidence]
        return result


@dataclass(frozen=True, slots=True)
class LegacyContext:
    pc_address: int
    pc_function_id: str | None
    channel: str
    value: str
    artifact: str
    details: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LegacyImport:
    claims: tuple[LegacyClaim, ...]
    context: tuple[LegacyContext, ...]

    @property
    def unresolved_claims(self) -> tuple[LegacyClaim, ...]:
        return tuple(claim for claim in self.claims if claim.pc_function_id is None)

    @property
    def evidence_count(self) -> int:
        return sum(len(claim.evidence) for claim in self.claims)

    @property
    def evidence_effect_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for claim in self.claims:
            for evidence in claim.evidence:
                counts[evidence.effect] = counts.get(evidence.effect, 0) + 1
        return counts

    @property
    def experimental_evidence_count(self) -> int:
        return sum(
            bool(evidence.details.get("experimental_artifact"))
            for claim in self.claims
            for evidence in claim.evidence
        )

    @property
    def experimental_claim_count(self) -> int:
        return sum(
            any(
                bool(evidence.details.get("experimental_artifact"))
                for evidence in claim.evidence
            )
            for claim in self.claims
        )


def load_legacy_claims(
    *,
    names_tiered_path: str | Path | None = None,
    names_final_path: str | Path | None = None,
    namemap_path: str | Path | None = None,
    strmatch_path: str | Path | None = None,
    pgm_path: str | Path | None = None,
    matched_ghidra_path: str | Path | None = None,
    agent_verdicts_path: str | Path | None = None,
    all_seeds_path: str | Path | None = None,
    assign_path: str | Path | None = None,
    vmatch_path: str | Path | None = None,
    fingerprint_path: str | Path | None = None,
    calleealign_path: str | Path | None = None,
    calleealign_new_path: str | Path | None = None,
    wrappers_path: str | Path | None = None,
    pgm2_path: str | Path | None = None,
    pgm_new_path: str | Path | None = None,
    constmatch_path: str | Path | None = None,
    known_pc_entries: Iterable[int] = (),
) -> LegacyImport:
    """Normalize the legacy accumulator into identity claims and context.

    ``public`` and ``source`` values are contextual observations, not identity
    proposals, and therefore never create additional name claims.  Conflicting
    vtable or other identity proposals are preserved as separate claims.
    Addresses absent from ``known_pc_entries`` remain unresolved instead of
    being coerced into function identities.
    """

    known = frozenset(int(entry) for entry in known_pc_entries)
    tiered = _load_object(names_tiered_path)
    final = _load_object(names_final_path)
    namemap = _load_object(namemap_path)
    strmatch = _load_object(strmatch_path)
    pgm = _load_object(pgm_path)
    matched_ghidra = _load_object(matched_ghidra_path)
    all_seeds = _load_object(all_seeds_path)
    assign = _load_object(assign_path)
    vmatch = _load_object(vmatch_path)
    fingerprint = _load_object(fingerprint_path)
    calleealign = _load_object(calleealign_path)
    calleealign_new = _load_object(calleealign_new_path)
    wrappers = _load_object(wrappers_path)
    pgm2 = _load_object(pgm2_path)
    pgm_new = _load_object(pgm_new_path)
    constmatch = _load_object(constmatch_path)

    claims: dict[tuple[int, str], dict[str, object]] = {}
    contexts: list[LegacyContext] = []

    def ensure(address: int, name: str) -> dict[str, object]:
        if not name:
            raise ValueError(f"empty legacy name at {address:#x}")
        return claims.setdefault(
            (address, name),
            {"tier": None, "evidence": []},
        )

    for raw_address, raw_name in final.items():
        address = parse_address(raw_address)
        name = str(raw_name)
        record = ensure(address, name)
        record["evidence"].append(
            LegacyEvidence(
                channel="legacy_master",
                kind="selected_claim_record",
                effect="context",
                independence_group="legacy_accumulator",
                artifact=Path(names_final_path).name if names_final_path else "names_final.json",
            )
        )

    for raw_address, raw_record in tiered.items():
        if not isinstance(raw_record, Mapping):
            raise ValueError(f"tiered entry {raw_address!r} is not an object")
        address = parse_address(raw_address)
        name = str(raw_record.get("name") or "")
        record = ensure(address, name)
        tier = str(raw_record.get("tier") or "") or None
        record["tier"] = tier
        record["evidence"].append(
            LegacyEvidence(
                channel="legacy_tier",
                kind="legacy_classification",
                effect="context",
                independence_group="legacy_accumulator",
                artifact=Path(names_tiered_path).name if names_tiered_path else "names_tiered.json",
                details={"tier": tier},
            )
        )
        raw_channels = raw_record.get("channels", [])
        if not isinstance(raw_channels, list):
            raise ValueError(f"tiered channels at {address:#x} must be an array")
        for channel_value in raw_channels:
            channel = str(channel_value)
            details = {
                key: raw_record[key]
                for key in ("depth", "shared", "votes", "agent")
                if key in raw_record
            }
            record["evidence"].append(
                LegacyEvidence(
                    channel=channel,
                    kind="identity_support" if channel not in {"public", "source"} else "context",
                    effect="context" if channel in {"public", "source"} else "supports",
                    independence_group=INDEPENDENCE_GROUPS.get(channel, f"legacy_channel:{channel}"),
                    artifact=Path(names_tiered_path).name if names_tiered_path else "names_tiered.json",
                    details=details,
                )
            )

        # ``tier_names.py`` writes the agent result as a top-level field rather
        # than adding ``agent`` to channels.  Preserve that observation even if
        # the raw verdict file is unavailable.
        if "agent" in raw_record:
            agent_value = str(raw_record["agent"])
            record["evidence"].append(
                LegacyEvidence(
                    channel="agent",
                    kind="agent_verdict_summary",
                    effect=(
                        "supports"
                        if agent_value.upper() == "CONFIRM"
                        else "contradicts"
                        if agent_value.upper() == "REJECT"
                        else "context"
                    ),
                    independence_group=INDEPENDENCE_GROUPS["agent"],
                    artifact=(
                        Path(names_tiered_path).name
                        if names_tiered_path
                        else "names_tiered.json"
                    ),
                    details={"verdict": agent_value, "summary_only": True},
                )
            )

    for raw_address, raw_record in namemap.items():
        if not isinstance(raw_record, Mapping):
            raise ValueError(f"namemap entry {raw_address!r} is not an object")
        address = parse_address(raw_address)
        notes = raw_record.get("_notes")
        note_details = dict(notes) if isinstance(notes, Mapping) else {}
        master_name = None
        if raw_address in tiered and isinstance(tiered[raw_address], Mapping):
            master_name = str(tiered[raw_address].get("name") or "") or None
        elif raw_address in final:
            master_name = str(final[raw_address])

        for raw_channel, raw_value in raw_record.items():
            channel = str(raw_channel)
            if channel.startswith("_"):
                continue
            value = str(raw_value)
            if channel in {"public", "source"}:
                contexts.append(
                    LegacyContext(
                        pc_address=address,
                        pc_function_id=stable_pc_function_id(address) if address in known else None,
                        channel=channel,
                        value=value,
                        artifact=Path(namemap_path).name if namemap_path else "namemap.json",
                        details=note_details,
                    )
                )
                continue
            record = ensure(address, value)
            record["evidence"].append(
                LegacyEvidence(
                    channel=channel,
                    kind="identity_support",
                    effect="supports",
                    independence_group=INDEPENDENCE_GROUPS.get(channel, f"legacy_channel:{channel}"),
                    artifact=Path(namemap_path).name if namemap_path else "namemap.json",
                    details={"agrees_with_legacy_master": value == master_name},
                )
            )

    def import_mapping_artifact(
        rows: Mapping[str, object],
        *,
        source_path: str | Path | None,
        channel: str,
        effect: str,
        experimental: bool = False,
        lineage: str | None = None,
    ) -> None:
        artifact = Path(source_path).name if source_path else f"{channel}.json"
        for raw_address, raw_record in rows.items():
            if not isinstance(raw_record, Mapping):
                raise ValueError(f"{artifact} entry {raw_address!r} is not an object")
            address = parse_address(raw_address)
            name = str(raw_record.get("name") or "")
            record = ensure(address, name)
            record["evidence"].append(
                LegacyEvidence(
                    channel=channel,
                    kind="raw_candidate_observation",
                    effect=effect,
                    independence_group=INDEPENDENCE_GROUPS[channel],
                    artifact=artifact,
                    details={
                        **{
                            key: value
                            for key, value in raw_record.items()
                            if key != "name"
                        },
                        **(
                            {"experimental_artifact": True}
                            if experimental
                            else {}
                        ),
                        **({"lineage": lineage} if lineage else {}),
                    },
                )
            )

    import_mapping_artifact(
        strmatch,
        source_path=strmatch_path,
        channel="strmatch",
        effect="supports",
    )
    import_mapping_artifact(
        pgm,
        source_path=pgm_path,
        channel="pgm",
        effect="supports",
    )
    graph_artifact = (
        Path(matched_ghidra_path).name
        if matched_ghidra_path
        else "matched_ghidra.json"
    )
    for raw_address, raw_record in matched_ghidra.items():
        if not isinstance(raw_record, Mapping):
            raise ValueError(
                f"{graph_artifact} entry {raw_address!r} is not an object"
            )
        address = parse_address(raw_address)
        name = str(raw_record.get("name") or "")
        depth = int(raw_record.get("depth") or 0)
        # Depth zero is the graph's seed set, not a propagated graph result.
        # Retain it as origin context and reserve graph/support for depth > 0.
        channel = "graph" if depth > 0 else "seed"
        effect = "supports" if depth > 0 else "context"
        record = ensure(address, name)
        record["evidence"].append(
            LegacyEvidence(
                channel=channel,
                kind=(
                    "raw_graph_propagation"
                    if depth > 0
                    else "raw_graph_seed_input"
                ),
                effect=effect,
                independence_group=INDEPENDENCE_GROUPS[channel],
                artifact=graph_artifact,
                details={
                    key: value
                    for key, value in raw_record.items()
                    if key != "name"
                },
            )
        )
    # ``all_seeds`` is an accumulator of upstream anchors.  It introduces a
    # candidate but does not independently validate that candidate.
    import_mapping_artifact(
        all_seeds,
        source_path=all_seeds_path,
        channel="seed",
        effect="context",
    )
    import_mapping_artifact(
        assign,
        source_path=assign_path,
        channel="assign",
        # assign.py combines call-graph, CFG, known-callee, size, locality and
        # vcall evidence.  The single-group legacy schema cannot express that
        # multi-parent lineage safely, so retain it as candidate context rather
        # than manufacture an additional independent supporting channel.
        effect="context",
    )
    import_mapping_artifact(
        vmatch,
        source_path=vmatch_path,
        channel="vmatch",
        effect="supports",
    )

    # Retained experimental outputs are part of the recoverable research
    # record, but their original methods have materially different dependency
    # lineages.  Importing them explicitly prevents candidate loss while the
    # effects below prevent a composite experiment from masquerading as an
    # independent confirmation.
    import_mapping_artifact(
        fingerprint,
        source_path=fingerprint_path,
        channel="fingerprint",
        effect="context",
        experimental=True,
        lineage="legacy seeds + name-keyed call graph + CFG + vcall + size",
    )
    import_mapping_artifact(
        calleealign,
        source_path=calleealign_path,
        channel="calleealign",
        effect="context",
        experimental=True,
        lineage="legacy seeds + name-keyed call graph + composite assignment",
    )
    import_mapping_artifact(
        calleealign_new,
        source_path=calleealign_new_path,
        channel="calleealign",
        effect="context",
        experimental=True,
        lineage="legacy seeds + name-keyed call graph + composite assignment",
    )
    import_mapping_artifact(
        wrappers,
        source_path=wrappers_path,
        channel="wrappers",
        effect="supports",
        experimental=True,
        lineage="third-party plugin PDB thin-wrapper author consensus",
    )
    import_mapping_artifact(
        pgm2,
        source_path=pgm2_path,
        channel="pgm",
        effect="supports",
        experimental=True,
        lineage="name-keyed call-graph propagation; same dependency as pgm",
    )
    import_mapping_artifact(
        pgm_new,
        source_path=pgm_new_path,
        channel="pgm",
        effect="supports",
        experimental=True,
        lineage="name-keyed call-graph propagation; same dependency as pgm",
    )
    import_mapping_artifact(
        constmatch,
        source_path=constmatch_path,
        channel="constmatch",
        # Numeric constants can be excellent evidence, but this retained pass
        # keyed the Xbox side through the lossy legacy name graph.  Preserve it
        # as context until the method is rerun against physical record IDs.
        effect="context",
        experimental=True,
        lineage="cross-build numeric constants keyed through legacy Xbox names",
    )

    if agent_verdicts_path is not None:
        agent_source = Path(agent_verdicts_path)
        if agent_source.exists():
            with agent_source.open(encoding="utf-8") as handle:
                agent_rows = json.load(handle)
            if not isinstance(agent_rows, list):
                raise ValueError(f"{agent_source}: expected a JSON array")
            for ordinal, raw_record in enumerate(agent_rows):
                if not isinstance(raw_record, Mapping):
                    raise ValueError(
                        f"{agent_source} row {ordinal} is not an object"
                    )
                address = parse_address(raw_record.get("address"))
                name = str(raw_record.get("claim") or "")
                verdict = str(raw_record.get("verdict") or "").upper()
                effect = (
                    "supports"
                    if verdict == "CONFIRM"
                    else "contradicts"
                    if verdict == "REJECT"
                    else "context"
                )
                record = ensure(address, name)
                record["evidence"].append(
                    LegacyEvidence(
                        channel="agent",
                        kind="raw_agent_verdict",
                        effect=effect,
                        independence_group=INDEPENDENCE_GROUPS["agent"],
                        artifact=agent_source.name,
                        details={
                            "row": ordinal,
                            **{
                                key: value
                                for key, value in raw_record.items()
                                if key not in {"address", "claim"}
                            },
                        },
                    )
                )

    normalized: list[LegacyClaim] = []
    for (address, name), record in sorted(claims.items()):
        function_id = stable_pc_function_id(address) if address in known else None
        evidence = tuple(
            sorted(
                record["evidence"],
                key=lambda item: (
                    item.artifact,
                    item.channel,
                    item.kind,
                    item.effect,
                    json.dumps(dict(item.details), sort_keys=True),
                ),
            )
        )
        normalized.append(
            LegacyClaim(
                claim_id=_claim_id(address, name),
                pc_address=address,
                pc_function_id=function_id,
                proposed_name=name,
                resolution="function_entry" if function_id else "unresolved_address",
                legacy_tier=record["tier"],
                evidence=evidence,
            )
        )

    contexts.sort(key=lambda item: (item.pc_address, item.channel, item.value, item.artifact))
    return LegacyImport(claims=tuple(normalized), context=tuple(contexts))
