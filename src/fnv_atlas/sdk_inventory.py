"""Variant-safe joins between SDK observations and the canonical PC image.

Numeric equality is not sufficient when one SDK contains both GAME and GECK
addresses.  This module therefore gives concrete GAME observations the only
definitive PC join, excludes GECK observations from PC matching, and labels
unguarded observations as candidates even when their address happens to be a
known PC function or section.

The join is read-only.  It creates no function, name, match claim, confidence,
or review decision.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .pc_inventory import PCFunction, PCInventory, PESection
from .sdk_prototypes import (
    SdkBoundaryCandidate,
    SdkCallTargetObservation,
    SdkDataAddressObservation,
    SdkPrototypeExtraction,
    SdkPrototypeObservation,
)


@dataclass(frozen=True, slots=True)
class SdkCodeJoin:
    """Classification of one declaration or call-target code observation."""

    observation_kind: str
    observation_id: str
    program_variant: str
    address: int
    classification: str
    pc_function_id: str | None
    candidate_pc_function_id: str | None
    section_name: str | None
    section_executable: bool | None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["address_hex"] = f"0x{self.address:08X}"
        return result


@dataclass(frozen=True, slots=True)
class SdkDataJoin:
    """Classification of one SDK global-data observation."""

    observation_id: str
    program_variant: str
    address: int
    data_kind: str
    classification: str
    section_name: str | None
    section_executable: bool | None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["address_hex"] = f"0x{self.address:08X}"
        return result


@dataclass(frozen=True, slots=True)
class SdkPcInventoryJoin:
    """Complete, deterministic SDK classification against one PC inventory."""

    prototype_joins: tuple[SdkCodeJoin, ...]
    call_target_joins: tuple[SdkCodeJoin, ...]
    data_joins: tuple[SdkDataJoin, ...]
    boundary_candidates: tuple[SdkBoundaryCandidate, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "prototype_join_count": len(self.prototype_joins),
            "call_target_join_count": len(self.call_target_joins),
            "data_join_count": len(self.data_joins),
            "boundary_candidate_count": len(self.boundary_candidates),
            "prototype_joins": [item.to_dict() for item in self.prototype_joins],
            "call_target_joins": [item.to_dict() for item in self.call_target_joins],
            "data_joins": [item.to_dict() for item in self.data_joins],
            "boundary_candidates": [
                item.to_dict() for item in self.boundary_candidates
            ],
        }


def _section_at(
    address: int, sections: tuple[PESection, ...]
) -> PESection | None:
    matches = tuple(
        section for section in sections if section.start <= address < section.end
    )
    if len(matches) > 1:
        raise ValueError(f"overlapping PE sections contain address 0x{address:08X}")
    return matches[0] if matches else None


def _code_classification(
    *,
    observation_kind: str,
    observation_id: str,
    program_variant: str,
    address: int,
    functions: dict[int, PCFunction],
    sections: tuple[PESection, ...],
) -> SdkCodeJoin:
    section = _section_at(address, sections)
    function = functions.get(address)
    if program_variant == "geck":
        classification = "non_game_variant"
        pc_function_id = None
        candidate_function_id = None
    elif program_variant == "game":
        candidate_function_id = None
        if function is not None:
            classification = "pc_function_entry"
            pc_function_id = function.function_id
        elif section is not None and section.executable:
            classification = "pc_executable_non_entry"
            pc_function_id = None
        elif section is not None:
            classification = "pc_non_executable_section"
            pc_function_id = None
        else:
            classification = "outside_pc_image_sections"
            pc_function_id = None
    elif program_variant == "unspecified_pc":
        pc_function_id = None
        candidate_function_id = function.function_id if function is not None else None
        if function is not None:
            classification = "pc_function_entry_variant_unspecified"
        elif section is not None and section.executable:
            classification = "pc_executable_non_entry_variant_unspecified"
        elif section is not None:
            classification = "pc_non_executable_section_variant_unspecified"
        else:
            classification = "outside_pc_image_sections_variant_unspecified"
    else:
        raise ValueError(f"unknown SDK program variant {program_variant!r}")

    return SdkCodeJoin(
        observation_kind=observation_kind,
        observation_id=observation_id,
        program_variant=program_variant,
        address=address,
        classification=classification,
        pc_function_id=pc_function_id,
        candidate_pc_function_id=candidate_function_id,
        section_name=section.name if section is not None else None,
        section_executable=section.executable if section is not None else None,
    )


def _data_classification(
    observation: SdkDataAddressObservation,
    sections: tuple[PESection, ...],
) -> SdkDataJoin:
    section = _section_at(observation.address, sections)
    if observation.program_variant == "geck":
        classification = "non_game_variant"
    elif observation.program_variant not in {"game", "unspecified_pc"}:
        raise ValueError(
            f"unknown SDK program variant {observation.program_variant!r}"
        )
    else:
        suffix = (
            "" if observation.program_variant == "game" else "_variant_unspecified"
        )
        if section is None:
            classification = "outside_pc_image_sections" + suffix
        elif section.executable:
            classification = "pc_executable_section" + suffix
        else:
            classification = "pc_data_section" + suffix
    return SdkDataJoin(
        observation_id=observation.observation_id,
        program_variant=observation.program_variant,
        address=observation.address,
        data_kind=observation.data_kind,
        classification=classification,
        section_name=section.name if section is not None else None,
        section_executable=section.executable if section is not None else None,
    )


def _boundary_candidates(
    observations: Iterable[SdkPrototypeObservation],
    joins: dict[str, SdkCodeJoin],
    functions: tuple[PCFunction, ...],
) -> tuple[SdkBoundaryCandidate, ...]:
    extents = tuple(
        sorted(
            (function.address, function.address + function.size)
            for function in functions
            if function.size > 0
        )
    )
    candidates: list[SdkBoundaryCandidate] = []
    for observation in observations:
        if observation.evidence_kind != "create_object_macro":
            continue
        joined = joins[observation.observation_id]
        if joined.classification not in {
            "pc_executable_non_entry",
            "pc_executable_non_entry_variant_unspecified",
        }:
            continue
        containing = tuple(
            start for start, end in extents if start <= observation.address < end
        )
        candidates.append(
            SdkBoundaryCandidate(
                source_observation=observation,
                inventory_classification=joined.classification,
                candidate_reason="sdk_create_object_target_is_executable_non_entry",
                containing_function_entries=containing,
            )
        )
    return tuple(
        sorted(
            candidates,
            key=lambda item: (
                item.source_observation.address,
                item.source_observation.source_path.casefold(),
                item.source_observation.address_line,
                item.candidate_id,
            ),
        )
    )


def join_sdk_to_pc_inventory(
    extraction: SdkPrototypeExtraction,
    inventory: PCInventory,
    sections: Iterable[PESection],
) -> SdkPcInventoryJoin:
    """Classify an SDK extraction without promoting any observation.

    Concrete GAME observations may carry ``pc_function_id`` when they match an
    exact canonical entry.  Unguarded observations instead carry
    ``candidate_pc_function_id``; GECK observations carry neither.
    """

    ordered_sections = tuple(sorted(sections, key=lambda item: (item.start, item.end)))
    if any(section.start < 0 or section.end <= section.start for section in ordered_sections):
        raise ValueError("PE sections must be non-negative, increasing ranges")
    for previous, current in zip(ordered_sections, ordered_sections[1:]):
        if current.start < previous.end:
            raise ValueError("PE sections must not overlap")

    functions = inventory.by_address()
    prototypes = tuple(
        _code_classification(
            observation_kind="prototype",
            observation_id=item.observation_id,
            program_variant=item.program_variant,
            address=item.address,
            functions=functions,
            sections=ordered_sections,
        )
        for item in extraction.observations
    )
    calls = tuple(
        _code_classification(
            observation_kind="call_target",
            observation_id=item.observation_id,
            program_variant=item.program_variant,
            address=item.address,
            functions=functions,
            sections=ordered_sections,
        )
        for item in extraction.call_targets
    )
    data = tuple(
        _data_classification(item, ordered_sections)
        for item in extraction.data_addresses
    )
    by_observation = {item.observation_id: item for item in prototypes}
    boundaries = _boundary_candidates(
        extraction.observations,
        by_observation,
        inventory.functions,
    )
    return SdkPcInventoryJoin(
        prototype_joins=prototypes,
        call_target_joins=calls,
        data_joins=data,
        boundary_candidates=boundaries,
    )


__all__ = [
    "SdkCodeJoin",
    "SdkDataJoin",
    "SdkPcInventoryJoin",
    "join_sdk_to_pc_inventory",
]
