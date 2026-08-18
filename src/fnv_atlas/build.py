"""Reproducible construction of the first source-atlas database.

The builder consumes legacy artifacts as evidence.  It never rewrites them and
never upgrades a legacy confidence tier into an accepted match.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable, Mapping

from . import __version__
from .database import AtlasDatabase, ManifestEntry, stable_id
from .control_flow_matching_persistence import (
    persist_control_flow_matching_result,
)
from .control_flow_matching_sqlite import (
    analyze_control_flow_candidates_from_sqlite,
)
from .legacy import LegacyClaim, LegacyContext, load_legacy_claims
from .pc_inventory import (
    PCInventory,
    executable_ranges_from_pe,
    load_ghidra_inventory,
    read_pe_sections,
)
from .pdb_globals import extract_data_symbols
from .pdb_symbols import ProcedureExtraction, ProcedureRecord, extract_procedures
from .pdb_vftables import extract_vftable_corpus
from .ppc_control_flow import (
    CALL_RELEVANT_V1_ROLES,
    extract_ppc_control_flow,
    read_xbox_pe_image,
    select_control_flow,
)
from .schema import SCHEMA_VERSION
from .sdk_inventory import join_sdk_to_pc_inventory
from .sdk_prototypes import extract_sdk_prototypes, sdk_source_manifest_bytes
from .tpi_signatures import (
    LF_MFUNCTION,
    LF_PROCEDURE,
    SignatureResolution,
    TpiTypeResolver,
)
from .tpi_layouts import (
    TpiLayoutCorpus,
    extract_type_layouts_from_resolver,
    extract_type_records_from_resolver,
)
from .validation import semantic_validation_counts, semantic_validation_ok
from .vtable_alignment import propose_vtable_alignments
from .vtable_hypotheses import (
    VtableHypothesisMaterialization,
    materialize_vtable_hypotheses,
)
from .vtables import VtableDataset, load_pc_vtables, load_xbox_vtables


PC_PROGRAM_ID = "program:pc:falloutnv"
XBOX_PROGRAM_ID = "program:xbox360:fallout-release-memdebug"


@dataclass(frozen=True, slots=True)
class BuildConfig:
    output_database: Path
    pc_functions: Path
    pc_executable: Path
    xbox_pdb: Path
    xbox_executable: Path
    xbox_modules: Path
    xbox_function_sources: Path
    pc_classes: Path
    xbox_vtables: Path
    xbox_types: Path
    legacy_names_tiered: Path
    legacy_names_final: Path
    legacy_namemap: Path
    legacy_strmatch: Path
    legacy_pgm: Path
    legacy_matched_ghidra: Path
    legacy_agent_verdicts: Path
    legacy_all_seeds: Path
    legacy_assign: Path
    legacy_vmatch: Path
    replace: bool = False
    legacy_fingerprint: Path | None = None
    legacy_calleealign: Path | None = None
    legacy_calleealign_new: Path | None = None
    legacy_wrappers: Path | None = None
    legacy_pgm2: Path | None = None
    legacy_pgm_new: Path | None = None
    legacy_constmatch: Path | None = None
    pc_sdk_root: Path | None = None

    @classmethod
    def from_repo(
        cls,
        repo: str | Path,
        *,
        xbox_pdb: str | Path,
        xbox_executable: str | Path,
        sdk_root: str | Path | None = None,
        output_database: str | Path | None = None,
        replace: bool = False,
    ) -> "BuildConfig":
        root = Path(repo).resolve()
        output = (
            Path(output_database).resolve()
            if output_database is not None
            else root / "source-atlas" / "build" / "fnv-source-atlas.sqlite"
        )
        return cls(
            output_database=output,
            pc_functions=root / "binport" / "ghidra_functions.json",
            pc_executable=root / "binport" / "FalloutNV.dumped.exe",
            xbox_pdb=Path(xbox_pdb).resolve(),
            xbox_executable=Path(xbox_executable).resolve(),
            xbox_modules=root / "symbol-port" / "modules_360.json",
            xbox_function_sources=root / "symbol-port" / "func_source_360.json",
            pc_classes=root / "symbol-port" / "pc_classes.json",
            xbox_vtables=root / "symbol-port" / "vtables_360.json",
            xbox_types=root / "symbol-port" / "types_360.json",
            legacy_names_tiered=root / "binport" / "names_tiered.json",
            legacy_names_final=root / "binport" / "names_final.json",
            legacy_namemap=root / "binport" / "namemap.json",
            legacy_strmatch=root / "binport" / "strmatch.json",
            legacy_pgm=root / "binport" / "pgm.json",
            legacy_matched_ghidra=root / "binport" / "matched_ghidra.json",
            legacy_agent_verdicts=root / "binport" / "agent_verdicts.json",
            legacy_all_seeds=root / "binport" / "all_seeds.json",
            legacy_assign=root / "binport" / "assign.json",
            legacy_vmatch=root / "binport" / "vmatch.json",
            replace=replace,
            legacy_fingerprint=root / "binport" / "fp3.json",
            legacy_calleealign=root / "binport" / "calleealign.json",
            legacy_calleealign_new=root / "binport" / "calleealign_new.json",
            legacy_wrappers=root / "binport" / "wrappers.json",
            legacy_pgm2=root / "binport" / "pgm2.json",
            legacy_pgm_new=root / "binport" / "pgm_new.json",
            legacy_constmatch=root / "binport" / "constmatch.json",
            pc_sdk_root=(
                Path(sdk_root).resolve() if sdk_root is not None else None
            ),
        )

    def input_files(self) -> tuple[tuple[str, Path, str], ...]:
        canonical = (
            ("pc_function_export", self.pc_functions, "application/json"),
            ("pc_executable", self.pc_executable, "application/vnd.microsoft.portable-executable"),
            ("xbox_pdb", self.xbox_pdb, "application/octet-stream"),
            ("xbox_executable", self.xbox_executable, "application/vnd.microsoft.portable-executable"),
            ("xbox_modules", self.xbox_modules, "application/json"),
            ("xbox_function_sources", self.xbox_function_sources, "application/json"),
            ("pc_rtti_vtables", self.pc_classes, "application/json"),
            ("xbox_vtables", self.xbox_vtables, "application/json"),
            ("xbox_types", self.xbox_types, "application/json"),
            ("legacy_names_tiered", self.legacy_names_tiered, "application/json"),
            ("legacy_names_final", self.legacy_names_final, "application/json"),
            ("legacy_namemap", self.legacy_namemap, "application/json"),
            ("legacy_strmatch", self.legacy_strmatch, "application/json"),
            ("legacy_pgm", self.legacy_pgm, "application/json"),
            ("legacy_matched_ghidra", self.legacy_matched_ghidra, "application/json"),
            ("legacy_agent_verdicts", self.legacy_agent_verdicts, "application/json"),
            ("legacy_all_seeds", self.legacy_all_seeds, "application/json"),
            ("legacy_assign", self.legacy_assign, "application/json"),
            ("legacy_vmatch", self.legacy_vmatch, "application/json"),
        )
        experimental = tuple(
            (role, path, "application/json")
            for role, path in (
                ("legacy_fingerprint_experiment", self.legacy_fingerprint),
                ("legacy_calleealign_experiment", self.legacy_calleealign),
                (
                    "legacy_calleealign_new_experiment",
                    self.legacy_calleealign_new,
                ),
                ("legacy_wrappers_experiment", self.legacy_wrappers),
                ("legacy_pgm2_experiment", self.legacy_pgm2),
                ("legacy_pgm_new_experiment", self.legacy_pgm_new),
                ("legacy_constmatch_experiment", self.legacy_constmatch),
            )
            if path is not None
        )
        return canonical + experimental

    def input_directories(self) -> tuple[tuple[str, Path, str], ...]:
        if self.pc_sdk_root is None:
            return ()
        return (
            (
                "pc_sdk_source_tree",
                self.pc_sdk_root,
                "application/vnd.fnv.sdk-source-manifest+json",
            ),
        )

    def protected_inputs(self) -> tuple[tuple[str, Path], ...]:
        return tuple(
            (role, path)
            for role, path, _media_type in (
                *self.input_files(),
                *self.input_directories(),
            )
        )


@dataclass(frozen=True, slots=True)
class BuildReport:
    database: str
    database_sha256: str
    manifest_id: str
    producer_version: str
    schema_version: int
    producer_source_id: str
    pc_functions: int
    function_assertions: int
    pc_resolved_call_edges: int
    pc_unresolved_call_edges: int
    pc_unresolved_call_targets: int
    xbox_procedure_records: int
    xbox_unique_addresses: int
    xbox_fold_groups: int
    xbox_source_links: int
    xbox_signature_rows: int
    xbox_signatures_resolved: int
    xbox_signatures_unresolved: int
    xbox_signature_arguments: int
    xbox_member_function_signatures: int
    xbox_procedure_signatures: int
    xbox_variadic_signatures: int
    xbox_unique_resolved_signature_types: int
    xbox_signature_rows_without_function: int
    xbox_tpi_raw_type_records: int
    xbox_tpi_raw_body_bytes: int
    xbox_tpi_tag_records: int
    xbox_tpi_definitions: int
    xbox_tpi_forward_references: int
    xbox_tpi_tag_member_occurrences: int
    xbox_tpi_physical_field_members: int
    xbox_tpi_physical_method_overloads: int
    xbox_tpi_diagnostics: int
    xbox_data_symbol_records: int
    xbox_data_symbol_resolved_records: int
    xbox_data_symbol_unresolved_records: int
    xbox_data_symbol_unique_addresses: int
    xbox_raw_vftable_physical_records: int
    xbox_raw_vftable_resolved_records: int
    xbox_raw_vftable_unresolved_records: int
    xbox_raw_vftable_canonical_names: int
    xbox_raw_vftable_address_groups: int
    xbox_raw_vftable_pointer_runs: int
    xbox_raw_vftable_pointer_slots: int
    xbox_raw_vftable_diagnostics: int
    pc_sdk_source_tree_sha256: str | None
    pc_sdk_source_files: int
    pc_sdk_prototype_observations: int
    pc_sdk_call_target_observations: int
    pc_sdk_data_observations: int
    pc_sdk_diagnostics: int
    pc_sdk_code_inventory_joins: int
    pc_sdk_data_inventory_joins: int
    pc_sdk_definitive_game_links: int
    pc_sdk_unspecified_entry_candidates: int
    pc_sdk_boundary_candidates: int
    pc_sdk_boundary_containers: int
    xbox_control_flow_persistence_policy: str
    xbox_control_flow_source_physical_sites: int
    xbox_control_flow_source_logical_uses: int
    xbox_control_flow_persisted_physical_sites: int
    xbox_control_flow_persisted_logical_uses: int
    xbox_control_flow_triggering_logical_uses: int
    xbox_control_flow_procedure_scans: int
    xbox_control_flow_source_summary: Mapping[str, object]
    xbox_control_flow_persisted_summary: Mapping[str, object]
    control_flow_matching_policy: str
    control_flow_mapping_source_alternatives: int
    control_flow_mapping_semantic_bundles: int
    control_flow_mapping_caller_anchors: int
    control_flow_mapping_closed_derivations: int
    control_flow_mapping_closed_evidence_occurrences: int
    control_flow_mapping_blocked_neighborhoods: int
    control_flow_mapping_fold_blocked_neighborhoods: int
    control_flow_mapping_proposal_derivations: int
    control_flow_mapping_proposal_sets: int
    control_flow_mapping_proposal_alternatives: int
    control_flow_mapping_proposal_evidence_occurrences: int
    control_flow_mapping_persisted_relation_sets: int
    control_flow_mapping_persisted_proposal_sets: int
    control_flow_mapping_persisted_proposal_alternatives: int
    control_flow_mapping_persisted_scalar_claims: int
    control_flow_mapping_persisted_fold_alternatives: int
    control_flow_mapping_persisted_evidence: int
    pc_vtable_classes: int
    pc_vtables: int
    pc_vtable_slots: int
    pc_primary_vtables: int
    pc_secondary_vtables: int
    pc_unknown_vtable_roles: int
    pc_extent_suspect_vtables: int
    xbox_vtable_classes: int
    xbox_vtables: int
    xbox_vtable_slots: int
    xbox_primary_vtables: int
    xbox_secondary_vtables: int
    xbox_unknown_vtable_roles: int
    xbox_extent_suspect_vtables: int
    vtable_alignment_candidates: int
    vtable_alignment_issues: int
    vtable_slot_alignments: int
    vtable_hypothesis_sets: int
    vtable_hypothesis_alternatives: int
    vtable_scalar_match_claims: int
    vtable_pc_resolved_subjects: int
    vtable_pc_unresolved_subjects: int
    vtable_xbox_exact_alternatives: int
    vtable_xbox_fold_bundle_alternatives: int
    vtable_xbox_unresolved_alternatives: int
    vtable_distinct_fold_groups_used: int
    vtable_structural_supporting_evidence: int
    vtable_structural_context_evidence: int
    vtable_clean_supporting_evidence: int
    vtable_suspect_safe_prefix_evidence: int
    vtable_overflow_context_evidence: int
    legacy_name_claims: int
    legacy_unique_xbox_matches: int
    legacy_ambiguous_xbox_claims: int
    legacy_unmatched_xbox_claims: int
    legacy_database_claims: int
    legacy_hypothesis_sets: int
    legacy_hypothesis_alternatives: int
    legacy_hypothesis_evidence_rows: int
    legacy_xbox_unresolved_sets: int
    legacy_unresolved_pc_claims: int
    legacy_context_observations: int
    legacy_experimental_claims: int
    legacy_experimental_evidence_occurrences: int
    legacy_source_evidence_occurrences: int
    legacy_source_supporting_evidence: int
    legacy_source_contradicting_evidence: int
    legacy_source_context_evidence: int
    claim_evidence_rows: int
    claim_supporting_evidence_rows: int
    claim_contradicting_evidence_rows: int
    claim_context_evidence_rows: int
    hypothesis_sets: int
    hypothesis_alternatives: int
    hypothesis_evidence_rows: int
    hypothesis_supporting_evidence_rows: int
    hypothesis_contradicting_evidence_rows: int
    hypothesis_context_evidence_rows: int
    alternative_evidence_rows: int
    alternative_supporting_evidence_rows: int
    alternative_contradicting_evidence_rows: int
    alternative_context_evidence_rows: int
    integrity_check: str
    foreign_key_violations: int
    semantic_violations: Mapping[str, int]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _require_inputs(config: BuildConfig) -> None:
    missing = [str(path) for _, path, _ in config.input_files() if not path.is_file()]
    missing.extend(
        str(path)
        for _, path, _ in config.input_directories()
        if not path.is_dir()
    )
    if missing:
        raise FileNotFoundError("missing source-atlas input(s):\n  " + "\n  ".join(missing))


def paths_alias(first: str | Path, second: str | Path) -> bool:
    """Return whether two paths identify the same destination or file.

    ``resolve`` catches lexical aliases and symlinks.  ``samefile`` additionally
    catches hard links when both paths already exist.
    """

    left = Path(first).resolve(strict=False)
    right = Path(second).resolve(strict=False)
    if os.path.normcase(str(left)) == os.path.normcase(str(right)):
        return True
    if left.exists() and right.exists():
        try:
            return os.path.samefile(left, right)
        except OSError:
            pass
    return False


def reject_destination_aliases(
    destination: str | Path,
    protected_paths: Iterable[tuple[str, str | Path]],
    *,
    destination_label: str,
) -> None:
    """Reject a destination that could overwrite any protected input/output."""

    resolved_destination = Path(destination).resolve(strict=False)
    for label, protected in protected_paths:
        resolved_protected = Path(protected).resolve(strict=False)
        inside_protected_directory = (
            resolved_protected.is_dir()
            and resolved_destination != resolved_protected
            and resolved_protected in resolved_destination.parents
        )
        if paths_alias(resolved_destination, protected) or inside_protected_directory:
            raise ValueError(
                f"{destination_label} {resolved_destination} aliases protected "
                f"{label} {Path(protected).resolve(strict=False)}"
            )


def _new_atomic_temporary(destination: Path) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".building",
        dir=destination.parent,
    )
    os.close(descriptor)
    # Keep the reserved zero-byte file.  SQLite initialization and write_text
    # both accept it, while unlinking here would reopen a name-substitution
    # race before the producer opens the temporary destination.
    return Path(raw_path)


def _publish_atomic_file(
    temporary: Path,
    destination: Path,
    *,
    replace: bool,
) -> None:
    """Publish a prepared file without a late no-clobber race.

    ``os.link`` atomically claims a previously absent destination on every
    supported build filesystem.  Unlike a final exists-check followed by
    ``os.replace``, another process cannot insert a file between the check and
    publication when ``replace`` is false.
    """

    if replace:
        os.replace(temporary, destination)
        return
    try:
        os.link(temporary, destination)
    except FileExistsError as exc:
        raise FileExistsError(
            f"{destination} appeared while building; refusing to overwrite it"
        ) from exc
    temporary.unlink()


def _image_base_from_ranges(ranges: Iterable[tuple[int, int]]) -> int | None:
    starts = [start for start, _ in ranges]
    return (min(starts) & ~0xFFFF) if starts else None


def _normalized_source_path(value: str) -> str:
    return value.replace("\\", "/").casefold()


def _load_json_object(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _register_manifest(
    db: AtlasDatabase, config: BuildConfig
) -> tuple[str, dict[str, str]]:
    entries: list[ManifestEntry] = []
    content_ids: dict[str, str] = {}
    for role, path, media_type in config.input_files():
        content_id = db.register_input(path, media_type=media_type)
        content_ids[role] = content_id
        entries.append(
            ManifestEntry(
                content_id=content_id,
                role=role,
                logical_name=path.name,
            )
        )
    for role, path, media_type in config.input_directories():
        payload = sdk_source_manifest_bytes(path)
        content_id = db.register_input_bytes(
            payload,
            media_type=media_type,
        )
        content_ids[role] = content_id
        entries.append(
            ManifestEntry(
                content_id=content_id,
                role=role,
                logical_name=f"{path.name}.source-manifest.json",
                metadata={"absolute_root_stored": False},
            )
        )
    manifest_id = db.create_manifest(entries)
    db.verify_manifest(manifest_id)
    return manifest_id, content_ids


def _content_id_for_path(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _content_id_for_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def producer_source_id() -> str:
    """Content identity of the Python implementation producing atlas rows."""

    package_root = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(package_root.glob("*.py"), key=lambda item: item.name):
        data = path.read_bytes()
        name = path.name.encode("utf-8")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return f"sha256:{digest.hexdigest()}"


def _verify_input_files_unchanged(
    config: BuildConfig, registered_content_ids: Mapping[str, str]
) -> None:
    """Reject a build if any source changed after manifest registration."""

    changed: list[str] = []
    for role, path, _media_type in config.input_files():
        expected = registered_content_ids.get(role)
        if expected is None:
            changed.append(f"{role}: missing registered content identity")
            continue
        try:
            actual = _content_id_for_path(path)
        except OSError as error:
            changed.append(f"{role}: {path} became unreadable: {error}")
            continue
        if actual != expected:
            changed.append(
                f"{role}: {path} changed ({expected} -> {actual})"
            )
    for role, path, _media_type in config.input_directories():
        expected = registered_content_ids.get(role)
        if expected is None:
            changed.append(f"{role}: missing registered content identity")
            continue
        try:
            actual = _content_id_for_bytes(sdk_source_manifest_bytes(path))
        except (OSError, ValueError) as error:
            changed.append(f"{role}: {path} became unreadable: {error}")
            continue
        if actual != expected:
            changed.append(
                f"{role}: {path} changed ({expected} -> {actual})"
            )
    if changed:
        raise RuntimeError(
            "source-atlas input changed during build:\n  "
            + "\n  ".join(changed)
        )


@dataclass(frozen=True, slots=True)
class _VtableInsertCounts:
    classes: int
    tables: int
    slots: int
    primary_tables: int
    secondary_tables: int
    unknown_role_tables: int
    extent_suspect_tables: int


@dataclass(frozen=True, slots=True)
class _VtableHypothesisInsertCounts:
    table_alignments: int
    slot_alignments: int
    issues: int
    hypothesis_sets: int
    alternatives: int
    scalar_claims: int
    pc_resolved_subjects: int
    pc_unresolved_subjects: int
    xbox_exact_alternatives: int
    xbox_fold_bundle_alternatives: int
    xbox_unresolved_alternatives: int
    distinct_fold_groups_used: int
    supporting_evidence: int
    context_evidence: int
    clean_supporting_evidence: int
    suspect_safe_prefix_evidence: int
    overflow_context_evidence: int


def _database_vtable_address_space(platform: str) -> str:
    if platform == "pc":
        return "ram"
    if platform == "xbox360":
        return "xbox-va"
    raise ValueError(f"unsupported vtable platform {platform!r}")


def _vtable_target_address_group(
    db: AtlasDatabase,
    *,
    program_id: str,
    address_space: str,
    address: int,
) -> str:
    """Return a slot target group without overwriting earlier observations."""

    row = db.connection.execute(
        """
        SELECT address_group_id FROM address_groups
        WHERE program_id = ? AND address_space = ? AND address = ?
        """,
        (program_id, address_space, address),
    ).fetchone()
    if row is not None:
        return str(row[0])
    return db.upsert_address_group(
        program_id=program_id,
        address_space=address_space,
        address=address,
        kind="code",
        details={
            "introduced_by": "vtable_slot_target",
            "does_not_assert_function_entry": True,
        },
    )


def _insert_vtable_dataset(
    db: AtlasDatabase,
    dataset: VtableDataset,
    *,
    program_id: str,
    provenance_id: str,
    source_artifact: str,
) -> _VtableInsertCounts:
    """Insert classes/tables/slots without creating semantic functions.

    Slot targets become address groups only.  In particular, an address-derived
    Xbox slot label remains JSON observation metadata and is never promoted to a
    function or function name.
    """

    expected_program = {
        "pc": PC_PROGRAM_ID,
        "xbox360": XBOX_PROGRAM_ID,
    }.get(dataset.platform)
    if expected_program is None or program_id != expected_program:
        raise ValueError(
            f"dataset platform {dataset.platform!r} does not match program "
            f"{program_id!r}"
        )

    address_space = _database_vtable_address_space(dataset.platform)
    tables_by_class: dict[str, list[object]] = defaultdict(list)
    for table in dataset.tables:
        if table.platform != dataset.platform:
            raise ValueError(
                f"table {table.vtable_id!r} has platform {table.platform!r}, "
                f"expected {dataset.platform!r}"
            )
        tables_by_class[table.class_name].append(table)

    class_ids: dict[str, str] = {}
    class_name_kind = (
        "pc_rtti_class_key"
        if dataset.platform == "pc"
        else "xbox_vftable_class_key"
    )
    for class_name in sorted(tables_by_class):
        class_id = stable_id("vtable-class", program_id, class_name)
        db.upsert_class(
            class_id,
            program_id=program_id,
            identity_key=f"vtable-artifact-class:{class_name}",
            details={
                "source_artifact": source_artifact,
                "source_class_key": class_name,
                "vtable_count": len(tables_by_class[class_name]),
            },
        )
        db.add_class_name(
            class_id,
            class_name,
            name_kind=class_name_kind,
            is_primary=True,
            provenance_id=provenance_id,
            details={"source_artifact": source_artifact},
        )
        class_ids[class_name] = class_id

    for table in dataset.tables:
        # ``declared_slot_count`` is reserved for a genuine same-build declared
        # map.  The pointer-run count remains in details, never in this column.
        declared_slot_count = (
            table.extent.reference_slot_count
            if table.extent.reference_kind
            == "xbox_tpi_primary_virtual_slot_map"
            else None
        )
        db.upsert_vtable(
            table.vtable_id,
            program_id=program_id,
            class_id=class_ids[table.class_name],
            address_space=address_space,
            address=table.address,
            vfptr_role=table.vfptr_role,
            subobject_offset=table.subobject_offset,
            table_index=table.source_table_index,
            declared_slot_count=declared_slot_count,
            provenance_id=provenance_id,
            details={
                "source_artifact": source_artifact,
                "source_address_space": table.address_space,
                "raw_table_identity": table.raw_table_identity,
                "raw_qualifier": table.raw_qualifier,
                "qualifier": table.qualifier,
                "role_basis": table.role_basis,
                "subobject_offset_candidates": list(
                    table.subobject_offset_candidates
                ),
                "col_address": table.col_address,
                "rtti_name": table.rtti_name,
                "observed_slot_count": table.slot_count,
                "extent": table.extent.to_dict(),
                "no_cross_platform_alignment_claim": True,
            },
        )
        for slot in table.slots:
            target_group_id = _vtable_target_address_group(
                db,
                program_id=program_id,
                address_space=address_space,
                address=slot.target_address,
            )
            db.upsert_vtable_slot(
                table.vtable_id,
                slot.slot_index,
                target_address_group_id=target_group_id,
                provenance_id=provenance_id,
                details={
                    "slot_id": slot.slot_id,
                    "source_target_address_space": slot.target_address_space,
                    "raw_target_address": slot.raw_target_address,
                    "name_observations": [
                        observation.to_dict()
                        for observation in slot.name_observations
                    ],
                    "target_is_address_only": True,
                },
            )

    return _VtableInsertCounts(
        classes=len(class_ids),
        tables=dataset.table_count,
        slots=dataset.slot_count,
        primary_tables=sum(
            table.vfptr_role == "primary" for table in dataset.tables
        ),
        secondary_tables=sum(
            table.vfptr_role == "secondary" for table in dataset.tables
        ),
        unknown_role_tables=sum(
            table.vfptr_role == "unknown" for table in dataset.tables
        ),
        extent_suspect_tables=dataset.extent_suspect_count,
    )


def _vtable_unresolved_target(
    db: AtlasDatabase,
    *,
    platform: str,
    address_space: str,
    address: int,
    provenance_id: str,
) -> str:
    if platform == "pc":
        program_id = PC_PROGRAM_ID
        target_kind = "vtable_slot_without_canonical_pc_function"
        reason = "vtable slot target is not a canonical Ghidra function entry"
    elif platform == "xbox360":
        program_id = XBOX_PROGRAM_ID
        target_kind = "vtable_slot_without_pdb_procedure"
        reason = "vtable slot target has no PDB procedure record at its Xbox VA"
    else:
        raise ValueError(f"unsupported vtable endpoint platform {platform!r}")
    address_group_id = _vtable_target_address_group(
        db,
        program_id=program_id,
        address_space=address_space,
        address=address,
    )
    return db.upsert_unresolved_target(
        target_id=stable_id(
            "vtable-unresolved-target",
            program_id,
            address_space,
            address,
            target_kind,
        ),
        program_id=program_id,
        address_group_id=address_group_id,
        target_kind=target_kind,
        reason=reason,
        provenance_id=provenance_id,
        details={
            "introduced_by": "conservative_vtable_slot_alignment",
            "does_not_assert_function_identity": True,
        },
    )


def _insert_vtable_hypotheses(
    db: AtlasDatabase,
    materialization: VtableHypothesisMaterialization,
    *,
    provenance_id: str,
) -> _VtableHypothesisInsertCounts:
    """Persist every structural occurrence without selecting names or folds."""

    for alignment in materialization.table_alignments:
        db.upsert_vtable_alignment_candidate(
            alignment.alignment_id,
            pc_vtable_id=alignment.pc_vtable_id,
            xbox_vtable_id=alignment.xbox_vtable_id,
            class_name=alignment.class_name,
            vfptr_role=alignment.vfptr_role,
            subobject_offset=alignment.subobject_offset,
            provenance_id=provenance_id,
            status="candidate",
            details={
                "pc_address_space": alignment.pc_address_space,
                "pc_address": alignment.pc_address,
                "xbox_address_space": alignment.xbox_address_space,
                "xbox_address": alignment.xbox_address,
                "pc_role_basis": alignment.pc_role_basis,
                "xbox_role_basis": alignment.xbox_role_basis,
                "pc_qualifier": alignment.pc_qualifier,
                "xbox_qualifier": alignment.xbox_qualifier,
                "pc_observed_slot_count": alignment.pc_observed_slot_count,
                "xbox_observed_slot_count": alignment.xbox_observed_slot_count,
                "shared_prefix_slot_count": alignment.shared_prefix_slot_count,
                "pc_unpaired_tail_count": alignment.pc_unpaired_tail_count,
                "xbox_unpaired_tail_count": alignment.xbox_unpaired_tail_count,
                "pc_extent": alignment.pc_extent.to_dict(),
                "xbox_extent": alignment.xbox_extent.to_dict(),
                "selection_policy": "exact_class_and_unique_structural_role",
                "no_cross_platform_identity_accepted": True,
            },
        )

    for issue in materialization.issues:
        db.upsert_vtable_alignment_issue(
            issue.issue_id,
            issue_kind=issue.issue_kind,
            class_name=issue.class_name,
            vfptr_role=issue.vfptr_role,
            subobject_offset=issue.subobject_offset,
            message=issue.message,
            provenance_id=provenance_id,
            details={
                "pc_vtable_ids": list(issue.pc_vtable_ids),
                "xbox_vtable_ids": list(issue.xbox_vtable_ids),
                "retained_for_audit": True,
            },
        )

    scalar_claim_ids: set[str] = set()
    fold_group_ids: set[str] = set()
    for item in materialization.hypothesis_sets:
        pc_function_id = pc_target_id = None
        if item.pc_subject.endpoint_kind == "exact_function":
            pc_function_id = item.pc_subject.function_id
        else:
            pc_target_id = _vtable_unresolved_target(
                db,
                platform="pc",
                address_space=item.pc_subject.address_space,
                address=item.pc_subject.address,
                provenance_id=provenance_id,
            )

        hypothesis_set_id = db.upsert_match_hypothesis_set(
            hypothesis_set_id=item.hypothesis_set_id,
            identity_key=item.hypothesis_set_id,
            pc_function_id=pc_function_id,
            pc_target_id=pc_target_id,
            status="candidate",
            provenance_id=provenance_id,
            rationale=(
                "Equal numeric slot index inside an exact-class, unique-role "
                "table pair; retained as an unscored hypothesis only"
            ),
            details={
                "producer": "fnv_atlas.vtable_hypotheses",
                "alignment_id": item.alignment_id,
                "class_name": item.class_name,
                "vfptr_role": item.vfptr_role,
                "subobject_offset": item.subobject_offset,
                "slot_index": item.slot_index,
                "semantic_pair_id": item.semantic_pair_id,
                "scoring_status": item.scoring_status,
                "names_transferred": False,
            },
        )

        alternative = item.xbox_alternative
        if alternative.endpoint_kind == "fold_group":
            fold_group_id = alternative.fold_group_id
            assert fold_group_id is not None
            fold_group_ids.add(fold_group_id)
            db.add_match_hypothesis_alternative(
                hypothesis_set_id,
                alternative_id=item.alternative_id,
                xbox_fold_group_id=fold_group_id,
                details={
                    "endpoint_kind": "fold_group",
                    "address_space": alternative.address_space,
                    "address": alternative.address,
                    "member_count": alternative.fold_member_count,
                    "bundle_not_member_selection": True,
                },
            )
        else:
            xbox_function_id = xbox_target_id = None
            if alternative.endpoint_kind == "exact_function":
                xbox_function_id = alternative.function_id
            else:
                xbox_target_id = _vtable_unresolved_target(
                    db,
                    platform="xbox360",
                    address_space=alternative.address_space,
                    address=alternative.address,
                    provenance_id=provenance_id,
                )
            claim_id = db.upsert_match_claim(
                pc_function_id=pc_function_id,
                pc_target_id=pc_target_id,
                xbox_function_id=xbox_function_id,
                xbox_target_id=xbox_target_id,
                provenance_id=provenance_id,
                status="candidate",
                rationale=(
                    "Scalar endpoint pair participating in one or more "
                    "unscored vtable slot hypotheses"
                ),
                details={
                    "producer": "fnv_atlas.vtable_hypotheses",
                    "semantic_pair_id": item.semantic_pair_id,
                    "endpoint_kind": alternative.endpoint_kind,
                    "names_transferred": False,
                },
            )
            scalar_claim_ids.add(claim_id)
            db.add_match_hypothesis_alternative(
                hypothesis_set_id,
                alternative_id=item.alternative_id,
                claim_id=claim_id,
                details={
                    "endpoint_kind": alternative.endpoint_kind,
                    "address_space": alternative.address_space,
                    "address": alternative.address,
                    "semantic_claim_reused_across_occurrences": True,
                },
            )

        db.add_match_hypothesis_evidence(
            hypothesis_set_id,
            evidence_id=stable_id(
                "vtable-slot-hypothesis-evidence", hypothesis_set_id
            ),
            effect=item.evidence_effect,
            evidence_kind="equal_vtable_slot_index",
            independence_group="class_slot_alignment",
            provenance_id=provenance_id,
            details={
                "reason": item.evidence_reason,
                "diagnostics": list(item.evidence_diagnostics),
                "alignment_id": item.alignment_id,
                "pc_vtable_id": item.pc_vtable_id,
                "xbox_vtable_id": item.xbox_vtable_id,
                "slot_index": item.slot_index,
                "pc_slot_id": item.pc_slot_id,
                "xbox_slot_id": item.xbox_slot_id,
                "pc_target": item.pc_subject.to_dict(),
                "xbox_target": item.xbox_alternative.to_dict(),
                "pc_source_target_address_space": (
                    item.pc_slot_target_address_space
                ),
                "xbox_source_target_address_space": (
                    item.xbox_slot_target_address_space
                ),
                "pc_raw_target_address": item.pc_raw_target_address,
                "xbox_raw_target_address": item.xbox_raw_target_address,
                "xbox_name_observations_context_only": [
                    observation.to_dict()
                    for observation in item.xbox_name_observations
                ],
                "does_not_transfer_names": True,
            },
        )
        db.upsert_vtable_slot_alignment(
            slot_alignment_id=stable_id(
                "vtable-slot-alignment", hypothesis_set_id
            ),
            alignment_id=item.alignment_id,
            pc_slot_index=item.slot_index,
            xbox_slot_index=item.slot_index,
            hypothesis_set_id=hypothesis_set_id,
            provenance_id=provenance_id,
            status="candidate",
            details={
                "pc_slot_id": item.pc_slot_id,
                "xbox_slot_id": item.xbox_slot_id,
                "occurrence_specific": True,
                "endpoint_pair_may_repeat": True,
            },
        )

    reasons = materialization.evidence_reason_counts
    clean = reasons.get("equal_index_in_conservatively_paired_table", 0)
    safe = (
        reasons.get("equal_index_within_declared_hole_free_tpi_extent", 0)
        + reasons.get("equal_index_in_shorter_observed_pointer_run", 0)
    )
    overflow = reasons.get(
        "slot_at_or_beyond_declared_hole_free_tpi_extent", 0
    )
    return _VtableHypothesisInsertCounts(
        table_alignments=materialization.table_alignment_count,
        slot_alignments=materialization.hypothesis_set_count,
        issues=materialization.issue_count,
        hypothesis_sets=materialization.hypothesis_set_count,
        alternatives=materialization.alternative_count,
        scalar_claims=len(scalar_claim_ids),
        pc_resolved_subjects=materialization.pc_exact_count,
        pc_unresolved_subjects=materialization.pc_unresolved_count,
        xbox_exact_alternatives=materialization.xbox_exact_count,
        xbox_fold_bundle_alternatives=materialization.xbox_fold_group_count,
        xbox_unresolved_alternatives=materialization.xbox_unresolved_count,
        distinct_fold_groups_used=len(fold_group_ids),
        supporting_evidence=materialization.supporting_evidence_count,
        context_evidence=materialization.context_evidence_count,
        clean_supporting_evidence=clean,
        suspect_safe_prefix_evidence=safe,
        overflow_context_evidence=overflow,
    )


def _insert_pc_inventory(
    db: AtlasDatabase,
    inventory: PCInventory,
    *,
    provenance_id: str,
) -> tuple[int, int, int]:
    function_ids = {function.address: function.function_id for function in inventory.functions}
    unresolved_target_ids: dict[tuple[str, int, str], str] = {}
    resolved_edges = unresolved_edges = 0

    for function in inventory.functions:
        address_group_id = db.upsert_address_group(
            program_id=PC_PROGRAM_ID,
            address_space=function.address_space,
            address=function.address,
            kind="code",
            details={"ghidra_entry": True},
        )
        db.upsert_function(
            address_group_id=address_group_id,
            identity_key="ghidra-function-entry",
            function_id=function.function_id,
            kind="thunk" if function.thunk else "function",
            provenance_id=provenance_id,
            details={
                "size": function.size,
                "in_executable_range": function.in_executable_range,
            },
        )
        if function.name:
            db.add_function_name(
                function.function_id,
                function.name,
                name_kind="ghidra_current_label",
                is_primary=False,
                provenance_id=provenance_id,
                details={"not_semantic_truth": True},
            )

    for function in inventory.functions:
        for callee in function.callees:
            callee_function_id = function_ids.get(callee.address)
            if callee_function_id is not None:
                db.upsert_call_edge(
                    caller_function_id=function.function_id,
                    callee_function_id=callee_function_id,
                    provenance_id=provenance_id,
                    edge_kind="ghidra_call",
                )
                resolved_edges += 1
                continue

            # The legacy Ghidra exporter discarded address-space identity.
            # Never reinterpret an out-of-image numeric offset as a RAM VA.
            address_space = (
                "ram"
                if callee.classification == "executable_non_entry"
                else "ghidra-offset-unknown"
            )
            key = (address_space, callee.address, callee.classification)
            target_id = unresolved_target_ids.get(key)
            if target_id is None:
                address_group_id = db.upsert_address_group(
                    program_id=PC_PROGRAM_ID,
                    address_space=address_space,
                    address=callee.address,
                    kind="unresolved-reference",
                    details={"classification": callee.classification},
                )
                target_id = db.upsert_unresolved_target(
                    program_id=PC_PROGRAM_ID,
                    address_group_id=address_group_id,
                    target_kind=callee.classification,
                    reason="callee is not a canonical Ghidra function entry",
                    provenance_id=provenance_id,
                )
                unresolved_target_ids[key] = target_id
            db.upsert_call_edge(
                caller_function_id=function.function_id,
                unresolved_target_id=target_id,
                provenance_id=provenance_id,
                edge_kind="ghidra_call",
                details={"classification": callee.classification},
            )
            unresolved_edges += 1

    return resolved_edges, unresolved_edges, len(unresolved_target_ids)


def _insert_xbox_procedures(
    db: AtlasDatabase,
    extraction: ProcedureExtraction,
    *,
    provenance_id: str,
) -> tuple[dict[str, tuple[str, ...]], dict[tuple[int, str], tuple[str, ...]]]:
    module_ids: dict[tuple[int, str], str] = {}
    by_name: dict[str, list[str]] = defaultdict(list)
    by_va_name: dict[tuple[int, str], list[str]] = defaultdict(list)

    for record in extraction.records:
        module_key = (record.module_index, record.module_name)
        module_id = module_ids.get(module_key)
        if module_id is None:
            module_id = stable_id(
                "module", XBOX_PROGRAM_ID, record.module_index, record.module_name
            )
            db.upsert_module(
                module_id,
                program_id=XBOX_PROGRAM_ID,
                name=record.module_name or f"module-{record.module_index}",
                compiland_index=record.module_index,
                details={"symbol_stream": record.symbol_stream},
            )
            module_ids[module_key] = module_id

        if record.va is None:
            db.upsert_unresolved_target(
                target_id=stable_id("pdb-record-target", record.record_id),
                program_id=XBOX_PROGRAM_ID,
                target_kind="pdb-procedure-without-va",
                name_hint=record.raw_name,
                reason="procedure referenced an unavailable PE section",
                provenance_id=provenance_id,
                details=record.to_dict(),
            )
            continue

        address_group_id = db.upsert_address_group(
            program_id=XBOX_PROGRAM_ID,
            address_space="xbox-va",
            address=record.va,
            kind="code",
        )
        db.upsert_function(
            address_group_id=address_group_id,
            identity_key=record.record_id,
            function_id=record.record_id,
            kind="function",
            type_index=record.type_index,
            module_id=module_id,
            symbol_record_kind=record.record_kind,
            provenance_id=provenance_id,
            details={
                "size": record.size,
                "section": record.section,
                "section_offset": record.section_offset,
                "symbol_stream": record.symbol_stream,
                "record_offset": record.record_offset,
                "record_length": record.record_length,
                "record_kind_code": record.record_kind_code,
                "flags": record.flags,
                "parent_offset": record.parent_offset,
                "end_offset": record.end_offset,
                "next_offset": record.next_offset,
                "debug_start": record.debug_start,
                "debug_end": record.debug_end,
            },
        )
        db.add_function_name(
            record.record_id,
            record.raw_name,
            name_kind="pdb_procedure_name",
            is_primary=True,
            provenance_id=provenance_id,
        )
        by_name[record.raw_name].append(record.record_id)
        by_va_name[(record.va, record.raw_name)].append(record.record_id)

    for group in extraction.alias_groups:
        db.upsert_fold_group(
            group.group_id,
            program_id=XBOX_PROGRAM_ID,
            kind="shared_procedure_va",
            provenance_id=provenance_id,
            details={"address": group.va, "record_count": group.count},
        )
        for record_id in group.record_ids:
            db.add_fold_member(group.group_id, record_id)

    return (
        {name: tuple(ids) for name, ids in by_name.items()},
        {key: tuple(ids) for key, ids in by_va_name.items()},
    )


@dataclass(frozen=True, slots=True)
class _SignatureInsertCounts:
    rows: int
    resolved: int
    unresolved: int
    arguments: int
    member_functions: int
    procedures: int
    variadic: int
    unique_resolved_types: int
    rows_without_function: int


def _insert_xbox_signatures(
    db: AtlasDatabase,
    procedures: ProcedureExtraction,
    resolution: SignatureResolution,
    *,
    provenance_id: str,
) -> _SignatureInsertCounts:
    """Attach one exact or unresolved TPI result to each procedure record.

    The join is positional only because ``resolve_many`` preserves the exact
    procedure-record input order and multiplicity.  The stable PDB record ID,
    not a function name or VA, selects the database function.
    """

    if len(procedures.records) != len(resolution.results):
        raise ValueError(
            "procedure/signature occurrence counts disagree: "
            f"{len(procedures.records)} != {len(resolution.results)}"
        )

    rows = resolved = unresolved = arguments = 0
    member_functions = ordinary_procedures = variadic = rows_without_function = 0
    resolved_types: set[int] = set()
    for record, result in zip(procedures.records, resolution.results, strict=True):
        if record.type_index != result.type_index:
            raise ValueError(
                f"signature type 0x{result.type_index:X} does not match "
                f"procedure {record.record_id} type 0x{record.type_index:X}"
            )
        if record.va is None:
            # The procedure extractor retains these as unresolved targets, so
            # there is deliberately no logical function row to attach to.
            rows_without_function += 1
            continue
        db.upsert_signature_result(
            record.record_id,
            result,
            provenance_id=provenance_id,
            details={
                "module_index": record.module_index,
                "module_name": record.module_name,
                "symbol_stream": record.symbol_stream,
                "record_offset": record.record_offset,
                "tpi_stream": 2,
            },
        )
        rows += 1
        signature = result.signature
        if signature is None:
            unresolved += 1
            continue
        resolved += 1
        resolved_types.add(signature.type_index)
        arguments += signature.argument_list_count
        variadic += int(signature.is_variadic)
        member_functions += int(signature.leaf_kind == LF_MFUNCTION)
        ordinary_procedures += int(signature.leaf_kind == LF_PROCEDURE)

    return _SignatureInsertCounts(
        rows=rows,
        resolved=resolved,
        unresolved=unresolved,
        arguments=arguments,
        member_functions=member_functions,
        procedures=ordinary_procedures,
        variadic=variadic,
        unique_resolved_types=len(resolved_types),
        rows_without_function=rows_without_function,
    )


def _insert_xbox_sources(
    db: AtlasDatabase,
    source_path: Path,
    by_va_name: Mapping[tuple[int, str], tuple[str, ...]],
    *,
    provenance_id: str,
) -> int:
    rows = _load_json_object(source_path)
    source_ids: dict[str, str] = {}
    links = 0
    for raw_address, raw_record in sorted(rows.items(), key=lambda item: int(item[0], 16)):
        if not isinstance(raw_record, Mapping):
            continue
        raw_file = raw_record.get("file")
        raw_line = raw_record.get("line")
        name = str(raw_record.get("name") or "")
        if not raw_file or raw_line is None or not name:
            continue
        function_ids = by_va_name.get((int(raw_address, 16), name), ())
        if not function_ids:
            continue
        normalized = _normalized_source_path(str(raw_file))
        source_file_id = source_ids.get(normalized)
        if source_file_id is None:
            source_file_id = stable_id("source-file", XBOX_PROGRAM_ID, normalized)
            db.upsert_source_file(
                source_file_id,
                program_id=XBOX_PROGRAM_ID,
                normalized_path=normalized,
                language="c++",
                details={"raw_path": str(raw_file)},
            )
            source_ids[normalized] = source_file_id
        line = max(0, int(raw_line))
        for function_id in function_ids:
            db.add_function_source_range(
                function_id,
                source_file_id,
                line_start=line,
                line_end=line,
                is_primary=True,
                provenance_id=provenance_id,
                details={"legacy_size": raw_record.get("size")},
            )
            links += 1
    return links


def _legacy_pc_endpoint(
    db: AtlasDatabase,
    claim: LegacyClaim,
    executable_ranges: tuple[tuple[int, int], ...],
    provenance_id: str,
) -> tuple[str | None, str | None]:
    if claim.pc_function_id is not None:
        return claim.pc_function_id, None
    in_executable = any(start <= claim.pc_address < end for start, end in executable_ranges)
    address_space = "ram" if in_executable else "legacy-offset-unknown"
    address_group_id = db.upsert_address_group(
        program_id=PC_PROGRAM_ID,
        address_space=address_space,
        address=claim.pc_address,
        kind="unresolved-reference",
        details={"legacy_claim": True, "in_executable_range": in_executable},
    )
    target_id = db.upsert_unresolved_target(
        program_id=PC_PROGRAM_ID,
        address_group_id=address_group_id,
        target_kind="legacy_non_entry_name_claim",
        name_hint=claim.proposed_name,
        reason="legacy name target is not a canonical PC function entry",
        provenance_id=provenance_id,
    )
    return None, target_id


def _insert_legacy_claims(
    db: AtlasDatabase,
    claims: tuple[LegacyClaim, ...],
    xbox_by_name: Mapping[str, tuple[str, ...]],
    executable_ranges: tuple[tuple[int, int], ...],
    *,
    provenance_id: str,
) -> tuple[int, int, int, int, int]:
    unique_matches = ambiguous_claims = unmatched_claims = database_claims = 0
    xbox_name_targets: dict[str, str] = {}

    for legacy_claim in claims:
        pc_function_id, pc_target_id = _legacy_pc_endpoint(
            db, legacy_claim, executable_ranges, provenance_id
        )
        hypothesis_set_id = db.upsert_match_hypothesis_set(
            hypothesis_set_id=stable_id(
                "legacy-hypothesis-set", legacy_claim.claim_id
            ),
            identity_key=legacy_claim.claim_id,
            pc_function_id=pc_function_id,
            pc_target_id=pc_target_id,
            provenance_id=provenance_id,
            status="candidate",
            rationale=(
                "One occurrence-specific legacy name proposal with all exact "
                "PDB-name alternatives retained"
            ),
            details={
                "legacy_claim_id": legacy_claim.claim_id,
                "proposed_name": legacy_claim.proposed_name,
                "legacy_tier": legacy_claim.legacy_tier,
                "resolution": legacy_claim.resolution,
                "confidence_imported": False,
            },
        )
        xbox_ids = xbox_by_name.get(legacy_claim.proposed_name, ())
        xbox_endpoints: list[tuple[str | None, str | None]] = []
        if len(xbox_ids) == 1:
            unique_matches += 1
            xbox_endpoints.append((xbox_ids[0], None))
        elif xbox_ids:
            ambiguous_claims += 1
            xbox_endpoints.extend((function_id, None) for function_id in xbox_ids)
        else:
            unmatched_claims += 1
            target_id = xbox_name_targets.get(legacy_claim.proposed_name)
            if target_id is None:
                target_id = db.upsert_unresolved_target(
                    program_id=XBOX_PROGRAM_ID,
                    target_kind="unresolved_symbol_name",
                    name_hint=legacy_claim.proposed_name,
                    reason="legacy name has no exact lossless PDB procedure-name match",
                    provenance_id=provenance_id,
                )
                xbox_name_targets[legacy_claim.proposed_name] = target_id
            xbox_endpoints.append((None, target_id))

        for xbox_function_id, xbox_target_id in xbox_endpoints:
            claim_id = stable_id(
                "legacy-match",
                legacy_claim.claim_id,
                xbox_function_id,
                xbox_target_id,
            )
            db.upsert_match_claim(
                claim_id=claim_id,
                pc_function_id=pc_function_id,
                pc_target_id=pc_target_id,
                xbox_function_id=xbox_function_id,
                xbox_target_id=xbox_target_id,
                provenance_id=provenance_id,
                status="candidate",
                details={
                    "proposed_name": legacy_claim.proposed_name,
                    "legacy_tier": legacy_claim.legacy_tier,
                    "xbox_name_candidate_count": len(xbox_ids),
                    "legacy_claim_id": legacy_claim.claim_id,
                },
                rationale="Imported from the v1 accumulator as an unverified candidate",
            )
            db.add_match_hypothesis_alternative(
                hypothesis_set_id,
                alternative_id=stable_id(
                    "legacy-hypothesis-alternative",
                    hypothesis_set_id,
                    claim_id,
                ),
                claim_id=claim_id,
                details={
                    "legacy_claim_id": legacy_claim.claim_id,
                    "proposed_name": legacy_claim.proposed_name,
                    "xbox_name_candidate_count": len(xbox_ids),
                    "unordered_alternative": True,
                },
            )
            database_claims += 1

        # Evidence describes the legacy proposal occurrence, not each possible
        # Xbox name resolution.  Store it once on the set so an ambiguous name
        # with N alternatives does not spuriously multiply its evidence N-fold.
        for ordinal, evidence in enumerate(legacy_claim.evidence):
            details = {
                "artifact": evidence.artifact,
                "legacy_kind": evidence.kind,
                "legacy_claim_id": legacy_claim.claim_id,
                "evidence_ordinal": ordinal,
                **dict(evidence.details),
            }
            db.add_match_hypothesis_evidence(
                hypothesis_set_id,
                evidence_id=stable_id(
                    "legacy-hypothesis-evidence",
                    legacy_claim.claim_id,
                    ordinal,
                    evidence.to_dict(),
                ),
                effect=evidence.effect,
                evidence_kind=evidence.channel,
                independence_group=evidence.independence_group,
                provenance_id=provenance_id,
                details=details,
            )

    return (
        unique_matches,
        ambiguous_claims,
        unmatched_claims,
        database_claims,
        len(xbox_name_targets),
    )


def _insert_legacy_context_observations(
    db: AtlasDatabase,
    contexts: tuple[LegacyContext, ...],
    executable_ranges: tuple[tuple[int, int], ...],
    *,
    provenance_id: str,
) -> int:
    unresolved_subjects: dict[tuple[str, int], str] = {}
    for context in contexts:
        function_id = context.pc_function_id
        unresolved_target_id = None
        if function_id is None:
            in_executable = any(
                start <= context.pc_address < end for start, end in executable_ranges
            )
            address_space = "ram" if in_executable else "legacy-offset-unknown"
            subject_key = (address_space, context.pc_address)
            unresolved_target_id = unresolved_subjects.get(subject_key)
            if unresolved_target_id is None:
                address_group_id = db.upsert_address_group(
                    program_id=PC_PROGRAM_ID,
                    address_space=address_space,
                    address=context.pc_address,
                    kind="unresolved-reference",
                    details={"legacy_context": True},
                )
                unresolved_target_id = db.upsert_unresolved_target(
                    program_id=PC_PROGRAM_ID,
                    address_group_id=address_group_id,
                    target_kind="legacy_context_address",
                    reason="legacy contextual observation is not a canonical PC function entry",
                    provenance_id=provenance_id,
                )
                unresolved_subjects[subject_key] = unresolved_target_id
        db.upsert_observation(
            function_id=function_id,
            unresolved_target_id=unresolved_target_id,
            observation_kind=context.channel,
            independence_group=(
                "public_reference_context"
                if context.channel == "public"
                else "source_file_context"
            ),
            effect="context",
            provenance_id=provenance_id,
            details={
                "artifact": context.artifact,
                "value": context.value,
                **dict(context.details),
            },
        )
    return len(contexts)


def build_atlas(config: BuildConfig) -> BuildReport:
    """Build one atomic atlas database from explicit, content-addressed inputs."""

    _require_inputs(config)
    output = config.output_database.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    reject_destination_aliases(
        output,
        config.protected_inputs(),
        destination_label="database output",
    )
    if output.exists() and not config.replace:
        raise FileExistsError(f"{output} already exists (pass replace=True to rebuild)")
    temporary = _new_atomic_temporary(output)

    try:
        with AtlasDatabase.create(temporary) as db:
            # Hash first, consume second, and rehash before finalization.  This
            # makes a file mutation during a build a hard failure instead of a
            # manifest silently describing bytes different from those parsed.
            manifest_id, registered_content_ids = _register_manifest(db, config)
            source_id = producer_source_id()
            common_provenance = {
                "schema_version": SCHEMA_VERSION,
                "producer_source_id": source_id,
            }
            pc_ranges = executable_ranges_from_pe(config.pc_executable)
            xbox_ranges = executable_ranges_from_pe(config.xbox_executable)
            inventory = load_ghidra_inventory(
                config.pc_functions,
                executable_ranges=pc_ranges,
            )
            procedures = extract_procedures(
                config.xbox_pdb,
                config.xbox_executable,
                config.xbox_modules,
            )
            xbox_control_flow = extract_ppc_control_flow(
                read_xbox_pe_image(config.xbox_executable),
                procedures.records,
            )
            xbox_control_flow_selected = select_control_flow(
                xbox_control_flow,
                policy="call_relevant_v1",
            )
            tpi_resolver = TpiTypeResolver.from_pdb(config.xbox_pdb)
            signature_resolution = tpi_resolver.resolve_many(
                record.type_index for record in procedures.records
            )
            tpi_layout_corpus = TpiLayoutCorpus(
                type_records=extract_type_records_from_resolver(tpi_resolver),
                layouts=extract_type_layouts_from_resolver(tpi_resolver),
            )
            data_symbols = extract_data_symbols(
                config.xbox_pdb,
                config.xbox_executable,
                config.xbox_modules,
            )
            raw_vftable_corpus = extract_vftable_corpus(
                config.xbox_pdb,
                config.xbox_executable,
            )
            sdk_extraction = None
            sdk_inventory_join = None
            if config.pc_sdk_root is not None:
                sdk_extraction = extract_sdk_prototypes(config.pc_sdk_root)
                sdk_inventory_join = join_sdk_to_pc_inventory(
                    sdk_extraction,
                    inventory,
                    read_pe_sections(config.pc_executable),
                )
            pc_vtable_dataset = load_pc_vtables(config.pc_classes)
            xbox_vtable_dataset = load_xbox_vtables(
                config.xbox_vtables,
                types_path=config.xbox_types,
            )
            vtable_alignment = propose_vtable_alignments(
                pc_vtable_dataset, xbox_vtable_dataset
            )
            vtable_hypotheses = materialize_vtable_hypotheses(
                vtable_alignment,
                inventory,
                procedures,
                pc_address_space_aliases={"va": "ram"},
                xbox_address_space_aliases={"va": "xbox-va"},
                xbox_procedure_address_space="xbox-va",
            )
            legacy = load_legacy_claims(
                names_tiered_path=config.legacy_names_tiered,
                names_final_path=config.legacy_names_final,
                namemap_path=config.legacy_namemap,
                strmatch_path=config.legacy_strmatch,
                pgm_path=config.legacy_pgm,
                matched_ghidra_path=config.legacy_matched_ghidra,
                agent_verdicts_path=config.legacy_agent_verdicts,
                all_seeds_path=config.legacy_all_seeds,
                assign_path=config.legacy_assign,
                vmatch_path=config.legacy_vmatch,
                fingerprint_path=config.legacy_fingerprint,
                calleealign_path=config.legacy_calleealign,
                calleealign_new_path=config.legacy_calleealign_new,
                wrappers_path=config.legacy_wrappers,
                pgm2_path=config.legacy_pgm2,
                pgm_new_path=config.legacy_pgm_new,
                constmatch_path=config.legacy_constmatch,
                known_pc_entries=inventory.entries,
            )
            pdb_provenance = db.upsert_provenance(
                kind="extraction",
                producer="fnv_atlas.pdb_symbols",
                producer_version=__version__,
                method="lossless CodeView S_GPROC32/S_LPROC32 module-stream extraction",
                manifest_id=manifest_id,
                parameters=common_provenance,
            )
            control_flow_provenance = db.upsert_provenance(
                kind="extraction",
                producer="fnv_atlas.ppc_control_flow",
                producer_version=__version__,
                method=(
                    "PowerPC-BE branch decoding with physical-site and stable "
                    "PDB-procedure membership identities"
                ),
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "persistence_policy": "call_relevant_v1",
                    "trigger_roles": sorted(CALL_RELEVANT_V1_ROLES),
                    "site_selection": "retain_site_if_any_membership_triggers",
                    "membership_policy": "retain_all_memberships_of_selected_site",
                    "scan_policy": "retain_every_procedure_scan",
                    "fold_policy": "one_complete_fold_group_no_member_fanout",
                    "non_entry_policy": "address_only_no_function_creation",
                    "name_resolution": "forbidden",
                },
                notes=(
                    "The canonical database stores the call-relevant subset; "
                    "the complete source counts and scan coverage remain explicit "
                    "and the full extraction is regenerable from manifested inputs."
                ),
            )
            control_flow_matching_provenance = db.upsert_provenance(
                kind="analysis",
                producer="fnv_atlas.control_flow_matching",
                producer_version=__version__,
                method=(
                    "candidate-only closed call squares and unique residual "
                    "cross-platform call-neighborhood proposals"
                ),
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "policy": "closed_square_unique_residual_v1",
                    "source_mapping_status": "candidate",
                    "eligible_xbox_roles": [
                        "direct_call",
                        "local_direct_call",
                    ],
                    "tail_and_indirect_policy": "exclude_with_diagnostics",
                    "fold_policy": "retain_bundle_and_block_scalar_member_choice",
                    "recursive_proposal_seeding": "forbidden",
                    "confidence": "none",
                    "acceptance": "forbidden",
                    "name_transfer": "forbidden",
                },
                notes=(
                    "Derived evidence remains explicitly conditional on its "
                    "candidate mapping anchors and is not an independent confirmation."
                ),
            )
            signature_provenance = db.upsert_provenance(
                kind="extraction",
                producer="fnv_atlas.tpi_signatures",
                producer_version=__version__,
                method=(
                    "exact CodeView LF_PROCEDURE/LF_MFUNCTION and LF_ARGLIST "
                    "resolution from PDB TPI stream 2"
                ),
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "unresolved_policy": "retain_explicit_error",
                    "join_identity": "stable_pdb_procedure_record_id",
                },
            )
            tpi_layout_provenance = db.upsert_provenance(
                kind="extraction",
                producer="fnv_atlas.tpi_layouts",
                producer_version=__version__,
                method=(
                    "lossless global-TPI raw-record and identity-safe decoded "
                    "tag/field/method extraction"
                ),
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "type_namespace": "global-tpi",
                    "identity": "program_namespace_type_index",
                    "duplicate_name_policy": "retain_every_type_record",
                    "raw_body_policy": "retain_exact_body_blob_and_sha256",
                    "unresolved_type_reference_policy": "retain_raw_index",
                },
                notes=(
                    "Primitive, local, and unavailable type references remain "
                    "explicit numeric indices; no display-name winner is selected."
                ),
            )
            data_symbol_provenance = db.upsert_provenance(
                kind="extraction",
                producer="fnv_atlas.pdb_globals",
                producer_version=__version__,
                method=(
                    "lossless CodeView S_GDATA32/S_LDATA32 module-stream extraction"
                ),
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "identity": "module_index_symbol_stream_record_offset",
                    "address_space": "xbox-va",
                    "same_address_policy": "retain_every_physical_record",
                    "invalid_section_policy": "retain_unresolved_record",
                    "function_creation": "forbidden",
                },
            )
            raw_vftable_provenance = db.upsert_provenance(
                kind="extraction",
                producer="fnv_atlas.pdb_vftables",
                producer_version=__version__,
                method=(
                    "lossless DBI symbol-record vftable extraction plus "
                    "non-declarative executable pointer-run observations"
                ),
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "identity": "symbol_record_stream_record_offset",
                    "same_address_policy": "retain_every_physical_record",
                    "address_member_order_is_preference": False,
                    "pointer_run_semantics": (
                        "observed_pointer_prefix_not_declared_extent"
                    ),
                    "scan_max_slots": 4096,
                    "function_creation": "forbidden",
                    "name_promotion": "forbidden",
                },
            )
            sdk_provenance = None
            if sdk_extraction is not None:
                sdk_provenance = db.upsert_provenance(
                    kind="extraction",
                    producer="fnv_atlas.sdk_prototypes",
                    producer_version=__version__,
                    method=(
                        "portable source-hashed SDK observations with "
                        "variant-safe PC inventory classification"
                    ),
                    manifest_id=manifest_id,
                    parameters={
                        **common_provenance,
                        "source_tree_sha256": sdk_extraction.source_tree_sha256,
                        "absolute_source_root_stored": False,
                        "pc_address_space": "ram",
                        "game_exact_entry_policy": "definitive_observation_link",
                        "unspecified_exact_entry_policy": "candidate_only",
                        "geck_pc_link_policy": "forbidden",
                        "function_creation": "forbidden",
                        "name_promotion": "forbidden",
                    },
                    notes=(
                        "Raw SDK source is not stored in the atlas or release "
                        "preview; portable observations retain per-file hashes."
                    ),
                )
            pc_provenance = db.upsert_provenance(
                kind="import",
                producer="fnv_atlas.pc_inventory",
                producer_version=__version__,
                method="canonical Ghidra function-key inventory",
                manifest_id=manifest_id,
                parameters=common_provenance,
            )
            source_provenance = db.upsert_provenance(
                kind="import",
                producer="fnv_atlas.build",
                producer_version=__version__,
                method="exact Xbox VA plus procedure-name source join",
                manifest_id=manifest_id,
                parameters=common_provenance,
            )
            pc_vtable_provenance = db.upsert_provenance(
                kind="import",
                producer="fnv_atlas.vtables",
                producer_version=__version__,
                method="lossless PC RTTI/COL vtable normalization",
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "role_source": "pc_complete_object_locator_offset",
                    "slot_targets": "address_groups_only",
                },
            )
            xbox_vtable_provenance = db.upsert_provenance(
                kind="import",
                producer="fnv_atlas.vtables",
                producer_version=__version__,
                method="lossless Xbox decorated-vftable/TPI normalization",
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "role_source": "xbox_vftable_qualifier_and_tpi_base_offset",
                    "extent_reference": "hole_free_xbox_tpi_primary_slot_map",
                    "address_derived_names": "ambiguous_observations_only",
                    "slot_targets": "address_groups_only",
                },
            )
            vtable_alignment_provenance = db.upsert_provenance(
                kind="analysis",
                producer="fnv_atlas.vtable_hypotheses",
                producer_version=__version__,
                method=(
                    "exact-class unique-role table pairing and equal-index "
                    "slot hypothesis materialization"
                ),
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "status": "candidate",
                    "scoring": "unscored",
                    "table_pairing": "exact_class_unique_structural_role",
                    "slot_pairing": "equal_index_shared_prefix",
                    "fold_policy": "one_alias_group_bundle_no_member_fanout",
                    "name_transfer": "forbidden",
                    "extent_overflow_effect": "context",
                    "pc_address_space_alias": {"va": "ram"},
                    "xbox_address_space_alias": {"va": "xbox-va"},
                },
                notes=(
                    "Structural candidates are auditable hypotheses, never "
                    "accepted source-name mappings."
                ),
            )
            legacy_provenance = db.upsert_provenance(
                kind="legacy_import",
                producer="fnv_atlas.legacy",
                producer_version=__version__,
                method="v1 names imported as candidate claims and contextual evidence",
                manifest_id=manifest_id,
                parameters={
                    **common_provenance,
                    "raw_candidate_inputs": [
                        "strmatch",
                        "pgm",
                        "matched_ghidra",
                        "agent_verdicts",
                        "all_seeds",
                        "assign",
                        "vmatch",
                    ],
                    "experimental_candidate_inputs": [
                        "fp3",
                        "calleealign",
                        "calleealign_new",
                        "wrappers",
                        "pgm2",
                        "pgm_new",
                        "constmatch",
                    ],
                    "agent_reject_effect": "contradicts",
                    "graph_depth_zero_effect": "context_seed",
                    "assign_effect": "context_composite_lineage",
                },
                notes="Legacy tiers are retained as metadata, never promoted to confidence.",
            )

            with db.batch():
                db.upsert_program(
                    PC_PROGRAM_ID,
                    platform="pc",
                    name="Fallout: New Vegas PC",
                    architecture="x86",
                    image_base=inventory.image_base,
                    details={"executable_ranges": [list(pair) for pair in pc_ranges]},
                )
                db.upsert_program(
                    XBOX_PROGRAM_ID,
                    platform="xbox360",
                    name="Fallout Release MemDebug Xbox 360",
                    architecture="powerpc-be",
                    image_base=_image_base_from_ranges(xbox_ranges),
                    details={"executable_ranges": [list(pair) for pair in xbox_ranges]},
                )
                resolved_edges, unresolved_edges, unresolved_call_targets = _insert_pc_inventory(
                    db, inventory, provenance_id=pc_provenance
                )
                xbox_by_name, xbox_by_va_name = _insert_xbox_procedures(
                    db, procedures, provenance_id=pdb_provenance
                )
                control_flow_counts = db.persist_control_flow_extraction(
                    xbox_control_flow,
                    program_id=XBOX_PROGRAM_ID,
                    provenance_id=control_flow_provenance,
                    policy="call_relevant_v1",
                    details={
                        "source_artifacts": [
                            "xbox_pdb",
                            "xbox_executable",
                            "xbox_modules",
                        ],
                        "address_space": "xbox-va",
                    },
                )
                signature_counts = _insert_xbox_signatures(
                    db,
                    procedures,
                    signature_resolution,
                    provenance_id=signature_provenance,
                )
                tpi_layout_counts = db.persist_tpi_layout_corpus(
                    tpi_layout_corpus,
                    program_id=XBOX_PROGRAM_ID,
                    provenance_id=tpi_layout_provenance,
                    details={
                        "source_artifact": "xbox_pdb",
                        "type_stream": 2,
                    },
                )
                data_symbol_counts = db.persist_data_symbol_extraction(
                    data_symbols,
                    program_id=XBOX_PROGRAM_ID,
                    provenance_id=data_symbol_provenance,
                    address_space="xbox-va",
                    details={
                        "source_artifacts": [
                            "xbox_pdb",
                            "xbox_executable",
                            "xbox_modules",
                        ],
                    },
                )
                raw_vftable_counts = db.persist_vftable_corpus(
                    stable_id(
                        "xbox-vftable-extraction",
                        XBOX_PROGRAM_ID,
                        raw_vftable_provenance,
                    ),
                    raw_vftable_corpus,
                    program_id=XBOX_PROGRAM_ID,
                    provenance_id=raw_vftable_provenance,
                    scan_max_slots=4096,
                    details={
                        "source_artifacts": ["xbox_pdb", "xbox_executable"],
                        "address_space": "xbox-va",
                    },
                )
                sdk_counts = None
                if (
                    sdk_extraction is not None
                    and sdk_inventory_join is not None
                    and sdk_provenance is not None
                ):
                    sdk_counts = db.persist_sdk_extraction(
                        stable_id(
                            "sdk-extraction",
                            PC_PROGRAM_ID,
                            sdk_extraction.source_tree_sha256,
                            sdk_provenance,
                        ),
                        sdk_extraction,
                        sdk_inventory_join,
                        pc_program_id=PC_PROGRAM_ID,
                        provenance_id=sdk_provenance,
                        pc_address_space="ram",
                        details={
                            "source_artifact": "pc_sdk_source_tree",
                            "pc_inventory_artifacts": [
                                "pc_function_export",
                                "pc_executable",
                            ],
                            "absolute_source_root_stored": False,
                        },
                    )
                source_links = _insert_xbox_sources(
                    db,
                    config.xbox_function_sources,
                    xbox_by_va_name,
                    provenance_id=source_provenance,
                )
                pc_vtable_counts = _insert_vtable_dataset(
                    db,
                    pc_vtable_dataset,
                    program_id=PC_PROGRAM_ID,
                    provenance_id=pc_vtable_provenance,
                    source_artifact="pc_classes.json",
                )
                xbox_vtable_counts = _insert_vtable_dataset(
                    db,
                    xbox_vtable_dataset,
                    program_id=XBOX_PROGRAM_ID,
                    provenance_id=xbox_vtable_provenance,
                    source_artifact="vtables_360.json + types_360.json",
                )
                vtable_hypothesis_counts = _insert_vtable_hypotheses(
                    db,
                    vtable_hypotheses,
                    provenance_id=vtable_alignment_provenance,
                )
                context_observations = _insert_legacy_context_observations(
                    db,
                    legacy.context,
                    pc_ranges,
                    provenance_id=legacy_provenance,
                )
                (
                    unique_matches,
                    ambiguous_claims,
                    unmatched_claims,
                    database_claims,
                    _unmatched_name_targets,
                ) = _insert_legacy_claims(
                    db,
                    legacy.claims,
                    xbox_by_name,
                    pc_ranges,
                    provenance_id=legacy_provenance,
                )
                control_flow_matching = (
                    analyze_control_flow_candidates_from_sqlite(
                        db.connection
                    )
                )
                control_flow_matching_counts = (
                    persist_control_flow_matching_result(
                        db,
                        control_flow_matching,
                        provenance_id=control_flow_matching_provenance,
                    )
                )
                matching_parity = {
                    "mapping_bundles": (
                        control_flow_matching_counts.mapping_bundles_observed,
                        len(control_flow_matching.mapping_bundles),
                    ),
                    "closed_relations": (
                        control_flow_matching_counts.closed_relations,
                        len(control_flow_matching.candidate_relations),
                    ),
                    "closed_relation_sets": (
                        control_flow_matching_counts.closed_relation_sets,
                        len(control_flow_matching.candidate_relations),
                    ),
                    "proposal_sets": (
                        control_flow_matching_counts.proposal_sets,
                        len(control_flow_matching.proposal_sets),
                    ),
                    "proposal_alternatives": (
                        control_flow_matching_counts.proposal_alternatives,
                        len(control_flow_matching.proposals),
                    ),
                    "alternative_evidence": (
                        control_flow_matching_counts.supporting_evidence,
                        len(control_flow_matching.evidence),
                    ),
                }
                mismatched_matching_counts = {
                    name: {"persisted": persisted, "source": source}
                    for name, (persisted, source) in matching_parity.items()
                    if persisted != source
                }
                if mismatched_matching_counts:
                    raise RuntimeError(
                        "control-flow matcher persistence lost source rows: "
                        + json.dumps(
                            mismatched_matching_counts, sort_keys=True
                        )
                    )

            claim_effect_counts = {
                str(row[0]): int(row[1])
                for row in db.connection.execute(
                    """
                    SELECT effect, COUNT(*) FROM claim_evidence
                    GROUP BY effect
                    """
                )
            }
            claim_evidence_rows = sum(claim_effect_counts.values())
            hypothesis_effect_counts = {
                str(row[0]): int(row[1])
                for row in db.connection.execute(
                    """
                    SELECT effect, COUNT(*) FROM match_hypothesis_evidence
                    GROUP BY effect
                    """
                )
            }
            hypothesis_evidence_rows = sum(
                hypothesis_effect_counts.values()
            )
            alternative_effect_counts = {
                str(row[0]): int(row[1])
                for row in db.connection.execute(
                    """
                    SELECT effect, COUNT(*)
                    FROM match_hypothesis_alternative_evidence
                    GROUP BY effect
                    """
                )
            }
            alternative_evidence_rows = sum(
                alternative_effect_counts.values()
            )
            hypothesis_set_rows = int(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_sets"
                ).fetchone()[0]
            )
            hypothesis_alternative_rows = int(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_alternatives"
                ).fetchone()[0]
            )
            function_assertion_rows = int(
                db.connection.execute(
                    "SELECT COUNT(*) FROM function_assertions"
                ).fetchone()[0]
            )

            db.connection.execute("ANALYZE")
            db.connection.execute("PRAGMA optimize")
            integrity = str(db.connection.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_keys = len(db.connection.execute("PRAGMA foreign_key_check").fetchall())
            semantic_violations = semantic_validation_counts(db.connection)
            if (
                integrity != "ok"
                or foreign_keys
                or not semantic_validation_ok(semantic_violations)
            ):
                raise RuntimeError(
                    f"atlas validation failed: integrity={integrity!r}, "
                    f"foreign_key_violations={foreign_keys}, "
                    f"semantic_violations={semantic_violations}"
                )
            _verify_input_files_unchanged(config, registered_content_ids)
            if producer_source_id() != source_id:
                raise RuntimeError(
                    "fnv_atlas producer source changed during build; refusing "
                    "to publish mixed-algorithm output"
                )

        _publish_atomic_file(temporary, output, replace=config.replace)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise

    return BuildReport(
        database=str(output),
        database_sha256=_content_id_for_path(output).removeprefix("sha256:"),
        manifest_id=manifest_id,
        producer_version=__version__,
        schema_version=SCHEMA_VERSION,
        producer_source_id=source_id,
        pc_functions=len(inventory.functions),
        function_assertions=function_assertion_rows,
        pc_resolved_call_edges=resolved_edges,
        pc_unresolved_call_edges=unresolved_edges,
        pc_unresolved_call_targets=unresolved_call_targets,
        xbox_procedure_records=procedures.record_count,
        xbox_unique_addresses=procedures.unique_va_count,
        xbox_fold_groups=len(procedures.alias_groups),
        xbox_source_links=source_links,
        xbox_signature_rows=signature_counts.rows,
        xbox_signatures_resolved=signature_counts.resolved,
        xbox_signatures_unresolved=signature_counts.unresolved,
        xbox_signature_arguments=signature_counts.arguments,
        xbox_member_function_signatures=signature_counts.member_functions,
        xbox_procedure_signatures=signature_counts.procedures,
        xbox_variadic_signatures=signature_counts.variadic,
        xbox_unique_resolved_signature_types=(
            signature_counts.unique_resolved_types
        ),
        xbox_signature_rows_without_function=(
            signature_counts.rows_without_function
        ),
        xbox_tpi_raw_type_records=tpi_layout_counts.raw_type_records,
        xbox_tpi_raw_body_bytes=tpi_layout_counts.raw_body_bytes,
        xbox_tpi_tag_records=tpi_layout_counts.tag_records,
        xbox_tpi_definitions=tpi_layout_counts.definitions,
        xbox_tpi_forward_references=tpi_layout_counts.forward_references,
        xbox_tpi_tag_member_occurrences=(
            tpi_layout_counts.tag_member_occurrences
        ),
        xbox_tpi_physical_field_members=(
            tpi_layout_counts.physical_field_members
        ),
        xbox_tpi_physical_method_overloads=(
            tpi_layout_counts.physical_method_overloads
        ),
        xbox_tpi_diagnostics=tpi_layout_counts.diagnostics,
        xbox_data_symbol_records=data_symbol_counts.records,
        xbox_data_symbol_resolved_records=data_symbol_counts.resolved_records,
        xbox_data_symbol_unresolved_records=(
            data_symbol_counts.unresolved_records
        ),
        xbox_data_symbol_unique_addresses=data_symbol_counts.unique_addresses,
        xbox_raw_vftable_physical_records=(
            raw_vftable_counts.physical_records
        ),
        xbox_raw_vftable_resolved_records=(
            raw_vftable_counts.resolved_records
        ),
        xbox_raw_vftable_unresolved_records=(
            raw_vftable_counts.unresolved_records
        ),
        xbox_raw_vftable_canonical_names=(
            raw_vftable_counts.canonical_names
        ),
        xbox_raw_vftable_address_groups=(
            raw_vftable_counts.address_groups
        ),
        xbox_raw_vftable_pointer_runs=raw_vftable_counts.pointer_runs,
        xbox_raw_vftable_pointer_slots=raw_vftable_counts.pointer_slots,
        xbox_raw_vftable_diagnostics=raw_vftable_counts.diagnostics,
        pc_sdk_source_tree_sha256=(
            sdk_counts.source_tree_sha256 if sdk_counts is not None else None
        ),
        pc_sdk_source_files=(
            sdk_counts.source_files if sdk_counts is not None else 0
        ),
        pc_sdk_prototype_observations=(
            sdk_counts.prototypes if sdk_counts is not None else 0
        ),
        pc_sdk_call_target_observations=(
            sdk_counts.call_targets if sdk_counts is not None else 0
        ),
        pc_sdk_data_observations=(
            sdk_counts.data_addresses if sdk_counts is not None else 0
        ),
        pc_sdk_diagnostics=(
            sdk_counts.diagnostics if sdk_counts is not None else 0
        ),
        pc_sdk_code_inventory_joins=(
            sdk_counts.code_joins if sdk_counts is not None else 0
        ),
        pc_sdk_data_inventory_joins=(
            sdk_counts.data_joins if sdk_counts is not None else 0
        ),
        pc_sdk_definitive_game_links=(
            sdk_counts.definitive_game_links if sdk_counts is not None else 0
        ),
        pc_sdk_unspecified_entry_candidates=(
            sdk_counts.unspecified_entry_candidates
            if sdk_counts is not None
            else 0
        ),
        pc_sdk_boundary_candidates=(
            sdk_counts.boundary_candidates if sdk_counts is not None else 0
        ),
        pc_sdk_boundary_containers=(
            sdk_counts.boundary_containers if sdk_counts is not None else 0
        ),
        xbox_control_flow_persistence_policy=(
            control_flow_counts.persistence_policy
        ),
        xbox_control_flow_source_physical_sites=(
            control_flow_counts.source_physical_sites
        ),
        xbox_control_flow_source_logical_uses=(
            control_flow_counts.source_logical_uses
        ),
        xbox_control_flow_persisted_physical_sites=(
            control_flow_counts.persisted_physical_sites
        ),
        xbox_control_flow_persisted_logical_uses=(
            control_flow_counts.persisted_logical_uses
        ),
        xbox_control_flow_triggering_logical_uses=(
            control_flow_counts.triggering_logical_uses
        ),
        xbox_control_flow_procedure_scans=(
            control_flow_counts.procedure_scans
        ),
        xbox_control_flow_source_summary=xbox_control_flow.to_summary(),
        xbox_control_flow_persisted_summary=(
            xbox_control_flow_selected.to_summary()
        ),
        control_flow_matching_policy=control_flow_matching.policy,
        control_flow_mapping_source_alternatives=(
            control_flow_matching.summary.source_mapping_alternatives
        ),
        control_flow_mapping_semantic_bundles=(
            control_flow_matching.summary.semantic_mapping_bundles
        ),
        control_flow_mapping_caller_anchors=(
            control_flow_matching.summary.caller_anchor_bundles
        ),
        control_flow_mapping_closed_derivations=(
            control_flow_matching.summary.closed_square_derivations
        ),
        control_flow_mapping_closed_evidence_occurrences=(
            control_flow_matching.summary.closed_square_evidence_occurrences
        ),
        control_flow_mapping_blocked_neighborhoods=(
            control_flow_matching.summary.blocked_neighborhoods
        ),
        control_flow_mapping_fold_blocked_neighborhoods=(
            control_flow_matching.summary.fold_member_blocked_neighborhoods
        ),
        control_flow_mapping_proposal_derivations=(
            control_flow_matching.summary.residual_proposal_derivations
        ),
        control_flow_mapping_proposal_sets=(
            control_flow_matching.summary.proposal_sets
        ),
        control_flow_mapping_proposal_alternatives=(
            control_flow_matching.summary.proposal_alternatives
        ),
        control_flow_mapping_proposal_evidence_occurrences=(
            control_flow_matching.summary.proposal_evidence_occurrences
        ),
        control_flow_mapping_persisted_relation_sets=(
            control_flow_matching_counts.closed_relation_sets
        ),
        control_flow_mapping_persisted_proposal_sets=(
            control_flow_matching_counts.proposal_sets
        ),
        control_flow_mapping_persisted_proposal_alternatives=(
            control_flow_matching_counts.proposal_alternatives
        ),
        control_flow_mapping_persisted_scalar_claims=(
            control_flow_matching_counts.scalar_claims
        ),
        control_flow_mapping_persisted_fold_alternatives=(
            control_flow_matching_counts.fold_bundle_alternatives
        ),
        control_flow_mapping_persisted_evidence=(
            control_flow_matching_counts.supporting_evidence
        ),
        pc_vtable_classes=pc_vtable_counts.classes,
        pc_vtables=pc_vtable_counts.tables,
        pc_vtable_slots=pc_vtable_counts.slots,
        pc_primary_vtables=pc_vtable_counts.primary_tables,
        pc_secondary_vtables=pc_vtable_counts.secondary_tables,
        pc_unknown_vtable_roles=pc_vtable_counts.unknown_role_tables,
        pc_extent_suspect_vtables=pc_vtable_counts.extent_suspect_tables,
        xbox_vtable_classes=xbox_vtable_counts.classes,
        xbox_vtables=xbox_vtable_counts.tables,
        xbox_vtable_slots=xbox_vtable_counts.slots,
        xbox_primary_vtables=xbox_vtable_counts.primary_tables,
        xbox_secondary_vtables=xbox_vtable_counts.secondary_tables,
        xbox_unknown_vtable_roles=xbox_vtable_counts.unknown_role_tables,
        xbox_extent_suspect_vtables=(
            xbox_vtable_counts.extent_suspect_tables
        ),
        vtable_alignment_candidates=(
            vtable_hypothesis_counts.table_alignments
        ),
        vtable_alignment_issues=vtable_hypothesis_counts.issues,
        vtable_slot_alignments=vtable_hypothesis_counts.slot_alignments,
        vtable_hypothesis_sets=vtable_hypothesis_counts.hypothesis_sets,
        vtable_hypothesis_alternatives=(
            vtable_hypothesis_counts.alternatives
        ),
        vtable_scalar_match_claims=vtable_hypothesis_counts.scalar_claims,
        vtable_pc_resolved_subjects=(
            vtable_hypothesis_counts.pc_resolved_subjects
        ),
        vtable_pc_unresolved_subjects=(
            vtable_hypothesis_counts.pc_unresolved_subjects
        ),
        vtable_xbox_exact_alternatives=(
            vtable_hypothesis_counts.xbox_exact_alternatives
        ),
        vtable_xbox_fold_bundle_alternatives=(
            vtable_hypothesis_counts.xbox_fold_bundle_alternatives
        ),
        vtable_xbox_unresolved_alternatives=(
            vtable_hypothesis_counts.xbox_unresolved_alternatives
        ),
        vtable_distinct_fold_groups_used=(
            vtable_hypothesis_counts.distinct_fold_groups_used
        ),
        vtable_structural_supporting_evidence=(
            vtable_hypothesis_counts.supporting_evidence
        ),
        vtable_structural_context_evidence=(
            vtable_hypothesis_counts.context_evidence
        ),
        vtable_clean_supporting_evidence=(
            vtable_hypothesis_counts.clean_supporting_evidence
        ),
        vtable_suspect_safe_prefix_evidence=(
            vtable_hypothesis_counts.suspect_safe_prefix_evidence
        ),
        vtable_overflow_context_evidence=(
            vtable_hypothesis_counts.overflow_context_evidence
        ),
        legacy_name_claims=len(legacy.claims),
        legacy_unique_xbox_matches=unique_matches,
        legacy_ambiguous_xbox_claims=ambiguous_claims,
        legacy_unmatched_xbox_claims=unmatched_claims,
        legacy_database_claims=database_claims,
        legacy_hypothesis_sets=len(legacy.claims),
        legacy_hypothesis_alternatives=database_claims,
        legacy_hypothesis_evidence_rows=legacy.evidence_count,
        legacy_xbox_unresolved_sets=unmatched_claims,
        legacy_unresolved_pc_claims=len(legacy.unresolved_claims),
        legacy_context_observations=context_observations,
        legacy_experimental_claims=legacy.experimental_claim_count,
        legacy_experimental_evidence_occurrences=(
            legacy.experimental_evidence_count
        ),
        legacy_source_evidence_occurrences=legacy.evidence_count,
        legacy_source_supporting_evidence=legacy.evidence_effect_counts.get(
            "supports", 0
        ),
        legacy_source_contradicting_evidence=legacy.evidence_effect_counts.get(
            "contradicts", 0
        ),
        legacy_source_context_evidence=legacy.evidence_effect_counts.get(
            "context", 0
        ),
        claim_evidence_rows=claim_evidence_rows,
        claim_supporting_evidence_rows=claim_effect_counts.get("supports", 0),
        claim_contradicting_evidence_rows=claim_effect_counts.get(
            "contradicts", 0
        ),
        claim_context_evidence_rows=claim_effect_counts.get("context", 0),
        hypothesis_sets=hypothesis_set_rows,
        hypothesis_alternatives=hypothesis_alternative_rows,
        hypothesis_evidence_rows=hypothesis_evidence_rows,
        hypothesis_supporting_evidence_rows=hypothesis_effect_counts.get(
            "supports", 0
        ),
        hypothesis_contradicting_evidence_rows=hypothesis_effect_counts.get(
            "contradicts", 0
        ),
        hypothesis_context_evidence_rows=hypothesis_effect_counts.get(
            "context", 0
        ),
        alternative_evidence_rows=alternative_evidence_rows,
        alternative_supporting_evidence_rows=(
            alternative_effect_counts.get("supports", 0)
        ),
        alternative_contradicting_evidence_rows=(
            alternative_effect_counts.get("contradicts", 0)
        ),
        alternative_context_evidence_rows=(
            alternative_effect_counts.get("context", 0)
        ),
        integrity_check=integrity,
        foreign_key_violations=foreign_keys,
        semantic_violations=semantic_violations,
    )


def write_report(
    report: BuildReport,
    path: str | Path,
    *,
    protected_paths: Iterable[tuple[str, str | Path]] = (),
) -> None:
    destination = Path(path).resolve()
    reject_destination_aliases(
        destination,
        (("atlas database", report.database), *tuple(protected_paths)),
        destination_label="report output",
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = _new_atomic_temporary(destination)
    try:
        temporary.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, destination)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise


def write_sha256_sidecar(
    source: str | Path,
    destination: str | Path | None = None,
) -> Path:
    """Atomically write the conventional checksum sidecar for one file."""

    source_path = Path(source).resolve()
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    sidecar = (
        Path(destination).resolve()
        if destination is not None
        else Path(str(source_path) + ".sha256.txt")
    )
    reject_destination_aliases(
        sidecar,
        (("checksum source", source_path),),
        destination_label="checksum sidecar",
    )
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    digest = _content_id_for_path(source_path).removeprefix("sha256:").upper()
    payload = f"{digest} *{source_path.name}\n"
    temporary = _new_atomic_temporary(sidecar)
    try:
        temporary.write_text(payload, encoding="ascii", newline="\n")
        os.replace(temporary, sidecar)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    return sidecar
