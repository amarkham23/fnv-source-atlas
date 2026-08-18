"""Command-line interface for the FNV source atlas."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Callable, Sequence

from . import __version__
from .build import (
    BuildConfig,
    build_atlas,
    reject_destination_aliases,
    write_report,
    write_sha256_sidecar,
)
from .database import AtlasDatabase
from .consumer_exports import (
    build_candidate_report,
    build_export_plan,
    candidate_report_json,
    export_plan_json,
    render_ghidra_script,
    render_idapython_script,
)
from .pdb_globals import extract_data_symbols, write_data_jsonl
from .pdb_symbols import extract_procedures, write_jsonl
from .pdb_vftables import (
    extract_vftable_corpus,
    write_pointer_runs_jsonl,
    write_vftable_symbols_jsonl,
)
from .ppc_control_flow import (
    extract_ppc_control_flow_from_files,
    write_control_flow_jsonl,
)
from .query import AtlasQuery, QueryError, render_human
from .review_queue import (
    build_review_queue_page,
    build_review_release_snapshot,
    evaluate_producers,
)
from .sdk_prototypes import extract_sdk_prototypes
from .validation import semantic_validation_counts, semantic_validation_ok


def database_summary(path: str | Path) -> dict[str, object]:
    with AtlasDatabase.open(path, read_only=True) as db:
        c = db.connection
        programs = {
            row["platform"]: {
                "program_id": row["program_id"],
                "name": row["name"],
                "functions": row["function_count"],
                "unique_addresses": row["address_count"],
            }
            for row in c.execute(
                """
                SELECT p.platform, p.program_id, p.name,
                       COUNT(DISTINCT f.function_id) AS function_count,
                       COUNT(DISTINCT f.address_group_id) AS address_count
                FROM programs p
                LEFT JOIN functions f USING (program_id)
                GROUP BY p.program_id ORDER BY p.platform
                """
            )
        }
        scalar = lambda sql: int(c.execute(sql).fetchone()[0])
        grouped_counts = lambda sql: {
            str(row[0]): int(row[1]) for row in c.execute(sql)
        }
        manifests = [row[0] for row in c.execute("SELECT manifest_id FROM input_manifests")]
        signature_status = {
            str(row[0]): int(row[1])
            for row in c.execute(
                """
                SELECT resolution_status, COUNT(*)
                FROM function_signatures GROUP BY resolution_status
                """
            )
        }
        hypothesis_effects = {
            str(row[0]): int(row[1])
            for row in c.execute(
                """
                SELECT effect, COUNT(*) FROM match_hypothesis_evidence
                GROUP BY effect ORDER BY effect
                """
            )
        }
        alternative_effects = {
            str(row[0]): int(row[1])
            for row in c.execute(
                """
                SELECT effect, COUNT(*)
                FROM match_hypothesis_alternative_evidence
                GROUP BY effect ORDER BY effect
                """
            )
        }
        vtable_summary: dict[str, dict[str, object]] = {}
        for row in c.execute(
            """
            SELECT p.platform,
                   (SELECT COUNT(*) FROM classes cl
                    WHERE cl.program_id = p.program_id) AS class_count,
                   (SELECT COUNT(*) FROM vtables v
                    WHERE v.program_id = p.program_id) AS table_count,
                   (SELECT COUNT(*) FROM vtable_slots vs
                    WHERE vs.program_id = p.program_id) AS slot_count,
                   (SELECT COUNT(*) FROM vtables v
                    WHERE v.program_id = p.program_id
                      AND json_extract(v.details_json,
                                       '$.extent.extent_suspect') = 1)
                       AS extent_suspect_count
            FROM programs p ORDER BY p.platform
            """
        ):
            roles = {
                role_row[0]: int(role_row[1])
                for role_row in c.execute(
                    """
                    SELECT vfptr_role, COUNT(*) FROM vtables
                    WHERE program_id = (
                        SELECT program_id FROM programs WHERE platform = ?
                    )
                    GROUP BY vfptr_role ORDER BY vfptr_role
                    """,
                    (row["platform"],),
                )
            }
            vtable_summary[str(row["platform"])] = {
                "classes": int(row["class_count"]),
                "tables": int(row["table_count"]),
                "slots": int(row["slot_count"]),
                "roles": roles,
                "extent_suspect_tables": int(row["extent_suspect_count"]),
            }
        return {
            "database": str(Path(path).resolve()),
            "programs": programs,
            "function_names": scalar("SELECT COUNT(*) FROM function_names"),
            "function_assertions": scalar(
                "SELECT COUNT(*) FROM function_assertions"
            ),
            "source_links": scalar("SELECT COUNT(*) FROM function_source_ranges"),
            "function_signatures": {
                "total": scalar("SELECT COUNT(*) FROM function_signatures"),
                "resolved": signature_status.get("resolved", 0),
                "unresolved": signature_status.get("unresolved", 0),
                "arguments": scalar(
                    "SELECT COUNT(*) FROM function_signature_arguments"
                ),
                "variadic": scalar(
                    "SELECT COUNT(*) FROM function_signatures WHERE is_variadic = 1"
                ),
            },
            "fold_groups": scalar("SELECT COUNT(*) FROM fold_groups"),
            "fold_members": scalar("SELECT COUNT(*) FROM fold_group_members"),
            "call_edges": {
                "total": scalar("SELECT COUNT(*) FROM call_edges"),
                "resolved": scalar(
                    "SELECT COUNT(*) FROM call_edges WHERE callee_function_id IS NOT NULL"
                ),
                "unresolved": scalar(
                    "SELECT COUNT(*) FROM call_edges WHERE unresolved_target_id IS NOT NULL"
                ),
            },
            "match_claims": scalar("SELECT COUNT(*) FROM match_claims"),
            "claim_evidence": scalar("SELECT COUNT(*) FROM claim_evidence"),
            "match_hypotheses": {
                "sets": scalar("SELECT COUNT(*) FROM match_hypothesis_sets"),
                "alternatives": scalar(
                    "SELECT COUNT(*) FROM match_hypothesis_alternatives"
                ),
                "evidence": scalar(
                    "SELECT COUNT(*) FROM match_hypothesis_evidence"
                ),
                "evidence_effects": hypothesis_effects,
                "alternative_evidence": scalar(
                    "SELECT COUNT(*) "
                    "FROM match_hypothesis_alternative_evidence"
                ),
                "alternative_evidence_effects": alternative_effects,
            },
            "codeview_types": {
                "extractions": scalar(
                    "SELECT COUNT(*) FROM codeview_type_extractions"
                ),
                "raw_records": scalar(
                    "SELECT COUNT(*) FROM codeview_type_records"
                ),
                "record_assertions": scalar(
                    "SELECT COUNT(*) FROM codeview_type_record_assertions"
                ),
                "raw_body_bytes": scalar(
                    "SELECT COALESCE(SUM(length(raw_body)), 0) "
                    "FROM codeview_type_records"
                ),
                "tags": scalar("SELECT COUNT(*) FROM codeview_tag_layouts"),
                "definitions": scalar(
                    "SELECT COUNT(*) FROM codeview_tag_layouts "
                    "WHERE is_forward_reference = 0"
                ),
                "forward_references": scalar(
                    "SELECT COUNT(*) FROM codeview_tag_layouts "
                    "WHERE is_forward_reference = 1"
                ),
                "tag_member_occurrences": scalar(
                    "SELECT COUNT(*) FROM codeview_tag_member_uses"
                ),
                "physical_field_members": scalar(
                    "SELECT COUNT(*) FROM codeview_field_members"
                ),
                "physical_method_overloads": scalar(
                    "SELECT COUNT(*) FROM codeview_method_overloads"
                ),
                "diagnostics": scalar(
                    "SELECT COUNT(*) FROM codeview_layout_diagnostics"
                ),
            },
            "data_symbols": {
                "extractions": scalar(
                    "SELECT COUNT(*) FROM data_symbol_extractions"
                ),
                "records": scalar("SELECT COUNT(*) FROM data_symbol_records"),
                "record_assertions": scalar(
                    "SELECT COUNT(*) FROM data_symbol_record_assertions"
                ),
                "resolved_records": scalar(
                    "SELECT COUNT(*) FROM data_symbol_record_assertions "
                    "WHERE address_group_id IS NOT NULL"
                ),
                "unresolved_records": scalar(
                    "SELECT COUNT(*) FROM data_symbol_record_assertions "
                    "WHERE address_group_id IS NULL"
                ),
                "unique_addresses": scalar(
                    "SELECT COUNT(DISTINCT address_group_id) "
                    "FROM data_symbol_record_assertions "
                    "WHERE address_group_id IS NOT NULL"
                ),
            },
            "xbox_raw_vftables": {
                "extractions": scalar(
                    "SELECT COUNT(*) FROM xbox_vftable_extractions"
                ),
                "physical_records": scalar(
                    "SELECT COUNT(*) FROM xbox_vftable_symbol_records"
                ),
                "record_assertions": scalar(
                    "SELECT COUNT(*) FROM xbox_vftable_symbol_assertions"
                ),
                "canonical_names": scalar(
                    "SELECT COUNT(*) FROM xbox_vftable_name_identities"
                ),
                "address_observations": scalar(
                    "SELECT COUNT(*) FROM xbox_vftable_address_observations"
                ),
                "address_members": scalar(
                    "SELECT COUNT(*) FROM xbox_vftable_address_members"
                ),
                "pointer_runs": scalar(
                    "SELECT COUNT(*) FROM xbox_vftable_pointer_runs"
                ),
                "pointer_slots": scalar(
                    "SELECT COUNT(*) FROM xbox_vftable_pointer_slots"
                ),
                "diagnostics": scalar(
                    "SELECT COUNT(*) FROM xbox_vftable_diagnostics"
                ),
            },
            "sdk": {
                "source_trees": scalar("SELECT COUNT(*) FROM sdk_source_trees"),
                "source_files": scalar(
                    "SELECT COUNT(*) FROM sdk_source_tree_files"
                ),
                "extractions": scalar("SELECT COUNT(*) FROM sdk_extractions"),
                "prototype_observations": scalar(
                    "SELECT COUNT(*) FROM sdk_prototype_observations"
                ),
                "call_target_observations": scalar(
                    "SELECT COUNT(*) FROM sdk_call_target_observations"
                ),
                "data_observations": scalar(
                    "SELECT COUNT(*) FROM sdk_data_observations"
                ),
                "diagnostics": scalar("SELECT COUNT(*) FROM sdk_diagnostics"),
                "code_inventory_joins": scalar(
                    "SELECT COUNT(*) FROM sdk_code_inventory_joins"
                ),
                "data_inventory_joins": scalar(
                    "SELECT COUNT(*) FROM sdk_data_inventory_joins"
                ),
                "definitive_game_links": scalar(
                    "SELECT COUNT(*) FROM sdk_game_exact_entry_links"
                ),
                "unspecified_entry_candidates": scalar(
                    "SELECT COUNT(*) "
                    "FROM sdk_unspecified_exact_entry_candidates"
                ),
                "boundary_candidates": scalar(
                    "SELECT COUNT(*) FROM sdk_boundary_candidates"
                ),
                "boundary_containers": scalar(
                    "SELECT COUNT(*) FROM sdk_boundary_candidate_containers"
                ),
            },
            "vtable_alignments": {
                "table_candidates": scalar(
                    "SELECT COUNT(*) FROM vtable_alignment_candidates"
                ),
                "slot_occurrences": scalar(
                    "SELECT COUNT(*) FROM vtable_slot_alignments"
                ),
                "issues": scalar(
                    "SELECT COUNT(*) FROM vtable_alignment_issues"
                ),
                "fold_bundle_alternatives": scalar(
                    """
                    SELECT COUNT(*)
                    FROM match_hypothesis_alternatives a
                    JOIN match_hypothesis_sets h USING (hypothesis_set_id)
                    JOIN provenance p USING (provenance_id)
                    WHERE p.producer = 'fnv_atlas.vtable_hypotheses'
                      AND a.xbox_fold_group_id IS NOT NULL
                    """
                ),
                "scalar_alternatives": scalar(
                    """
                    SELECT COUNT(*)
                    FROM match_hypothesis_alternatives a
                    JOIN match_hypothesis_sets h USING (hypothesis_set_id)
                    JOIN provenance p USING (provenance_id)
                    WHERE p.producer = 'fnv_atlas.vtable_hypotheses'
                      AND a.claim_id IS NOT NULL
                    """
                ),
            },
            "control_flow": {
                "extractions": scalar(
                    "SELECT COUNT(*) FROM control_flow_extractions"
                ),
                "physical_sites": scalar(
                    "SELECT COUNT(*) FROM control_flow_sites"
                ),
                "site_assertions": scalar(
                    "SELECT COUNT(*) FROM control_flow_site_assertions"
                ),
                "logical_uses": scalar(
                    "SELECT COUNT(*) FROM control_flow_uses"
                ),
                "use_assertions": scalar(
                    "SELECT COUNT(*) FROM control_flow_use_assertions"
                ),
                "procedure_scans": scalar(
                    "SELECT COUNT(*) FROM control_flow_scans"
                ),
                "target_kinds": grouped_counts(
                    """
                    SELECT target_kind, COUNT(*)
                    FROM control_flow_site_assertions
                    GROUP BY target_kind ORDER BY target_kind
                    """
                ),
                "roles": grouped_counts(
                    """
                    SELECT role, COUNT(*) FROM control_flow_use_assertions
                    GROUP BY role ORDER BY role
                    """
                ),
                "scan_statuses": grouped_counts(
                    """
                    SELECT status, COUNT(*) FROM control_flow_scans
                    GROUP BY status ORDER BY status
                    """
                ),
            },
            "reviews": {
                "reviewers": scalar("SELECT COUNT(*) FROM reviewers"),
                "releases": scalar("SELECT COUNT(*) FROM review_releases"),
                "decisions": scalar("SELECT COUNT(*) FROM review_decisions"),
                "current_decisions": scalar(
                    "SELECT COUNT(*) FROM current_review_decisions"
                ),
                "historical_actions": grouped_counts(
                    """
                    SELECT action, COUNT(*) FROM review_decisions
                    GROUP BY action ORDER BY action
                    """
                ),
                "current_statuses": grouped_counts(
                    """
                    SELECT derived_status, COUNT(*)
                    FROM current_review_decisions
                    GROUP BY derived_status ORDER BY derived_status
                    """
                ),
            },
            "observations": scalar("SELECT COUNT(*) FROM observations"),
            "unresolved_targets": scalar(
                "SELECT COUNT(*) FROM unresolved_targets WHERE status = 'open'"
            ),
            "shared_address_groups": scalar(
                """
                SELECT COUNT(*) FROM (
                    SELECT address_group_id FROM functions
                    GROUP BY address_group_id HAVING COUNT(*) > 1
                )
                """
            ),
            "vtables": vtable_summary,
            "input_manifests": manifests,
        }


def validate_database(path: str | Path) -> dict[str, object]:
    with AtlasDatabase.open(path, read_only=True) as db:
        integrity = str(db.connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = [tuple(row) for row in db.connection.execute("PRAGMA foreign_key_check")]
        manifests = [row[0] for row in db.connection.execute("SELECT manifest_id FROM input_manifests")]
        manifest_results = {manifest: db.verify_manifest(manifest) for manifest in manifests}
        semantic_violations = semantic_validation_counts(db.connection)
    return {
        "database": str(Path(path).resolve()),
        "integrity_check": integrity,
        "foreign_key_violations": len(foreign_keys),
        "manifests": manifest_results,
        "semantic_violations": semantic_violations,
        "ok": (
            integrity == "ok"
            and not foreign_keys
            and all(manifest_results.values())
            and semantic_validation_ok(semantic_violations)
        ),
    }


def _render_summary_human(summary: dict[str, object]) -> str:
    lines = [f"Source atlas: {summary['database']}", "Programs:"]
    programs = summary.get("programs", {})
    assert isinstance(programs, dict)
    for platform in sorted(programs):
        record = programs[platform]
        assert isinstance(record, dict)
        lines.append(
            f"  {platform}: {record['functions']} functions at "
            f"{record['unique_addresses']} addresses"
        )
    lines.extend(
        [
            f"Function names: {summary['function_names']}",
            f"Fold groups: {summary['fold_groups']}",
            f"Match claims: {summary['match_claims']}",
        ]
    )
    hypotheses = summary.get("match_hypotheses", {})
    if isinstance(hypotheses, dict):
        lines.append(
            "Hypotheses: "
            f"{hypotheses.get('sets', 0)} sets / "
            f"{hypotheses.get('alternatives', 0)} alternatives / "
            f"{hypotheses.get('evidence', 0)} set evidence / "
            f"{hypotheses.get('alternative_evidence', 0)} "
            "alternative evidence"
        )
    alignments = summary.get("vtable_alignments", {})
    if isinstance(alignments, dict):
        lines.append(
            "Vtable alignments: "
            f"{alignments.get('table_candidates', 0)} tables / "
            f"{alignments.get('slot_occurrences', 0)} slots / "
            f"{alignments.get('issues', 0)} issues"
        )
    control_flow = summary.get("control_flow", {})
    if isinstance(control_flow, dict):
        lines.append(
            "Control flow: "
            f"{control_flow.get('extractions', 0)} extractions / "
            f"{control_flow.get('physical_sites', 0)} physical sites / "
            f"{control_flow.get('logical_uses', 0)} logical uses / "
            f"{control_flow.get('procedure_scans', 0)} scans"
        )
    codeview_types = summary.get("codeview_types", {})
    if isinstance(codeview_types, dict):
        lines.append(
            "Xbox types: "
            f"{codeview_types.get('raw_records', 0)} raw records / "
            f"{codeview_types.get('tags', 0)} tags / "
            f"{codeview_types.get('tag_member_occurrences', 0)} member uses"
        )
    data_symbols = summary.get("data_symbols", {})
    if isinstance(data_symbols, dict):
        lines.append(
            "Xbox data symbols: "
            f"{data_symbols.get('records', 0)} records / "
            f"{data_symbols.get('unique_addresses', 0)} addresses"
        )
    raw_vftables = summary.get("xbox_raw_vftables", {})
    if isinstance(raw_vftables, dict):
        lines.append(
            "Raw Xbox vftables: "
            f"{raw_vftables.get('physical_records', 0)} symbols / "
            f"{raw_vftables.get('address_observations', 0)} addresses / "
            f"{raw_vftables.get('pointer_slots', 0)} pointer observations"
        )
    sdk = summary.get("sdk", {})
    if isinstance(sdk, dict):
        lines.append(
            "SDK observations: "
            f"{sdk.get('prototype_observations', 0)} prototypes / "
            f"{sdk.get('call_target_observations', 0)} call targets / "
            f"{sdk.get('data_observations', 0)} data addresses / "
            f"{sdk.get('boundary_candidates', 0)} boundary candidates"
        )
    reviews = summary.get("reviews", {})
    if isinstance(reviews, dict):
        lines.append(
            "Reviews: "
            f"{reviews.get('reviewers', 0)} reviewers / "
            f"{reviews.get('releases', 0)} releases / "
            f"{reviews.get('decisions', 0)} decisions / "
            f"{reviews.get('current_decisions', 0)} current"
        )
    return "\n".join(lines)


def _emit(document: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(document, indent=2, sort_keys=True))
    elif document.get("kind"):
        print(render_human(document))
    else:
        print(_render_summary_human(document))


def _add_page_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--limit", type=int, default=50, help="maximum records to return (1-1000)"
    )
    command.add_argument(
        "--offset", type=int, default=0, help="zero-based result offset"
    )
    command.add_argument(
        "--json", action="store_true", help="emit stable JSON instead of text"
    )


def _add_name_mode(command: argparse.ArgumentParser) -> None:
    mode = command.add_mutually_exclusive_group()
    mode.add_argument(
        "--exact",
        dest="name_mode",
        action="store_const",
        const="exact",
        help="require an exact name (default)",
    )
    mode.add_argument(
        "--contains",
        dest="name_mode",
        action="store_const",
        const="contains",
        help="case-insensitive substring search",
    )
    command.set_defaults(name_mode="exact")


def _write_atomic_text(
    destination: Path,
    payload: str,
    *,
    protected_paths: Sequence[tuple[str, Path]] = (),
) -> Path:
    resolved = destination.resolve()
    reject_destination_aliases(
        resolved,
        protected_paths,
        destination_label="artifact output",
    )
    resolved.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=resolved.name + ".",
        suffix=".building",
        dir=resolved.parent,
    )
    os.close(descriptor)
    temporary = Path(raw_temporary)
    try:
        temporary.write_text(payload, encoding="utf-8", newline="\n")
        os.replace(temporary, resolved)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    return resolved


def _write_atomic_via(
    destination: Path,
    writer: Callable[[Path], None],
    *,
    protected_paths: Sequence[tuple[str, Path]] = (),
    destination_label: str = "artifact output",
) -> Path:
    """Run a path-based writer against a temporary file, then publish it.

    The extraction writers predate the CLI's path-alias checks and open their
    destination with truncation semantics.  Giving them a private temporary
    path means a late symlink or hard-link swap can replace only the directory
    entry at ``destination``; it can never truncate a manifested input.
    """

    resolved = destination.resolve(strict=False)
    reject_destination_aliases(
        resolved,
        protected_paths,
        destination_label=destination_label,
    )
    resolved.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=resolved.name + ".",
        suffix=".building",
        dir=resolved.parent,
    )
    os.close(descriptor)
    temporary = Path(raw_temporary)
    try:
        writer(temporary)
        reject_destination_aliases(
            resolved,
            protected_paths,
            destination_label=destination_label,
        )
        os.replace(temporary, resolved)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return resolved


def _selected_manifest_id(db: AtlasDatabase, requested: str | None) -> str:
    if requested is not None:
        row = db.connection.execute(
            "SELECT 1 FROM input_manifests WHERE manifest_id = ?",
            (requested,),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown input manifest {requested!r}")
        return requested
    rows = [
        str(row[0])
        for row in db.connection.execute(
            "SELECT manifest_id FROM input_manifests ORDER BY manifest_id"
        )
    ]
    if len(rows) != 1:
        raise ValueError(
            "--manifest-id is required unless the atlas has exactly one manifest"
        )
    return rows[0]


def _human_review_provenance(
    db: AtlasDatabase,
    *,
    manifest_id: str | None,
    method: str,
) -> str:
    return db.upsert_provenance(
        kind="human_review",
        producer="fnv_atlas.cli.review",
        producer_version=__version__,
        method=method,
        manifest_id=manifest_id,
        parameters={
            "consensus_inferred": False,
            "candidate_status_mutated": False,
        },
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fnv-atlas",
        description="Build and inspect the evidence-backed FNV PC/Xbox source atlas.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="build an atomic atlas from current artifacts")
    build.add_argument("--repo", required=True, type=Path, help="FNV-Mods root")
    build.add_argument("--xbox-pdb", required=True, type=Path)
    build.add_argument("--xbox-exe", required=True, type=Path)
    build.add_argument(
        "--sdk-root",
        type=Path,
        help="private local SDK tree to include explicitly (omitted by default)",
    )
    build.add_argument("--output", type=Path)
    build.add_argument("--report", type=Path)
    build.add_argument("--replace", action="store_true")

    summary = commands.add_parser("summary", help="show atlas coverage counts")
    summary.add_argument("database", type=Path)
    summary.add_argument(
        "--json", action="store_true", help="emit stable JSON instead of text"
    )

    pc = commands.add_parser(
        "pc", help="inspect a PC address, function, vtable use, and mappings"
    )
    pc.add_argument("database", type=Path)
    pc.add_argument("address", help="decimal or 0x-prefixed hexadecimal address")
    pc.add_argument("--address-space", default="ram")
    _add_page_options(pc)

    xbox = commands.add_parser(
        "xbox", help="find Xbox PDB records/folds and their PC hypotheses"
    )
    xbox.add_argument("database", type=Path)
    xbox.add_argument("query", help="symbol/name or decimal/0x Xbox address")
    xbox.add_argument("--address-space", default="xbox-va")
    _add_name_mode(xbox)
    _add_page_options(xbox)

    class_query = commands.add_parser(
        "class", help="inspect PC/Xbox class vtables, slots, and alignments"
    )
    class_query.add_argument("database", type=Path)
    class_query.add_argument("name")
    _add_name_mode(class_query)
    _add_page_options(class_query)
    class_query.add_argument(
        "--slot-limit", type=int, default=50, help="slots per table (1-1000)"
    )
    class_query.add_argument(
        "--slot-offset", type=int, default=0, help="zero-based slot offset"
    )

    type_query = commands.add_parser(
        "type",
        help="inspect raw Xbox CodeView records, tags, fields, and overloads",
    )
    type_query.add_argument("database", type=Path)
    type_query.add_argument("query", help="type index or exact/partial type name")
    _add_name_mode(type_query)
    _add_page_options(type_query)
    type_query.add_argument(
        "--member-limit", type=int, default=50, help="members per tag (1-1000)"
    )
    type_query.add_argument(
        "--member-offset", type=int, default=0, help="zero-based member offset"
    )

    data_query = commands.add_parser(
        "data",
        help="inspect typed Xbox data-symbol records without collapsing aliases",
    )
    data_query.add_argument("database", type=Path)
    data_query.add_argument("query", help="symbol name or decimal/0x Xbox address")
    data_query.add_argument("--address-space", default="xbox-va")
    _add_name_mode(data_query)
    _add_page_options(data_query)

    raw_vftable_query = commands.add_parser(
        "raw-vftable",
        help="inspect physical Xbox vftable symbols and pointer observations",
    )
    raw_vftable_query.add_argument("database", type=Path)
    raw_vftable_query.add_argument(
        "query", help="decorated/owner name or decimal/0x Xbox address"
    )
    raw_vftable_query.add_argument("--address-space", default="xbox-va")
    _add_name_mode(raw_vftable_query)
    _add_page_options(raw_vftable_query)
    raw_vftable_query.add_argument(
        "--slot-limit",
        type=int,
        default=50,
        help="pointer observations per run (1-1000)",
    )
    raw_vftable_query.add_argument(
        "--slot-offset", type=int, default=0, help="zero-based pointer offset"
    )

    sdk_query = commands.add_parser(
        "sdk",
        help="inspect portable SDK observations and variant-safe PC joins",
    )
    sdk_query.add_argument("database", type=Path)
    sdk_query.add_argument("query", help="address or declaration/name/file text")
    _add_name_mode(sdk_query)
    _add_page_options(sdk_query)
    sdk_query.add_argument(
        "--variant",
        choices=("game", "geck", "unspecified_pc"),
    )
    sdk_query.add_argument(
        "--observation-kind",
        choices=("all", "prototype", "call_target", "data"),
        default="all",
    )

    candidates = commands.add_parser(
        "candidates", help="list unresolved, conflicted, or ambiguous candidates"
    )
    candidates.add_argument("database", type=Path)
    candidates.add_argument(
        "--kind",
        dest="candidate_kind",
        choices=("unresolved", "conflicted", "ambiguous", "all"),
        default="ambiguous",
    )
    _add_page_options(candidates)

    flow = commands.add_parser(
        "flow",
        help="inspect persisted Xbox procedure and physical-site control flow",
    )
    flow.add_argument("database", type=Path)
    flow.add_argument(
        "procedure",
        nargs="?",
        help="procedure ID/name or decimal/0x entry address",
    )
    flow.add_argument(
        "--site",
        "--site-address",
        dest="site_address",
        help="exact decimal/0x physical branch-instruction address",
    )
    flow.add_argument("--address-space", default="xbox-va")
    _add_name_mode(flow)
    _add_page_options(flow)

    validate = commands.add_parser("validate", help="run database and manifest checks")
    validate.add_argument("database", type=Path)

    reviewer = commands.add_parser(
        "reviewer-register",
        help="register one durable human reviewer identity",
    )
    reviewer.add_argument("database", type=Path)
    reviewer.add_argument("--identity-kind", required=True)
    reviewer.add_argument("--identity-key", required=True)
    reviewer.add_argument("--display-name", required=True)
    reviewer.add_argument("--affiliation")
    reviewer.add_argument("--reviewer-id")

    review_release = commands.add_parser(
        "review-release",
        help="register one immutable atlas release context for review",
    )
    review_release.add_argument("database", type=Path)
    review_release.add_argument("--release-key", required=True)
    review_release.add_argument("--label", required=True)
    review_release.add_argument("--version")
    review_release.add_argument("--source-revision")
    review_release.add_argument("--manifest-id")
    review_release.add_argument("--review-release-id")

    decision = commands.add_parser(
        "review-decide",
        help="append one scoped human review decision",
    )
    decision.add_argument("database", type=Path)
    decision.add_argument("--reviewer", required=True)
    decision.add_argument("--release", required=True)
    decision.add_argument(
        "--action",
        required=True,
        choices=("accept", "reject", "defer", "reopen", "supersede"),
    )
    decision.add_argument(
        "--decided-at",
        required=True,
        help="explicit RFC3339 timestamp with UTC offset",
    )
    decision.add_argument("--rationale", required=True)
    decision.add_argument("--previous")
    target = decision.add_mutually_exclusive_group(required=True)
    target.add_argument("--set", dest="hypothesis_set_id")
    target.add_argument("--alternative", dest="alternative_id")
    target.add_argument("--claim", dest="claim_id")

    review_queue = commands.add_parser(
        "review-queue",
        help="emit one bounded deterministic candidate-review page",
    )
    review_queue.add_argument("database", type=Path)
    review_queue.add_argument("--reviewer", required=True)
    review_queue.add_argument("--release", required=True)
    review_queue.add_argument("--limit", type=int, default=50)
    review_queue.add_argument("--after")
    review_queue.add_argument("--fold-sample-limit", type=int, default=8)
    review_queue.add_argument("--output", type=Path)

    review_snapshot = commands.add_parser(
        "review-snapshot",
        help="write a complete immutable normalized review snapshot",
    )
    review_snapshot.add_argument("database", type=Path)
    review_snapshot.add_argument("--reviewer", required=True)
    review_snapshot.add_argument("--release", required=True)
    review_snapshot.add_argument("--output", required=True, type=Path)
    review_snapshot.add_argument("--fold-sample-limit", type=int, default=8)

    review_evaluate = commands.add_parser(
        "review-evaluate",
        help="write count-only per-producer evaluation for one review snapshot",
    )
    review_evaluate.add_argument("database", type=Path)
    review_evaluate.add_argument("--reviewer", required=True)
    review_evaluate.add_argument("--release", required=True)
    review_evaluate.add_argument("--output", required=True, type=Path)
    review_evaluate.add_argument("--fold-sample-limit", type=int, default=8)

    consumer_export = commands.add_parser(
        "consumer-export",
        help="write an accepted-only export or a non-executable candidate report",
    )
    consumer_export.add_argument("database", type=Path)
    consumer_export.add_argument("--reviewer", required=True)
    consumer_export.add_argument("--release", required=True)
    consumer_export.add_argument(
        "--format",
        required=True,
        choices=("plan", "ghidra", "ida", "candidates"),
    )
    consumer_export.add_argument("--output", required=True, type=Path)

    extract = commands.add_parser(
        "extract-xbox-procedures",
        help="write every PDB procedure record to deterministic JSONL",
    )
    extract.add_argument("--pdb", required=True, type=Path)
    extract.add_argument("--exe", required=True, type=Path)
    extract.add_argument("--modules", required=True, type=Path)
    extract.add_argument("--output", required=True, type=Path)

    data_symbols = commands.add_parser(
        "extract-xbox-data-symbols",
        help="write every typed PDB data-symbol record to deterministic JSONL",
    )
    data_symbols.add_argument("--pdb", required=True, type=Path)
    data_symbols.add_argument("--exe", required=True, type=Path)
    data_symbols.add_argument("--modules", required=True, type=Path)
    data_symbols.add_argument("--output", required=True, type=Path)

    vftables = commands.add_parser(
        "extract-xbox-vftables",
        help=(
            "write lossless PDB vftable symbols and non-declarative pointer "
            "runs to separate deterministic JSONL files"
        ),
    )
    vftables.add_argument("--pdb", required=True, type=Path)
    vftables.add_argument("--exe", required=True, type=Path)
    vftables.add_argument("--symbols-output", required=True, type=Path)
    vftables.add_argument("--runs-output", required=True, type=Path)

    sdk = commands.add_parser(
        "extract-sdk-observations",
        help=(
            "write source-hashed SDK prototype, call-target, and data "
            "observations to deterministic JSON"
        ),
    )
    sdk.add_argument("--sdk-root", required=True, type=Path)
    sdk.add_argument("--output", required=True, type=Path)

    control_flow = commands.add_parser(
        "extract-xbox-control-flow",
        help="write lossless physical/logical Xbox branch observations to JSONL",
    )
    control_flow.add_argument("--pdb", required=True, type=Path)
    control_flow.add_argument("--exe", required=True, type=Path)
    control_flow.add_argument("--modules", required=True, type=Path)
    control_flow.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "build":
        config = BuildConfig.from_repo(
            args.repo,
            xbox_pdb=args.xbox_pdb,
            xbox_executable=args.xbox_exe,
            sdk_root=args.sdk_root,
            output_database=args.output,
            replace=args.replace,
        )
        report_path = args.report or config.output_database.with_suffix(".report.json")
        checksum_path = Path(
            str(config.output_database.resolve()) + ".sha256.txt"
        )
        reject_destination_aliases(
            report_path,
            (
                ("atlas database output", config.output_database),
                ("database checksum output", checksum_path),
                *config.protected_inputs(),
            ),
            destination_label="report output",
        )
        reject_destination_aliases(
            checksum_path,
            (
                ("atlas database output", config.output_database),
                ("report output", report_path),
                *config.protected_inputs(),
            ),
            destination_label="database checksum output",
        )
        report = build_atlas(config)
        write_report(
            report,
            report_path,
            protected_paths=(
                config.protected_inputs()
            ),
        )
        checksum_path = write_sha256_sidecar(
            config.output_database, checksum_path
        )
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        print(f"report: {report_path.resolve()}", file=sys.stderr)
        print(f"checksum: {checksum_path}", file=sys.stderr)
        return 0
    if args.command == "summary":
        _emit(database_summary(args.database), as_json=args.json)
        return 0
    if args.command in {
        "pc",
        "xbox",
        "class",
        "type",
        "data",
        "raw-vftable",
        "sdk",
        "candidates",
        "flow",
    }:
        try:
            with AtlasDatabase.open(args.database, read_only=True) as db:
                query = AtlasQuery(db.connection)
                if args.command == "pc":
                    result = query.pc_address(
                        args.address,
                        address_space=args.address_space,
                        limit=args.limit,
                        offset=args.offset,
                    )
                elif args.command == "xbox":
                    result = query.xbox(
                        args.query,
                        name_mode=args.name_mode,
                        address_space=args.address_space,
                        limit=args.limit,
                        offset=args.offset,
                    )
                elif args.command == "class":
                    result = query.class_lookup(
                        args.name,
                        name_mode=args.name_mode,
                        limit=args.limit,
                        offset=args.offset,
                        slot_limit=args.slot_limit,
                        slot_offset=args.slot_offset,
                    )
                elif args.command == "type":
                    result = query.codeview_type(
                        args.query,
                        name_mode=args.name_mode,
                        limit=args.limit,
                        offset=args.offset,
                        member_limit=args.member_limit,
                        member_offset=args.member_offset,
                    )
                elif args.command == "data":
                    result = query.xbox_data(
                        args.query,
                        name_mode=args.name_mode,
                        address_space=args.address_space,
                        limit=args.limit,
                        offset=args.offset,
                    )
                elif args.command == "raw-vftable":
                    result = query.xbox_vftable(
                        args.query,
                        name_mode=args.name_mode,
                        address_space=args.address_space,
                        limit=args.limit,
                        offset=args.offset,
                        slot_limit=args.slot_limit,
                        slot_offset=args.slot_offset,
                    )
                elif args.command == "sdk":
                    result = query.sdk(
                        args.query,
                        name_mode=args.name_mode,
                        program_variant=args.variant,
                        observation_kind=args.observation_kind,
                        limit=args.limit,
                        offset=args.offset,
                    )
                elif args.command == "flow":
                    result = query.flow(
                        args.procedure,
                        site_address=args.site_address,
                        name_mode=args.name_mode,
                        address_space=args.address_space,
                        limit=args.limit,
                        offset=args.offset,
                    )
                else:
                    result = query.candidates(
                        args.candidate_kind,
                        limit=args.limit,
                        offset=args.offset,
                    )
        except QueryError as error:
            parser.error(str(error))
        _emit(result, as_json=args.json)
        return 0
    if args.command == "validate":
        result = validate_database(args.database)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ok"] else 1
    if args.command == "reviewer-register":
        with AtlasDatabase.open(args.database) as db:
            reviewer_id = db.upsert_reviewer(
                reviewer_id=args.reviewer_id,
                identity_kind=args.identity_kind,
                identity_key=args.identity_key,
                display_name=args.display_name,
                affiliation=args.affiliation,
                details={"registered_by": "fnv-atlas reviewer-register"},
            )
        checksum_path = write_sha256_sidecar(args.database)
        print(
            json.dumps(
                {
                    "reviewer_id": reviewer_id,
                    "database_checksum": str(checksum_path),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "review-release":
        with AtlasDatabase.open(args.database) as db:
            manifest_id = _selected_manifest_id(db, args.manifest_id)
            provenance_id = _human_review_provenance(
                db,
                manifest_id=manifest_id,
                method="register immutable human-review release context",
            )
            review_release_id = db.upsert_review_release(
                review_release_id=args.review_release_id,
                release_key=args.release_key,
                label=args.label,
                version=args.version,
                source_revision=args.source_revision,
                manifest_id=manifest_id,
                provenance_id=provenance_id,
                details={"registered_by": "fnv-atlas review-release"},
            )
        checksum_path = write_sha256_sidecar(args.database)
        print(
            json.dumps(
                {
                    "review_release_id": review_release_id,
                    "manifest_id": manifest_id,
                    "database_checksum": str(checksum_path),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "review-decide":
        with AtlasDatabase.open(args.database) as db:
            release = db.connection.execute(
                "SELECT manifest_id FROM review_releases "
                "WHERE review_release_id = ?",
                (args.release,),
            ).fetchone()
            if release is None:
                parser.error(f"unknown review release {args.release!r}")
            provenance_id = _human_review_provenance(
                db,
                manifest_id=release["manifest_id"],
                method="append scoped human mapping review decision",
            )
            decision_id = db.add_review_decision(
                reviewer_id=args.reviewer,
                review_release_id=args.release,
                action=args.action,
                decided_at=args.decided_at,
                rationale=args.rationale,
                previous_decision_id=args.previous,
                hypothesis_set_id=args.hypothesis_set_id,
                alternative_id=args.alternative_id,
                claim_id=args.claim_id,
                provenance_id=provenance_id,
                details={"recorded_by": "fnv-atlas review-decide"},
            )
        checksum_path = write_sha256_sidecar(args.database)
        print(
            json.dumps(
                {
                    "decision_id": decision_id,
                    "database_checksum": str(checksum_path),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "review-queue":
        page = build_review_queue_page(
            args.database,
            reviewer_id=args.reviewer,
            review_release_id=args.release,
            limit=args.limit,
            after=args.after,
            fold_sample_limit=args.fold_sample_limit,
        )
        payload = page.to_json() + "\n"
        if args.output is None:
            sys.stdout.write(payload)
        else:
            output = _write_atomic_text(
                args.output,
                payload,
                protected_paths=(("atlas database", args.database),),
            )
            print(
                json.dumps(
                    {"output": str(output), "page_sha256": page.page_sha256},
                    indent=2,
                    sort_keys=True,
                )
            )
        return 0
    if args.command in {"review-snapshot", "review-evaluate"}:
        reject_destination_aliases(
            args.output,
            (("atlas database", args.database),),
            destination_label="review artifact output",
        )
        snapshot = build_review_release_snapshot(
            args.database,
            reviewer_id=args.reviewer,
            review_release_id=args.release,
            fold_sample_limit=args.fold_sample_limit,
        )
        if args.command == "review-snapshot":
            payload = snapshot.to_json() + "\n"
            identity_key = "snapshot_sha256"
            identity = snapshot.snapshot_sha256
        else:
            evaluation = evaluate_producers(snapshot)
            payload = evaluation.to_json() + "\n"
            identity_key = "evaluation_sha256"
            identity = evaluation.evaluation_sha256
        output = _write_atomic_text(
            args.output,
            payload,
            protected_paths=(("atlas database", args.database),),
        )
        print(
            json.dumps(
                {"output": str(output), identity_key: identity},
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "consumer-export":
        reject_destination_aliases(
            args.output,
            (("atlas database", args.database),),
            destination_label="consumer artifact output",
        )
        if args.format == "candidates":
            report = build_candidate_report(
                args.database,
                reviewer_id=args.reviewer,
                review_release_id=args.release,
            )
            payload = candidate_report_json(report) + "\n"
            identity = report.to_dict()["report_sha256"]
        else:
            plan = build_export_plan(
                args.database,
                reviewer_id=args.reviewer,
                review_release_id=args.release,
            )
            if args.format == "plan":
                payload = export_plan_json(plan) + "\n"
            elif args.format == "ghidra":
                payload = render_ghidra_script(plan)
            else:
                payload = render_idapython_script(plan)
            identity = plan.to_dict()["plan_sha256"]
        output = _write_atomic_text(
            args.output,
            payload,
            protected_paths=(("atlas database", args.database),),
        )
        print(
            json.dumps(
                {
                    "output": str(output),
                    "format": args.format,
                    "source_artifact_sha256": identity,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "extract-xbox-procedures":
        protected = (
            ("PDB input", args.pdb),
            ("executable input", args.exe),
            ("module-map input", args.modules),
        )
        reject_destination_aliases(
            args.output, protected, destination_label="JSONL output"
        )
        result = extract_procedures(args.pdb, args.exe, args.modules)
        output = _write_atomic_via(
            args.output,
            lambda path: write_jsonl(result.records, path),
            protected_paths=protected,
            destination_label="JSONL output",
        )
        print(
            json.dumps(
                {
                    "output": str(output),
                    "records": result.record_count,
                    "unique_va": result.unique_va_count,
                    "alias_groups": len(result.alias_groups),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "extract-xbox-data-symbols":
        protected = (
            ("PDB input", args.pdb),
            ("executable input", args.exe),
            ("module-map input", args.modules),
        )
        reject_destination_aliases(
            args.output,
            protected,
            destination_label="data-symbol JSONL output",
        )
        result = extract_data_symbols(args.pdb, args.exe, args.modules)
        output = _write_atomic_via(
            args.output,
            lambda path: write_data_jsonl(result.records, path),
            protected_paths=protected,
            destination_label="data-symbol JSONL output",
        )
        print(
            json.dumps(
                {
                    "output": str(output),
                    "records": result.record_count,
                    "unique_va": result.unique_va_count,
                    "unresolved_va": result.unresolved_va_count,
                    "multi_record_address_groups": sum(
                        group.count > 1 for group in result.address_groups
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "extract-xbox-vftables":
        reject_destination_aliases(
            args.symbols_output,
            (
                ("PDB input", args.pdb),
                ("executable input", args.exe),
                ("pointer-run JSONL output", args.runs_output),
            ),
            destination_label="vftable-symbol JSONL output",
        )
        reject_destination_aliases(
            args.runs_output,
            (
                ("PDB input", args.pdb),
                ("executable input", args.exe),
                ("vftable-symbol JSONL output", args.symbols_output),
            ),
            destination_label="pointer-run JSONL output",
        )
        result = extract_vftable_corpus(args.pdb, args.exe)
        symbols_output = _write_atomic_via(
            args.symbols_output,
            lambda path: write_vftable_symbols_jsonl(result.symbols.records, path),
            protected_paths=(
                ("PDB input", args.pdb),
                ("executable input", args.exe),
                ("pointer-run JSONL output", args.runs_output),
            ),
            destination_label="vftable-symbol JSONL output",
        )
        runs_output = _write_atomic_via(
            args.runs_output,
            lambda path: write_pointer_runs_jsonl(result.pointer_runs.runs, path),
            protected_paths=(
                ("PDB input", args.pdb),
                ("executable input", args.exe),
                ("vftable-symbol JSONL output", args.symbols_output),
            ),
            destination_label="pointer-run JSONL output",
        )
        print(
            json.dumps(
                {
                    "symbols_output": str(symbols_output),
                    "runs_output": str(runs_output),
                    "physical_symbol_records": result.symbols.record_count,
                    "unique_symbol_addresses": result.symbols.unique_va_count,
                    "unresolved_symbol_addresses": (
                        result.symbols.unresolved_va_count
                    ),
                    "pointer_runs": result.pointer_runs.run_count,
                    "pointer_occurrences": result.pointer_runs.slot_count,
                    "symbol_diagnostics": [
                        item.to_dict() for item in result.symbols.diagnostics
                    ],
                    "scan_diagnostics": [
                        item.to_dict()
                        for item in result.pointer_runs.diagnostics
                    ],
                    "pointer_runs_are_declared_extents": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "extract-sdk-observations":
        result = extract_sdk_prototypes(args.sdk_root)
        output = _write_atomic_text(
            args.output,
            json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
            protected_paths=(("SDK source tree", args.sdk_root),),
        )
        print(
            json.dumps(
                {
                    "output": str(output),
                    "source_tree_sha256": result.source_tree_sha256,
                    "files_scanned": result.files_scanned,
                    "prototype_observations": len(result.observations),
                    "call_target_observations": len(result.call_targets),
                    "data_observations": len(result.data_addresses),
                    "diagnostics": len(result.diagnostics),
                    "absolute_root_stored": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "extract-xbox-control-flow":
        protected = (
            ("PDB input", args.pdb),
            ("executable input", args.exe),
            ("module-map input", args.modules),
        )
        reject_destination_aliases(
            args.output,
            protected,
            destination_label="control-flow JSONL output",
        )
        result = extract_ppc_control_flow_from_files(
            pdb_path=args.pdb,
            executable_path=args.exe,
            modules_path=args.modules,
        )
        output = _write_atomic_via(
            args.output,
            lambda path: write_control_flow_jsonl(result, path),
            protected_paths=protected,
            destination_label="control-flow JSONL output",
        )
        print(
            json.dumps(
                {
                    "output": str(output),
                    **result.to_summary(),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
