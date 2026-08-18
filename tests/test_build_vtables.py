from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.build import (
    BuildConfig,
    PC_PROGRAM_ID,
    XBOX_PROGRAM_ID,
    _insert_pc_inventory,
    _insert_vtable_hypotheses,
    _insert_vtable_dataset,
    _insert_xbox_procedures,
    _publish_atomic_file,
    _register_manifest,
    _verify_input_files_unchanged,
)
from fnv_atlas.cli import database_summary
from fnv_atlas.database import AtlasDatabase
from fnv_atlas.pc_inventory import PCFunction, PCInventory
from fnv_atlas.pdb_symbols import (
    ProcedureExtraction,
    ProcedureRecord,
    S_GPROC32,
    build_alias_groups,
    make_record_id,
)
from fnv_atlas.vtable_alignment import propose_vtable_alignments
from fnv_atlas.vtable_hypotheses import materialize_vtable_hypotheses
from fnv_atlas.vtables import parse_pc_vtables, parse_xbox_vtables
from fnv_atlas.validation import semantic_validation_counts


def _config(root: Path) -> BuildConfig:
    fields = {
        "pc_functions": root / "pc-functions.json",
        "pc_executable": root / "pc.exe",
        "xbox_pdb": root / "xbox.pdb",
        "xbox_executable": root / "xbox.exe",
        "xbox_modules": root / "modules.json",
        "xbox_function_sources": root / "sources.json",
        "pc_classes": root / "pc_classes.json",
        "xbox_vtables": root / "vtables_360.json",
        "xbox_types": root / "types_360.json",
        "legacy_names_tiered": root / "names_tiered.json",
        "legacy_names_final": root / "names_final.json",
        "legacy_namemap": root / "namemap.json",
        "legacy_strmatch": root / "strmatch.json",
        "legacy_pgm": root / "pgm.json",
        "legacy_matched_ghidra": root / "matched_ghidra.json",
        "legacy_agent_verdicts": root / "agent_verdicts.json",
        "legacy_all_seeds": root / "all_seeds.json",
        "legacy_assign": root / "assign.json",
        "legacy_vmatch": root / "vmatch.json",
    }
    for name, path in fields.items():
        path.write_bytes((name + "\n").encode("ascii"))
    return BuildConfig(
        output_database=root / "atlas.sqlite",
        **fields,
    )


class BuildVtableTests(unittest.TestCase):
    def test_atomic_publication_never_clobbers_a_late_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            temporary = root / "atlas.building"
            destination = root / "atlas.sqlite"
            temporary.write_bytes(b"new atlas")
            destination.write_bytes(b"appeared late")
            with self.assertRaisesRegex(FileExistsError, "appeared while building"):
                _publish_atomic_file(temporary, destination, replace=False)
            self.assertEqual(destination.read_bytes(), b"appeared late")
            self.assertEqual(temporary.read_bytes(), b"new atlas")

            _publish_atomic_file(temporary, destination, replace=True)
            self.assertEqual(destination.read_bytes(), b"new atlas")
            self.assertFalse(temporary.exists())

    def test_repo_config_manifests_the_explicit_experimental_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = BuildConfig.from_repo(
                root,
                xbox_pdb=root / "xbox.pdb",
                xbox_executable=root / "xbox.exe",
            )
        roles = {role for role, _path, _media_type in config.input_files()}
        self.assertEqual(len(roles), 26)
        self.assertEqual(
            {
                role
                for role in roles
                if role.endswith("_experiment")
            },
            {
                "legacy_fingerprint_experiment",
                "legacy_calleealign_experiment",
                "legacy_calleealign_new_experiment",
                "legacy_wrappers_experiment",
                "legacy_pgm2_experiment",
                "legacy_pgm_new_experiment",
                "legacy_constmatch_experiment",
            },
        )

    def test_manifest_registers_vtable_inputs_and_detects_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _config(root)
            database = root / "manifest.sqlite"
            with AtlasDatabase.create(database) as db:
                manifest_id, content_ids = _register_manifest(db, config)
                roles = {
                    row[0]
                    for row in db.connection.execute(
                        "SELECT role FROM manifest_entries WHERE manifest_id = ?",
                        (manifest_id,),
                    )
                }
                self.assertIn("pc_rtti_vtables", roles)
                self.assertIn("xbox_vtables", roles)
                self.assertIn("xbox_types", roles)
                self.assertEqual(len(roles), len(config.input_files()))
                _verify_input_files_unchanged(config, content_ids)

                config.xbox_types.write_text("changed\n", encoding="ascii")
                with self.assertRaisesRegex(
                    RuntimeError, "xbox_types: .* changed"
                ):
                    _verify_input_files_unchanged(config, content_ids)

    def test_manifest_content_addresses_complete_sdk_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / "sdk"
            sdk.mkdir()
            source = sdk / "unused.cpp"
            source.write_text("int first;\n", encoding="utf-8")
            config = replace(_config(root), pc_sdk_root=sdk)
            database = root / "manifest-sdk.sqlite"
            with AtlasDatabase.create(database) as db:
                manifest_id, content_ids = _register_manifest(db, config)
                entry = db.connection.execute(
                    "SELECT logical_name FROM manifest_entries "
                    "WHERE manifest_id = ? AND role = 'pc_sdk_source_tree'",
                    (manifest_id,),
                ).fetchone()
                self.assertEqual(entry[0], "sdk.source-manifest.json")
                self.assertEqual(
                    db.connection.execute(
                        "SELECT COUNT(*) FROM manifest_entries "
                        "WHERE manifest_id = ?",
                        (manifest_id,),
                    ).fetchone()[0],
                    len(config.input_files()) + 1,
                )
                _verify_input_files_unchanged(config, content_ids)

                # Even a file with no extracted address observation remains a
                # source input and invalidates the registered tree identity.
                source.write_text("int changed;\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    RuntimeError, "pc_sdk_source_tree: .* changed"
                ):
                    _verify_input_files_unchanged(config, content_ids)

    def test_vtable_ingestion_creates_no_functions_and_preserves_observations(self):
        pc_dataset = parse_pc_vtables(
            {
                "classes": {
                    "SharedClass": [
                        {
                            "rtti_name": ".?AVSharedClass@@",
                            "vtable_va": 0x01001000,
                            "col_va": 0x01101000,
                            "offset": 0,
                            "slot_count": 2,
                            "slots": ["0x00401000", "0x00401000"],
                        }
                    ]
                }
            }
        )
        xbox_dataset = parse_xbox_vtables(
            {
                "SharedClass": [
                    {
                        "symbol": "??_7SharedClass@@6B@",
                        "vtable_va": "0x82001000",
                        "slot_count": 2,
                        "slots": [
                            {"va": "0x82601000", "name": "first_alias"},
                            {"va": "0x82601010", "name": "second_alias"},
                        ],
                    }
                ]
            },
            types={
                "SharedClass": {
                    "bases": [],
                    "virtuals": [
                        {"name": "only", "kind": "intro", "slot": 0}
                    ],
                }
            },
        )

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "atlas.sqlite"
            with AtlasDatabase.create(database) as db:
                db.upsert_program(
                    PC_PROGRAM_ID,
                    platform="pc",
                    name="PC",
                )
                db.upsert_program(
                    XBOX_PROGRAM_ID,
                    platform="xbox360",
                    name="Xbox",
                )
                provenance_id = db.upsert_provenance(
                    kind="test",
                    producer="tests.test_build_vtables",
                )

                # A canonical function already owns this PC address group. The
                # vtable importer must reuse it without replacing its details.
                pc_target_group = db.upsert_address_group(
                    program_id=PC_PROGRAM_ID,
                    address_space="ram",
                    address=0x00401000,
                    details={"ghidra_entry": True},
                )
                db.upsert_function(
                    address_group_id=pc_target_group,
                    identity_key="fixture-function",
                )

                pc_counts = _insert_vtable_dataset(
                    db,
                    pc_dataset,
                    program_id=PC_PROGRAM_ID,
                    provenance_id=provenance_id,
                    source_artifact="pc_classes.json",
                )
                xbox_counts = _insert_vtable_dataset(
                    db,
                    xbox_dataset,
                    program_id=XBOX_PROGRAM_ID,
                    provenance_id=provenance_id,
                    source_artifact="vtables_360.json + types_360.json",
                )

                self.assertEqual(pc_counts.classes, 1)
                self.assertEqual(pc_counts.tables, 1)
                self.assertEqual(pc_counts.slots, 2)
                self.assertEqual(xbox_counts.extent_suspect_tables, 1)
                self.assertEqual(
                    db.connection.execute(
                        "SELECT COUNT(*) FROM functions"
                    ).fetchone()[0],
                    1,
                )
                group_details = json.loads(
                    db.connection.execute(
                        "SELECT details_json FROM address_groups WHERE address_group_id = ?",
                        (pc_target_group,),
                    ).fetchone()[0]
                )
                self.assertEqual(group_details, {"ghidra_entry": True})

                xbox_table = db.connection.execute(
                    """
                    SELECT declared_slot_count, details_json FROM vtables
                    WHERE program_id = ?
                    """,
                    (XBOX_PROGRAM_ID,),
                ).fetchone()
                self.assertEqual(xbox_table["declared_slot_count"], 1)
                table_details = json.loads(xbox_table["details_json"])
                self.assertTrue(table_details["no_cross_platform_alignment_claim"])
                self.assertTrue(table_details["extent"]["extent_suspect"])

                slot_details = json.loads(
                    db.connection.execute(
                        """
                        SELECT details_json FROM vtable_slots
                        WHERE program_id = ? AND slot_index = 0
                        """,
                        (XBOX_PROGRAM_ID,),
                    ).fetchone()[0]
                )
                self.assertTrue(slot_details["target_is_address_only"])
                self.assertEqual(
                    slot_details["name_observations"][0]["raw_name"],
                    "first_alias",
                )
                self.assertEqual(
                    slot_details["name_observations"][0]["ambiguity"],
                    "address_may_have_multiple_symbol_aliases",
                )

            summary = database_summary(database)

        self.assertEqual(summary["vtables"]["pc"]["classes"], 1)
        self.assertEqual(summary["vtables"]["pc"]["slots"], 2)
        self.assertEqual(
            summary["vtables"]["xbox360"]["extent_suspect_tables"], 1
        )
        self.assertEqual(
            summary["vtables"]["xbox360"]["roles"], {"primary": 1}
        )

    def test_alignment_materialization_preserves_occurrences_and_fold_bundle(self):
        pc_targets = [0x401000, 0x401100, 0x401000, 0x401200]
        xbox_targets = [0x82001000, 0x82002000, 0x82001000, 0x82003000]
        pc_dataset = parse_pc_vtables(
            {
                "classes": {
                    "SharedClass": [
                        {
                            "rtti_name": ".?AVSharedClass@@",
                            "vtable_va": 0x01001000,
                            "col_va": 0x01101000,
                            "offset": 0,
                            "slot_count": 4,
                            "slots": pc_targets,
                        }
                    ]
                }
            }
        )
        xbox_dataset = parse_xbox_vtables(
            {
                "SharedClass": [
                    {
                        "symbol": "??_7SharedClass@@6B@",
                        "vtable_va": 0x82010000,
                        "slot_count": 4,
                        "slots": [
                            {"va": target, "name": f"observed_{index}"}
                            for index, target in enumerate(xbox_targets)
                        ],
                    }
                ]
            }
        )
        inventory = PCInventory(
            image_base=0x400000,
            functions=tuple(
                PCFunction(
                    function_id=f"pc:ram:{address:08x}",
                    address=address,
                    address_space="ram",
                    name=f"FUN_{address:08x}",
                    size=16,
                    thunk=False,
                    in_executable_range=True,
                    callees=(),
                )
                for address in (0x401000, 0x401200)
            ),
        )

        def procedure(va: int, ordinal: int, name: str) -> ProcedureRecord:
            record_offset = ordinal * 48 + 4
            return ProcedureRecord(
                record_id=make_record_id(1, 10, record_offset),
                module_index=1,
                module_name="fixture.obj",
                symbol_stream=10,
                record_offset=record_offset,
                record_length=42,
                record_kind="S_GPROC32",
                record_kind_code=S_GPROC32,
                va=va,
                section=1,
                section_offset=va - 0x82000000,
                size=16,
                type_index=0,
                flags=0,
                raw_name=name,
                parent_offset=0,
                end_offset=0,
                next_offset=0,
                debug_start=0,
                debug_end=16,
            )

        records = (
            procedure(0x82001000, 1, "?Exact@@YAXXZ"),
            procedure(0x82002000, 2, "?FoldA@@YAXXZ"),
            procedure(0x82002000, 3, "?FoldB@@YAXXZ"),
        )
        procedures = ProcedureExtraction(records, build_alias_groups(records))
        materialization = materialize_vtable_hypotheses(
            propose_vtable_alignments(pc_dataset, xbox_dataset),
            inventory,
            procedures,
        )

        with AtlasDatabase.create() as db:
            db.upsert_program(PC_PROGRAM_ID, platform="pc", name="PC")
            db.upsert_program(XBOX_PROGRAM_ID, platform="xbox360", name="Xbox")
            provenance = db.upsert_provenance(
                kind="test", producer="tests.test_build_vtables"
            )
            _insert_pc_inventory(db, inventory, provenance_id=provenance)
            _insert_xbox_procedures(db, procedures, provenance_id=provenance)
            _insert_vtable_dataset(
                db,
                pc_dataset,
                program_id=PC_PROGRAM_ID,
                provenance_id=provenance,
                source_artifact="pc_classes.json",
            )
            _insert_vtable_dataset(
                db,
                xbox_dataset,
                program_id=XBOX_PROGRAM_ID,
                provenance_id=provenance,
                source_artifact="vtables_360.json",
            )
            functions_before = db.connection.execute(
                "SELECT COUNT(*) FROM functions"
            ).fetchone()[0]

            counts = _insert_vtable_hypotheses(
                db, materialization, provenance_id=provenance
            )

            self.assertEqual(counts.table_alignments, 1)
            self.assertEqual(counts.slot_alignments, 4)
            self.assertEqual(counts.hypothesis_sets, 4)
            self.assertEqual(counts.alternatives, 4)
            self.assertEqual(counts.scalar_claims, 2)
            self.assertEqual(counts.xbox_exact_alternatives, 2)
            self.assertEqual(counts.xbox_fold_bundle_alternatives, 1)
            self.assertEqual(counts.xbox_unresolved_alternatives, 1)
            self.assertEqual(counts.pc_unresolved_subjects, 1)
            self.assertEqual(counts.supporting_evidence, 4)
            self.assertEqual(counts.context_evidence, 0)
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM functions"
                ).fetchone()[0],
                functions_before,
            )
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM vtable_slot_alignments"
                ).fetchone()[0],
                4,
            )
            self.assertEqual(
                db.connection.execute(
                    """
                    SELECT COUNT(*) FROM match_hypothesis_alternatives
                    WHERE xbox_fold_group_id IS NOT NULL
                    """
                ).fetchone()[0],
                1,
            )
            # Address-derived observations remain evidence context only; they
            # never create names for the unresolved Xbox target.
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM function_names"
                ).fetchone()[0],
                5,
            )
            observed_names = db.connection.execute(
                """
                SELECT COUNT(*) FROM function_names
                WHERE name LIKE 'observed_%'
                """
            ).fetchone()[0]
            self.assertEqual(observed_names, 0)
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM function_assertions"
                ).fetchone()[0],
                functions_before,
            )

            # Stable occurrence, alternative, claim, and evidence identities
            # make a repeated import idempotent rather than duplicative.
            _insert_vtable_hypotheses(
                db, materialization, provenance_id=provenance
            )
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_sets"
                ).fetchone()[0],
                4,
            )
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_alternatives"
                ).fetchone()[0],
                4,
            )
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_evidence"
                ).fetchone()[0],
                4,
            )
            semantic = semantic_validation_counts(db.connection)
            alignment_checks = {
                name: count
                for name, count in semantic.items()
                if name.startswith("vtable_slot_alignment")
            }
            self.assertTrue(alignment_checks)
            self.assertEqual(set(alignment_checks.values()), {0})


if __name__ == "__main__":
    unittest.main()
