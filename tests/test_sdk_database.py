from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest

from fnv_atlas.database import AtlasDatabase, IdentityConflictError, stable_id
from fnv_atlas.pc_inventory import PCFunction, PCInventory, PESection
from fnv_atlas.sdk_inventory import join_sdk_to_pc_inventory
from fnv_atlas.sdk_prototypes import extract_sdk_prototypes


SDK_SOURCE = """
// GAME - 0x401000
void GameExact();
// GECK - 0x401000
void EditorCollision();
class Existing {
    CREATE_OBJECT(Existing, 0x401000);
};
class NewType {
    CREATE_OBJECT(NewType, 0x401020);
};
class Bridge {
public:
    int Run(int value) {
#if GAME
        return ThisCall<int>(0x401000, this, value);
#else
        return CdeclCall<int>(0x401000, value);
#endif
    }
};
class Data {
#if GAME
    static constexpr AddressPtr<int, 0x500010> value;
#else
    static constexpr AddressPtr<int, 0x401010> editorValue;
#endif
    NIRTTI_ADDRESS(0x500020);
};
"""


def _extract_and_join():
    directory = tempfile.TemporaryDirectory()
    root = Path(directory.name)
    (root / "sdk.hpp").write_text(SDK_SOURCE, encoding="utf-8")
    (root / "broken.cpp").write_text(
        "// GAME - pending\nint value = 3;\n", encoding="utf-8"
    )
    (root / "unused.c").write_text("int unused;\n", encoding="utf-8")
    extraction = extract_sdk_prototypes(root)
    inventory = PCInventory(
        image_base=0x400000,
        functions=(
            PCFunction(
                function_id="pc:ram:00401000",
                address=0x401000,
                address_space="ram",
                name="GameExact",
                size=0x40,
                thunk=False,
                in_executable_range=True,
                callees=(),
            ),
        ),
    )
    sections = (
        PESection(".text", 0x401000, 0x402000, 0x20000000),
        PESection(".data", 0x500000, 0x501000, 0xC0000040),
    )
    joined = join_sdk_to_pc_inventory(extraction, inventory, sections)
    return directory, extraction, joined


def _prepare_database() -> tuple[AtlasDatabase, str]:
    db = AtlasDatabase.create(":memory:")
    db.upsert_program("pc", platform="pc", name="Fallout New Vegas PC")
    db.upsert_program(
        "xbox", platform="xbox360", name="Fallout New Vegas Xbox"
    )
    address_group = db.upsert_address_group(
        program_id="pc", address_space="ram", address=0x401000
    )
    db.upsert_function(
        address_group_id=address_group,
        identity_key="inventory",
        function_id="pc:ram:00401000",
    )
    provenance = db.upsert_provenance(
        kind="test", producer="tests.test_sdk_database"
    )
    return db, provenance


class SdkDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory, self.extraction, self.joined = _extract_and_join()
        self.db, self.provenance = _prepare_database()

    def tearDown(self) -> None:
        self.db.close()
        self.directory.cleanup()

    def test_portable_full_payload_variant_links_candidates_and_replay(self):
        canonical_before = {
            table: self.db.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in (
                "address_groups",
                "functions",
                "function_names",
                "vtables",
                "match_claims",
            )
        }
        result = self.db.persist_sdk_extraction(
            "sdk-one",
            self.extraction,
            self.joined,
            pc_program_id="pc",
            provenance_id=self.provenance,
        )

        self.assertEqual(result.source_files, 3)
        self.assertEqual(result.prototypes, len(self.extraction.observations))
        self.assertEqual(result.call_targets, 2)
        self.assertEqual(result.data_addresses, 3)
        self.assertEqual(result.definitive_game_links, 2)
        self.assertEqual(result.unspecified_entry_candidates, 1)
        self.assertEqual(result.boundary_candidates, 1)
        self.assertEqual(result.boundary_containers, 1)
        self.assertTrue(self.db.validate_sdk_extraction("sdk-one"))

        extraction_row = self.db.get_sdk_extraction("sdk-one")
        assert extraction_row is not None
        self.assertNotIn("root", extraction_row)
        self.assertEqual(
            extraction_row["source_tree_sha256"],
            self.extraction.source_tree_sha256,
        )
        self.assertEqual(
            [item["relative_path"] for item in extraction_row["source_files"]],
            ["broken.cpp", "sdk.hpp", "unused.c"],
        )
        calls = list(
            self.db.iter_sdk_call_target_observations(extraction_id="sdk-one")
        )
        self.assertEqual(calls[0]["argument_expressions"], ["this", "value"])
        self.assertIsNone(calls[0]["parameter_types"])
        data = list(self.db.iter_sdk_data_observations(extraction_id="sdk-one"))
        self.assertEqual(
            {(item["program_variant"], item["data_kind"]) for item in data},
            {
                ("game", "address_ptr"),
                ("geck", "address_ptr"),
                ("unspecified_pc", "ni_rtti"),
            },
        )

        code_joins = list(self.db.iter_sdk_code_inventory_joins("sdk-one"))
        game_exact = [
            item for item in code_joins
            if item["classification"] == "pc_function_entry"
        ]
        self.assertTrue(game_exact)
        self.assertTrue(
            all(item["definitive_pc_function_id"] for item in game_exact)
        )
        unspecified_exact = next(
            item for item in code_joins
            if item["classification"]
            == "pc_function_entry_variant_unspecified"
        )
        self.assertIsNone(unspecified_exact["definitive_pc_function_id"])
        self.assertEqual(
            unspecified_exact["candidate_function_id"], "pc:ram:00401000"
        )
        geck = [item for item in code_joins if item["program_variant"] == "geck"]
        self.assertTrue(geck)
        self.assertTrue(
            all(
                item["definitive_pc_function_id"] is None
                and item["candidate_function_id"] is None
                for item in geck
            )
        )
        boundaries = list(self.db.iter_sdk_boundary_candidates("sdk-one"))
        self.assertEqual(boundaries[0]["address"], 0x401020)
        self.assertEqual(
            boundaries[0]["containing_entries"][0]["entry_address"], 0x401000
        )
        self.assertEqual(
            [item["code"] for item in self.db.iter_sdk_diagnostics("sdk-one")],
            ["address_comment_without_address"],
        )
        canonical_after = {
            table: self.db.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in canonical_before
        }
        self.assertEqual(canonical_after, canonical_before)

        self.db.persist_sdk_extraction(
            "sdk-one",
            self.extraction,
            self.joined,
            pc_program_id="pc",
            provenance_id=self.provenance,
        )
        second_provenance = self.db.upsert_provenance(
            kind="test", producer="second-sdk-producer"
        )
        self.db.persist_sdk_extraction(
            "sdk-two",
            self.extraction,
            self.joined,
            pc_program_id="pc",
            provenance_id=second_provenance,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM sdk_prototype_observations"
            ).fetchone()[0],
            len(self.extraction.observations),
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM sdk_prototype_extraction_assertions"
            ).fetchone()[0],
            2 * len(self.extraction.observations),
        )
        with self.assertRaises(IdentityConflictError):
            self.db.persist_sdk_extraction(
                "sdk-one",
                self.extraction,
                self.joined,
                pc_program_id="pc",
                provenance_id=self.provenance,
                details={"changed": True},
            )

    def test_direct_sql_variant_platform_endpoint_and_immutability_guards(self):
        self.db.persist_sdk_extraction(
            "sdk-guards",
            self.extraction,
            self.joined,
            pc_program_id="pc",
            provenance_id=self.provenance,
        )
        geck_join = self.db.connection.execute(
            """
            SELECT code_join_id FROM sdk_code_inventory_joins
            WHERE extraction_id = 'sdk-guards' AND program_variant = 'geck'
            LIMIT 1
            """
        ).fetchone()[0]
        with self.assertRaisesRegex(sqlite3.IntegrityError, "invalid definitive"):
            self.db.connection.execute(
                "INSERT INTO sdk_game_exact_entry_links(code_join_id, function_id) "
                "VALUES (?, 'pc:ram:00401000')",
                (geck_join,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "not PC"):
            self.db.connection.execute(
                """
                INSERT INTO sdk_extractions(
                    extraction_id, source_tree_sha256, pc_program_id,
                    files_scanned, prototype_count,
                    unique_prototype_address_count,
                    game_prototype_address_count, geck_prototype_address_count,
                    call_target_count, data_address_count, diagnostic_count,
                    prototype_join_count, call_target_join_count, data_join_count,
                    definitive_game_link_count,
                    unspecified_entry_candidate_count,
                    boundary_candidate_count, boundary_container_count,
                    provenance_id
                ) VALUES ('wrong-sdk-platform', ?, 'xbox', 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?)
                """,
                (self.extraction.source_tree_sha256, self.provenance),
            )
        prototype_id = self.db.connection.execute(
            "SELECT prototype_observation_id FROM sdk_prototype_observations LIMIT 1"
        ).fetchone()[0]
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.db.connection.execute(
                "UPDATE sdk_prototype_observations SET declared_name = 'changed' "
                "WHERE prototype_observation_id = ?",
                (prototype_id,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "endpoint"):
            self.db.connection.execute(
                "UPDATE functions SET address_group_id = address_group_id "
                "WHERE function_id = 'pc:ram:00401000'"
            )

    def test_late_observation_conflict_rolls_back_sdk_extraction(self):
        rollback_db, provenance = _prepare_database()
        try:
            tree = self.extraction.source_tree_sha256
            rollback_db.connection.execute(
                """
                INSERT INTO sdk_source_trees(
                    source_tree_sha256, file_count, total_byte_count
                ) VALUES (?, ?, ?)
                """,
                (
                    tree,
                    len(self.extraction.source_files),
                    sum(item.byte_length for item in self.extraction.source_files),
                ),
            )
            file_ids = {}
            for item in self.extraction.source_files:
                file_id = stable_id("sdk-source-file", tree, item.relative_path)
                file_ids[item.relative_path] = file_id
                rollback_db.connection.execute(
                    """
                    INSERT INTO sdk_source_tree_files(
                        source_file_id, source_tree_sha256, relative_path,
                        relative_path_casefold, source_file_sha256, byte_length
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        file_id,
                        tree,
                        item.relative_path,
                        item.relative_path.casefold(),
                        item.sha256,
                        item.byte_length,
                    ),
                )
            observation = self.extraction.observations[0]
            observation_id = stable_id(
                "sdk-prototype-observation", tree, observation.observation_id
            )
            rollback_db.connection.execute(
                """
                INSERT INTO sdk_prototype_observations(
                    prototype_observation_id, source_tree_sha256,
                    source_observation_id, source_file_id, program_variant,
                    address, declared_name, signature, evidence_kind,
                    source_path, source_file_sha256, address_line,
                    declaration_line, source_text, address_ordinal,
                    declaration_text
                ) VALUES (?, ?, ?, ?, ?, ?, 'conflicting-name', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    tree,
                    observation.observation_id,
                    file_ids[observation.source_path],
                    observation.program_variant,
                    observation.address,
                    observation.signature,
                    observation.evidence_kind,
                    observation.source_path,
                    observation.source_file_sha256,
                    observation.address_line,
                    observation.declaration_line,
                    observation.source_text,
                    observation.address_ordinal,
                    observation.declaration_text,
                ),
            )

            with self.assertRaises(IdentityConflictError):
                rollback_db.persist_sdk_extraction(
                    "rollback-sdk",
                    self.extraction,
                    self.joined,
                    pc_program_id="pc",
                    provenance_id=provenance,
                )
            self.assertIsNone(rollback_db.get_sdk_extraction("rollback-sdk"))
            self.assertEqual(
                rollback_db.connection.execute(
                    "SELECT COUNT(*) FROM sdk_code_inventory_joins"
                ).fetchone()[0],
                0,
            )
        finally:
            rollback_db.close()


if __name__ == "__main__":
    unittest.main()
