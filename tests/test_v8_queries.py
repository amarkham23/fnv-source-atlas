from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))


from fnv_atlas.pdb_globals import (  # noqa: E402
    DataSymbolExtraction,
    build_data_address_groups,
)
from fnv_atlas.cli import main  # noqa: E402
from fnv_atlas.query import (  # noqa: E402
    AtlasQuery,
    QueryError,
    render_human,
)
from test_sdk_database import _extract_and_join, _prepare_database  # noqa: E402
from test_type_data_database import (  # noqa: E402
    _data_record,
    _tpi_fixture,
)
from test_vftable_database import _corpus  # noqa: E402


class V8QueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sdk_directory, sdk_extraction, sdk_join = _extract_and_join()
        self.db, self.provenance = _prepare_database()
        self.type_result = self.db.persist_tpi_layout_corpus(
            _tpi_fixture(),
            program_id="xbox",
            provenance_id=self.provenance,
        )
        data_records = (
            _data_record(
                1,
                4,
                va=0x82001000,
                name="first",
                type_index=0x74,
            ),
            _data_record(
                1,
                32,
                va=0x82001000,
                name="alias",
                type_index=0xBEEF,
            ),
            _data_record(
                2,
                4,
                va=None,
                name="unresolved",
                type_index=0xDEAD,
            ),
        )
        self.data_result = self.db.persist_data_symbol_extraction(
            DataSymbolExtraction(
                data_records, build_data_address_groups(data_records)
            ),
            program_id="xbox",
            provenance_id=self.provenance,
        )
        self.db.persist_vftable_corpus(
            "vftable-query-fixture",
            _corpus(),
            program_id="xbox",
            provenance_id=self.provenance,
        )
        self.db.persist_sdk_extraction(
            "sdk-query-fixture",
            sdk_extraction,
            sdk_join,
            pc_program_id="pc",
            provenance_id=self.provenance,
        )
        self.query = AtlasQuery(self.db.connection)

    def tearDown(self) -> None:
        self.db.close()
        self.sdk_directory.cleanup()

    def test_codeview_lookup_retains_duplicate_tags_and_forwards(self) -> None:
        result = self.query.codeview_type("Duplicate", name_mode="exact")

        self.assertEqual(result["physical_records_page"]["total"], 3)
        self.assertIn(
            "multiple_physical_type_identities_match",
            result["ambiguity"]["reasons"],
        )
        layouts = [
            layout
            for record in result["physical_records"]
            for layout in record["tag_layouts"]
        ]
        self.assertEqual(
            [layout["is_forward_reference"] for layout in layouts],
            [False, False, True],
        )
        self.assertEqual(
            {layout["unique_name"] for layout in layouts},
            {".?AVDuplicate@One@@", ".?AVDuplicate@Two@@"},
        )
        self.assertIn(
            "forward_references_and_definitions_coexist",
            result["ambiguity"]["reasons"],
        )
        definition = next(
            layout for layout in layouts if not layout["is_forward_reference"]
        )
        self.assertEqual(definition["members_page"]["total"], 2)
        self.assertEqual(
            [item["method_type_index_hex"] for item in definition["members"][1]["overloads"]],
            ["0x2000", "0x2001"],
        )

        by_index = self.query.codeview_type("0x1300", member_limit=1)
        self.assertEqual(by_index["physical_records_page"]["total"], 1)
        self.assertEqual(
            by_index["physical_records"][0]["type_index_hex"], "0x1300"
        )
        self.assertTrue(
            by_index["physical_records"][0]["tag_layouts"][0]["members_page"][
                "has_more"
            ]
        )
        next_member = self.query.codeview_type(
            "0x1300", member_limit=1, member_offset=1
        )
        self.assertNotEqual(
            by_index["physical_records"][0]["tag_layouts"][0]["members"][0][
                "field_member_id"
            ],
            next_member["physical_records"][0]["tag_layouts"][0]["members"][0][
                "field_member_id"
            ],
        )

        first = self.query.codeview_type(
            "plic", name_mode="contains", limit=1
        )
        second = self.query.codeview_type(
            "plic", name_mode="contains", limit=1, offset=1
        )
        self.assertEqual(first["physical_records_page"]["total"], 3)
        self.assertNotEqual(
            first["physical_records"][0]["type_record_id"],
            second["physical_records"][0]["type_record_id"],
        )
        json.dumps(result, sort_keys=True)

    def test_data_lookup_retains_aliases_and_unresolved_records(self) -> None:
        address = self.query.xbox_data("0x82001000")

        self.assertEqual(address["physical_records_page"]["total"], 2)
        self.assertEqual(
            {
                assertion["raw_name"]
                for record in address["physical_records"]
                for assertion in record["assertions"]
            },
            {"first", "alias"},
        )
        self.assertIn(
            "same_address_has_multiple_physical_data_records",
            address["ambiguity"]["reasons"],
        )

        unresolved = self.query.xbox_data("unresolved")
        self.assertEqual(unresolved["physical_records_page"]["total"], 1)
        assertion = unresolved["physical_records"][0]["assertions"][0]
        self.assertFalse(assertion["is_resolved"])
        self.assertIsNone(assertion["address_group_id"])
        self.assertEqual(assertion["type_index_hex"], "0xDEAD")
        self.assertIn(
            "one_or_more_records_have_unresolved_addresses",
            unresolved["ambiguity"]["reasons"],
        )
        self.assertIn("<unresolved>", render_human(unresolved))

    def test_raw_vftable_lookup_preserves_groups_and_boundary_semantics(self) -> None:
        result = self.query.xbox_vftable("0x82001000")

        self.assertEqual(result["physical_records_page"]["total"], 2)
        self.assertEqual(len(result["address_observations"]), 1)
        group = result["address_observations"][0]
        self.assertEqual(len(group["physical_members"]), 2)
        self.assertTrue(
            all(not member["is_ranked"] for member in group["physical_members"])
        )
        run = group["observed_pointer_prefix"]
        self.assertIsNotNone(run)
        assert run is not None
        self.assertEqual(run["observed_pointer_count"], 3)
        self.assertEqual(
            run["extent_semantics"],
            "observed_pointer_prefix_not_declared_extent",
        )
        self.assertEqual(
            run["boundary_relation"], "next_vftable_inside_pointer_run"
        )
        self.assertNotIn("extent", run)
        self.assertIn("not a declared or inferred vftable extent", run["semantics"])
        second_slot = self.query.xbox_vftable(
            "0x82001000", slot_limit=1, slot_offset=1
        )["address_observations"][0]["observed_pointer_prefix"]
        assert second_slot is not None
        self.assertEqual(
            second_slot["observed_pointer_slots"][0]["slot_index"], 1
        )

        names = self.query.xbox_vftable("First", name_mode="contains")
        self.assertEqual(names["physical_records_page"]["total"], 2)
        self.assertEqual(
            len(names["address_observations"][0]["physical_members"]), 2
        )
        unresolved = self.query.xbox_vftable(
            "??_7Unresolved@@6B@", name_mode="exact"
        )
        self.assertIsNone(
            unresolved["physical_records"][0]["assertions"][0]["resolved_va"]
        )
        self.assertIn(
            "unresolved_pe_section",
            [item["code"] for item in unresolved["extraction_diagnostics"]],
        )
        self.assertIn("observed pointer prefix", render_human(result))

    def test_sdk_lookup_preserves_variant_classification_and_link_strength(self) -> None:
        result = self.query.sdk("0x401000")

        self.assertGreater(result["observations_page"]["total"], 1)
        self.assertEqual(
            set(result["observed_program_variants"]),
            {"game", "geck", "unspecified_pc"},
        )
        self.assertIn(
            "definitive_game_exact_entry", result["observed_pc_link_kinds"]
        )
        self.assertIn(
            "variant_unspecified_exact_entry_candidate",
            result["observed_pc_link_kinds"],
        )
        geck = self.query.sdk("0x401000", program_variant="geck")
        self.assertTrue(geck["observations"])
        self.assertTrue(
            all(
                join["pc_link"]["link_kind"] == "none"
                for observation in geck["observations"]
                for join in observation["inventory_joins"]
            )
        )

        boundary = self.query.sdk("NewType", name_mode="contains")
        self.assertGreater(boundary["boundary_candidate_count_on_page"], 0)
        boundary_rows = [
            candidate
            for observation in boundary["observations"]
            for join in observation["inventory_joins"]
            for candidate in join.get("boundary_candidates", [])
        ]
        self.assertTrue(boundary_rows)
        self.assertTrue(
            all(item["promotion_status"] == "candidate_only" for item in boundary_rows)
        )

        by_file = self.query.sdk("sdk.hpp", name_mode="contains", limit=1)
        by_file_next = self.query.sdk(
            "sdk.hpp", name_mode="contains", limit=1, offset=1
        )
        self.assertTrue(by_file["observations_page"]["has_more"])
        self.assertNotEqual(
            (
                by_file["observations"][0]["observation_kind"],
                by_file["observations"][0]["source_observation_id"],
            ),
            (
                by_file_next["observations"][0]["observation_kind"],
                by_file_next["observations"][0]["source_observation_id"],
            ),
        )
        self.assertIn("classification=", render_human(result))
        json.dumps(result, sort_keys=True)

    def test_v8_queries_issue_selects_only(self) -> None:
        actions: list[int] = []
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}

        def authorizer(
            action: int,
            _arg1: str | None,
            _arg2: str | None,
            _database: str | None,
            _trigger: str | None,
        ) -> int:
            actions.append(action)
            return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY

        before = self.db.connection.total_changes
        self.db.connection.set_authorizer(authorizer)
        try:
            self.query.codeview_type(0x1300)
            self.query.xbox_data(0x82001000)
            self.query.xbox_vftable(0x82001000)
            self.query.sdk(0x401000)
        finally:
            self.db.connection.set_authorizer(None)
        self.assertTrue(actions)
        self.assertLessEqual(set(actions), allowed)
        self.assertEqual(self.db.connection.total_changes, before)

    def test_v8_query_arguments_are_bounded_and_explicit(self) -> None:
        with self.assertRaises(QueryError):
            self.query.codeview_type("Duplicate", name_mode="fuzzy")
        with self.assertRaises(QueryError):
            self.query.xbox_data("", name_mode="contains")
        with self.assertRaises(QueryError):
            self.query.xbox_vftable("First", limit=0)
        with self.assertRaises(QueryError):
            self.query.sdk("Existing", program_variant="both")
        with self.assertRaises(QueryError):
            self.query.sdk("Existing", observation_kind="function")

    def test_cli_exposes_all_v8_query_surfaces_as_stable_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "atlas.sqlite"
            destination = sqlite3.connect(database)
            try:
                self.db.connection.backup(destination)
            finally:
                destination.close()

            for command, query in (
                ("type", "Duplicate"),
                ("data", "0x82001000"),
                ("raw-vftable", "0x82001000"),
                ("sdk", "0x401000"),
            ):
                first = io.StringIO()
                second = io.StringIO()
                arguments = [command, str(database), query, "--json"]
                with redirect_stdout(first):
                    self.assertEqual(main(arguments), 0)
                with redirect_stdout(second):
                    self.assertEqual(main(arguments), 0)
                self.assertEqual(first.getvalue(), second.getvalue())
                self.assertIsInstance(json.loads(first.getvalue()), dict)


if __name__ == "__main__":
    unittest.main()
