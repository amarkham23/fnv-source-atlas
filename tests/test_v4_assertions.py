from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import AtlasDatabase  # noqa: E402


class MultiProducerAssertionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.first_provenance = self.db.upsert_provenance(
            kind="test", producer="producer-one"
        )
        self.second_provenance = self.db.upsert_provenance(
            kind="test", producer="producer-two"
        )
        self.module = self.db.upsert_module(
            "pc:module", program_id="pc", name="fixture.obj"
        )
        self.group = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x401000
        )

    def tearDown(self) -> None:
        self.db.close()

    def test_conflicting_function_metadata_is_retained_per_producer(self) -> None:
        function = self.db.upsert_function(
            function_id="pc:function",
            address_group_id=self.group,
            identity_key="entry",
            kind="function",
            type_index=0x1000,
            module_id=self.module,
            symbol_record_kind="first-kind",
            provenance_id=self.first_provenance,
            details={"size": 10},
        )
        self.db.upsert_function(
            function_id=function,
            address_group_id=self.group,
            identity_key="entry",
            kind="thunk",
            type_index=0x1001,
            module_id=self.module,
            symbol_record_kind="second-kind",
            provenance_id=self.second_provenance,
            details={"size": 20},
        )
        # Repeating the identical assertion is idempotent.
        self.db.upsert_function(
            function_id=function,
            address_group_id=self.group,
            identity_key="entry",
            kind="thunk",
            type_index=0x1001,
            module_id=self.module,
            symbol_record_kind="second-kind",
            provenance_id=self.second_provenance,
            details={"size": 20},
        )

        assertions = list(self.db.iter_function_assertions(function))
        self.assertEqual(len(assertions), 2)
        self.assertEqual(
            {row["provenance_id"] for row in assertions},
            {self.first_provenance, self.second_provenance},
        )
        self.assertEqual({row["type_index"] for row in assertions}, {0x1000, 0x1001})
        self.assertEqual({row["details"]["size"] for row in assertions}, {10, 20})
        # The compatibility projection may select a value, but neither source
        # assertion disappeared when it changed.
        self.assertEqual(self.db.get_function(function)["type_index"], 0x1001)

    def test_name_range_class_and_slot_assertions_do_not_overwrite_history(self) -> None:
        function = self.db.upsert_function(
            function_id="pc:function",
            address_group_id=self.group,
            identity_key="entry",
        )
        name_id = self.db.add_function_name(
            function,
            "Fixture",
            name_kind="display",
            is_primary=True,
            provenance_id=self.first_provenance,
            details={"spelling": "one"},
        )
        self.db.add_function_name(
            function,
            "Fixture",
            name_kind="display",
            is_primary=False,
            provenance_id=self.second_provenance,
            details={"spelling": "two"},
        )
        self.assertEqual(
            len(list(self.db.iter_function_name_assertions(name_id=name_id))), 2
        )

        source = self.db.upsert_source_file(
            "pc:source", program_id="pc", normalized_path="src/fixture.cpp"
        )
        self.db.add_function_source_range(
            function,
            source,
            line_start=10,
            line_end=15,
            provenance_id=self.first_provenance,
            details={"producer": 1},
        )
        self.db.add_function_source_range(
            function,
            source,
            line_start=10,
            line_end=22,
            provenance_id=self.second_provenance,
            details={"producer": 2},
        )
        ranges = list(self.db.iter_function_source_range_assertions(function))
        self.assertEqual({row["line_end"] for row in ranges}, {15, 22})

        class_id = self.db.upsert_class(
            "pc:class", program_id="pc", identity_key="Fixture"
        )
        class_name_id = self.db.add_class_name(
            class_id,
            "Fixture",
            name_kind="rtti",
            is_primary=True,
            provenance_id=self.first_provenance,
            details={"form": "decorated"},
        )
        self.db.add_class_name(
            class_id,
            "Fixture",
            name_kind="rtti",
            is_primary=False,
            provenance_id=self.second_provenance,
            details={"form": "normalized"},
        )
        self.assertEqual(
            len(
                list(
                    self.db.iter_class_name_assertions(name_id=class_name_id)
                )
            ),
            2,
        )

        vtable = self.db.upsert_vtable(
            "pc:vtable",
            program_id="pc",
            class_id=class_id,
            address_space="ram",
            address=0x500000,
            vfptr_role="primary",
        )
        other_group = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x402000
        )
        self.db.upsert_vtable_slot(
            vtable,
            0,
            target_address_group_id=self.group,
            provenance_id=self.first_provenance,
            details={"producer": 1},
        )
        self.db.upsert_vtable_slot(
            vtable,
            0,
            target_address_group_id=other_group,
            provenance_id=self.second_provenance,
            details={"producer": 2},
        )
        slots = list(self.db.iter_vtable_slot_assertions(vtable, slot_index=0))
        self.assertEqual(len(slots), 2)
        self.assertEqual(
            {row["target_address_group_id"] for row in slots},
            {self.group, other_group},
        )
        canonical = self.db.connection.execute(
            "SELECT target_address_group_id FROM vtable_slots WHERE vtable_id = ?",
            (vtable,),
        ).fetchone()
        self.assertEqual(canonical[0], other_group)

    def test_assertion_rows_require_a_real_producer(self) -> None:
        function = self.db.upsert_function(
            function_id="pc:function",
            address_group_id=self.group,
            identity_key="entry",
        )
        name_id = self.db.add_function_name(
            function, "Fixture", name_kind="display"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                INSERT INTO function_name_assertions
                    (assertion_id, name_id, provenance_id)
                VALUES ('bad', ?, NULL)
                """,
                (name_id,),
            )


if __name__ == "__main__":
    unittest.main()
