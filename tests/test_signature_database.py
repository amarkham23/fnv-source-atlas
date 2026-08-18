from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import (  # noqa: E402
    AtlasDatabase,
    IdentityConflictError,
)
from fnv_atlas.schema import APPLICATION_ID, SCHEMA_VERSION, SchemaError  # noqa: E402
from fnv_atlas.tpi_signatures import (  # noqa: E402
    FunctionSignature,
    LF_MFUNCTION,
    LF_PROCEDURE,
    SignatureResult,
)


def _procedure_signature(type_index: int) -> FunctionSignature:
    return FunctionSignature(
        type_index=type_index,
        leaf_kind=LF_PROCEDURE,
        leaf_name="LF_PROCEDURE",
        return_type_index=0x75,
        class_type_index=None,
        this_type_index=None,
        calling_convention=0x0F,
        calling_convention_name="ppc_call",
        attributes=0xA5,
        this_adjustment=None,
        parameter_count=1,
        argument_list_type_index=0x2222,
        argument_list_count=2,
        argument_type_indices=(0x74, 0),
        is_variadic=True,
        rendered_return_type="unsigned int",
        rendered_class_type=None,
        rendered_this_type=None,
        rendered_argument_types=("int", "..."),
        rendered_signature="unsigned int __ppccall (int, ...)",
    )


def _member_signature(type_index: int) -> FunctionSignature:
    return FunctionSignature(
        type_index=type_index,
        leaf_kind=LF_MFUNCTION,
        leaf_name="LF_MFUNCTION",
        return_type_index=3,
        class_type_index=0x3000,
        this_type_index=0x3001,
        calling_convention=0,
        calling_convention_name="near_c",
        attributes=2,
        this_adjustment=-8,
        parameter_count=1,
        argument_list_type_index=0x3002,
        argument_list_count=1,
        argument_type_indices=(0x74,),
        is_variadic=False,
        rendered_return_type="void",
        rendered_class_type="Actor",
        rendered_this_type="Actor*",
        rendered_argument_types=("int",),
        rendered_signature="void __cdecl Actor::*(int)",
    )


class SignatureDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program(
            "x360", platform="xbox360", name="Fallout Release MemDebug"
        )
        self.provenance = self.db.upsert_provenance(
            kind="extractor",
            producer="fnv_atlas.tpi_signatures",
            producer_version="1",
        )

    def tearDown(self) -> None:
        self.db.close()

    def _function(
        self,
        function_id: str,
        type_index: int,
        *,
        address: int = 0x82001000,
        identity_key: str | None = None,
    ) -> str:
        group = self.db.upsert_address_group(
            program_id="x360", address_space="va", address=address
        )
        return self.db.upsert_function(
            function_id=function_id,
            address_group_id=group,
            identity_key=identity_key or function_id,
            type_index=type_index,
            symbol_record_kind="S_GPROC32",
        )

    def test_exact_resolved_signature_and_arguments_round_trip(self) -> None:
        function = self._function("x360-proc:1", 0x2000)
        signature = _procedure_signature(0x2000)
        self.db.upsert_signature_result(
            function,
            SignatureResult(0x2000, signature),
            provenance_id=self.provenance,
            details={"tpi_stream": 2},
        )

        stored = self.db.get_function_signature(function)
        assert stored is not None
        self.assertEqual(stored["function_id"], function)
        self.assertEqual(stored["type_index"], 0x2000)
        self.assertEqual(stored["resolution_status"], "resolved")
        self.assertEqual(stored["leaf_kind"], LF_PROCEDURE)
        self.assertEqual(stored["return_type_index"], 0x75)
        self.assertEqual(stored["calling_convention"], 0x0F)
        self.assertEqual(stored["attributes"], 0xA5)
        self.assertEqual(stored["parameter_count"], 1)
        self.assertEqual(stored["argument_list_type_index"], 0x2222)
        self.assertEqual(stored["argument_list_count"], 2)
        self.assertTrue(stored["is_variadic"])
        self.assertEqual(stored["details"], {"tpi_stream": 2})
        self.assertEqual(
            [argument["type_index"] for argument in stored["arguments"]],
            [0x74, 0],
        )
        self.assertFalse(stored["arguments"][0]["is_vararg_marker"])
        self.assertTrue(stored["arguments"][1]["is_vararg_marker"])

        # A deterministic rerun updates metadata but creates no duplicate args.
        self.db.upsert_signature_result(
            function,
            SignatureResult(0x2000, signature),
            provenance_id=self.provenance,
            details={"rerun": True},
        )
        rerun = self.db.get_function_signature(function)
        assert rerun is not None
        self.assertEqual(len(rerun["arguments"]), 2)
        self.assertEqual(rerun["details"], {"rerun": True})

    def test_member_fields_and_signed_this_adjustment_round_trip(self) -> None:
        function = self._function("x360-proc:member", 0x2100)
        signature = _member_signature(0x2100)
        self.db.upsert_signature_result(
            function,
            SignatureResult(0x2100, signature),
            provenance_id=self.provenance,
        )
        stored = self.db.get_function_signature(function)
        assert stored is not None
        self.assertEqual(stored["leaf_kind"], LF_MFUNCTION)
        self.assertEqual(stored["class_type_index"], 0x3000)
        self.assertEqual(stored["this_type_index"], 0x3001)
        self.assertEqual(stored["this_adjustment"], -8)
        self.assertEqual(stored["rendered_class_type"], "Actor")

    def test_unresolved_havok_type_is_a_first_class_resolution_row(self) -> None:
        function = self._function("x360-proc:havok", 0xAC8B)
        unresolved = SignatureResult(
            type_index=0xAC8B,
            signature=None,
            error_code="not_function_type",
            error_message="type index 0xAC8B is LF_POINTER",
            actual_leaf_kind=0x1002,
            actual_leaf_name="LF_POINTER",
        )
        self.db.upsert_signature_result(
            function,
            unresolved,
            provenance_id=self.provenance,
            details={"module_family": "Havok SDK"},
        )

        stored = self.db.get_function_signature(function)
        assert stored is not None
        self.assertEqual(stored["resolution_status"], "unresolved")
        self.assertEqual(stored["type_index"], 0xAC8B)
        self.assertEqual(stored["leaf_kind"], 0x1002)
        self.assertEqual(stored["error_code"], "not_function_type")
        self.assertEqual(stored["arguments"], [])
        self.assertEqual(stored["provenance_id"], self.provenance)
        self.assertEqual(stored["details"], {"module_family": "Havok SDK"})

    def test_signature_rows_are_per_function_not_per_name_or_address(self) -> None:
        first = self._function("x360-proc:fold:1", 0x2200, identity_key="record-1")
        second = self._function("x360-proc:fold:2", 0x2200, identity_key="record-2")
        for function in (first, second):
            self.db.add_function_name(
                function, "folded_name", name_kind="display", is_primary=True
            )
            self.db.upsert_signature_result(
                function,
                SignatureResult(0x2200, _procedure_signature(0x2200)),
                provenance_id=self.provenance,
            )
        rows = list(self.db.iter_function_signatures(program_id="x360"))
        self.assertEqual({row["function_id"] for row in rows}, {first, second})
        self.assertEqual(len(rows), 2)

    def test_type_identity_and_structural_constraints_are_enforced(self) -> None:
        function = self._function("x360-proc:identity", 0x2300)
        with self.assertRaises(IdentityConflictError):
            self.db.upsert_signature_result(
                function,
                SignatureResult(0x2301, _procedure_signature(0x2301)),
                provenance_id=self.provenance,
            )

        unresolved = SignatureResult(
            0x2300,
            None,
            error_code="not_function_type",
            actual_leaf_kind=0x1002,
            actual_leaf_name="LF_POINTER",
        )
        self.db.upsert_signature_result(
            function, unresolved, provenance_id=self.provenance
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                INSERT INTO function_signature_arguments
                    (function_id, position, type_index, rendered_type)
                VALUES (?, 0, 116, 'int')
                """,
                (function,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE functions SET type_index = 0x2301 WHERE function_id = ?",
                (function,),
            )

    def test_schema_upgrade_policy_requires_rebuild(self) -> None:
        self.assertGreaterEqual(SCHEMA_VERSION, 3)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "old-atlas.sqlite"
            connection = sqlite3.connect(path)
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION - 1}")
            connection.commit()
            connection.close()
            with self.assertRaises(SchemaError):
                AtlasDatabase.create(path)
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0],
                    SCHEMA_VERSION - 1,
                )
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()

