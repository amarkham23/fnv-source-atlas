from __future__ import annotations

import hashlib
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
    ManifestEntry,
    ManifestVerificationError,
    make_address_group_id,
    make_function_id,
    stable_id,
)
from fnv_atlas.schema import APPLICATION_ID, SCHEMA_VERSION, SchemaError  # noqa: E402


class AtlasDatabaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program(
            "pc",
            platform="pc",
            name="FalloutNV.exe",
            architecture="x86",
            image_base=0x400000,
        )
        self.db.upsert_program(
            "x360",
            platform="xbox360",
            name="Fallout_Release_MemDebug.xex",
            architecture="powerpc",
        )
        self.provenance_id = self.db.upsert_provenance(
            kind="test", producer="unit-test", producer_version="1"
        )

    def tearDown(self) -> None:
        self.db.close()

    def _function(
        self,
        program_id: str,
        address: int,
        identity_key: str,
        *,
        type_index: int | None = None,
    ) -> str:
        address_group_id = self.db.upsert_address_group(
            program_id=program_id, address_space="va", address=address
        )
        return self.db.upsert_function(
            address_group_id=address_group_id,
            identity_key=identity_key,
            type_index=type_index,
        )

    def test_schema_is_versioned_and_reopens(self) -> None:
        self.assertEqual(
            self.db.connection.execute("PRAGMA user_version").fetchone()[0],
            SCHEMA_VERSION,
        )
        self.assertEqual(
            self.db.connection.execute("PRAGMA application_id").fetchone()[0],
            APPLICATION_ID,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "atlas.sqlite3"
            with AtlasDatabase.create(path) as created:
                created.upsert_program("pc", platform="pc", name="game.exe")
            with AtlasDatabase.open(path, read_only=True) as reopened:
                count = reopened.connection.execute(
                    "SELECT count(*) FROM programs"
                ).fetchone()[0]
                self.assertEqual(count, 1)
            with AtlasDatabase.open(
                path, read_only=True, immutable=True
            ) as immutable:
                self.assertEqual(
                    immutable.connection.execute(
                        "SELECT count(*) FROM programs"
                    ).fetchone()[0],
                    1,
                )
                with self.assertRaises(sqlite3.OperationalError):
                    immutable.connection.execute(
                        "INSERT INTO programs(program_id, platform, name) "
                        "VALUES ('blocked', 'pc', 'blocked.exe')"
                    )
            with self.assertRaisesRegex(ValueError, "requires read_only"):
                AtlasDatabase.open(path, immutable=True)

    def test_non_atlas_database_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "foreign.sqlite3"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE valuable_data(value TEXT)")
            connection.commit()
            connection.close()
            with self.assertRaises(SchemaError):
                AtlasDatabase.create(path)
            connection = sqlite3.connect(path)
            try:
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT name FROM sqlite_master WHERE name = 'valuable_data'"
                    ).fetchone()
                )
            finally:
                connection.close()

    def test_stable_ids_are_unambiguous_and_repeatable(self) -> None:
        self.assertEqual(stable_id("x", "a:b", "c"), stable_id("x", "a:b", "c"))
        self.assertNotEqual(stable_id("x", "a:b", "c"), stable_id("x", "a", "b:c"))
        group = make_address_group_id("pc", "ram", 0x401000)
        self.assertTrue(group.startswith("address:sha256:"))
        function = make_function_id("pc", "ram", 0x401000, "entry")
        self.assertTrue(function.startswith("function:sha256:"))

    def test_context_observation_does_not_require_a_match_claim(self) -> None:
        function_id = self._function("pc", 0x401000, "entry")
        observation_id = self.db.upsert_observation(
            function_id=function_id,
            observation_kind="public_reference",
            independence_group="public_reference_context",
            provenance_id=self.provenance_id,
            details={"referenced_by": "Patch::Install"},
        )
        row = self.db.connection.execute(
            "SELECT * FROM observations WHERE observation_id = ?",
            (observation_id,),
        ).fetchone()
        self.assertEqual(row["function_id"], function_id)
        self.assertIsNone(row["unresolved_target_id"])
        self.assertEqual(
            self.db.connection.execute("SELECT count(*) FROM match_claims").fetchone()[0],
            0,
        )
        with self.assertRaises(ValueError):
            self.db.upsert_observation(
                observation_kind="invalid",
                independence_group="test",
                provenance_id=self.provenance_id,
            )

    def test_multiple_logical_functions_and_names_survive_one_address(self) -> None:
        module_id = self.db.upsert_module(
            "x360:module:12",
            program_id="x360",
            name="Renderer",
            object_path=r"renderer\shader.obj",
            compiland_index=12,
        )
        source_file_id = self.db.upsert_source_file(
            "x360:source:shader",
            program_id="x360",
            normalized_path=r"game\renderer\shader.cpp",
            language="c++",
        )
        address_group_id = self.db.upsert_address_group(
            program_id="x360", address_space="va", address=0x826F14B0
        )
        first = self.db.upsert_function(
            function_id="x360-proc:m0012:s0008:o00000010",
            address_group_id=address_group_id,
            identity_key="x360-proc:m0012:s0008:o00000010",
            type_index=0x1001,
            module_id=module_id,
            symbol_record_kind="S_GPROC32",
        )
        second = self.db.upsert_function(
            function_id="x360-proc:m0012:s0008:o00000040",
            address_group_id=address_group_id,
            identity_key="x360-proc:m0012:s0008:o00000040",
            type_index=0x1002,
            module_id=module_id,
            symbol_record_kind="S_GPROC32",
        )
        self.db.add_function_name(
            first,
            "NiObject::CreateObject",
            name_kind="qualified",
            is_primary=True,
            provenance_id=self.provenance_id,
        )
        self.db.add_function_name(
            first,
            "?CreateObject@NiObject@@SAPAV1@XZ",
            name_kind="decorated",
            is_primary=True,
            provenance_id=self.provenance_id,
        )
        self.db.add_function_name(
            first,
            "NiObject factory",
            name_kind="display",
            provenance_id=self.provenance_id,
        )
        self.db.add_function_name(
            second,
            "NiAVObject::CreateObject",
            name_kind="qualified",
            is_primary=True,
            provenance_id=self.provenance_id,
        )
        self.db.add_function_source_range(
            first,
            source_file_id,
            line_start=101,
            line_end=117,
            is_primary=True,
            provenance_id=self.provenance_id,
        )

        functions = self.db.functions_at("x360", "va", 0x826F14B0)
        self.assertEqual({item["function_id"] for item in functions}, {first, second})
        first_record = self.db.get_function(first)
        assert first_record is not None
        self.assertEqual(first_record["type_index"], 0x1001)
        self.assertEqual(len(first_record["names"]), 3)
        self.assertEqual(first_record["source_ranges"][0]["line_start"], 101)

    def test_stable_upsert_rejects_identity_motion(self) -> None:
        group = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x401000
        )
        function = self.db.upsert_function(
            function_id="pc:entry:401000",
            address_group_id=group,
            identity_key="ghidra-entry",
        )
        other = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x402000
        )
        with self.assertRaises(IdentityConflictError):
            self.db.upsert_function(
                function_id=function,
                address_group_id=other,
                identity_key="ghidra-entry",
            )
        record = self.db.get_function(function)
        assert record is not None
        self.assertEqual(record["address"], 0x401000)

    def test_nested_transactions_are_atomic_but_savepoints_are_local(self) -> None:
        with self.db.transaction():
            self.db.upsert_module("keep", program_id="pc", name="keep")
            with self.assertRaises(RuntimeError):
                with self.db.transaction():
                    self.db.upsert_module("drop", program_id="pc", name="drop")
                    raise RuntimeError("rollback nested work")
        names = {
            row[0] for row in self.db.connection.execute("SELECT module_id FROM modules")
        }
        self.assertEqual(names, {"keep"})

        with self.assertRaises(RuntimeError):
            with self.db.transaction():
                self.db.upsert_module("outer-drop", program_id="pc", name="outer-drop")
                raise RuntimeError("rollback outer work")
        self.assertIsNone(
            self.db.connection.execute(
                "SELECT 1 FROM modules WHERE module_id = 'outer-drop'"
            ).fetchone()
        )

    def test_batch_uses_one_atomic_transaction_and_rolls_back(self) -> None:
        savepoints: list[str] = []
        self.db.connection.set_trace_callback(
            lambda statement: savepoints.append(statement)
            if statement.startswith("SAVEPOINT")
            else None
        )
        with self.db.batch():
            for index in range(25):
                self.db.upsert_module(
                    f"batch:{index}", program_id="pc", name=f"batch-{index}"
                )
        self.assertEqual(savepoints, [])
        count = self.db.connection.execute(
            "SELECT count(*) FROM modules WHERE module_id LIKE 'batch:%'"
        ).fetchone()[0]
        self.assertEqual(count, 25)

        with self.assertRaises(RuntimeError):
            with self.db.batch():
                self.db.upsert_module(
                    "rolled-back-batch", program_id="pc", name="rolled-back-batch"
                )
                raise RuntimeError("abort the bulk load")
        self.assertIsNone(
            self.db.connection.execute(
                "SELECT 1 FROM modules WHERE module_id = 'rolled-back-batch'"
            ).fetchone()
        )
        self.db.connection.set_trace_callback(None)

    def test_content_addressed_manifest_is_order_independent_and_verifiable(self) -> None:
        pdb_id = self.db.register_input_bytes(
            b"PDB bytes", media_type="application/octet-stream"
        )
        exe_id = self.db.register_input_bytes(
            b"EXE bytes", media_type="application/vnd.microsoft.portable-executable"
        )
        expected_pdb = "sha256:" + hashlib.sha256(b"PDB bytes").hexdigest()
        self.assertEqual(pdb_id, expected_pdb)
        entries = [
            ManifestEntry(exe_id, "target", "FalloutNV.exe"),
            ManifestEntry(pdb_id, "reference-symbols", "Fallout.pdb", {"build": "debug"}),
        ]
        forward = self.db.create_manifest(entries)
        reverse = self.db.create_manifest(reversed(entries))
        self.assertEqual(forward, reverse)
        self.assertTrue(self.db.verify_manifest(forward))

        self.db.connection.execute(
            """
            UPDATE manifest_entries SET logical_name = 'tampered.pdb'
            WHERE manifest_id = ? AND role = 'reference-symbols'
            """,
            (forward,),
        )
        with self.assertRaises(ManifestVerificationError):
            self.db.verify_manifest(forward)

    def test_manifest_verification_rejects_shifted_ordinals(self) -> None:
        first_id = self.db.register_input_bytes(b"first")
        second_id = self.db.register_input_bytes(b"second")
        manifest_id = self.db.create_manifest(
            (
                ManifestEntry(first_id, "first", "first.bin"),
                ManifestEntry(second_id, "second", "second.bin"),
            )
        )
        self.assertTrue(self.db.verify_manifest(manifest_id))

        # Preserve the canonical row order while corrupting both stored ordinals.
        # A verifier that only orders by the column cannot detect this shift.
        self.db.connection.execute(
            """
            UPDATE manifest_entries SET ordinal = ordinal + 10
            WHERE manifest_id = ?
            """,
            (manifest_id,),
        )
        with self.assertRaises(ManifestVerificationError):
            self.db.verify_manifest(manifest_id)

    def test_fold_groups_and_vtable_roles_preserve_aliases(self) -> None:
        first = self._function("pc", 0x4534F0, "slot:Actor::Process")
        second = self._function("pc", 0x4534F0, "slot:TESForm::Unk_01")
        fold_id = self.db.upsert_fold_group(
            "pc:fold:4534f0",
            program_id="pc",
            provenance_id=self.provenance_id,
        )
        self.db.add_fold_member(fold_id, first, member_role="alias")
        self.db.add_fold_member(fold_id, second, member_role="alias")

        self.db.upsert_class(
            "pc:class:Actor", program_id="pc", identity_key="msvc:.?AVActor@@"
        )
        self.db.add_class_name(
            "pc:class:Actor", "Actor", name_kind="qualified", is_primary=True
        )
        self.db.upsert_vtable(
            "pc:vtable:Actor:primary",
            program_id="pc",
            class_id="pc:class:Actor",
            address_space="ram",
            address=0x10D1234,
            vfptr_role="primary:Actor",
            subobject_offset=0,
            declared_slot_count=128,
            provenance_id=self.provenance_id,
        )
        group_id = make_address_group_id("pc", "va", 0x4534F0)
        self.db.upsert_vtable_slot(
            "pc:vtable:Actor:primary",
            42,
            target_address_group_id=group_id,
            declared_type_index=0x2222,
            provenance_id=self.provenance_id,
        )
        record = self.db.get_function(first)
        assert record is not None
        self.assertEqual(record["fold_groups"][0]["fold_group_id"], fold_id)
        slot = self.db.connection.execute(
            "SELECT * FROM vtable_slots WHERE vtable_id = ? AND slot_index = 42",
            ("pc:vtable:Actor:primary",),
        ).fetchone()
        self.assertEqual(slot["target_address_group_id"], group_id)

    def test_vtable_slot_requires_exactly_one_target_kind(self) -> None:
        function = self._function("pc", 0x4534F0, "slot-target")
        group_id = self.db.connection.execute(
            "SELECT address_group_id FROM functions WHERE function_id = ?",
            (function,),
        ).fetchone()[0]
        unresolved = self.db.upsert_unresolved_target(
            address_group_id=group_id,
            target_kind="vtable-slot-target",
            provenance_id=self.provenance_id,
        )
        self.db.upsert_class(
            "pc:class:xor", program_id="pc", identity_key="xor-class"
        )
        self.db.upsert_vtable(
            "pc:vtable:xor",
            program_id="pc",
            class_id="pc:class:xor",
            address_space="ram",
            address=0x10D2000,
            vfptr_role="primary",
            provenance_id=self.provenance_id,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_vtable_slot(
                "pc:vtable:xor",
                0,
                target_address_group_id=group_id,
                unresolved_target_id=unresolved,
                provenance_id=self.provenance_id,
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_vtable_slot(
                "pc:vtable:xor", 0, provenance_id=self.provenance_id
            )

    def test_claims_keep_evidence_independent_and_confidence_explicit(self) -> None:
        pc_function = self._function("pc", 0x401000, "ghidra-entry")
        xbox_function = self._function("x360", 0x82001000, "pdb-record:10")
        claim = self.db.upsert_match_claim(
            pc_function_id=pc_function,
            xbox_function_id=xbox_function,
            provenance_id=self.provenance_id,
            rationale="candidate generated from a structural comparison",
        )
        self.db.add_claim_evidence(
            claim,
            effect="supports",
            evidence_kind="vtable-slot",
            independence_group="class-slot-alignment",
            provenance_id=self.provenance_id,
            details={"pc_slot": 7, "xbox_slot": 7},
        )
        self.db.add_claim_evidence(
            claim,
            effect="supports",
            evidence_kind="vtable-reconstruction",
            independence_group="class-slot-alignment",
            provenance_id=self.provenance_id,
            details={"same_underlying_assumption": True},
        )
        self.db.add_claim_evidence(
            claim,
            effect="contradicts",
            evidence_kind="signature",
            independence_group="type-signature",
            provenance_id=self.provenance_id,
        )
        record = self.db.get_claim(claim)
        assert record is not None
        self.assertIsNone(record["confidence_label"])
        self.assertIsNone(record["confidence_value"])
        self.assertEqual(len(record["evidence"]), 3)
        self.assertEqual(
            [item["independence_group"] for item in record["evidence"]].count(
                "class-slot-alignment"
            ),
            2,
        )

    def test_claim_evidence_strength_is_part_of_assertion_identity(self) -> None:
        pc_function = self._function("pc", 0x401100, "ghidra-entry")
        xbox_function = self._function("x360", 0x82001100, "pdb-record:11")
        claim = self.db.upsert_match_claim(
            pc_function_id=pc_function,
            xbox_function_id=xbox_function,
            provenance_id=self.provenance_id,
        )
        weak = self.db.add_claim_evidence(
            claim,
            effect="supports",
            evidence_kind="manual-review",
            independence_group="manual-review",
            provenance_id=self.provenance_id,
            asserted_strength="weak",
        )
        strong = self.db.add_claim_evidence(
            claim,
            effect="supports",
            evidence_kind="manual-review",
            independence_group="manual-review",
            provenance_id=self.provenance_id,
            asserted_strength="strong",
        )

        self.assertNotEqual(weak, strong)
        stored = self.db.get_claim(claim)
        assert stored is not None
        self.assertEqual(
            {item["asserted_strength"] for item in stored["evidence"]},
            {"weak", "strong"},
        )

    def test_unresolved_claim_endpoint_can_later_be_resolved(self) -> None:
        pc_group = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x500000
        )
        pc_target = self.db.upsert_unresolved_target(
            address_group_id=pc_group,
            target_kind="function-entry",
            reason="not yet imported from Ghidra",
            provenance_id=self.provenance_id,
        )
        xbox_function = self._function("x360", 0x82002000, "pdb-record:20")
        claim = self.db.upsert_match_claim(
            pc_target_id=pc_target,
            xbox_function_id=xbox_function,
            provenance_id=self.provenance_id,
        )
        self.assertIsNotNone(self.db.get_claim(claim))
        self.assertEqual(len(list(self.db.iter_unresolved(program_id="pc"))), 1)

        pc_function = self.db.upsert_function(
            address_group_id=pc_group, identity_key="ghidra-entry"
        )
        self.db.resolve_target(pc_target, pc_function)
        self.assertEqual(len(list(self.db.iter_unresolved(program_id="pc"))), 0)
        resolved = list(self.db.iter_unresolved(program_id="pc", status="resolved"))
        self.assertEqual(resolved[0]["resolved_function_id"], pc_function)

    def test_address_specific_target_cannot_resolve_at_another_address(self) -> None:
        target_group = self.db.upsert_address_group(
            program_id="pc", address_space="ram", address=0x500000
        )
        target = self.db.upsert_unresolved_target(
            address_group_id=target_group,
            target_kind="function-entry",
            provenance_id=self.provenance_id,
        )
        wrong_function = self._function("pc", 0x600000, "different-address")
        with self.assertRaises(IdentityConflictError):
            self.db.resolve_target(target, wrong_function)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                UPDATE unresolved_targets
                SET status = 'resolved', resolved_function_id = ?
                WHERE target_id = ?
                """,
                (wrong_function, target),
            )

        # A name-only target carries no address assertion and may resolve to
        # any function in its own program.
        name_only = self.db.upsert_unresolved_target(
            program_id="pc",
            target_kind="symbol-name",
            name_hint="KnownFunction",
            provenance_id=self.provenance_id,
        )
        self.db.resolve_target(name_only, wrong_function)
        resolved = list(self.db.iter_unresolved(program_id="pc", status="resolved"))
        self.assertEqual(resolved[0]["resolved_function_id"], wrong_function)

    def test_call_edges_preserve_resolved_and_unresolved_callees(self) -> None:
        caller = self._function("pc", 0x401000, "caller")
        callee = self._function("pc", 0x402000, "callee")
        external_group = self.db.upsert_address_group(
            program_id="pc",
            address_space="external",
            address=0x28,
            kind="external",
        )
        external = self.db.upsert_unresolved_target(
            address_group_id=external_group,
            target_kind="external-function",
            name_hint="DebugBreak",
            provenance_id=self.provenance_id,
        )
        direct_edge = self.db.upsert_call_edge(
            caller_function_id=caller,
            callee_function_id=callee,
            call_site_address_space="ram",
            call_site_address=0x401020,
            edge_kind="direct-call",
            provenance_id=self.provenance_id,
        )
        unresolved_edge = self.db.upsert_call_edge(
            caller_function_id=caller,
            unresolved_target_id=external,
            call_site_address_space="ram",
            call_site_address=0x401030,
            edge_kind="external-call",
            provenance_id=self.provenance_id,
            details={"address_space_preserved": True},
        )
        calls = list(self.db.iter_call_edges(caller))
        self.assertEqual({item["edge_id"] for item in calls}, {direct_edge, unresolved_edge})
        self.assertEqual(calls[1]["details"], {"address_space_preserved": True})

        xbox_callee = self._function("x360", 0x82001000, "wrong-program")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_call_edge(
                caller_function_id=caller,
                callee_function_id=xbox_callee,
                provenance_id=self.provenance_id,
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_call_edge(
                caller_function_id=caller,
                callee_function_id=callee,
                unresolved_target_id=external,
                provenance_id=self.provenance_id,
            )

    def test_claim_platform_and_endpoint_constraints_are_enforced(self) -> None:
        pc_function = self._function("pc", 0x401000, "pc")
        xbox_function = self._function("x360", 0x82001000, "xbox")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_match_claim(
                pc_function_id=xbox_function,
                xbox_function_id=pc_function,
                provenance_id=self.provenance_id,
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_match_claim(
                pc_function_id=pc_function,
                xbox_function_id=xbox_function,
                xbox_target_id="also-not-allowed",
                provenance_id=self.provenance_id,
            )

    def test_confidence_must_be_explicit_and_bounded(self) -> None:
        pc_function = self._function("pc", 0x401000, "pc")
        xbox_function = self._function("x360", 0x82001000, "xbox")
        accepted = self.db.upsert_match_claim(
            pc_function_id=pc_function,
            xbox_function_id=xbox_function,
            provenance_id=self.provenance_id,
            confidence_label="manually-confirmed",
            confidence_value=1.0,
        )
        self.assertEqual(self.db.get_claim(accepted)["confidence_value"], 1.0)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.upsert_match_claim(
                claim_id="invalid-confidence",
                pc_function_id=pc_function,
                xbox_function_id=xbox_function,
                provenance_id=self.provenance_id,
                confidence_value=1.01,
            )


if __name__ == "__main__":
    unittest.main()
