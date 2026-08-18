from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.consumer_exports import (  # noqa: E402
    CANDIDATE_REPORT_FORMAT,
    EXPORT_PLAN_FORMAT,
    ConsumerExportError,
    build_candidate_report,
    build_export_plan,
    candidate_report_json,
    export_plan_json,
    render_ghidra_script,
    render_idapython_script,
)
from fnv_atlas.database import AtlasDatabase, ManifestEntry  # noqa: E402


class ConsumerExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary.name) / "atlas.sqlite"
        self.db = AtlasDatabase.create(self.database_path)
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("xbox", platform="xbox360", name="Xbox 360")
        self.executable_bytes = b"fixture FalloutNV executable bytes"
        executable_id = self.db.register_input_bytes(
            self.executable_bytes,
            media_type="application/vnd.microsoft.portable-executable",
        )
        self.manifest = self.db.create_manifest(
            [
                ManifestEntry(
                    executable_id,
                    "pc_executable",
                    "FalloutNV.exe",
                    {"fixture": True},
                )
            ]
        )
        self.provenance = self.db.upsert_provenance(
            kind="fixture",
            producer="consumer-export-tests",
            manifest_id=self.manifest,
        )
        self.reviewer = self.db.upsert_reviewer(
            identity_kind="person",
            identity_key="alice@example.invalid",
            display_name="Alice",
        )
        self.release = self.db.upsert_review_release(
            review_release_id="review-release:fixture",
            release_key="fixture-r1",
            label="Fixture release 1",
            version="1",
            source_revision="abc123",
            manifest_id=self.manifest,
            provenance_id=self.provenance,
        )
        self.other_reviewer = self.db.upsert_reviewer(
            identity_kind="person",
            identity_key="bob@example.invalid",
            display_name="Bob",
        )
        self.pc = self._function("pc", "ram", 0x401000, "pc:main")
        self.xbox = self._function(
            "xbox", "xbox-va", 0x82001000, "xbox:main"
        )
        self.db.add_function_name(
            self.xbox,
            "?DoThing@Actor@@QAEXH@Z",
            name_kind="pdb_procedure_name",
            is_primary=True,
            provenance_id=self.provenance,
        )
        self.claim = self._claim(self.pc, self.xbox)
        self.hypothesis = self.db.upsert_match_hypothesis_set(
            pc_function_id=self.pc,
            provenance_id=self.provenance,
            identity_key="fixture-occurrence",
        )
        self.alternative = self.db.add_match_hypothesis_alternative(
            self.hypothesis, claim_id=self.claim
        )
        self._timestamp = 0

    def tearDown(self) -> None:
        self.db.close()
        self.temporary.cleanup()

    def _function(
        self,
        program_id: str,
        address_space: str,
        address: int,
        identity: str,
        *,
        provenance_id: str | None = None,
    ) -> str:
        group = self.db.upsert_address_group(
            program_id=program_id,
            address_space=address_space,
            address=address,
        )
        return self.db.upsert_function(
            function_id=identity,
            address_group_id=group,
            identity_key=identity,
            provenance_id=provenance_id or self.provenance,
        )

    def _claim(self, pc_function: str, xbox_function: str) -> str:
        return self.db.upsert_match_claim(
            pc_function_id=pc_function,
            xbox_function_id=xbox_function,
            provenance_id=self.provenance,
        )

    def _accept(
        self,
        *,
        reviewer: str | None = None,
        claim: str | None = None,
        alternative: str | None = None,
        hypothesis: str | None = None,
    ) -> str:
        self._timestamp += 1
        return self.db.add_review_decision(
            reviewer_id=reviewer or self.reviewer,
            action="accept",
            decided_at=f"2026-08-17T12:00:{self._timestamp:02d}Z",
            rationale="Explicit fixture acceptance.",
            provenance_id=self.provenance,
            review_release_id=self.release,
            claim_id=claim,
            alternative_id=alternative,
            hypothesis_set_id=hypothesis,
        )

    def test_plan_deduplicates_same_mapping_and_preserves_both_lineages(self) -> None:
        direct = self._accept(claim=self.claim)
        via_alternative = self._accept(alternative=self.alternative)
        # Another reviewer's acceptance never participates in Alice's plan.
        self._accept(reviewer=self.other_reviewer, claim=self.claim)

        first = build_export_plan(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )
        second = build_export_plan(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )

        self.assertEqual(export_plan_json(first), export_plan_json(second))
        document = first.to_dict()
        self.assertEqual(document["format"], EXPORT_PLAN_FORMAT)
        self.assertFalse(document["policy"]["consensus_inferred"])
        self.assertEqual(document["counts"], {"actions": 1, "blocked": 0})
        action = document["actions"][0]
        self.assertEqual(action["pc_address"], 0x401000)
        self.assertEqual(action["xbox_function_id"], self.xbox)
        self.assertEqual(
            {item["decision"]["decision_id"] for item in action["lineages"]},
            {direct, via_alternative},
        )
        self.assertEqual(
            action["xbox_primary_name"], "?DoThing@Actor@@QAEXH@Z"
        )
        self.assertRegex(action["tool_label"], r"^FNVX360_[A-Za-z0-9_]+__[0-9a-f]{12}$")
        self.assertEqual(
            document["pc_executable"]["sha256"],
            hashlib.sha256(self.executable_bytes).hexdigest(),
        )
        self.assertEqual(len(document["plan_sha256"]), 64)
        for lineage in action["lineages"]:
            compatibility = lineage["manifest_compatibility"]
            self.assertTrue(compatibility["compatible"])
            self.assertEqual(
                compatibility["required_manifest_id"], self.manifest
            )
            self.assertTrue(
                all(item["compatible"] for item in compatibility["components"])
            )

    def test_cross_manifest_mapping_is_blocked_even_with_release_decision_provenance(
        self,
    ) -> None:
        other_executable = self.db.register_input_bytes(
            b"different FalloutNV executable bytes",
            media_type="application/vnd.microsoft.portable-executable",
        )
        other_manifest = self.db.create_manifest(
            [
                ManifestEntry(
                    other_executable,
                    "pc_executable",
                    "FalloutNV-other.exe",
                    {"fixture": "other-release"},
                )
            ]
        )
        other_provenance = self.db.upsert_provenance(
            kind="fixture",
            producer="consumer-export-tests-other-manifest",
            manifest_id=other_manifest,
        )
        other_pc = self._function(
            "pc",
            "ram",
            0x402000,
            "pc:other-manifest",
            provenance_id=other_provenance,
        )
        other_xbox = self._function(
            "xbox",
            "xbox-va",
            0x82002000,
            "xbox:other-manifest",
            provenance_id=other_provenance,
        )
        self.db.add_function_name(
            other_xbox,
            "OtherManifestFunction",
            name_kind="pdb_procedure_name",
            is_primary=True,
            provenance_id=other_provenance,
        )
        other_claim = self.db.upsert_match_claim(
            pc_function_id=other_pc,
            xbox_function_id=other_xbox,
            provenance_id=other_provenance,
        )
        other_set = self.db.upsert_match_hypothesis_set(
            pc_function_id=other_pc,
            provenance_id=other_provenance,
            identity_key="other-manifest-occurrence",
        )
        other_alternative = self.db.add_match_hypothesis_alternative(
            other_set,
            claim_id=other_claim,
        )
        decision_id = self._accept(alternative=other_alternative)

        plan = build_export_plan(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )

        self.assertEqual(plan.actions, ())
        self.assertEqual(len(plan.blocked), 1)
        block = plan.blocked[0]
        self.assertEqual(block["lineage"]["decision"]["decision_id"], decision_id)
        self.assertEqual(
            block["lineage"]["decision"]["provenance_id"], self.provenance
        )
        self.assertIn("provenance_manifest_mismatch", block["reasons"])
        compatibility = block["lineage"]["manifest_compatibility"]
        self.assertFalse(compatibility["compatible"])
        self.assertEqual(compatibility["required_manifest_id"], self.manifest)
        self.assertEqual(
            {
                observation["manifest_id"]
                for component in compatibility["components"]
                for observation in component["observations"]
            },
            {other_manifest},
        )

    def test_missing_endpoint_assertion_lineage_blocks_an_otherwise_valid_claim(
        self,
    ) -> None:
        self.db.connection.execute(
            "DELETE FROM function_assertions WHERE function_id = ?",
            (self.xbox,),
        )
        self._accept(claim=self.claim)

        plan = build_export_plan(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )

        self.assertEqual(plan.actions, ())
        self.assertEqual(len(plan.blocked), 1)
        block = plan.blocked[0]
        self.assertEqual(block["reasons"], ["provenance_manifest_mismatch"])
        components = block["lineage"]["manifest_compatibility"]["components"]
        xbox_component = next(
            item
            for item in components
            if item["component_kind"] == "xbox_endpoint_function"
        )
        self.assertFalse(xbox_component["compatible"])
        self.assertEqual(xbox_component["observations"], [])

    def test_scripts_verify_hash_require_exact_existing_entry_and_never_create(self) -> None:
        self._accept(claim=self.claim)
        plan = build_export_plan(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )

        ghidra = render_ghidra_script(plan)
        ida = render_idapython_script(plan)
        expected = hashlib.sha256(self.executable_bytes).hexdigest()
        self.assertIn("getExecutablePath", ghidra)
        self.assertIn("getFunctionAt(address)", ghidra)
        self.assertIn("function.getEntryPoint() != address", ghidra)
        self.assertNotIn("createFunction", ghidra)
        self.assertIn("ida_nalt.get_input_file_path", ida)
        self.assertIn("ida_funcs.get_func(address)", ida)
        self.assertIn("function.start_ea) != address", ida)
        self.assertNotIn("add_func", ida)
        # Payloads are base64 encoded, but the strict mismatch gate is visible.
        self.assertIn("PC executable SHA-256 mismatch", ghidra)
        self.assertIn("PC executable SHA-256 mismatch", ida)
        self.assertIn("embedded action payload failed its digest check", ghidra)
        self.assertIn("embedded action payload failed its digest check", ida)
        self.assertEqual(expected, plan.pc_executable["sha256"])
        compile(ghidra, "accepted-ghidra.py", "exec")
        compile(ida, "accepted-ida.py", "exec")

    def test_only_current_leaf_accept_from_exact_release_is_authorized(self) -> None:
        accepted = self._accept(claim=self.claim)
        second_release = self.db.upsert_review_release(
            release_key="fixture-r2",
            label="Fixture release 2",
            version="2",
            source_revision="def456",
            manifest_id=self.manifest,
            provenance_id=self.provenance,
        )
        self.db.add_review_decision(
            reviewer_id=self.reviewer,
            action="reopen",
            decided_at="2026-08-17T13:00:00Z",
            rationale="New evidence requires another review.",
            provenance_id=self.provenance,
            review_release_id=second_release,
            previous_decision_id=accepted,
            claim_id=self.claim,
        )

        first_plan = build_export_plan(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )
        second_plan = build_export_plan(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=second_release,
        )
        self.assertEqual(first_plan.actions, ())
        self.assertEqual(second_plan.actions, ())
        self.assertEqual(first_plan.blocked, ())
        self.assertEqual(second_plan.blocked, ())

    def test_unsafe_acceptances_are_retained_as_reasoned_blockers(self) -> None:
        self._accept(hypothesis=self.hypothesis)

        fold_first = self._function(
            "xbox", "xbox-va", 0x82002000, "xbox:fold:first"
        )
        fold_second = self._function(
            "xbox", "xbox-va", 0x82002000, "xbox:fold:second"
        )
        fold = self.db.upsert_fold_group(
            "xbox:fold", program_id="xbox", provenance_id=self.provenance
        )
        self.db.add_fold_member(fold, fold_first)
        self.db.add_fold_member(fold, fold_second)
        fold_set = self.db.upsert_match_hypothesis_set(
            pc_function_id=self.pc,
            provenance_id=self.provenance,
            identity_key="fold-occurrence",
        )
        fold_alternative = self.db.add_match_hypothesis_alternative(
            fold_set, xbox_fold_group_id=fold
        )
        self._accept(alternative=fold_alternative)

        target = self.db.upsert_unresolved_target(
            program_id="xbox",
            target_kind="address-only",
            name_hint="unknown Xbox target",
            provenance_id=self.provenance,
        )
        unresolved_claim = self.db.upsert_match_claim(
            pc_function_id=self.pc,
            xbox_target_id=target,
            provenance_id=self.provenance,
        )
        self._accept(claim=unresolved_claim)

        nameless = self._function(
            "xbox", "xbox-va", 0x82003000, "xbox:nameless"
        )
        nameless_claim = self._claim(self.pc, nameless)
        self._accept(claim=nameless_claim)

        plan = build_export_plan(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )
        self.assertEqual(len(plan.actions), 0)
        reasons = {
            reason for item in plan.blocked for reason in item["reasons"]
        }
        self.assertTrue(
            {
                "hypothesis_set_only_acceptance",
                "xbox_fold_bundle",
                "xbox_unresolved_endpoint",
                "missing_xbox_name",
            }.issubset(reasons)
        )
        for item in plan.blocked:
            self.assertEqual(
                item["lineage"]["reviewer"]["reviewer_id"], self.reviewer
            )
            self.assertEqual(
                item["lineage"]["review_release"]["review_release_id"],
                self.release,
            )

    def test_conflicting_destinations_at_one_pc_entry_block_every_decision(self) -> None:
        other_xbox = self._function(
            "xbox", "xbox-va", 0x82004000, "xbox:other"
        )
        self.db.add_function_name(
            other_xbox,
            "OtherDestination",
            name_kind="pdb_procedure_name",
            is_primary=True,
            provenance_id=self.provenance,
        )
        other_claim = self._claim(self.pc, other_xbox)
        self._accept(claim=self.claim)
        self._accept(claim=other_claim)

        plan = build_export_plan(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )
        self.assertEqual(plan.actions, ())
        self.assertEqual(len(plan.blocked), 2)
        for item in plan.blocked:
            self.assertIn("conflicting_accepted_destination", item["reasons"])
            self.assertIn("conflicting_accepted_name", item["reasons"])

    def test_candidate_report_is_separate_non_executable_artifact(self) -> None:
        accepted = self._accept(claim=self.claim)
        report = build_candidate_report(
            self.db.connection,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )
        document = report.to_dict()
        self.assertEqual(document["format"], CANDIDATE_REPORT_FORMAT)
        self.assertFalse(document["executable"])
        claim_record = next(
            item
            for item in document["records"]
            if item["record_kind"] == "claim" and item["target_id"] == self.claim
        )
        self.assertEqual(
            claim_record["reviewer_current_leaf"]["decision_id"], accepted
        )
        self.assertEqual(candidate_report_json(report), candidate_report_json(report))
        with self.assertRaises(TypeError):
            render_ghidra_script(report)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            render_idapython_script(report)  # type: ignore[arg-type]

    def test_path_and_connection_apis_are_select_only(self) -> None:
        self._accept(claim=self.claim)
        self.db.close()
        before = hashlib.sha256(self.database_path.read_bytes()).digest()

        write_actions = {
            sqlite3.SQLITE_INSERT,
            sqlite3.SQLITE_UPDATE,
            sqlite3.SQLITE_DELETE,
            sqlite3.SQLITE_CREATE_INDEX,
            sqlite3.SQLITE_CREATE_TABLE,
            sqlite3.SQLITE_CREATE_TRIGGER,
            sqlite3.SQLITE_CREATE_VIEW,
            sqlite3.SQLITE_DROP_INDEX,
            sqlite3.SQLITE_DROP_TABLE,
            sqlite3.SQLITE_DROP_TRIGGER,
            sqlite3.SQLITE_DROP_VIEW,
            sqlite3.SQLITE_ALTER_TABLE,
        }
        attempted_writes: list[int] = []

        def authorize(action: int, *_: object) -> int:
            if action in write_actions:
                attempted_writes.append(action)
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        uri = self.database_path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        try:
            connection.set_authorizer(authorize)
            from_connection = build_export_plan(
                connection,
                reviewer_id=self.reviewer,
                review_release_id=self.release,
            )
            report = build_candidate_report(
                connection,
                reviewer_id=self.reviewer,
                review_release_id=self.release,
            )
        finally:
            connection.close()
        from_path = build_export_plan(
            self.database_path,
            reviewer_id=self.reviewer,
            review_release_id=self.release,
        )

        self.assertEqual(attempted_writes, [])
        self.assertEqual(export_plan_json(from_connection), export_plan_json(from_path))
        self.assertGreater(len(report.records), 0)
        self.assertEqual(before, hashlib.sha256(self.database_path.read_bytes()).digest())

    def test_release_without_manifest_is_refused(self) -> None:
        release = self.db.upsert_review_release(
            release_key="fixture-no-manifest",
            label="No manifest",
            provenance_id=self.provenance,
        )
        with self.assertRaisesRegex(ConsumerExportError, "no input manifest"):
            build_export_plan(
                self.db.connection,
                reviewer_id=self.reviewer,
                review_release_id=release,
            )

    def test_tampered_normalized_manifest_is_refused(self) -> None:
        self.db.connection.execute(
            """
            UPDATE manifest_entries SET logical_name = 'tampered.exe'
            WHERE manifest_id = ? AND role = 'pc_executable'
            """,
            (self.manifest,),
        )
        with self.assertRaisesRegex(
            ConsumerExportError, "normalized manifest entries"
        ):
            build_export_plan(
                self.db.connection,
                reviewer_id=self.reviewer,
                review_release_id=self.release,
            )


if __name__ == "__main__":
    unittest.main()
