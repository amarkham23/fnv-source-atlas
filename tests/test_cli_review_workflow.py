from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))


from fnv_atlas.cli import main
from fnv_atlas.database import AtlasDatabase, ManifestEntry


class CliReviewWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "atlas.sqlite"
        with AtlasDatabase.create(self.database) as db:
            executable_id = db.register_input_bytes(
                b"fixture PC executable",
                media_type="application/vnd.microsoft.portable-executable",
            )
            self.manifest_id = db.create_manifest(
                (
                    ManifestEntry(
                        content_id=executable_id,
                        role="pc_executable",
                        logical_name="FalloutNV.exe",
                    ),
                )
            )
            provenance = db.upsert_provenance(
                kind="fixture",
                producer="tests.test_cli_review_workflow",
                manifest_id=self.manifest_id,
            )
            db.upsert_program("pc", platform="pc", name="PC")
            db.upsert_program("xbox", platform="xbox360", name="Xbox")
            pc_group = db.upsert_address_group(
                program_id="pc", address_space="ram", address=0x401000
            )
            xbox_group = db.upsert_address_group(
                program_id="xbox", address_space="xbox-va", address=0x82001000
            )
            db.upsert_function(
                function_id="pc:function",
                address_group_id=pc_group,
                identity_key="pc:function",
                provenance_id=provenance,
            )
            db.upsert_function(
                function_id="xbox:function",
                address_group_id=xbox_group,
                identity_key="xbox:function",
                provenance_id=provenance,
            )
            db.add_function_name(
                "xbox:function",
                "Actor::Tick",
                name_kind="pdb",
                is_primary=True,
                provenance_id=provenance,
            )
            claim = db.upsert_match_claim(
                claim_id="claim:fixture",
                pc_function_id="pc:function",
                xbox_function_id="xbox:function",
                provenance_id=provenance,
            )
            hypothesis = db.upsert_match_hypothesis_set(
                hypothesis_set_id="set:fixture",
                identity_key="fixture",
                pc_function_id="pc:function",
                provenance_id=provenance,
            )
            db.add_match_hypothesis_alternative(
                hypothesis,
                alternative_id="alternative:fixture",
                claim_id=claim,
            )
            db.add_match_hypothesis_alternative_evidence(
                "alternative:fixture",
                effect="supports",
                evidence_kind="fixture",
                independence_group="fixture",
                provenance_id=provenance,
            )

    def invoke_json(self, arguments: list[str]) -> dict[str, object]:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(arguments), 0)
        return json.loads(output.getvalue())

    def test_cli_registers_reviews_pages_snapshots_and_guarded_exports(self) -> None:
        reviewer = self.invoke_json(
            [
                "reviewer-register",
                str(self.database),
                "--identity-kind",
                "person",
                "--identity-key",
                "reviewer@example.invalid",
                "--display-name",
                "Fixture Reviewer",
            ]
        )["reviewer_id"]
        release = self.invoke_json(
            [
                "review-release",
                str(self.database),
                "--release-key",
                "fixture-r1",
                "--label",
                "Fixture review 1",
                "--manifest-id",
                self.manifest_id,
            ]
        )["review_release_id"]
        decision = self.invoke_json(
            [
                "review-decide",
                str(self.database),
                "--reviewer",
                str(reviewer),
                "--release",
                str(release),
                "--action",
                "accept",
                "--decided-at",
                "2026-08-17T20:00:00Z",
                "--rationale",
                "Fixture independently inspected.",
                "--alternative",
                "alternative:fixture",
            ]
        )["decision_id"]
        self.assertTrue(str(decision).startswith("review-decision:sha256:"))

        queue = self.root / "queue.json"
        self.invoke_json(
            [
                "review-queue",
                str(self.database),
                "--reviewer",
                str(reviewer),
                "--release",
                str(release),
                "--output",
                str(queue),
            ]
        )
        queue_document = json.loads(queue.read_text(encoding="utf-8"))
        self.assertEqual(queue_document["returned_count"], 1)
        self.assertEqual(
            queue_document["items"][0]["alternatives"][0]["review"]
            ["selected_reviewer"]["state"],
            "accepted",
        )

        snapshot = self.root / "snapshot.json"
        evaluation = self.root / "evaluation.json"
        for command, destination in (
            ("review-snapshot", snapshot),
            ("review-evaluate", evaluation),
        ):
            self.invoke_json(
                [
                    command,
                    str(self.database),
                    "--reviewer",
                    str(reviewer),
                    "--release",
                    str(release),
                    "--output",
                    str(destination),
                ]
            )
            self.assertTrue(destination.is_file())

        plan_path = self.root / "plan.json"
        script_path = self.root / "apply-ghidra.py"
        for export_format, destination in (
            ("plan", plan_path),
            ("ghidra", script_path),
        ):
            self.invoke_json(
                [
                    "consumer-export",
                    str(self.database),
                    "--reviewer",
                    str(reviewer),
                    "--release",
                    str(release),
                    "--format",
                    export_format,
                    "--output",
                    str(destination),
                ]
            )
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        self.assertEqual(plan["counts"], {"actions": 1, "blocked": 0})
        script = script_path.read_text(encoding="utf-8")
        self.assertIn("PC executable SHA-256 mismatch", script)
        self.assertIn("never create", script.lower())
        checksum_path = Path(str(self.database) + ".sha256.txt")
        expected = hashlib.sha256(self.database.read_bytes()).hexdigest().upper()
        self.assertEqual(
            checksum_path.read_text(encoding="ascii"),
            f"{expected} *{self.database.name}\n",
        )


if __name__ == "__main__":
    unittest.main()
