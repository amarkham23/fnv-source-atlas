from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas import __version__  # noqa: E402
import fnv_atlas.release as release_module  # noqa: E402
from fnv_atlas.build import producer_source_id  # noqa: E402
from fnv_atlas.database import AtlasDatabase, ManifestEntry  # noqa: E402
from fnv_atlas.release import (  # noqa: E402
    ARCHIVE_ROOT,
    DEFAULT_SOURCE_DATE_EPOCH,
    ReleaseError,
    create_research_preview,
    verify_research_preview,
)
from fnv_atlas.schema import SCHEMA_VERSION  # noqa: E402
from fnv_atlas.validation import SEMANTIC_CHECKS  # noqa: E402


PUBLIC_DOCUMENTATION_FILES = (
    "docs/CONTRIBUTING.md",
    "docs/CONSUMER_EXPORTS.md",
    "docs/DATA_MODEL.md",
    "docs/DATA_SOURCES.md",
    "docs/MAINTENANCE.md",
    "docs/PUBLICATION.md",
    "docs/REVIEW_WORKFLOW.md",
)


class ResearchPreviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "source-atlas"
        (self.root / "src" / "fnv_atlas").mkdir(parents=True)
        (self.root / "tests").mkdir()
        (self.root / "docs").mkdir()
        (self.root / "scripts").mkdir()
        (self.root / "build").mkdir()
        for source in (PROJECT_ROOT / "src" / "fnv_atlas").glob("*.py"):
            shutil.copyfile(source, self.root / "src" / "fnv_atlas" / source.name)
        (self.root / "README.md").write_text("# Fixture\r\n", encoding="utf-8")
        (self.root / "pyproject.toml").write_text(
            f"""
[project]
name = "fixture"
version = "{__version__}"
license = {{text = "MIT"}}
""".lstrip(),
            encoding="utf-8",
        )
        for relative in PUBLIC_DOCUMENTATION_FILES:
            (self.root / relative).write_text(
                f"# {Path(relative).stem.replace('_', ' ').title()}\n",
                encoding="utf-8",
            )
        (self.root / "tests" / "test_fixture.py").write_text(
            "def test_fixture():\n    pass\n", encoding="utf-8"
        )
        for script_name in (
            "build_research_preview.py",
            "build_source_package.py",
        ):
            shutil.copyfile(
                PROJECT_ROOT / "scripts" / script_name,
                self.root / "scripts" / script_name,
            )
        database_path = self.root / "build" / "fnv-source-atlas.sqlite"
        source_id = producer_source_id()
        with AtlasDatabase.create(database_path) as database:
            content_id = database.register_input_bytes(
                b"fixture input", media_type="application/octet-stream"
            )
            manifest_id = database.create_manifest(
                [
                    ManifestEntry(
                        content_id=content_id,
                        role="fixture",
                        logical_name="fixture.bin",
                    )
                ]
            )
            database.upsert_provenance(
                kind="extraction",
                producer="tests.release_fixture",
                producer_version=__version__,
                method="release boundary fixture",
                manifest_id=manifest_id,
                parameters={
                    "producer_source_id": source_id,
                    "schema_version": SCHEMA_VERSION,
                },
            )
        self.database_digest = hashlib.sha256(database_path.read_bytes()).hexdigest()
        local_path = "C:" + chr(92) + "Users" + chr(92) + "LocalAccount"
        report = {
            "database": local_path + chr(92) + "fnv-source-atlas.sqlite",
            "database_sha256": self.database_digest,
            "schema_version": SCHEMA_VERSION,
            "manifest_id": manifest_id,
            "producer_version": __version__,
            "producer_source_id": source_id,
            "integrity_check": "ok",
            "foreign_key_violations": 0,
            "semantic_violations": {name: 0 for name, _sql in SEMANTIC_CHECKS},
            "pc_sdk_source_tree_sha256": None,
            "pc_sdk_source_files": 0,
            "pc_sdk_prototype_observations": 0,
            "pc_sdk_call_target_observations": 0,
            "pc_sdk_data_observations": 0,
            "pc_sdk_diagnostics": 0,
            "pc_sdk_code_inventory_joins": 0,
            "pc_sdk_data_inventory_joins": 0,
            "pc_sdk_definitive_game_links": 0,
            "pc_sdk_unspecified_entry_candidates": 0,
            "pc_sdk_boundary_candidates": 0,
            "pc_sdk_boundary_containers": 0,
        }
        (self.root / "build" / "fnv-source-atlas.report.json").write_text(
            json.dumps(report), encoding="utf-8"
        )
        (self.root / "build" / "fnv-source-atlas.sqlite.sha256.txt").write_text(
            f"{self.database_digest.upper()} *fnv-source-atlas.sqlite\n",
            encoding="ascii",
        )
        # These are deliberate traps: allowlisting must ignore them completely.
        (self.root / "raw-symbols.pdb").write_bytes(b"proprietary fixture")
        (self.root / "FalloutNV.exe").write_bytes(b"proprietary fixture")
        (self.root / "raw-extraction.json").write_text(
            '{"proprietary": true}\n', encoding="utf-8"
        )
        (self.root / "private-sdk-fixture" / "include").mkdir(parents=True)
        (self.root / "private-sdk-fixture" / "include" / "GameAPI.h").write_text(
            "// raw SDK fixture\n", encoding="utf-8"
        )
        # A documentation file is not public merely because it is under docs/.
        (self.root / "docs" / "SDK_OBSERVATIONS.md").write_text(
            "# Unselected fixture\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _create(self, name: str):
        return create_research_preview(
            self.root, Path(self.temporary.name) / name
        )

    def _rewrite_manifest(self, source_path: Path, output_path: Path, mutate) -> None:
        manifest_name = f"{ARCHIVE_ROOT}/PUBLICATION-MANIFEST.json"
        with zipfile.ZipFile(source_path) as source:
            members = [(info, source.read(info.filename)) for info in source.infolist()]
        rewritten = []
        for info, data in members:
            if info.filename == manifest_name:
                manifest = json.loads(data)
                mutate(manifest)
                data = (
                    json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)
                    + "\n"
                ).encode("utf-8")
            rewritten.append((info, data))
        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_STORED) as output:
            for info, data in sorted(rewritten, key=lambda item: item[0].filename):
                output.writestr(info, data)

    def test_preview_is_deterministic_sanitized_and_database_free(self) -> None:
        first = self._create("first.zip")
        second = self._create("second.zip")
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(first.archive.read_bytes(), second.archive.read_bytes())

        verified = verify_research_preview(
            first.archive, checksum_file=first.checksum_file
        )
        self.assertTrue(verified.checksum_file_verified)
        self.assertEqual(verified.sha256, first.sha256)
        with zipfile.ZipFile(first.archive) as bundle:
            names = bundle.namelist()
            expected_docs = {
                f"{ARCHIVE_ROOT}/{relative}"
                for relative in PUBLIC_DOCUMENTATION_FILES
            }
            self.assertTrue(expected_docs.issubset(names))
            self.assertIn(
                f"{ARCHIVE_ROOT}/scripts/build_source_package.py",
                names,
            )
            self.assertNotIn(
                f"{ARCHIVE_ROOT}/docs/SDK_OBSERVATIONS.md", names
            )
            self.assertFalse(
                any(
                    name.lower().endswith((".sqlite", ".pdb", ".exe"))
                    for name in names
                )
            )
            self.assertFalse(
                any(
                    "private-sdk-fixture" in name or "raw-extraction" in name
                    for name in names
                )
            )
            report = bundle.read(
                f"{ARCHIVE_ROOT}/artifacts/fnv-source-atlas.report.json"
            ).decode("utf-8")
            self.assertNotIn("LocalAccount", report)
            self.assertIn("external; not included", report)
            manifest = json.loads(
                bundle.read(f"{ARCHIVE_ROOT}/PUBLICATION-MANIFEST.json")
            )
            self.assertFalse(manifest["archive_policy"]["database_included"])
            self.assertFalse(manifest["archive_policy"]["executables_included"])
            self.assertFalse(manifest["archive_policy"]["pdb_included"])
            self.assertFalse(manifest["archive_policy"]["raw_inputs_included"])
            self.assertFalse(manifest["archive_policy"]["sdk_source_included"])
            self.assertFalse(
                manifest["archive_policy"]["sdk_derived_observations_included"]
            )
            self.assertEqual(
                manifest["external_database"]["sha256"], self.database_digest
            )
            self.assertTrue(
                manifest["license_review"]["redistribution_review_required"]
            )
            self.assertTrue(
                all(info.compress_type == zipfile.ZIP_STORED for info in bundle.infolist())
            )
            self.assertTrue(
                all(
                    info.date_time == (1980, 1, 1, 0, 0, 0)
                    for info in bundle.infolist()
                )
            )

    def test_schema_snapshot_initializes_an_empty_database(self) -> None:
        result = self._create("schema.zip")
        with zipfile.ZipFile(result.archive) as bundle:
            sql = bundle.read(
                f"{ARCHIVE_ROOT}/schema/source-atlas-v{SCHEMA_VERSION}.sql"
            ).decode("utf-8")
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(sql)
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
            self.assertIsNotNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='match_hypothesis_sets'"
                ).fetchone()
            )
        finally:
            connection.close()

    def test_verifier_requires_every_public_document(self) -> None:
        result = self._create("complete-docs.zip")
        altered = Path(self.temporary.name) / "missing-doc.zip"
        missing_relative = "docs/MAINTENANCE.md"
        missing_name = f"{ARCHIVE_ROOT}/{missing_relative}"
        manifest_name = f"{ARCHIVE_ROOT}/PUBLICATION-MANIFEST.json"
        with zipfile.ZipFile(result.archive) as source:
            members = [
                (info, source.read(info.filename))
                for info in source.infolist()
                if info.filename != missing_name
            ]
        rewritten = []
        for info, data in members:
            if info.filename == manifest_name:
                manifest = json.loads(data)
                manifest["files"] = [
                    entry
                    for entry in manifest["files"]
                    if entry["path"] != missing_relative
                ]
                data = (
                    json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)
                    + "\n"
                ).encode("utf-8")
            rewritten.append((info, data))
        with zipfile.ZipFile(altered, "w", compression=zipfile.ZIP_STORED) as output:
            for info, data in rewritten:
                output.writestr(info, data)
        with self.assertRaisesRegex(ReleaseError, "missing required payloads"):
            verify_research_preview(altered, verify_checksum_file=False)

    def test_verifier_rejects_manifested_sdk_source(self) -> None:
        result = self._create("no-sdk.zip")
        altered = Path(self.temporary.name) / "sdk-injected.zip"
        sdk_relative = "private-sdk-fixture/include/GameAPI.h"
        sdk_name = f"{ARCHIVE_ROOT}/{sdk_relative}"
        sdk_data = b"// raw SDK fixture\n"
        manifest_name = f"{ARCHIVE_ROOT}/PUBLICATION-MANIFEST.json"
        with zipfile.ZipFile(result.archive) as source:
            members = [(info, source.read(info.filename)) for info in source.infolist()]
        timestamp = members[0][0].date_time
        injected = zipfile.ZipInfo(sdk_name, date_time=timestamp)
        injected.compress_type = zipfile.ZIP_STORED
        injected.create_system = 3
        injected.external_attr = (0o100644 & 0xFFFF) << 16
        rewritten = []
        for info, data in members:
            if info.filename == manifest_name:
                manifest = json.loads(data)
                manifest["files"].append(
                    {
                        "path": sdk_relative,
                        "role": "package-source",
                        "sha256": hashlib.sha256(sdk_data).hexdigest(),
                        "size_bytes": len(sdk_data),
                    }
                )
                manifest["files"].sort(key=lambda entry: entry["path"])
                data = (
                    json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)
                    + "\n"
                ).encode("utf-8")
            rewritten.append((info, data))
        rewritten.append((injected, sdk_data))
        with zipfile.ZipFile(altered, "w", compression=zipfile.ZIP_STORED) as output:
            for info, data in sorted(rewritten, key=lambda item: item[0].filename):
                output.writestr(info, data)
        with self.assertRaisesRegex(ReleaseError, "outside the allowlist"):
            verify_research_preview(altered, verify_checksum_file=False)

    def test_legal_file_does_not_imply_third_party_redistribution_clearance(
        self,
    ) -> None:
        (self.root / "LICENSE").write_text("fixture license\n", encoding="utf-8")
        result = self._create("licensed.zip")
        with zipfile.ZipFile(result.archive) as bundle:
            manifest = json.loads(
                bundle.read(f"{ARCHIVE_ROOT}/PUBLICATION-MANIFEST.json")
            )
        review = manifest["license_review"]
        self.assertEqual(review["legal_files"], ["LICENSE"])
        self.assertFalse(review["project_license_file_missing"])
        self.assertTrue(review["redistribution_review_required"])

    def test_sensitive_checkout_path_is_rejected(self) -> None:
        local_path = "C:" + chr(92) + "Users" + chr(92) + "LocalAccount"
        (self.root / "README.md").write_text(local_path + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ReleaseError, "machine-local user path"):
            self._create("sensitive.zip")

    def test_invalid_database_checksum_is_rejected(self) -> None:
        (self.root / "build" / "fnv-source-atlas.sqlite.sha256.txt").write_text(
            "not-a-checksum\n", encoding="ascii"
        )
        with self.assertRaisesRegex(ReleaseError, "checksum"):
            self._create("bad-checksum.zip")

    def test_external_database_bytes_must_match_checksum(self) -> None:
        (self.root / "build" / "fnv-source-atlas.sqlite").write_bytes(b"changed")
        with self.assertRaisesRegex(ReleaseError, "does not match"):
            self._create("wrong-database.zip")

    def test_live_sqlite_sidecar_state_is_rejected(self) -> None:
        database = self.root / "build" / "fnv-source-atlas.sqlite"
        Path(str(database) + "-wal").write_bytes(b"uncommitted fixture")
        with self.assertRaisesRegex(ReleaseError, "live SQLite sidecar"):
            self._create("wal-state.zip")

    def test_public_preview_rejects_private_sdk_derived_rows(self) -> None:
        report_path = self.root / "build" / "fnv-source-atlas.report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["pc_sdk_source_tree_sha256"] = "sha256:" + "1" * 64
        report["pc_sdk_source_files"] = 1
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(
            ReleaseError, "private SDK-derived observations"
        ):
            self._create("private-sdk-derived.zip")

    def test_outputs_may_not_alias_any_protected_input(self) -> None:
        archive = Path(self.temporary.name) / "aliased.zip"
        checksum = archive.with_name(archive.name + ".sha256")
        shutil.copyfile(
            self.root / "build" / "fnv-source-atlas.sqlite.sha256.txt",
            checksum,
        )
        original = checksum.read_bytes()
        with self.assertRaisesRegex(ReleaseError, "aliases protected database checksum"):
            create_research_preview(
                self.root,
                archive,
                database_checksum_path=checksum,
                overwrite=True,
            )
        self.assertEqual(checksum.read_bytes(), original)
        self.assertFalse(archive.exists())

        report = self.root / "build" / "fnv-source-atlas.report.json"
        hardlinked_archive = Path(self.temporary.name) / "hardlinked.zip"
        os.link(report, hardlinked_archive)
        report_before = report.read_bytes()
        with self.assertRaisesRegex(ReleaseError, "aliases protected build report"):
            create_research_preview(
                self.root,
                hardlinked_archive,
                overwrite=True,
            )
        self.assertEqual(report.read_bytes(), report_before)

    def test_database_is_rehashed_at_the_publication_boundary(self) -> None:
        database = self.root / "build" / "fnv-source-atlas.sqlite"
        original_boundary = release_module._verify_public_database_boundary

        def mutate_after_boundary(*args, **kwargs) -> None:
            original_boundary(*args, **kwargs)
            database.write_bytes(b"changed after initial verification")

        with mock.patch.object(
            release_module,
            "_verify_public_database_boundary",
            side_effect=mutate_after_boundary,
        ):
            with self.assertRaisesRegex(
                ReleaseError, "external database changed after checksum verification"
            ):
                self._create("database-race.zip")
        self.assertFalse((Path(self.temporary.name) / "database-race.zip").exists())

    def test_report_database_hash_and_manifest_are_bound_to_database(self) -> None:
        report_path = self.root / "build" / "fnv-source-atlas.report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["database_sha256"] = "0" * 64
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ReleaseError, "not bound to the verified"):
            self._create("wrong-report-database.zip")

        report["database_sha256"] = self.database_digest
        report["manifest_id"] = "sha256:" + "f" * 64
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ReleaseError, "manifest"):
            self._create("wrong-report-manifest.zip")

    def test_review_mutation_requires_a_copy_and_invalidates_build_attestation(self):
        database_path = self.root / "build" / "fnv-source-atlas.sqlite"
        with AtlasDatabase.open(database_path) as database:
            database.upsert_reviewer(
                identity_kind="handle",
                identity_key="fixture-reviewer",
                display_name="Fixture Reviewer",
            )
        digest = hashlib.sha256(database_path.read_bytes()).hexdigest()
        (self.root / "build" / "fnv-source-atlas.sqlite.sha256.txt").write_text(
            f"{digest.upper()} *fnv-source-atlas.sqlite\n", encoding="ascii"
        )
        with self.assertRaisesRegex(ReleaseError, "not bound to the verified"):
            self._create("review-mutated.zip")

    def test_database_sdk_provenance_is_rejected_even_with_a_clean_report(self) -> None:
        database_path = self.root / "build" / "fnv-source-atlas.sqlite"
        report_path = self.root / "build" / "fnv-source-atlas.report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        with AtlasDatabase.open(database_path) as database:
            database.upsert_provenance(
                kind="extraction",
                producer="fnv_atlas.sdk.private_fixture",
                producer_version=__version__,
                method="private fixture",
                manifest_id=report["manifest_id"],
                parameters={
                    "producer_source_id": report["producer_source_id"],
                    "schema_version": SCHEMA_VERSION,
                },
            )
        digest = hashlib.sha256(database_path.read_bytes()).hexdigest()
        report["database_sha256"] = digest
        report_path.write_text(json.dumps(report), encoding="utf-8")
        (self.root / "build" / "fnv-source-atlas.sqlite.sha256.txt").write_text(
            f"{digest.upper()} *fnv-source-atlas.sqlite\n", encoding="ascii"
        )
        with self.assertRaisesRegex(ReleaseError, "SDK extraction provenance"):
            self._create("private-database.zip")

    def test_common_private_key_headers_are_rejected(self) -> None:
        readme = self.root / "README.md"
        for prefix in (
            "",
            "RSA ",
            "EC ",
            "DSA ",
            "OPENSSH ",
            "ENCRYPTED ",
        ):
            marker = "-----BEGIN " + prefix + "PRIVATE KEY-----"
            with self.subTest(marker=marker):
                readme.write_text(marker + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ReleaseError, "private-key marker"):
                    self._create("private-key.zip")

    def test_real_selected_checkout_is_sensitive_scan_clean(self) -> None:
        for relative, path, _role in release_module._selected_repository_files(
            PROJECT_ROOT
        ):
            release_module._normalized_text(path.read_bytes(), logical_name=relative)

    def test_verifier_rejects_private_sdk_fields_in_a_repacked_report(self) -> None:
        result = self._create("clean-report.zip")
        altered = Path(self.temporary.name) / "private-report.zip"
        report_name = f"{ARCHIVE_ROOT}/artifacts/fnv-source-atlas.report.json"
        manifest_name = f"{ARCHIVE_ROOT}/PUBLICATION-MANIFEST.json"
        with zipfile.ZipFile(result.archive) as source:
            members = {
                info.filename: (info, source.read(info.filename))
                for info in source.infolist()
            }
        report = json.loads(members[report_name][1])
        report["pc_sdk_source_tree_sha256"] = "sha256:" + "2" * 64
        report["pc_sdk_source_files"] = 1
        report_bytes = release_module._canonical_json(report)
        members[report_name] = (members[report_name][0], report_bytes)
        manifest = json.loads(members[manifest_name][1])
        relative_report = "artifacts/fnv-source-atlas.report.json"
        for entry in manifest["files"]:
            if entry["path"] == relative_report:
                entry["sha256"] = hashlib.sha256(report_bytes).hexdigest()
                entry["size_bytes"] = len(report_bytes)
                break
        members[manifest_name] = (
            members[manifest_name][0],
            release_module._canonical_json(manifest),
        )
        with zipfile.ZipFile(altered, "w", compression=zipfile.ZIP_STORED) as output:
            for name in sorted(members):
                output.writestr(*members[name])
        with self.assertRaisesRegex(ReleaseError, "private SDK-derived"):
            verify_research_preview(altered, verify_checksum_file=False)

    def test_stale_build_report_is_rejected(self) -> None:
        report_path = self.root / "build" / "fnv-source-atlas.report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["schema_version"] = SCHEMA_VERSION - 1
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ReleaseError, "schema_version is stale"):
            self._create("stale-report.zip")

    def test_stale_producer_source_report_is_rejected(self) -> None:
        report_path = self.root / "build" / "fnv-source-atlas.report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["producer_source_id"] = "sha256:" + "0" * 64
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ReleaseError, "producer_source_id is stale"):
            self._create("stale-source-report.zip")

    def test_failed_semantic_validation_report_is_rejected(self) -> None:
        report_path = self.root / "build" / "fnv-source-atlas.report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["semantic_violations"]["fixture"] = 1
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ReleaseError, "semantic validation violations"):
            self._create("invalid-validation-report.zip")

    def test_verifier_rejects_manifest_version_lie(self) -> None:
        result = self._create("valid-version.zip")
        altered = Path(self.temporary.name) / "altered-version.zip"
        self._rewrite_manifest(
            result.archive,
            altered,
            lambda manifest: manifest.__setitem__("package_version", "99.0.0"),
        )
        with self.assertRaisesRegex(ReleaseError, "package versions differ"):
            verify_research_preview(altered, verify_checksum_file=False)

    def test_verifier_requires_explicit_sdk_exclusion_policy(self) -> None:
        result = self._create("valid-policy.zip")
        altered = Path(self.temporary.name) / "altered-policy.zip"

        def include_sdk_source(manifest) -> None:
            manifest["archive_policy"]["sdk_source_included"] = True

        self._rewrite_manifest(result.archive, altered, include_sdk_source)
        with self.assertRaisesRegex(ReleaseError, "exclude SDK source"):
            verify_research_preview(altered, verify_checksum_file=False)

    def test_verifier_requires_private_sdk_derived_exclusion_policy(self) -> None:
        result = self._create("valid-derived-policy.zip")
        altered = Path(self.temporary.name) / "altered-derived-policy.zip"

        def include_sdk_derived(manifest) -> None:
            manifest["archive_policy"]["sdk_derived_observations_included"] = True

        self._rewrite_manifest(result.archive, altered, include_sdk_derived)
        with self.assertRaisesRegex(ReleaseError, "SDK-derived observations"):
            verify_research_preview(altered, verify_checksum_file=False)

    def test_verifier_rejects_path_traversal_and_archive_tampering(self) -> None:
        result = self._create("valid.zip")
        malicious = Path(self.temporary.name) / "malicious.zip"
        with zipfile.ZipFile(result.archive) as source:
            members = [(info, source.read(info.filename)) for info in source.infolist()]
        escape = zipfile.ZipInfo(
            f"{ARCHIVE_ROOT}/../escape.txt", date_time=members[0][0].date_time
        )
        escape.compress_type = zipfile.ZIP_STORED
        escape.create_system = 3
        escape.external_attr = (0o100644 & 0xFFFF) << 16
        members.append((escape, b"unexpected unmanifested file"))
        with zipfile.ZipFile(malicious, "w", compression=zipfile.ZIP_STORED) as output:
            for info, data in sorted(members, key=lambda item: item[0].filename):
                output.writestr(info, data)
        with self.assertRaisesRegex(ReleaseError, "unsafe archive path"):
            verify_research_preview(malicious, verify_checksum_file=False)

    def test_archive_sidecar_names_and_hashes_exact_archive(self) -> None:
        result = self._create("preview.zip")
        expected = hashlib.sha256(result.archive.read_bytes()).hexdigest()
        self.assertEqual(result.sha256, expected)
        self.assertEqual(
            result.checksum_file.read_text(encoding="ascii"),
            f"{expected} *preview.zip\n",
        )
        self.assertEqual(DEFAULT_SOURCE_DATE_EPOCH, 315532800)


if __name__ == "__main__":
    unittest.main()
