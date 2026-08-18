from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
from io import StringIO
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "build_source_package.py"
SPEC = importlib.util.spec_from_file_location("build_source_package", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
source_package = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = source_package
SPEC.loader.exec_module(source_package)


PUBLIC_DOCUMENTATION = (
    "docs/CONTRIBUTING.md",
    "docs/CONSUMER_EXPORTS.md",
    "docs/DATA_MODEL.md",
    "docs/DATA_SOURCES.md",
    "docs/MAINTENANCE.md",
    "docs/PUBLICATION.md",
    "docs/REVIEW_WORKFLOW.md",
)
FORBIDDEN_SUFFIXES = (
    ".7z",
    ".db",
    ".dll",
    ".dmp",
    ".exe",
    ".pdb",
    ".sqlite",
    ".sqlite3",
    ".whl",
    ".xex",
    ".zip",
)


class SourcePackageTests(unittest.TestCase):
    def test_atomic_publication_does_not_clobber_a_late_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name)
            temporary = root / "prepared.tmp"
            destination = root / "package.tar.gz"
            temporary.write_bytes(b"prepared")
            destination.write_bytes(b"appeared late")
            with self.assertRaisesRegex(
                source_package.SourcePackageError, "appeared while packaging"
            ):
                source_package._publish_temporary(
                    temporary,
                    destination,
                    overwrite=False,
                )
            self.assertEqual(destination.read_bytes(), b"appeared late")
            self.assertEqual(temporary.read_bytes(), b"prepared")

    def test_source_tree_guard_rejects_reparse_points_and_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            root = Path(temporary_name).resolve()
            inside = root / "inside"
            inside.mkdir()
            outside = root.parent / f"{root.name}-outside"
            outside.mkdir()
            self.addCleanup(lambda: outside.rmdir() if outside.exists() else None)

            source_package._assert_safe_source_tree(inside, root)
            with self.assertRaisesRegex(
                source_package.SourcePackageError, "escapes the repository root"
            ):
                source_package._assert_safe_source_tree(outside, root)

            path_type = type(inside)
            original_is_junction = path_type.is_junction
            with mock.patch.object(
                path_type,
                "is_junction",
                lambda self: self == inside or original_is_junction(self),
            ):
                with self.assertRaisesRegex(
                    source_package.SourcePackageError, "reparse point"
                ):
                    source_package._assert_safe_source_tree(inside, root)

    def test_manifest_has_explicit_public_boundary(self) -> None:
        manifest = (PROJECT_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        for relative in (
            ".gitattributes",
            "LICENSE",
            "scripts/build_research_preview.py",
            "scripts/build_source_package.py",
            *PUBLIC_DOCUMENTATION,
        ):
            self.assertIn(f"include {relative}\n", manifest)
        self.assertIn("recursive-include tests test_*.py\n", manifest)
        self.assertNotIn("recursive-include docs", manifest)
        for pattern in ("*.pdb", "*.exe", "*.sqlite", "*.zip", "*.whl"):
            self.assertIn(pattern, manifest)
        self.assertEqual(
            set(PUBLIC_DOCUMENTATION),
            source_package._PUBLIC_DOCUMENTATION_FILES,
        )

    def test_canonical_sdist_is_complete_safe_and_repeatable(self) -> None:
        epoch = 1_704_067_200
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            fixture = temporary / "fixture"
            fixture.mkdir()
            source_package._copy_build_inputs(PROJECT_ROOT, fixture)
            (fixture / "docs" / "UNSELECTED.md").write_text(
                "not part of the public documentation boundary\n",
                encoding="utf-8",
            )
            (fixture / "src" / "fnv_atlas" / "trap.pdb").write_bytes(b"trap")
            (fixture / "tests" / "trap.exe").write_bytes(b"trap")
            build_log = StringIO()
            with redirect_stdout(build_log), redirect_stderr(build_log):
                first = source_package.build_deterministic_sdist(
                    fixture,
                    temporary / "first",
                    source_date_epoch=epoch,
                )
                second = source_package.build_deterministic_sdist(
                    fixture,
                    temporary / "second",
                    source_date_epoch=epoch,
                )

            first_bytes = first.archive.read_bytes()
            self.assertEqual(first_bytes, second.archive.read_bytes())
            self.assertEqual(first.sha256, hashlib.sha256(first_bytes).hexdigest())
            self.assertEqual(first.sha256, second.sha256)
            self.assertEqual(
                first.checksum_file.read_text(encoding="ascii"),
                f"{first.sha256.upper()} *{first.archive.name}\n",
            )

            with tarfile.open(first.archive, mode="r:gz") as package:
                members = package.getmembers()
                names = {member.name for member in members}
                roots = {PurePosixPath(name).parts[0] for name in names}
                self.assertEqual(len(roots), 1)
                root = next(iter(roots))
                required = {
                    ".gitattributes",
                    "LICENSE",
                    "MANIFEST.in",
                    "PKG-INFO",
                    "README.md",
                    "pyproject.toml",
                    "scripts/build_research_preview.py",
                    "scripts/build_source_package.py",
                    *PUBLIC_DOCUMENTATION,
                }
                required.update(
                    path.relative_to(PROJECT_ROOT).as_posix()
                    for path in (PROJECT_ROOT / "tests").glob("test_*.py")
                )
                for relative in required:
                    self.assertIn(f"{root}/{relative}", names)
                self.assertNotIn(f"{root}/docs/UNSELECTED.md", names)
                self.assertNotIn(f"{root}/src/fnv_atlas/trap.pdb", names)
                self.assertNotIn(f"{root}/tests/trap.exe", names)

                for member in members:
                    path = PurePosixPath(member.name)
                    self.assertFalse(path.is_absolute())
                    self.assertNotIn("..", path.parts)
                    self.assertFalse(
                        member.isfile()
                        and member.name.casefold().endswith(FORBIDDEN_SUFFIXES)
                    )
                    self.assertNotIn("__pycache__", path.parts)
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.uname, "")
                    self.assertEqual(member.gname, "")
                    self.assertEqual(member.mtime, epoch)
                    if member.isdir():
                        self.assertEqual(member.mode, 0o755)
                    elif member.isfile():
                        self.assertEqual(member.mode, 0o644)
                    else:
                        self.fail(f"unexpected special archive member: {member.name}")

    def test_rejects_epoch_outside_gzip_range(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            output = Path(temporary_name) / "output"
            for epoch in (-1, 2**32):
                with self.subTest(epoch=epoch):
                    with self.assertRaisesRegex(
                        source_package.SourcePackageError,
                        "gzip uint32",
                    ):
                        source_package.build_deterministic_sdist(
                            PROJECT_ROOT,
                            output,
                            source_date_epoch=epoch,
                        )


if __name__ == "__main__":
    unittest.main()
