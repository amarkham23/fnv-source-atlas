"""Build a canonical, byte-repeatable source distribution.

Setuptools' regular ``sdist`` output is structurally correct but does not
normalize every tar and gzip timestamp.  This wrapper builds that authoritative
sdist in a temporary project copy, validates its members, and repacks the same
payload with canonical ordering and metadata.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from fnmatch import fnmatchcase
import gzip
import hashlib
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile
from typing import Iterator, Sequence


DEFAULT_SOURCE_DATE_EPOCH = 315532800  # 1980-01-01T00:00:00Z
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024

_COPY_FILES = (
    ".gitattributes",
    "MANIFEST.in",
    "README.md",
    "pyproject.toml",
)
_COPY_DIRECTORIES = ("docs", "scripts", "src", "tests")
_PUBLIC_DOCUMENTATION_FILES = {
    "docs/CONTRIBUTING.md",
    "docs/CONSUMER_EXPORTS.md",
    "docs/DATA_MODEL.md",
    "docs/DATA_SOURCES.md",
    "docs/MAINTENANCE.md",
    "docs/PUBLICATION.md",
    "docs/REVIEW_WORKFLOW.md",
}
_RELEASE_TOOL_FILES = {
    "scripts/build_research_preview.py",
    "scripts/build_source_package.py",
}
_LEGAL_PATTERNS = ("LICENSE*", "COPYING*", "NOTICE*")
_ROOT_GENERATED_FILES = {"PKG-INFO", "setup.cfg"}
_EGG_INFO_FILES = {
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "entry_points.txt",
    "not-zip-safe",
    "requires.txt",
    "top_level.txt",
}
_GENERATED_NAMES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
}
_FORBIDDEN_SUFFIXES = {
    ".7z",
    ".bz2",
    ".db",
    ".dll",
    ".dmp",
    ".exe",
    ".gz",
    ".lib",
    ".obj",
    ".pdb",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".whl",
    ".xex",
    ".xz",
    ".zip",
}


class SourcePackageError(RuntimeError):
    """The source package cannot be built without ambiguity or unsafe input."""


@dataclass(frozen=True, slots=True)
class SourcePackageResult:
    archive: Path
    checksum_file: Path
    sha256: str
    member_count: int


@contextmanager
def _working_directory(path: Path) -> Iterator[None]:
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _ignore_generated(_directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        lowered = name.casefold()
        if lowered in _GENERATED_NAMES or lowered.endswith(".egg-info"):
            ignored.add(name)
        elif lowered.endswith((".pyc", ".pyo")):
            ignored.add(name)
    return ignored


def _assert_safe_source_tree(path: Path, repository_root: Path) -> None:
    attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
    is_junction = bool(getattr(path, "is_junction", lambda: False)())
    if path.is_symlink() or is_junction or attributes & 0x400:
        raise SourcePackageError(
            f"source-package input may not be a symlink or reparse point: {path}"
        )
    try:
        path.resolve(strict=True).relative_to(repository_root)
    except ValueError as exc:
        raise SourcePackageError(
            f"source-package input escapes the repository root: {path}"
        ) from exc
    if path.is_dir():
        for child in path.iterdir():
            _assert_safe_source_tree(child, repository_root)


def _copy_build_inputs(repo_root: Path, destination: Path) -> None:
    resolved_root = repo_root.resolve(strict=True)
    for relative in _COPY_FILES:
        source = repo_root / relative
        if not source.is_file():
            raise SourcePackageError(f"required packaging input is missing: {source}")
        _assert_safe_source_tree(source, resolved_root)
        shutil.copy2(source, destination / relative)

    for pattern in _LEGAL_PATTERNS:
        for source in sorted(repo_root.glob(pattern), key=lambda item: item.name.casefold()):
            if not source.is_file():
                continue
            _assert_safe_source_tree(source, resolved_root)
            shutil.copy2(source, destination / source.name)

    for relative in _COPY_DIRECTORIES:
        source = repo_root / relative
        if not source.is_dir():
            raise SourcePackageError(f"required packaging directory is missing: {source}")
        _assert_safe_source_tree(source, resolved_root)
        shutil.copytree(
            source,
            destination / relative,
            ignore=_ignore_generated,
        )


def _build_backend_sdist(source_root: Path, output_directory: Path) -> Path:
    try:
        import setuptools.build_meta as backend
    except ImportError as exc:  # pragma: no cover - depends on caller environment
        raise SourcePackageError(
            "setuptools is required; install the build-system requirements from "
            "pyproject.toml"
        ) from exc

    output_directory.mkdir(parents=True, exist_ok=True)
    with _working_directory(source_root):
        archive_name = backend.build_sdist(str(output_directory))
    archive = output_directory / archive_name
    if not archive.is_file() or not archive.name.endswith(".tar.gz"):
        raise SourcePackageError(f"backend returned an invalid sdist: {archive}")
    return archive


def _is_allowed_member(relative: PurePosixPath, *, is_directory: bool) -> bool:
    text = relative.as_posix()
    parts = relative.parts
    if is_directory:
        if text in {"docs", "scripts", "src", "src/fnv_atlas", "tests"}:
            return True
        if len(parts) >= 2 and parts[:2] == ("src", "fnv_atlas"):
            return True
        if len(parts) == 2 and parts[0] == "src" and parts[1].endswith(
            ".egg-info"
        ):
            return True
        if (
            len(parts) == 3
            and parts[0] == "src"
            and parts[1].endswith(".egg-info")
            and parts[2] == "licenses"
        ):
            return True
        if len(parts) >= 1 and parts[0] == "tests":
            return True
        return False

    if len(parts) == 1:
        return (
            text in {*_COPY_FILES, *_ROOT_GENERATED_FILES}
            or any(fnmatchcase(parts[0], pattern) for pattern in _LEGAL_PATTERNS)
        )
    if text in _PUBLIC_DOCUMENTATION_FILES or text in _RELEASE_TOOL_FILES:
        return True
    if len(parts) >= 3 and parts[:2] == ("src", "fnv_atlas"):
        return parts[-1].endswith(".py")
    if len(parts) >= 2 and parts[0] == "tests":
        return fnmatchcase(parts[-1], "test_*.py")
    if len(parts) == 3 and parts[0] == "src" and parts[1].endswith(
        ".egg-info"
    ):
        return parts[2] in _EGG_INFO_FILES
    if (
        len(parts) == 4
        and parts[0] == "src"
        and parts[1].endswith(".egg-info")
        and parts[2] == "licenses"
    ):
        return any(fnmatchcase(parts[3], pattern) for pattern in _LEGAL_PATTERNS)
    return False


def _validated_members(source_archive: Path) -> list[tuple[str, bool, bytes]]:
    members: list[tuple[str, bool, bytes]] = []
    seen: set[str] = set()
    seen_casefolded: set[str] = set()
    roots: set[str] = set()
    total_bytes = 0
    with tarfile.open(source_archive, mode="r:gz") as source:
        for item in source.getmembers():
            pure = PurePosixPath(item.name)
            if pure.is_absolute() or ".." in pure.parts or "\\" in item.name:
                raise SourcePackageError(f"unsafe sdist member path: {item.name!r}")
            normalized = pure.as_posix().rstrip("/")
            casefolded = normalized.casefold()
            if (
                not normalized
                or normalized in seen
                or casefolded in seen_casefolded
            ):
                raise SourcePackageError(f"duplicate or empty sdist member: {item.name!r}")
            seen.add(normalized)
            seen_casefolded.add(casefolded)
            roots.add(pure.parts[0])
            if any(part.casefold() in _GENERATED_NAMES for part in pure.parts):
                raise SourcePackageError(f"generated directory entered sdist: {item.name}")
            relative = PurePosixPath(*pure.parts[1:])
            if len(pure.parts) == 1:
                if not item.isdir():
                    raise SourcePackageError("sdist root entry must be a directory")
            elif not _is_allowed_member(relative, is_directory=item.isdir()):
                raise SourcePackageError(f"unallowlisted member entered sdist: {item.name}")
            if item.isfile():
                lowered = normalized.casefold()
                if any(lowered.endswith(suffix) for suffix in _FORBIDDEN_SUFFIXES):
                    raise SourcePackageError(f"forbidden binary entered sdist: {item.name}")
                if item.size > MAX_MEMBER_BYTES:
                    raise SourcePackageError(f"oversized sdist member: {item.name}")
                total_bytes += item.size
                if total_bytes > MAX_TOTAL_BYTES:
                    raise SourcePackageError("sdist payload exceeds the total size limit")
                extracted = source.extractfile(item)
                if extracted is None:
                    raise SourcePackageError(f"could not read sdist member: {item.name}")
                payload = extracted.read()
                members.append((normalized, False, payload))
            elif item.isdir():
                members.append((normalized, True, b""))
            else:
                raise SourcePackageError(
                    f"links and special files are forbidden in sdist: {item.name}"
                )
    if len(roots) != 1:
        raise SourcePackageError(f"sdist must have exactly one root directory: {roots}")
    return sorted(members, key=lambda member: member[0].encode("utf-8"))


def _write_canonical_archive(
    output: Path,
    members: list[tuple[str, bool, bytes]],
    source_date_epoch: int,
    *,
    overwrite: bool,
) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
            delete=False,
        ) as raw:
            temporary = Path(raw.name)
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw,
                mtime=source_date_epoch,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as target:
                    for name, is_directory, payload in members:
                        info = tarfile.TarInfo(name)
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        info.mtime = source_date_epoch
                        info.pax_headers = {}
                        if is_directory:
                            info.type = tarfile.DIRTYPE
                            info.mode = 0o755
                            info.size = 0
                            target.addfile(info)
                        else:
                            info.type = tarfile.REGTYPE
                            info.mode = 0o644
                            info.size = len(payload)
                            target.addfile(info, BytesIO(payload))
        _publish_temporary(temporary, output, overwrite=overwrite)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _publish_temporary(
    temporary: Path,
    destination: Path,
    *,
    overwrite: bool,
) -> None:
    if overwrite:
        os.replace(temporary, destination)
        return
    try:
        os.link(temporary, destination)
    except FileExistsError as exc:
        raise SourcePackageError(
            f"output appeared while packaging; refusing to overwrite it: {destination}"
        ) from exc
    temporary.unlink()


def build_deterministic_sdist(
    repo_root: Path,
    output_directory: Path,
    *,
    source_date_epoch: int = DEFAULT_SOURCE_DATE_EPOCH,
    overwrite: bool = False,
) -> SourcePackageResult:
    """Build a validated canonical sdist and adjacent SHA-256 sidecar."""

    repo_root = repo_root.resolve(strict=True)
    if not repo_root.is_dir():
        raise SourcePackageError(f"repository root is not a directory: {repo_root}")
    if not 0 <= source_date_epoch <= 0xFFFFFFFF:
        raise SourcePackageError("source-date epoch must fit the gzip uint32 field")
    output_directory = output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fnv-atlas-sdist-") as temporary_name:
        temporary_root = Path(temporary_name)
        source_copy = temporary_root / "source"
        source_copy.mkdir()
        _copy_build_inputs(repo_root, source_copy)
        raw_archive = _build_backend_sdist(source_copy, temporary_root / "raw")
        members = _validated_members(raw_archive)

        output = output_directory / raw_archive.name
        checksum_file = output.with_name(f"{output.name}.sha256")
        if not overwrite and (output.exists() or checksum_file.exists()):
            raise SourcePackageError(
                f"output already exists; pass --overwrite to replace it: {output}"
            )
        _write_canonical_archive(
            output,
            members,
            source_date_epoch,
            overwrite=overwrite,
        )

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    checksum_text = f"{digest.upper()} *{output.name}\n"
    checksum_temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            newline="\n",
            prefix=f".{checksum_file.name}.",
            suffix=".tmp",
            dir=checksum_file.parent,
            delete=False,
        ) as temporary_file:
            checksum_temporary = Path(temporary_file.name)
            temporary_file.write(checksum_text)
        _publish_temporary(
            checksum_temporary,
            checksum_file,
            overwrite=overwrite,
        )
    finally:
        if checksum_temporary is not None and checksum_temporary.exists():
            checksum_temporary.unlink()
    return SourcePackageResult(
        archive=output,
        checksum_file=checksum_file,
        sha256=digest,
        member_count=len(members),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a canonical, validated fnv-source-atlas sdist."
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=DEFAULT_SOURCE_DATE_EPOCH,
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = build_deterministic_sdist(
            args.repo_root,
            args.output_dir,
            source_date_epoch=args.source_date_epoch,
            overwrite=args.overwrite,
        )
    except (OSError, SourcePackageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"archive={result.archive}")
    print(f"checksum={result.checksum_file}")
    print(f"sha256={result.sha256}")
    print(f"members={result.member_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
