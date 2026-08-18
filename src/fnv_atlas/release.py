"""Deterministic, sanitized research-preview release packaging.

This module deliberately packages an allowlisted source/documentation boundary.
It never packages the Xbox PDB, either executable, raw JSON inputs, or the
generated SQLite database.  The build report and the database's checksum may be
included as metadata for a separately handled local database artifact.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import tempfile
import tomllib
from typing import Iterable, Mapping, Sequence
import zipfile

from . import __version__
from .database import AtlasDatabase, AtlasError
from .schema import APPLICATION_ID, SCHEMA_STATEMENTS, SCHEMA_VERSION
from .validation import SEMANTIC_CHECKS


ARCHIVE_ROOT = "fnv-source-atlas-research-preview"
MANIFEST_BASENAME = "PUBLICATION-MANIFEST.json"
MANIFEST_FORMAT = "fnv-source-atlas-research-preview-v1"
DEFAULT_SOURCE_DATE_EPOCH = 315532800  # 1980-01-01T00:00:00Z; ZIP's lower bound.
MAX_PAYLOAD_FILE_BYTES = 8 * 1024 * 1024
MAX_PAYLOAD_TOTAL_BYTES = 64 * 1024 * 1024

_CORE_FILES = ("README.md", "pyproject.toml")
_DOCUMENTATION_FILES = (
    "docs/CONTRIBUTING.md",
    "docs/CONSUMER_EXPORTS.md",
    "docs/DATA_MODEL.md",
    "docs/DATA_SOURCES.md",
    "docs/MAINTENANCE.md",
    "docs/PUBLICATION.md",
    "docs/REVIEW_WORKFLOW.md",
)
_RELEASE_TOOL_FILES = (
    "scripts/build_research_preview.py",
    "scripts/build_source_package.py",
)
_OPTIONAL_LEGAL_GLOBS = ("LICENSE*", "COPYING*", "NOTICE*")
_FORBIDDEN_SUFFIXES = {
    ".7z",
    ".a",
    ".db",
    ".dll",
    ".dmp",
    ".exe",
    ".gz",
    ".lib",
    ".pdb",
    ".rar",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".xex",
}
_TEXT_SUFFIXES = {".json", ".md", ".py", ".sql", ".toml", ".txt"}
_PROFILE_DIRECTORY = "us" "ers"
_HOME_DIRECTORY = "ho" "me"
_LOCAL_PATH_PATTERN = re.compile(
    rf"(?i)(?:[a-z]:[\\/]+{_PROFILE_DIRECTORY}[\\/]+[^\\/\s\"']+"
    rf"|/{_PROFILE_DIRECTORY}/[^/\s\"']+"
    rf"|/{_HOME_DIRECTORY}/[^/\s\"']+)"
)
_TOKEN_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
)
_REQUIRED_PAYLOADS = {
    "README.md",
    "pyproject.toml",
    *_DOCUMENTATION_FILES,
    *_RELEASE_TOOL_FILES,
    "src/fnv_atlas/__init__.py",
    "src/fnv_atlas/build.py",
    "src/fnv_atlas/release.py",
    "src/fnv_atlas/schema.py",
    "artifacts/fnv-source-atlas.report.json",
    "artifacts/fnv-source-atlas.sqlite.sha256.txt",
    "PUBLICATION-NOTICE.md",
}


class ReleaseError(RuntimeError):
    """The requested preview would be unsafe, ambiguous, or non-reproducible."""


@dataclass(frozen=True, slots=True)
class ReleaseResult:
    archive: Path
    checksum_file: Path
    sha256: str
    payload_files: int
    payload_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "archive": str(self.archive),
            "checksum_file": str(self.checksum_file),
            "sha256": self.sha256,
            "payload_files": self.payload_files,
            "payload_bytes": self.payload_bytes,
        }


@dataclass(frozen=True, slots=True)
class VerificationResult:
    archive: Path
    sha256: str
    package_version: str
    schema_version: int
    payload_files: int
    payload_bytes: int
    checksum_file_verified: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "archive": str(self.archive),
            "sha256": self.sha256,
            "package_version": self.package_version,
            "schema_version": self.schema_version,
            "payload_files": self.payload_files,
            "payload_bytes": self.payload_bytes,
            "checksum_file_verified": self.checksum_file_verified,
        }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _normalized_text(data: bytes, *, logical_name: str) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseError(f"{logical_name} is not valid UTF-8 text") from exc
    if "\x00" in text:
        raise ReleaseError(f"{logical_name} contains a NUL byte")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    _reject_sensitive_text(text, logical_name=logical_name)
    return text.encode("utf-8")


def _reject_sensitive_text(text: str, *, logical_name: str) -> None:
    match = _LOCAL_PATH_PATTERN.search(text)
    if match is not None:
        raise ReleaseError(
            f"{logical_name} contains a machine-local user path near offset "
            f"{match.start()}"
        )
    if _PRIVATE_KEY_PATTERN.search(text) is not None:
        raise ReleaseError(f"{logical_name} contains a private-key marker")
    for pattern in _TOKEN_PATTERNS:
        if pattern.search(text) is not None:
            raise ReleaseError(f"{logical_name} contains a credential-like token")


def _python_constant(data: bytes, name: str, *, logical_name: str) -> object:
    """Read one literal module assignment without importing archive code."""

    try:
        module = ast.parse(data.decode("utf-8"), filename=logical_name)
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise ReleaseError(f"{logical_name} is not valid Python source") from exc
    values: list[object] = []
    for statement in module.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            if not isinstance(statement.value, ast.Constant):
                raise ReleaseError(f"{logical_name} {name} is not a literal")
            values.append(statement.value.value)
    if len(values) != 1:
        raise ReleaseError(f"{logical_name} must declare {name} exactly once")
    return values[0]


def _read_stable(path: Path) -> bytes:
    first = path.read_bytes()
    second = path.read_bytes()
    if first != second:
        raise ReleaseError(f"input changed while packaging: {path}")
    return first


def _safe_repository_file(root: Path, relative: str) -> Path:
    path = root / Path(relative)
    if not path.is_file():
        raise ReleaseError(f"required release input is missing: {relative}")
    if path.is_symlink():
        raise ReleaseError(f"release inputs may not be symlinks: {relative}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ReleaseError(f"release input escapes repository root: {relative}") from exc
    return path


def _selected_repository_files(root: Path) -> tuple[tuple[str, Path, str], ...]:
    selected: dict[str, tuple[Path, str]] = {}

    def add(relative: str, role: str, *, required: bool = True) -> None:
        path = root / Path(relative)
        if not path.is_file() and not required:
            return
        selected[relative] = (_safe_repository_file(root, relative), role)

    for relative in _CORE_FILES:
        add(relative, "project-metadata")
    for relative in _DOCUMENTATION_FILES:
        add(relative, "documentation")
    for path in sorted((root / "src" / "fnv_atlas").glob("*.py")):
        add(path.relative_to(root).as_posix(), "package-source")
    for path in sorted((root / "tests").glob("test_*.py")):
        add(path.relative_to(root).as_posix(), "test-source")
    for relative in _RELEASE_TOOL_FILES:
        add(relative, "release-tool")
    for pattern in _OPTIONAL_LEGAL_GLOBS:
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                add(path.relative_to(root).as_posix(), "legal")
    if not any(role == "package-source" for _, role in selected.values()):
        raise ReleaseError("no package source files were selected")
    return tuple(
        (relative, path, role)
        for relative, (path, role) in sorted(selected.items())
    )


def _assert_runtime_matches_checkout(root: Path) -> None:
    checkout_root = root / "src" / "fnv_atlas"
    runtime_root = Path(__file__).resolve().parent
    checkout_files = {path.name: path for path in checkout_root.glob("*.py")}
    runtime_files = {path.name: path for path in runtime_root.glob("*.py")}
    if checkout_files.keys() != runtime_files.keys():
        raise ReleaseError("running package and checkout have different Python files")
    for name in sorted(checkout_files):
        if _read_stable(checkout_files[name]) != _read_stable(runtime_files[name]):
            raise ReleaseError(
                f"running package does not match checkout file src/fnv_atlas/{name}"
            )


def _producer_source_id_for_checkout(root: Path) -> str:
    """Reproduce build.producer_source_id() against the selected checkout."""

    package_root = root / "src" / "fnv_atlas"
    paths = sorted(package_root.glob("*.py"), key=lambda item: item.name)
    if not paths:
        raise ReleaseError("checkout contains no fnv_atlas Python source")
    digest = hashlib.sha256()
    for path in paths:
        data = _read_stable(path)
        name = path.name.encode("utf-8")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return f"sha256:{digest.hexdigest()}"


def _packaged_source_id(payloads: Mapping[str, bytes]) -> str:
    """Content ID for the normalized Python source actually in the archive."""

    prefix = "src/fnv_atlas/"
    sources = sorted(
        (
            (relative[len(prefix) :], data)
            for relative, data in payloads.items()
            if relative.startswith(prefix)
            and "/" not in relative[len(prefix) :]
            and relative.endswith(".py")
        ),
        key=lambda item: item[0],
    )
    if not sources:
        raise ReleaseError("preview contains no fnv_atlas Python source")
    digest = hashlib.sha256()
    for name_text, data in sources:
        name = name_text.encode("utf-8")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return f"sha256:{digest.hexdigest()}"


def _schema_snapshot() -> bytes:
    statements = [
        "-- Deterministic schema-only snapshot; no game or symbol data is included.",
        f"-- fnv-source-atlas {__version__}; schema version {SCHEMA_VERSION}",
        "PRAGMA foreign_keys = ON;",
        f"PRAGMA application_id = {APPLICATION_ID};",
        "BEGIN;",
    ]
    for statement in SCHEMA_STATEMENTS:
        statements.append(statement.strip() + ";")
    statements.extend(
        (
            "INSERT INTO atlas_meta(key, value) "
            f"VALUES ('schema_version', '{SCHEMA_VERSION}');",
            f"PRAGMA user_version = {SCHEMA_VERSION};",
            "COMMIT;",
            "",
        )
    )
    return "\n\n".join(statements).encode("utf-8")


def _sanitized_report(path: Path, *, expected_source_id: str) -> bytes:
    try:
        value = json.loads(_read_stable(path))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read build report {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseError("build report must be a JSON object")
    expectations = {
        "schema_version": SCHEMA_VERSION,
        "producer_version": __version__,
        "producer_source_id": expected_source_id,
    }
    for key, expected in expectations.items():
        if value.get(key) != expected:
            raise ReleaseError(
                f"build report {key} is stale: expected {expected!r}, "
                f"found {value.get(key)!r}"
            )
    if not re.fullmatch(r"[0-9a-f]{64}", str(value.get("database_sha256", ""))):
        raise ReleaseError("build report database_sha256 is missing or invalid")
    if value.get("integrity_check") != "ok" or value.get("foreign_key_violations") != 0:
        raise ReleaseError("build report does not record clean database integrity")
    _validate_public_report_fields(value)
    if "database" not in value:
        raise ReleaseError("build report has no database field to sanitize")
    value["database"] = "fnv-source-atlas.sqlite (external; not included)"
    value["publication_boundary"] = {
        "database_included": False,
        "private_sdk_derived_observations_included": False,
        "proprietary_inputs_included": False,
        "report_path_sanitized": True,
    }
    data = _canonical_json(value)
    _reject_sensitive_text(data.decode("utf-8"), logical_name="sanitized build report")
    return data


_PRIVATE_SDK_TABLES = (
    "sdk_source_trees",
    "sdk_source_tree_files",
    "sdk_extractions",
    "sdk_prototype_observations",
    "sdk_call_target_observations",
    "sdk_call_parameter_types",
    "sdk_call_argument_expressions",
    "sdk_data_observations",
    "sdk_prototype_extraction_assertions",
    "sdk_call_target_extraction_assertions",
    "sdk_data_extraction_assertions",
    "sdk_diagnostics",
    "sdk_code_inventory_joins",
    "sdk_game_exact_entry_links",
    "sdk_unspecified_exact_entry_candidates",
    "sdk_data_inventory_joins",
    "sdk_boundary_candidates",
    "sdk_boundary_candidate_containers",
)

_PRIVATE_SDK_REPORT_COUNTS = (
    "pc_sdk_source_files",
    "pc_sdk_prototype_observations",
    "pc_sdk_call_target_observations",
    "pc_sdk_data_observations",
    "pc_sdk_diagnostics",
    "pc_sdk_code_inventory_joins",
    "pc_sdk_data_inventory_joins",
    "pc_sdk_definitive_game_links",
    "pc_sdk_unspecified_entry_candidates",
    "pc_sdk_boundary_candidates",
    "pc_sdk_boundary_containers",
)


def _validate_public_report_fields(value: Mapping[str, object]) -> None:
    semantic = value.get("semantic_violations")
    expected_semantic_names = {name for name, _sql in SEMANTIC_CHECKS}
    if (
        not isinstance(semantic, dict)
        or set(semantic) != expected_semantic_names
        or any(type(count) is not int or count != 0 for count in semantic.values())
    ):
        raise ReleaseError("build report contains semantic validation violations")
    if value.get("pc_sdk_source_tree_sha256") is not None or any(
        value.get(key) != 0 for key in _PRIVATE_SDK_REPORT_COUNTS
    ):
        raise ReleaseError(
            "public preview refuses a database containing private SDK-derived "
            "observations; rebuild without --sdk-root"
        )


def _verify_public_database_boundary(
    database_path: Path,
    *,
    report: Mapping[str, object],
    database_sha256: str,
) -> None:
    if report.get("database_sha256") != database_sha256:
        raise ReleaseError(
            "build report is not bound to the verified external database SHA-256"
        )
    for suffix in ("-journal", "-shm", "-wal"):
        sidecar = Path(str(database_path) + suffix)
        if sidecar.exists():
            raise ReleaseError(
                f"external database has live SQLite sidecar state: {sidecar.name}"
            )
    try:
        with AtlasDatabase.open(
            database_path, read_only=True, immutable=True
        ) as database:
            connection = database.connection
            manifest_id = report.get("manifest_id")
            if (
                not isinstance(manifest_id, str)
            ):
                raise ReleaseError("build report manifest_id is invalid")
            database.verify_manifest(manifest_id)
            manifests = connection.execute(
                "SELECT manifest_id FROM input_manifests ORDER BY manifest_id"
            ).fetchall()
            if [str(row[0]) for row in manifests] != [manifest_id]:
                raise ReleaseError(
                    "external database manifest inventory differs from the build report"
                )
            producer_source_id = report.get("producer_source_id")
            producer_rows = connection.execute(
                "SELECT 1 FROM provenance WHERE kind != 'human_review' LIMIT 1"
            ).fetchone()
            if producer_rows is None:
                raise ReleaseError("external database has no build provenance")
            if connection.execute(
                """
                SELECT 1 FROM provenance
                WHERE kind != 'human_review'
                  AND (
                    manifest_id IS NOT ?
                    OR json_extract(parameters_json, '$.producer_source_id') IS NOT ?
                  )
                LIMIT 1
                """,
                (manifest_id, producer_source_id),
            ).fetchone():
                raise ReleaseError(
                    "external database provenance differs from report manifest/source"
                )
            for table in _PRIVATE_SDK_TABLES:
                if connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                    raise ReleaseError(
                        "public preview refuses a database containing private "
                        f"SDK-derived rows ({table})"
                    )
            if connection.execute(
                "SELECT 1 FROM provenance "
                "WHERE producer LIKE 'fnv_atlas.sdk%' LIMIT 1"
            ).fetchone():
                raise ReleaseError(
                    "public preview refuses private SDK extraction provenance"
                )
    except ReleaseError:
        raise
    except (AtlasError, sqlite3.Error, ValueError, RuntimeError) as exc:
        raise ReleaseError(f"cannot verify external atlas database: {exc}") from exc


def _normalized_database_checksum(path: Path) -> tuple[bytes, str]:
    try:
        text = _read_stable(path).decode("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseError(f"cannot read database checksum {path}: {exc}") from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ReleaseError("database checksum must contain exactly one non-empty line")
    match = re.fullmatch(r"([0-9A-Fa-f]{64})\s+[* ]?([^\\/]+)", lines[0])
    if match is None:
        raise ReleaseError("database checksum is not a recognized SHA-256 sidecar")
    digest, filename = match.groups()
    if filename != "fnv-source-atlas.sqlite":
        raise ReleaseError(
            "database checksum must name fnv-source-atlas.sqlite, not "
            f"{filename!r}"
        )
    digest = digest.lower()
    return f"{digest} *fnv-source-atlas.sqlite\n".encode("ascii"), digest


def _license_metadata(root: Path, pyproject_bytes: bytes) -> dict[str, object]:
    try:
        project = tomllib.loads(pyproject_bytes.decode("utf-8"))["project"]
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError("pyproject.toml has no valid [project] metadata") from exc
    if project.get("version") != __version__:
        raise ReleaseError(
            "pyproject.toml version does not match the running package version"
        )
    declaration = project.get("license")
    license_files = sorted(
        path.name
        for pattern in _OPTIONAL_LEGAL_GLOBS
        for path in root.glob(pattern)
        if path.is_file()
    )
    return {
        "project_declaration": declaration,
        "legal_files": license_files,
        "project_license_file_missing": not bool(license_files),
        # A project license file cannot settle third-party input/data rights.
        "redistribution_review_required": True,
    }


def _publication_notice(database_sha256: str, license_info: Mapping[str, object]) -> bytes:
    legal_files = license_info.get("legal_files") or []
    legal_summary = ", ".join(str(item) for item in legal_files) or "none"
    return (
        "# Research-preview publication boundary\n\n"
        "This deterministic archive contains source code, tests, documentation, "
        "a schema-only SQL snapshot, and sanitized build metadata.\n\n"
        "It intentionally excludes the Fallout: New Vegas executables, Xbox 360 "
        "PDB, raw SDK source, raw extraction/matching inputs, bulk extracted "
        "corpora, and the generated SQLite database. "
        "The database SHA-256 below identifies a separately handled local artifact; "
        "the database is not an archive member.\n\n"
        f"External database SHA-256: `{database_sha256}`\n\n"
        f"Legal files present: {legal_summary}.\n\n"
        "Licensing and third-party redistribution rights require an owner review "
        "before any public upload. This notice records that flag and is not a legal "
        "conclusion.\n"
    ).encode("utf-8")


def _safe_payload_name(relative: str) -> None:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ReleaseError(f"unsafe archive path: {relative!r}")
    if (
        "\\" in relative
        or relative.startswith("/")
        or pure.as_posix() != relative
        or any(part in {"", "."} for part in relative.split("/"))
    ):
        raise ReleaseError(f"non-canonical archive path: {relative!r}")
    if pure.suffix.lower() in _FORBIDDEN_SUFFIXES:
        raise ReleaseError(f"forbidden artifact type selected: {relative}")


def _expected_payload_role(relative: str, schema_version: int) -> str | None:
    """Return the only valid role for a member in the preview allowlist."""

    if relative in _CORE_FILES:
        return "project-metadata"
    if relative in _DOCUMENTATION_FILES:
        return "documentation"
    pure = PurePosixPath(relative)
    if pure.parent == PurePosixPath("src/fnv_atlas") and fnmatchcase(
        pure.name, "*.py"
    ):
        return "package-source"
    if pure.parent == PurePosixPath("tests") and fnmatchcase(
        pure.name, "test_*.py"
    ):
        return "test-source"
    if relative in _RELEASE_TOOL_FILES:
        return "release-tool"
    if len(pure.parts) == 1 and any(
        fnmatchcase(pure.name, pattern) for pattern in _OPTIONAL_LEGAL_GLOBS
    ):
        return "legal"
    generated = {
        "artifacts/fnv-source-atlas.report.json": "sanitized-build-report",
        "artifacts/fnv-source-atlas.sqlite.sha256.txt": (
            "external-database-checksum"
        ),
        f"schema/source-atlas-v{schema_version}.sql": "schema-snapshot",
        "PUBLICATION-NOTICE.md": "publication-boundary",
    }
    return generated.get(relative)


def _payload_entry(relative: str, data: bytes, role: str) -> dict[str, object]:
    return {
        "path": relative,
        "role": role,
        "sha256": _sha256(data),
        "size_bytes": len(data),
    }


def _zip_datetime(source_date_epoch: int) -> tuple[int, int, int, int, int, int]:
    if type(source_date_epoch) is not int:
        raise ReleaseError("source-date epoch must be an integer")
    if source_date_epoch < DEFAULT_SOURCE_DATE_EPOCH:
        raise ReleaseError("source-date epoch predates ZIP's 1980 lower bound")
    try:
        moment = datetime.fromtimestamp(source_date_epoch, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ReleaseError("source-date epoch is outside the supported range") from exc
    if moment.year > 2107:
        raise ReleaseError("source-date epoch exceeds ZIP's 2107 upper bound")
    second = moment.second - (moment.second % 2)
    return (moment.year, moment.month, moment.day, moment.hour, moment.minute, second)


def _zip_info(name: str, source_date_epoch: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_zip_datetime(source_date_epoch))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100644 & 0xFFFF) << 16
    info.extra = b""
    info.comment = b""
    return info


def _paths_alias(first: Path, second: Path) -> bool:
    left = first.resolve(strict=False)
    right = second.resolve(strict=False)
    if os.path.normcase(str(left)) == os.path.normcase(str(right)):
        return True
    if left.exists() and right.exists():
        try:
            return os.path.samefile(left, right)
        except OSError:
            pass
    return False


def _reject_release_aliases(
    inputs: Iterable[tuple[str, Path]],
    outputs: Iterable[tuple[str, Path]],
) -> None:
    input_rows = tuple(inputs)
    output_rows = tuple(outputs)
    for output_label, output in output_rows:
        for input_label, source in input_rows:
            if _paths_alias(output, source):
                raise ReleaseError(
                    f"{output_label} {output} aliases protected "
                    f"{input_label} {source}"
                )
        for other_label, other in output_rows:
            if other_label != output_label and _paths_alias(output, other):
                raise ReleaseError(
                    f"{output_label} {output} aliases {other_label} {other}"
                )


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
        raise ReleaseError(f"output appeared while packaging: {destination}") from exc
    temporary.unlink()


def _atomic_write(path: Path, data: bytes, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise ReleaseError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _publish_temporary(temporary, path, overwrite=overwrite)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _build_payloads(
    root: Path,
    *,
    report_path: Path,
    database_checksum_path: Path,
    database_path: Path,
    source_date_epoch: int,
) -> tuple[dict[str, bytes], dict[str, str], dict[str, object]]:
    _assert_runtime_matches_checkout(root)
    producer_source_id = _producer_source_id_for_checkout(root)
    payloads: dict[str, bytes] = {}
    roles: dict[str, str] = {}
    selected_files = _selected_repository_files(root)
    for relative, path, role in selected_files:
        _safe_payload_name(relative)
        if path.suffix.lower() not in _TEXT_SUFFIXES and role != "legal":
            raise ReleaseError(f"non-text file is outside the preview boundary: {relative}")
        data = _normalized_text(_read_stable(path), logical_name=relative)
        if len(data) > MAX_PAYLOAD_FILE_BYTES:
            raise ReleaseError(f"release input exceeds size limit: {relative}")
        payloads[relative] = data
        roles[relative] = role

    report = _sanitized_report(
        report_path, expected_source_id=producer_source_id
    )
    report_value = json.loads(report)
    checksum, database_sha256 = _normalized_database_checksum(database_checksum_path)
    if not database_path.is_file():
        raise ReleaseError(f"external database does not exist: {database_path}")
    if database_path.is_symlink():
        raise ReleaseError("external database may not be a symlink")
    if _file_sha256(database_path) != database_sha256:
        raise ReleaseError("external database does not match its SHA-256 sidecar")
    _verify_public_database_boundary(
        database_path,
        report=report_value,
        database_sha256=database_sha256,
    )
    if _producer_source_id_for_checkout(root) != producer_source_id:
        raise ReleaseError("package source changed while packaging")
    for relative, path, _role in selected_files:
        current = _normalized_text(_read_stable(path), logical_name=relative)
        if current != payloads[relative]:
            raise ReleaseError(f"release input changed while packaging: {relative}")
    if (
        _sanitized_report(report_path, expected_source_id=producer_source_id)
        != report
    ):
        raise ReleaseError("build report changed while packaging")
    if _normalized_database_checksum(database_checksum_path)[0] != checksum:
        raise ReleaseError("database checksum changed while packaging")
    payloads["artifacts/fnv-source-atlas.report.json"] = report
    roles["artifacts/fnv-source-atlas.report.json"] = "sanitized-build-report"
    payloads["artifacts/fnv-source-atlas.sqlite.sha256.txt"] = checksum
    roles["artifacts/fnv-source-atlas.sqlite.sha256.txt"] = (
        "external-database-checksum"
    )
    payloads[f"schema/source-atlas-v{SCHEMA_VERSION}.sql"] = _schema_snapshot()
    roles[f"schema/source-atlas-v{SCHEMA_VERSION}.sql"] = "schema-snapshot"

    license_info = _license_metadata(root, payloads["pyproject.toml"])
    payloads["PUBLICATION-NOTICE.md"] = _publication_notice(
        database_sha256, license_info
    )
    roles["PUBLICATION-NOTICE.md"] = "publication-boundary"

    total = sum(len(data) for data in payloads.values())
    if total > MAX_PAYLOAD_TOTAL_BYTES:
        raise ReleaseError(
            f"preview payload exceeds {MAX_PAYLOAD_TOTAL_BYTES} byte limit"
        )
    for relative, data in payloads.items():
        _safe_payload_name(relative)
        if Path(relative).suffix.lower() in _TEXT_SUFFIXES:
            _reject_sensitive_text(data.decode("utf-8"), logical_name=relative)

    metadata = {
        "database_sha256": database_sha256,
        "license": license_info,
        "packaged_source_id": _packaged_source_id(payloads),
        "producer_source_id": producer_source_id,
        "source_date_epoch": source_date_epoch,
    }
    return payloads, roles, metadata


def create_research_preview(
    repository_root: str | Path,
    archive: str | Path,
    *,
    report_path: str | Path | None = None,
    database_checksum_path: str | Path | None = None,
    database_path: str | Path | None = None,
    source_date_epoch: int = DEFAULT_SOURCE_DATE_EPOCH,
    overwrite: bool = False,
) -> ReleaseResult:
    """Create and verify one deterministic, database-free research preview."""

    root = Path(repository_root).resolve()
    archive_path = Path(archive).resolve()
    if not root.is_dir():
        raise ReleaseError(f"repository root does not exist: {root}")
    if archive_path.suffix.lower() != ".zip":
        raise ReleaseError("research-preview output must have a .zip suffix")
    _zip_datetime(source_date_epoch)
    report = (
        Path(report_path).resolve()
        if report_path is not None
        else root / "build" / "fnv-source-atlas.report.json"
    )
    checksum = (
        Path(database_checksum_path).resolve()
        if database_checksum_path is not None
        else root / "build" / "fnv-source-atlas.sqlite.sha256.txt"
    )
    database = (
        Path(database_path).resolve()
        if database_path is not None
        else checksum.with_name("fnv-source-atlas.sqlite")
    )
    if not report.is_file():
        raise ReleaseError(f"build report does not exist: {report}")
    if not checksum.is_file():
        raise ReleaseError(f"database checksum does not exist: {checksum}")
    checksum_path = archive_path.with_name(archive_path.name + ".sha256")
    protected_inputs = (
        ("build report", report),
        ("database checksum", checksum),
        ("external database", database),
    )
    release_outputs = (
        ("research-preview archive", archive_path),
        ("research-preview checksum", checksum_path),
    )
    _reject_release_aliases(protected_inputs, release_outputs)
    if not overwrite:
        for output in (archive_path, checksum_path):
            if output.exists():
                raise ReleaseError(f"output already exists: {output}")

    payloads, roles, metadata = _build_payloads(
        root,
        report_path=report,
        database_checksum_path=checksum,
        database_path=database,
        source_date_epoch=source_date_epoch,
    )
    entries = [
        _payload_entry(relative, payloads[relative], roles[relative])
        for relative in sorted(payloads)
    ]
    manifest = {
        "format": MANIFEST_FORMAT,
        "package_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "producer_source_id": metadata["producer_source_id"],
        "packaged_source_id": metadata["packaged_source_id"],
        "source_date_epoch": source_date_epoch,
        "archive_policy": {
            "compression": "stored",
            "database_included": False,
            "executables_included": False,
            "pdb_included": False,
            "raw_inputs_included": False,
            "sdk_source_included": False,
            "sdk_derived_observations_included": False,
            "timestamps_normalized": True,
            "text_line_endings": "LF",
        },
        "external_database": {
            "filename": "fnv-source-atlas.sqlite",
            "included": False,
            "sha256": metadata["database_sha256"],
            "checksum_verified_at_packaging": True,
        },
        "license_review": metadata["license"],
        "files": entries,
    }
    manifest_bytes = _canonical_json(manifest)

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{archive_path.name}.", suffix=".tmp", dir=archive_path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as output:
            members = dict(payloads)
            members[MANIFEST_BASENAME] = manifest_bytes
            for relative in sorted(members):
                name = f"{ARCHIVE_ROOT}/{relative}"
                output.writestr(_zip_info(name, source_date_epoch), members[relative])
        verify_research_preview(temporary, verify_checksum_file=False)
        if _file_sha256(database) != metadata["database_sha256"]:
            raise ReleaseError(
                "external database changed after checksum verification"
            )
        _reject_release_aliases(protected_inputs, release_outputs)
        _publish_temporary(temporary, archive_path, overwrite=overwrite)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

    archive_sha256 = _file_sha256(archive_path)
    sidecar = f"{archive_sha256} *{archive_path.name}\n".encode("ascii")
    _reject_release_aliases(protected_inputs, release_outputs)
    _atomic_write(checksum_path, sidecar, overwrite=overwrite)
    verified = verify_research_preview(archive_path, checksum_file=checksum_path)
    return ReleaseResult(
        archive=archive_path,
        checksum_file=checksum_path,
        sha256=verified.sha256,
        payload_files=verified.payload_files,
        payload_bytes=verified.payload_bytes,
    )


def _read_archive_checksum(path: Path, archive_name: str) -> str:
    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseError(f"cannot read archive checksum {path}: {exc}") from exc
    match = re.fullmatch(
        r"([0-9A-Fa-f]{64})\s+\*?([^\\/\r\n]+)\r?\n?", text
    )
    if match is None or match.group(2) != archive_name:
        raise ReleaseError("archive checksum sidecar has invalid content or filename")
    return match.group(1).lower()


def verify_research_preview(
    archive: str | Path,
    *,
    checksum_file: str | Path | None = None,
    verify_checksum_file: bool = True,
) -> VerificationResult:
    """Verify paths, policy, per-file hashes, metadata, and optional sidecar."""

    archive_path = Path(archive).resolve()
    if not archive_path.is_file():
        raise ReleaseError(f"archive does not exist: {archive_path}")
    archive_sha256 = _file_sha256(archive_path)
    sidecar_verified = False
    if verify_checksum_file:
        sidecar = (
            Path(checksum_file).resolve()
            if checksum_file is not None
            else archive_path.with_name(archive_path.name + ".sha256")
        )
        expected = _read_archive_checksum(sidecar, archive_path.name)
        if expected != archive_sha256:
            raise ReleaseError("archive SHA-256 does not match its sidecar")
        sidecar_verified = True

    manifest_name = f"{ARCHIVE_ROOT}/{MANIFEST_BASENAME}"
    try:
        with zipfile.ZipFile(archive_path, "r") as bundle:
            if bundle.comment:
                raise ReleaseError("archive carries a non-deterministic ZIP comment")
            infos = bundle.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ReleaseError("archive contains duplicate member names")
            if len(names) != len({name.casefold() for name in names}):
                raise ReleaseError("archive contains case-colliding member names")
            if names != sorted(names):
                raise ReleaseError("archive members are not lexicographically ordered")
            if manifest_name not in names:
                raise ReleaseError("archive has no publication manifest")
            for info in infos:
                if info.file_size > MAX_PAYLOAD_FILE_BYTES:
                    raise ReleaseError(f"oversized archive member: {info.filename}")
                if info.compress_size != info.file_size:
                    raise ReleaseError("stored archive member has inconsistent size")
            if sum(info.file_size for info in infos) > (
                MAX_PAYLOAD_TOTAL_BYTES + MAX_PAYLOAD_FILE_BYTES
            ):
                raise ReleaseError("archive exceeds its maximum expanded size")
            if bundle.testzip() is not None:
                raise ReleaseError("archive CRC verification failed")
            manifest_bytes = bundle.read(manifest_name)
            manifest = json.loads(manifest_bytes)
            if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
                raise ReleaseError("archive publication manifest has unknown format")
            if manifest_bytes != _canonical_json(manifest):
                raise ReleaseError("publication manifest is not canonical JSON")
            _reject_sensitive_text(
                manifest_bytes.decode("utf-8"), logical_name=MANIFEST_BASENAME
            )
            package_version = manifest.get("package_version")
            if not isinstance(package_version, str) or not package_version:
                raise ReleaseError("manifest package_version is invalid")
            schema_version = manifest.get("schema_version")
            if type(schema_version) is not int or schema_version < 1:
                raise ReleaseError("manifest schema_version is invalid")
            producer_source_id = manifest.get("producer_source_id")
            packaged_source_id = manifest.get("packaged_source_id")
            source_id_pattern = r"sha256:[0-9a-f]{64}"
            if not isinstance(producer_source_id, str) or not re.fullmatch(
                source_id_pattern, producer_source_id
            ):
                raise ReleaseError("manifest producer_source_id is invalid")
            if not isinstance(packaged_source_id, str) or not re.fullmatch(
                source_id_pattern, packaged_source_id
            ):
                raise ReleaseError("manifest packaged_source_id is invalid")
            source_date_epoch = manifest.get("source_date_epoch")
            if type(source_date_epoch) is not int:
                raise ReleaseError("manifest source_date_epoch is invalid")
            expected_time = _zip_datetime(source_date_epoch)
            for info in infos:
                if not info.filename.startswith(ARCHIVE_ROOT + "/"):
                    raise ReleaseError(f"archive member escapes bundle root: {info.filename}")
                relative = info.filename[len(ARCHIVE_ROOT) + 1 :]
                _safe_payload_name(relative)
                if info.is_dir():
                    raise ReleaseError("archive must not contain directory entries")
                if info.compress_type != zipfile.ZIP_STORED:
                    raise ReleaseError("archive member is not deterministically stored")
                if info.date_time != expected_time:
                    raise ReleaseError("archive member timestamp is not normalized")
                if info.extra or info.comment:
                    raise ReleaseError("archive member carries non-deterministic metadata")
                if info.create_system != 3 or (info.external_attr >> 16) != 0o100644:
                    raise ReleaseError("archive member permissions are not normalized")
                if info.flag_bits & 0x1:
                    raise ReleaseError("archive member must not be encrypted")

            policy = manifest.get("archive_policy")
            if not isinstance(policy, dict):
                raise ReleaseError("manifest has no archive policy")
            if policy.get("compression") != "stored":
                raise ReleaseError("manifest compression policy is invalid")
            if policy.get("database_included") is not False:
                raise ReleaseError("manifest does not explicitly exclude the database")
            if policy.get("executables_included") is not False:
                raise ReleaseError("manifest does not explicitly exclude executables")
            if policy.get("pdb_included") is not False:
                raise ReleaseError("manifest does not explicitly exclude PDB input")
            if policy.get("raw_inputs_included") is not False:
                raise ReleaseError("manifest does not explicitly exclude raw inputs")
            if policy.get("sdk_source_included") is not False:
                raise ReleaseError("manifest does not explicitly exclude SDK source")
            if policy.get("sdk_derived_observations_included") is not False:
                raise ReleaseError(
                    "manifest does not explicitly exclude private SDK-derived "
                    "observations"
                )
            if policy.get("timestamps_normalized") is not True:
                raise ReleaseError("manifest timestamp policy is invalid")
            if policy.get("text_line_endings") != "LF":
                raise ReleaseError("manifest line-ending policy is invalid")
            external = manifest.get("external_database")
            if not isinstance(external, dict) or external.get("included") is not False:
                raise ReleaseError("external database boundary is missing")
            if external.get("filename") != "fnv-source-atlas.sqlite":
                raise ReleaseError("external database filename is invalid")
            if external.get("checksum_verified_at_packaging") is not True:
                raise ReleaseError("external database checksum was not verified at packaging")
            if not re.fullmatch(r"[0-9a-f]{64}", str(external.get("sha256", ""))):
                raise ReleaseError("external database SHA-256 is invalid")
            license_review = manifest.get("license_review")
            if (
                not isinstance(license_review, dict)
                or type(license_review.get("project_license_file_missing")) is not bool
                or license_review.get("redistribution_review_required") is not True
            ):
                raise ReleaseError("manifest license-review metadata is invalid")

            listed = manifest.get("files")
            if not isinstance(listed, list):
                raise ReleaseError("manifest file list is invalid")
            expected_names: set[str] = {manifest_name}
            payload_bytes = 0
            seen_relative: set[str] = set()
            payloads: dict[str, bytes] = {}
            for entry in listed:
                if not isinstance(entry, dict):
                    raise ReleaseError("manifest file entry is not an object")
                relative = entry.get("path")
                if not isinstance(relative, str):
                    raise ReleaseError("manifest file entry has no path")
                _safe_payload_name(relative)
                expected_role = _expected_payload_role(relative, schema_version)
                if expected_role is None or entry.get("role") != expected_role:
                    raise ReleaseError(
                        f"manifest member is outside the allowlist: {relative}"
                    )
                if relative in seen_relative:
                    raise ReleaseError(f"manifest repeats file {relative}")
                seen_relative.add(relative)
                name = f"{ARCHIVE_ROOT}/{relative}"
                expected_names.add(name)
                if name not in names:
                    raise ReleaseError(f"manifest member is absent: {relative}")
                data = bundle.read(name)
                size_bytes = entry.get("size_bytes")
                if type(size_bytes) is not int or size_bytes < 0:
                    raise ReleaseError(f"invalid size metadata for {relative}")
                if len(data) != size_bytes:
                    raise ReleaseError(f"size mismatch for {relative}")
                digest = entry.get("sha256")
                if not isinstance(digest, str) or not re.fullmatch(
                    r"[0-9a-f]{64}", digest
                ):
                    raise ReleaseError(f"invalid SHA-256 metadata for {relative}")
                if _sha256(data) != digest:
                    raise ReleaseError(f"SHA-256 mismatch for {relative}")
                if len(data) > MAX_PAYLOAD_FILE_BYTES:
                    raise ReleaseError(f"oversized payload member: {relative}")
                payload_bytes += len(data)
                payloads[relative] = data
                if (
                    Path(relative).suffix.lower() in _TEXT_SUFFIXES
                    or expected_role == "legal"
                ):
                    text = data.decode("utf-8")
                    if "\r" in text:
                        raise ReleaseError(f"non-LF line ending in {relative}")
                    _reject_sensitive_text(text, logical_name=relative)
            if set(names) != expected_names:
                extras = sorted(set(names) - expected_names)
                raise ReleaseError(f"archive contains unmanifested members: {extras}")
            if payload_bytes > MAX_PAYLOAD_TOTAL_BYTES:
                raise ReleaseError("archive payload exceeds total size limit")
            required = _REQUIRED_PAYLOADS | {
                f"schema/source-atlas-v{schema_version}.sql"
            }
            missing = sorted(required - payloads.keys())
            if missing:
                raise ReleaseError(f"archive is missing required payloads: {missing}")
            if not any(
                entry.get("role") == "test-source" for entry in listed
            ):
                raise ReleaseError("archive contains no test source")

            try:
                project = tomllib.loads(payloads["pyproject.toml"].decode("utf-8"))[
                    "project"
                ]
                report = json.loads(
                    payloads["artifacts/fnv-source-atlas.report.json"]
                )
            except (KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
                raise ReleaseError("archive project metadata is invalid") from exc
            if not isinstance(project, dict):
                raise ReleaseError("archive [project] metadata is not a table")
            if not isinstance(report, dict):
                raise ReleaseError("archive build report is invalid")
            if project.get("version") != package_version:
                raise ReleaseError("manifest and pyproject package versions differ")
            if _python_constant(
                payloads["src/fnv_atlas/__init__.py"],
                "__version__",
                logical_name="src/fnv_atlas/__init__.py",
            ) != package_version:
                raise ReleaseError("manifest and package source versions differ")
            if _python_constant(
                payloads["src/fnv_atlas/schema.py"],
                "SCHEMA_VERSION",
                logical_name="src/fnv_atlas/schema.py",
            ) != schema_version:
                raise ReleaseError("manifest and schema source versions differ")
            if report.get("producer_version") != package_version:
                raise ReleaseError("manifest and build-report producer versions differ")
            if report.get("schema_version") != schema_version:
                raise ReleaseError("manifest and build-report schema versions differ")
            if report.get("producer_source_id") != producer_source_id:
                raise ReleaseError("manifest and build-report producer source IDs differ")
            if report.get("database_sha256") != external.get("sha256"):
                raise ReleaseError(
                    "manifest database SHA-256 and build report differ"
                )
            if report.get("integrity_check") != "ok" or report.get(
                "foreign_key_violations"
            ) != 0:
                raise ReleaseError("build report does not record clean integrity")
            _validate_public_report_fields(report)
            if report.get("database") != (
                "fnv-source-atlas.sqlite (external; not included)"
            ):
                raise ReleaseError("build report database path is not sanitized")
            boundary = report.get("publication_boundary")
            if not isinstance(boundary, dict) or boundary != {
                "database_included": False,
                "private_sdk_derived_observations_included": False,
                "proprietary_inputs_included": False,
                "report_path_sanitized": True,
            }:
                raise ReleaseError("build report publication boundary is invalid")
            if _packaged_source_id(payloads) != packaged_source_id:
                raise ReleaseError("manifest packaged source ID does not match source")
            actual_legal_files = sorted(
                relative
                for relative in payloads
                if _expected_payload_role(relative, schema_version) == "legal"
            )
            if license_review.get("legal_files") != actual_legal_files:
                raise ReleaseError("manifest legal-file inventory differs from payload")
            if license_review.get("project_declaration") != project.get("license"):
                raise ReleaseError("manifest and pyproject license declarations differ")
            if license_review.get("project_license_file_missing") is not (
                not bool(actual_legal_files)
            ):
                raise ReleaseError("manifest project-license flag is inconsistent")
            checksum_text = payloads[
                "artifacts/fnv-source-atlas.sqlite.sha256.txt"
            ].decode("ascii")
            checksum_match = re.fullmatch(
                r"([0-9a-f]{64}) \*fnv-source-atlas\.sqlite\n", checksum_text
            )
            if checksum_match is None or checksum_match.group(1) != external.get(
                "sha256"
            ):
                raise ReleaseError("external database checksum metadata differs")
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot verify research preview: {exc}") from exc

    if _file_sha256(archive_path) != archive_sha256:
        raise ReleaseError("archive changed while it was being verified")

    return VerificationResult(
        archive=archive_path,
        sha256=archive_sha256,
        package_version=package_version,
        schema_version=schema_version,
        payload_files=len(listed),
        payload_bytes=payload_bytes,
        checksum_file_verified=sidecar_verified,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fnv-atlas-research-preview",
        description="Create or verify a sanitized deterministic research preview.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create and verify a preview ZIP")
    create.add_argument("--repo-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--report", type=Path)
    create.add_argument("--database-checksum", type=Path)
    create.add_argument("--database", type=Path)
    create.add_argument(
        "--source-date-epoch", type=int, default=DEFAULT_SOURCE_DATE_EPOCH
    )
    create.add_argument("--overwrite", action="store_true")
    verify = commands.add_parser("verify", help="verify a preview ZIP and sidecar")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--checksum-file", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "create":
            result: ReleaseResult | VerificationResult = create_research_preview(
                arguments.repo_root,
                arguments.output,
                report_path=arguments.report,
                database_checksum_path=arguments.database_checksum,
                database_path=arguments.database,
                source_date_epoch=arguments.source_date_epoch,
                overwrite=arguments.overwrite,
            )
        else:
            result = verify_research_preview(
                arguments.archive, checksum_file=arguments.checksum_file
            )
    except ReleaseError as exc:
        parser = _parser()
        parser.error(str(exc))
        return 2
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ARCHIVE_ROOT",
    "DEFAULT_SOURCE_DATE_EPOCH",
    "ReleaseError",
    "ReleaseResult",
    "VerificationResult",
    "create_research_preview",
    "verify_research_preview",
]
