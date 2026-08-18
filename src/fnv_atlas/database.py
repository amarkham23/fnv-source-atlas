"""Transactional access to the source-atlas evidence database.

Only Python's standard library is required.  IDs may be supplied by an
extractor, or generated deterministically with :func:`stable_id`.  Upserts do
not permit the identity-bearing columns of an existing row to move silently.
Producer assertions retain every conflicting observation; canonical fact rows
are compatibility projections rather than a substitute for assertion history.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, BinaryIO

from .pdb_vftables import (
    S_PUB32,
    VftableCorpus,
    build_vftable_address_groups,
    make_canonical_name_id,
    make_vftable_record_id,
)
from .ppc_control_flow import (
    CALL_RELEVANT_V1_ROLES,
    CONTROL_FLOW_POLICIES,
    ControlFlowExtraction,
    select_control_flow,
)
from .pdb_globals import (
    DataSymbolExtraction,
    build_data_address_groups,
    make_data_record_id,
)
from .sdk_inventory import SdkPcInventoryJoin
from .sdk_prototypes import SdkPrototypeExtraction
from .schema import initialize_schema, validate_schema
from .tpi_layouts import LayoutMember, TpiLayoutCorpus
from .tpi_signatures import SignatureResult


class AtlasError(RuntimeError):
    """Base class for database API errors."""


class IdentityConflictError(AtlasError):
    """An upsert attempted to change the identity represented by a stable ID."""


class ManifestVerificationError(AtlasError):
    """A content-addressed manifest no longer matches its identifier or rows."""


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """One logical input in a content-addressed extraction manifest."""

    content_id: str
    role: str
    logical_name: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ControlFlowPersistenceResult:
    """Counts for one atomic, policy-filtered control-flow persistence run."""

    extraction_id: str
    persistence_policy: str
    source_physical_sites: int
    source_logical_uses: int
    persisted_physical_sites: int
    persisted_logical_uses: int
    triggering_logical_uses: int
    procedure_scans: int


@dataclass(frozen=True, slots=True)
class TpiLayoutPersistenceResult:
    """Counts for one atomic, lossless global-TPI persistence run."""

    extraction_id: str
    raw_type_records: int
    raw_body_bytes: int
    tag_records: int
    definitions: int
    forward_references: int
    tag_member_occurrences: int
    physical_field_members: int
    physical_method_overloads: int
    diagnostics: int


@dataclass(frozen=True, slots=True)
class DataSymbolPersistenceResult:
    """Counts for one atomic typed-data-symbol persistence run."""

    extraction_id: str
    records: int
    resolved_records: int
    unresolved_records: int
    unique_addresses: int


@dataclass(frozen=True, slots=True)
class VftablePersistenceResult:
    """Counts for one atomic lossless Xbox vftable persistence run."""

    extraction_id: str
    physical_records: int
    resolved_records: int
    unresolved_records: int
    canonical_names: int
    address_groups: int
    pointer_runs: int
    pointer_slots: int
    diagnostics: int


@dataclass(frozen=True, slots=True)
class SdkPersistenceResult:
    """Counts for one portable SDK extraction and PC-inventory observation join."""

    extraction_id: str
    source_tree_sha256: str
    source_files: int
    prototypes: int
    call_targets: int
    data_addresses: int
    diagnostics: int
    code_joins: int
    data_joins: int
    definitive_game_links: int
    unspecified_entry_candidates: int
    boundary_candidates: int
    boundary_containers: int


def _canonical_json(value: Mapping[str, Any]) -> str:
    if not isinstance(value, Mapping):
        raise TypeError("JSON object values must be mappings")
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"value is not canonical JSON data: {exc}") from exc


def _decode_json(value: str) -> dict[str, Any]:
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise AtlasError("database JSON column did not contain an object")
    return decoded


def _canonical_review_timestamp(value: str | datetime) -> str:
    """Normalize an explicitly zoned timestamp to deterministic UTC RFC 3339."""

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            raise ValueError("review timestamp must not be empty")
        if candidate.endswith(("Z", "z")):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError("review timestamp must be ISO 8601") from exc
    else:
        raise TypeError("review timestamp must be a string or datetime")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("review timestamp must include an explicit UTC offset")
    parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _review_target(
    *,
    hypothesis_set_id: str | None,
    alternative_id: str | None,
    claim_id: str | None,
) -> tuple[str, str, str]:
    targets = [
        ("hypothesis_set", "hypothesis_set_id", hypothesis_set_id),
        ("alternative", "alternative_id", alternative_id),
        ("claim", "claim_id", claim_id),
    ]
    present = [target for target in targets if target[2] is not None]
    if len(present) != 1:
        raise ValueError(
            "exactly one of hypothesis_set_id, alternative_id, and claim_id is required"
        )
    kind, column, identifier = present[0]
    assert identifier is not None
    return kind, column, identifier


def stable_id(namespace: str, *components: object) -> str:
    """Return a deterministic, full-length SHA-256 identifier.

    Components are encoded as canonical JSON, so delimiters inside a path or
    symbol name cannot create ambiguous identities.
    """

    if not namespace or ":" in namespace:
        raise ValueError("namespace must be non-empty and may not contain ':'")
    payload = json.dumps(
        {"namespace": namespace, "components": components},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"{namespace}:sha256:{hashlib.sha256(payload).hexdigest()}"


def _canonical_row_digest(rows: Iterable[object]) -> str:
    """Hash an ordered row stream without constructing one giant JSON value."""

    digest = hashlib.sha256()
    for row in rows:
        encoded = json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _integer_text(value: int | None) -> str | None:
    """Store arbitrary-width CodeView numeric leaves losslessly in SQLite."""

    return None if value is None else str(value)


def _decode_integer_text(value: str | None) -> int | None:
    return None if value is None else int(value)


def _physical_member_payload(member: LayoutMember) -> str:
    """Canonical physical field content, excluding tag-relative ordinal."""

    payload = member.to_dict()
    payload.pop("ordinal")
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _validated_sha256(value: str, payload: bytes, *, label: str) -> str:
    expected = hashlib.sha256(payload).hexdigest()
    if value != expected:
        raise ValueError(
            f"{label} SHA-256 mismatch: declared {value!r}, expected {expected!r}"
        )
    return value


def _portable_sdk_path(value: str) -> str:
    """Validate one source-root-relative POSIX path without normalizing it."""

    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("SDK source paths must be non-empty relative POSIX paths")
    if value.startswith("/") or (
        len(value) >= 2 and value[0].isalpha() and value[1] == ":"
    ):
        raise ValueError("SDK source paths must not be absolute or drive-qualified")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("SDK source paths must not contain empty, dot, or dot-dot parts")
    return value


def _validated_sdk_source_manifest(
    extraction: SdkPrototypeExtraction,
) -> tuple[str, tuple[Any, ...]]:
    """Recompute the extractor's exact portable source-tree content identity."""

    files = tuple(
        sorted(
            extraction.source_files,
            key=lambda item: (item.relative_path.casefold(), item.relative_path),
        )
    )
    if extraction.files_scanned != len(files):
        raise ValueError("SDK source-file manifest count does not match files_scanned")
    digest = hashlib.sha256()
    folded_paths: set[str] = set()
    exact_paths: set[str] = set()
    for item in files:
        path = _portable_sdk_path(item.relative_path)
        folded = path.casefold()
        if folded in folded_paths or path in exact_paths:
            raise ValueError(f"SDK source manifest has a colliding path {path!r}")
        folded_paths.add(folded)
        exact_paths.add(path)
        if (
            len(item.sha256) != 64
            or item.sha256 != item.sha256.lower()
            or any(character not in "0123456789abcdef" for character in item.sha256)
        ):
            raise ValueError("SDK source-file SHA-256 must be lowercase hexadecimal")
        if item.byte_length < 0:
            raise ValueError("SDK source-file byte length cannot be negative")
        path_bytes = path.encode("utf-8")
        if len(path_bytes) > 0xFFFFFFFF:
            raise ValueError("SDK source path is too large for manifest framing")
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(item.byte_length.to_bytes(8, "big"))
        digest.update(bytes.fromhex(item.sha256))
    source_tree_sha256 = f"sha256:{digest.hexdigest()}"
    if extraction.source_tree_sha256 != source_tree_sha256:
        raise ValueError("SDK source-tree SHA-256 does not match its portable manifest")
    return source_tree_sha256, files


def make_address_group_id(program_id: str, address_space: str, address: int) -> str:
    return stable_id("address", program_id, address_space, address)


def make_function_id(
    program_id: str, address_space: str, address: int, identity_key: str
) -> str:
    return stable_id("function", program_id, address_space, address, identity_key)


class AtlasDatabase:
    """A small, explicit API around the versioned SQLite schema."""

    def __init__(
        self,
        path: str | Path,
        *,
        create: bool = False,
        read_only: bool = False,
        immutable: bool = False,
        timeout: float = 30.0,
    ) -> None:
        if create and read_only:
            raise ValueError("create and read_only are mutually exclusive")
        if immutable and not read_only:
            raise ValueError("immutable access requires read_only=True")
        raw_path = str(path)
        if read_only:
            if raw_path == ":memory:":
                raise ValueError("an in-memory database cannot be opened read-only")
            query = "mode=ro&immutable=1" if immutable else "mode=ro"
            uri = Path(raw_path).resolve().as_uri() + "?" + query
            self.connection = sqlite3.connect(
                uri, uri=True, timeout=timeout, isolation_level=None
            )
        else:
            self.connection = sqlite3.connect(
                raw_path, timeout=timeout, isolation_level=None
            )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = %d" % int(timeout * 1000))
        self._savepoint_counter = 0
        self._batch_depth = 0
        self._closed = False
        try:
            if create:
                initialize_schema(self.connection)
            else:
                validate_schema(self.connection)
        except Exception:
            self.connection.close()
            self._closed = True
            raise

    @classmethod
    def create(cls, path: str | Path = ":memory:") -> "AtlasDatabase":
        """Create an atlas, or open it if it is already a compatible atlas."""

        return cls(path, create=True)

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        read_only: bool = False,
        immutable: bool = False,
    ) -> "AtlasDatabase":
        return cls(path, read_only=read_only, immutable=immutable)

    def close(self) -> None:
        if not self._closed:
            if self.connection.in_transaction:
                self.connection.rollback()
            self.connection.close()
            self._closed = True

    def __enter__(self) -> "AtlasDatabase":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator["AtlasDatabase"]:
        """Run a transaction, using savepoints when transactions are nested."""

        if self._closed:
            raise AtlasError("database is closed")
        # Method-level transactions become cheap no-ops during a bulk batch.
        # The batch itself remains one atomic outer transaction.
        if self._batch_depth and self.connection.in_transaction:
            yield self
            return
        if self.connection.in_transaction:
            self._savepoint_counter += 1
            savepoint = f"atlas_sp_{self._savepoint_counter}"
            self.connection.execute(f"SAVEPOINT {savepoint}")
            try:
                yield self
            except BaseException:
                self.connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            else:
                self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        else:
            self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield self
            except BaseException:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()

    @contextmanager
    def batch(self, *, immediate: bool = True) -> Iterator["AtlasDatabase"]:
        """Group a bulk import into one transaction without per-row savepoints.

        All nested batches and method-level writes participate in the same
        atomic unit.  An exception escaping the outermost batch rolls back the
        entire load.  Normal :meth:`transaction` nesting continues to use
        savepoints when no batch is active.
        """

        if self._batch_depth:
            self._batch_depth += 1
            try:
                yield self
            finally:
                self._batch_depth -= 1
            return
        with self.transaction(immediate=immediate):
            self._batch_depth = 1
            try:
                yield self
            finally:
                self._batch_depth = 0

    def _stable_upsert(
        self,
        table: str,
        primary_key: str,
        values: Mapping[str, Any],
        *,
        immutable: Sequence[str],
    ) -> None:
        """Insert or update while protecting the meaning of an existing ID."""

        primary_value = values[primary_key]
        row = self.connection.execute(
            f"SELECT * FROM {table} WHERE {primary_key} = ?", (primary_value,)
        ).fetchone()
        if row is None:
            columns = tuple(values)
            placeholders = ", ".join("?" for _ in columns)
            self.connection.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
                tuple(values[column] for column in columns),
            )
            return
        conflicts = [
            column
            for column in immutable
            if row[column] != values[column]
        ]
        if conflicts:
            joined = ", ".join(conflicts)
            raise IdentityConflictError(
                f"{table} ID {primary_value!r} conflicts in immutable column(s): {joined}"
            )
        mutable = [
            column for column in values if column != primary_key and column not in immutable
        ]
        if mutable:
            assignments = ", ".join(f"{column} = ?" for column in mutable)
            self.connection.execute(
                f"UPDATE {table} SET {assignments} WHERE {primary_key} = ?",
                tuple(values[column] for column in mutable) + (primary_value,),
            )

    def _bulk_insert_immutable(
        self,
        table: str,
        primary_key: str,
        rows: Iterable[Mapping[str, Any]],
    ) -> int:
        """Stage and insert immutable rows with one set-based conflict check.

        Exact replays are ignored only after every supplied column is compared
        null-safely against the existing row.  A stable ID with different
        content raises :class:`IdentityConflictError`; unrelated UNIQUE, CHECK,
        trigger, and foreign-key violations remain ordinary SQLite errors.
        """

        for identifier in (table, primary_key):
            if not identifier.isidentifier():
                raise ValueError(f"unsafe SQLite identifier {identifier!r}")
        iterator = iter(rows)
        try:
            first = next(iterator)
        except StopIteration:
            return 0
        columns = tuple(first)
        if primary_key not in columns:
            raise ValueError(f"bulk rows for {table} omit primary key {primary_key}")
        if not columns or any(not column.isidentifier() for column in columns):
            raise ValueError(f"bulk rows for {table} have unsafe columns")

        self._savepoint_counter += 1
        stage = f"atlas_stage_{self._savepoint_counter}"
        quoted_columns = ", ".join(columns)

        def value_stream() -> Iterator[tuple[Any, ...]]:
            for row in (first,):
                yield tuple(row[column] for column in columns)
            for row in iterator:
                if tuple(row) != columns:
                    raise ValueError(f"inconsistent bulk row columns for {table}")
                yield tuple(row[column] for column in columns)

        try:
            self.connection.execute(
                f"CREATE TEMP TABLE {stage} AS "
                f"SELECT {quoted_columns} FROM {table} WHERE 0"
            )
            placeholders = ", ".join("?" for _ in columns)
            self.connection.executemany(
                f"INSERT INTO {stage} ({quoted_columns}) VALUES ({placeholders})",
                value_stream(),
            )
            self.connection.execute(
                f"CREATE UNIQUE INDEX {stage}_pk ON {stage}({primary_key})"
            )
            comparisons = " AND ".join(
                f"target.{column} IS source.{column}" for column in columns
            )
            conflict = self.connection.execute(
                f"""
                SELECT source.{primary_key}
                FROM {stage} source
                JOIN {table} target
                  ON target.{primary_key} = source.{primary_key}
                WHERE NOT ({comparisons})
                LIMIT 1
                """
            ).fetchone()
            if conflict is not None:
                raise IdentityConflictError(
                    f"{table} ID {conflict[0]!r} conflicts with immutable content"
                )
            before = self.connection.total_changes
            self.connection.execute(
                f"""
                INSERT INTO {table} ({quoted_columns})
                SELECT {', '.join(f'source.{column}' for column in columns)}
                FROM {stage} source
                WHERE NOT EXISTS (
                    SELECT 1 FROM {table} target
                    WHERE target.{primary_key} = source.{primary_key}
                )
                """
            )
            return self.connection.total_changes - before
        finally:
            self.connection.execute(f"DROP TABLE IF EXISTS {stage}")

    def upsert_program(
        self,
        program_id: str,
        *,
        platform: str,
        name: str,
        architecture: str | None = None,
        image_base: int | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        values = {
            "program_id": program_id,
            "platform": platform,
            "name": name,
            "architecture": architecture,
            "image_base": image_base,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "programs", "program_id", values, immutable=("platform",)
            )
        return program_id

    def upsert_module(
        self,
        module_id: str,
        *,
        program_id: str,
        name: str,
        object_path: str | None = None,
        compiland_index: int | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        values = {
            "module_id": module_id,
            "program_id": program_id,
            "name": name,
            "object_path": object_path,
            "compiland_index": compiland_index,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "modules",
                "module_id",
                values,
                immutable=("program_id", "name", "compiland_index"),
            )
        return module_id

    def upsert_source_file(
        self,
        source_file_id: str,
        *,
        program_id: str,
        normalized_path: str,
        checksum_kind: str | None = None,
        checksum: str | None = None,
        language: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        values = {
            "source_file_id": source_file_id,
            "program_id": program_id,
            "normalized_path": normalized_path,
            "checksum_kind": checksum_kind,
            "checksum": checksum,
            "language": language,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "source_files",
                "source_file_id",
                values,
                immutable=("program_id", "normalized_path"),
            )
        return source_file_id

    def upsert_address_group(
        self,
        *,
        program_id: str,
        address_space: str,
        address: int,
        address_group_id: str | None = None,
        kind: str = "code",
        details: Mapping[str, Any] = {},
    ) -> str:
        group_id = address_group_id or make_address_group_id(
            program_id, address_space, address
        )
        values = {
            "address_group_id": group_id,
            "program_id": program_id,
            "address_space": address_space,
            "address": address,
            "kind": kind,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "address_groups",
                "address_group_id",
                values,
                immutable=("program_id", "address_space", "address"),
            )
        return group_id

    def upsert_function(
        self,
        *,
        address_group_id: str,
        identity_key: str,
        function_id: str | None = None,
        kind: str = "function",
        type_index: int | None = None,
        module_id: str | None = None,
        symbol_record_kind: str | None = None,
        provenance_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        address_row = self.connection.execute(
            """
            SELECT program_id, address_space, address
            FROM address_groups WHERE address_group_id = ?
            """,
            (address_group_id,),
        ).fetchone()
        if address_row is None:
            raise AtlasError(f"unknown address group {address_group_id!r}")
        generated_id = make_function_id(
            address_row["program_id"],
            address_row["address_space"],
            address_row["address"],
            identity_key,
        )
        function_id = function_id or generated_id
        values = {
            "function_id": function_id,
            "program_id": address_row["program_id"],
            "address_group_id": address_group_id,
            "identity_key": identity_key,
            "kind": kind,
            "type_index": type_index,
            "module_id": module_id,
            "symbol_record_kind": symbol_record_kind,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            existing = self.connection.execute(
                "SELECT * FROM functions WHERE function_id = ?", (function_id,)
            ).fetchone()
            if existing is not None:
                conflicts = [
                    column
                    for column in ("program_id", "address_group_id", "identity_key")
                    if existing[column] != values[column]
                ]
                if conflicts:
                    raise IdentityConflictError(
                        f"functions ID {function_id!r} conflicts in immutable "
                        f"column(s): {', '.join(conflicts)}"
                    )
            else:
                self._stable_upsert(
                    "functions",
                    "function_id",
                    values,
                    immutable=("program_id", "address_group_id", "identity_key"),
                )

            # Assertions are the non-destructive producer record.  The functions
            # row remains a compatibility projection of the latest safe import.
            if provenance_id is not None:
                self.add_function_assertion(
                    function_id,
                    kind=kind,
                    type_index=type_index,
                    module_id=module_id,
                    symbol_record_kind=symbol_record_kind,
                    provenance_id=provenance_id,
                    details=details,
                )

            # A stored signature locks its exact type index.  A conflicting
            # producer assertion is still retained, but cannot mutate that
            # canonical projection into an internally inconsistent state.
            signature = self.connection.execute(
                "SELECT type_index FROM function_signatures WHERE function_id = ?",
                (function_id,),
            ).fetchone()
            if existing is not None and (
                signature is None or signature["type_index"] == type_index
            ):
                self._stable_upsert(
                    "functions",
                    "function_id",
                    values,
                    immutable=("program_id", "address_group_id", "identity_key"),
                )
        return function_id

    def add_function_assertion(
        self,
        function_id: str,
        *,
        kind: str,
        provenance_id: str,
        type_index: int | None = None,
        module_id: str | None = None,
        symbol_record_kind: str | None = None,
        assertion_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        """Append one producer's extracted metadata for a logical function."""

        function = self.connection.execute(
            "SELECT program_id FROM functions WHERE function_id = ?", (function_id,)
        ).fetchone()
        if function is None:
            raise AtlasError(f"unknown function {function_id!r}")
        details_json = _canonical_json(details)
        assertion_id = assertion_id or stable_id(
            "function-assertion",
            function_id,
            kind,
            type_index,
            module_id,
            symbol_record_kind,
            provenance_id,
            json.loads(details_json),
        )
        values = {
            "assertion_id": assertion_id,
            "function_id": function_id,
            "program_id": function["program_id"],
            "kind": kind,
            "type_index": type_index,
            "module_id": module_id,
            "symbol_record_kind": symbol_record_kind,
            "provenance_id": provenance_id,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "function_assertions",
                "assertion_id",
                values,
                immutable=tuple(values),
            )
        return assertion_id

    def iter_function_assertions(
        self, function_id: str
    ) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            """
            SELECT * FROM function_assertions
            WHERE function_id = ? ORDER BY provenance_id, assertion_id
            """,
            (function_id,),
        ):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def add_function_name(
        self,
        function_id: str,
        name: str,
        *,
        name_kind: str,
        is_primary: bool = False,
        provenance_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> int:
        details_json = _canonical_json(details)
        with self.transaction():
            if is_primary:
                self.connection.execute(
                    """
                    UPDATE function_names SET is_primary = 0
                    WHERE function_id = ? AND name_kind = ? AND name <> ?
                    """,
                    (function_id, name_kind, name),
                )
            self.connection.execute(
                """
                INSERT INTO function_names
                    (function_id, name, name_kind, is_primary, provenance_id, details_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(function_id, name_kind, name) DO NOTHING
                """,
                (
                    function_id,
                    name,
                    name_kind,
                    int(is_primary),
                    provenance_id,
                    details_json,
                ),
            )
            row = self.connection.execute(
                """
                SELECT name_id FROM function_names
                WHERE function_id = ? AND name_kind = ? AND name = ?
                """,
                (function_id, name_kind, name),
            ).fetchone()
            assert row is not None
            name_id = int(row[0])
            if provenance_id is not None:
                self.add_function_name_assertion(
                    name_id,
                    is_primary=is_primary,
                    provenance_id=provenance_id,
                    details=details,
                )
            self.connection.execute(
                """
                UPDATE function_names
                SET is_primary = ?, provenance_id = ?, details_json = ?
                WHERE name_id = ?
                """,
                (int(is_primary), provenance_id, details_json, name_id),
            )
        return name_id

    def add_function_name_assertion(
        self,
        name_id: int,
        *,
        is_primary: bool,
        provenance_id: str,
        assertion_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        name = self.connection.execute(
            """
            SELECT function_id, name, name_kind
            FROM function_names WHERE name_id = ?
            """,
            (name_id,),
        ).fetchone()
        if name is None:
            raise AtlasError(f"unknown function name row {name_id!r}")
        details_json = _canonical_json(details)
        assertion_id = assertion_id or stable_id(
            "function-name-assertion",
            name["function_id"],
            name["name_kind"],
            name["name"],
            bool(is_primary),
            provenance_id,
            json.loads(details_json),
        )
        values = {
            "assertion_id": assertion_id,
            "name_id": name_id,
            "is_primary": int(is_primary),
            "provenance_id": provenance_id,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "function_name_assertions",
                "assertion_id",
                values,
                immutable=tuple(values),
            )
        return assertion_id

    def iter_function_name_assertions(
        self, *, function_id: str | None = None, name_id: int | None = None
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if function_id is not None:
            clauses.append("n.function_id = ?")
            parameters.append(function_id)
        if name_id is not None:
            clauses.append("a.name_id = ?")
            parameters.append(name_id)
        sql = """
            SELECT a.*, n.function_id, n.name, n.name_kind
            FROM function_name_assertions a
            JOIN function_names n USING (name_id)
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY n.function_id, n.name_kind, n.name, a.assertion_id"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["is_primary"] = bool(result["is_primary"])
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def add_function_source_range(
        self,
        function_id: str,
        source_file_id: str,
        *,
        line_start: int = 0,
        line_end: int | None = None,
        column_start: int = 0,
        column_end: int | None = None,
        is_primary: bool = False,
        provenance_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> None:
        program_row = self.connection.execute(
            "SELECT program_id FROM functions WHERE function_id = ?", (function_id,)
        ).fetchone()
        if program_row is None:
            raise AtlasError(f"unknown function {function_id!r}")
        with self.transaction():
            if is_primary:
                self.connection.execute(
                    "UPDATE function_source_ranges SET is_primary = 0 WHERE function_id = ?",
                    (function_id,),
                )
            self.connection.execute(
                """
                INSERT INTO function_source_ranges
                    (function_id, program_id, source_file_id, line_start, line_end,
                     column_start, column_end, is_primary, provenance_id, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(function_id, source_file_id, line_start, column_start)
                DO NOTHING
                """,
                (
                    function_id,
                    program_row[0],
                    source_file_id,
                    line_start,
                    line_end,
                    column_start,
                    column_end,
                    int(is_primary),
                    provenance_id,
                    _canonical_json(details),
                ),
            )
            if provenance_id is not None:
                self.add_function_source_range_assertion(
                    function_id,
                    source_file_id,
                    line_start=line_start,
                    line_end=line_end,
                    column_start=column_start,
                    column_end=column_end,
                    is_primary=is_primary,
                    provenance_id=provenance_id,
                    details=details,
                )
            self.connection.execute(
                """
                UPDATE function_source_ranges
                SET line_end = ?, column_end = ?, is_primary = ?,
                    provenance_id = ?, details_json = ?
                WHERE function_id = ? AND source_file_id = ?
                  AND line_start = ? AND column_start = ?
                """,
                (
                    line_end,
                    column_end,
                    int(is_primary),
                    provenance_id,
                    _canonical_json(details),
                    function_id,
                    source_file_id,
                    line_start,
                    column_start,
                ),
            )

    def add_function_source_range_assertion(
        self,
        function_id: str,
        source_file_id: str,
        *,
        line_start: int = 0,
        line_end: int | None = None,
        column_start: int = 0,
        column_end: int | None = None,
        is_primary: bool = False,
        provenance_id: str,
        assertion_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        fact = self.connection.execute(
            """
            SELECT 1 FROM function_source_ranges
            WHERE function_id = ? AND source_file_id = ?
              AND line_start = ? AND column_start = ?
            """,
            (function_id, source_file_id, line_start, column_start),
        ).fetchone()
        if fact is None:
            raise AtlasError("unknown canonical function source range")
        details_json = _canonical_json(details)
        assertion_id = assertion_id or stable_id(
            "function-source-range-assertion",
            function_id,
            source_file_id,
            line_start,
            column_start,
            line_end,
            column_end,
            bool(is_primary),
            provenance_id,
            json.loads(details_json),
        )
        values = {
            "assertion_id": assertion_id,
            "function_id": function_id,
            "source_file_id": source_file_id,
            "line_start": line_start,
            "column_start": column_start,
            "line_end": line_end,
            "column_end": column_end,
            "is_primary": int(is_primary),
            "provenance_id": provenance_id,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "function_source_range_assertions",
                "assertion_id",
                values,
                immutable=tuple(values),
            )
        return assertion_id

    def iter_function_source_range_assertions(
        self, function_id: str
    ) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            """
            SELECT * FROM function_source_range_assertions
            WHERE function_id = ?
            ORDER BY source_file_id, line_start, column_start, assertion_id
            """,
            (function_id,),
        ):
            result = dict(row)
            result["is_primary"] = bool(result["is_primary"])
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def upsert_signature_result(
        self,
        function_id: str,
        result: SignatureResult,
        *,
        provenance_id: str,
        details: Mapping[str, Any] = {},
    ) -> None:
        """Persist one exact or unresolved CodeView function-type result.

        ``function_id`` is the stable logical/procedure-record identity.  No
        symbol name participates in this join.  Re-importing may improve an
        unresolved row into a resolved row, but it may not move the stable
        function to a different raw type index.
        """

        function = self.connection.execute(
            "SELECT program_id, type_index FROM functions WHERE function_id = ?",
            (function_id,),
        ).fetchone()
        if function is None:
            raise AtlasError(f"unknown function {function_id!r}")
        if function["type_index"] != result.type_index:
            raise IdentityConflictError(
                f"signature type 0x{result.type_index:X} does not match "
                f"function type {function['type_index']!r}"
            )

        signature = result.signature
        if signature is not None:
            if signature.type_index != result.type_index:
                raise IdentityConflictError(
                    "signature result and structured signature type indices disagree"
                )
            values = {
                "function_id": function_id,
                "program_id": function["program_id"],
                "type_index": result.type_index,
                "resolution_status": "resolved",
                "error_code": None,
                "error_message": None,
                "leaf_kind": signature.leaf_kind,
                "leaf_name": signature.leaf_name,
                "return_type_index": signature.return_type_index,
                "class_type_index": signature.class_type_index,
                "this_type_index": signature.this_type_index,
                "calling_convention": signature.calling_convention,
                "calling_convention_name": signature.calling_convention_name,
                "attributes": signature.attributes,
                "this_adjustment": signature.this_adjustment,
                "parameter_count": signature.parameter_count,
                "argument_list_type_index": signature.argument_list_type_index,
                "argument_list_count": signature.argument_list_count,
                "is_variadic": int(signature.is_variadic),
                "rendered_return_type": signature.rendered_return_type,
                "rendered_class_type": signature.rendered_class_type,
                "rendered_this_type": signature.rendered_this_type,
                "rendered_signature": signature.rendered_signature,
                "provenance_id": provenance_id,
                "details_json": _canonical_json(details),
            }
            arguments = tuple(
                (
                    position,
                    type_index,
                    int(
                        signature.is_variadic
                        and position == signature.argument_list_count - 1
                        and type_index == 0
                    ),
                    signature.rendered_argument_types[position],
                )
                for position, type_index in enumerate(
                    signature.argument_type_indices
                )
            )
            if len(arguments) != signature.argument_list_count or len(
                signature.rendered_argument_types
            ) != signature.argument_list_count:
                raise AtlasError(
                    "structured signature argument counts are internally inconsistent"
                )
        else:
            if not result.error_code:
                raise ValueError("an unresolved signature result needs an error_code")
            values = {
                "function_id": function_id,
                "program_id": function["program_id"],
                "type_index": result.type_index,
                "resolution_status": "unresolved",
                "error_code": result.error_code,
                "error_message": result.error_message,
                "leaf_kind": result.actual_leaf_kind,
                "leaf_name": result.actual_leaf_name,
                "return_type_index": None,
                "class_type_index": None,
                "this_type_index": None,
                "calling_convention": None,
                "calling_convention_name": None,
                "attributes": None,
                "this_adjustment": None,
                "parameter_count": None,
                "argument_list_type_index": None,
                "argument_list_count": None,
                "is_variadic": None,
                "rendered_return_type": None,
                "rendered_class_type": None,
                "rendered_this_type": None,
                "rendered_signature": None,
                "provenance_id": provenance_id,
                "details_json": _canonical_json(details),
            }
            arguments = ()

        with self.transaction():
            # Shape changes are deliberate replacements.  Deleting children
            # first also keeps direct-SQL triggers from permitting stale args.
            self.connection.execute(
                "DELETE FROM function_signature_arguments WHERE function_id = ?",
                (function_id,),
            )
            self._stable_upsert(
                "function_signatures",
                "function_id",
                values,
                immutable=("program_id", "type_index"),
            )
            self.connection.executemany(
                """
                INSERT INTO function_signature_arguments
                    (function_id, position, type_index, is_vararg_marker,
                     rendered_type, details_json)
                VALUES (?, ?, ?, ?, ?, '{}')
                """,
                (
                    (function_id, position, type_index, marker, rendered)
                    for position, type_index, marker, rendered in arguments
                ),
            )
            self.connection.execute(
                """
                UPDATE function_signatures
                SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE function_id = ?
                """,
                (function_id,),
            )

    def get_function_signature(self, function_id: str) -> dict[str, Any] | None:
        """Return a stored signature resolution and its exact ordered args."""

        row = self.connection.execute(
            "SELECT * FROM function_signatures WHERE function_id = ?",
            (function_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        if result["is_variadic"] is not None:
            result["is_variadic"] = bool(result["is_variadic"])
        argument_rows = self.connection.execute(
            """
            SELECT position, type_index, is_vararg_marker, rendered_type, details_json
            FROM function_signature_arguments
            WHERE function_id = ? ORDER BY position
            """,
            (function_id,),
        ).fetchall()
        result["arguments"] = [
            {
                "position": argument["position"],
                "type_index": argument["type_index"],
                "is_vararg_marker": bool(argument["is_vararg_marker"]),
                "rendered_type": argument["rendered_type"],
                "details": _decode_json(argument["details_json"]),
            }
            for argument in argument_rows
        ]
        return result

    def iter_function_signatures(
        self,
        *,
        program_id: str | None = None,
        resolution_status: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield stored signature resolutions in stable function-ID order."""

        clauses: list[str] = []
        parameters: list[Any] = []
        if program_id is not None:
            clauses.append("program_id = ?")
            parameters.append(program_id)
        if resolution_status is not None:
            clauses.append("resolution_status = ?")
            parameters.append(resolution_status)
        sql = "SELECT function_id FROM function_signatures"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY function_id"
        for row in self.connection.execute(sql, parameters):
            result = self.get_function_signature(row[0])
            assert result is not None
            yield result

    def upsert_fold_group(
        self,
        fold_group_id: str,
        *,
        program_id: str,
        kind: str = "icf",
        provenance_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        values = {
            "fold_group_id": fold_group_id,
            "program_id": program_id,
            "kind": kind,
            "provenance_id": provenance_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "fold_groups",
                "fold_group_id",
                values,
                immutable=("program_id",),
            )
        return fold_group_id

    def add_fold_member(
        self, fold_group_id: str, function_id: str, *, member_role: str = "member"
    ) -> None:
        row = self.connection.execute(
            "SELECT program_id FROM fold_groups WHERE fold_group_id = ?",
            (fold_group_id,),
        ).fetchone()
        if row is None:
            raise AtlasError(f"unknown fold group {fold_group_id!r}")
        with self.transaction():
            self.connection.execute(
                """
                INSERT INTO fold_group_members
                    (fold_group_id, program_id, function_id, member_role)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(fold_group_id, function_id)
                DO UPDATE SET member_role = excluded.member_role
                """,
                (fold_group_id, row[0], function_id, member_role),
            )

    def upsert_class(
        self,
        class_id: str,
        *,
        program_id: str,
        identity_key: str,
        type_index: int | None = None,
        size_bytes: int | None = None,
        module_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        values = {
            "class_id": class_id,
            "program_id": program_id,
            "identity_key": identity_key,
            "type_index": type_index,
            "size_bytes": size_bytes,
            "module_id": module_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "classes",
                "class_id",
                values,
                immutable=("program_id", "identity_key"),
            )
        return class_id

    def add_class_name(
        self,
        class_id: str,
        name: str,
        *,
        name_kind: str,
        is_primary: bool = False,
        provenance_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> int:
        with self.transaction():
            if is_primary:
                self.connection.execute(
                    """
                    UPDATE class_names SET is_primary = 0
                    WHERE class_id = ? AND name_kind = ? AND name <> ?
                    """,
                    (class_id, name_kind, name),
                )
            self.connection.execute(
                """
                INSERT INTO class_names
                    (class_id, name, name_kind, is_primary, provenance_id, details_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(class_id, name_kind, name) DO NOTHING
                """,
                (
                    class_id,
                    name,
                    name_kind,
                    int(is_primary),
                    provenance_id,
                    _canonical_json(details),
                ),
            )
            row = self.connection.execute(
                """
                SELECT name_id FROM class_names
                WHERE class_id = ? AND name_kind = ? AND name = ?
                """,
                (class_id, name_kind, name),
            ).fetchone()
            assert row is not None
            name_id = int(row[0])
            if provenance_id is not None:
                self.add_class_name_assertion(
                    name_id,
                    is_primary=is_primary,
                    provenance_id=provenance_id,
                    details=details,
                )
            self.connection.execute(
                """
                UPDATE class_names
                SET is_primary = ?, provenance_id = ?, details_json = ?
                WHERE name_id = ?
                """,
                (int(is_primary), provenance_id, _canonical_json(details), name_id),
            )
        return name_id

    def add_class_name_assertion(
        self,
        name_id: int,
        *,
        is_primary: bool,
        provenance_id: str,
        assertion_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        name = self.connection.execute(
            """
            SELECT class_id, name, name_kind FROM class_names WHERE name_id = ?
            """,
            (name_id,),
        ).fetchone()
        if name is None:
            raise AtlasError(f"unknown class name row {name_id!r}")
        details_json = _canonical_json(details)
        assertion_id = assertion_id or stable_id(
            "class-name-assertion",
            name["class_id"],
            name["name_kind"],
            name["name"],
            bool(is_primary),
            provenance_id,
            json.loads(details_json),
        )
        values = {
            "assertion_id": assertion_id,
            "name_id": name_id,
            "is_primary": int(is_primary),
            "provenance_id": provenance_id,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "class_name_assertions",
                "assertion_id",
                values,
                immutable=tuple(values),
            )
        return assertion_id

    def iter_class_name_assertions(
        self, *, class_id: str | None = None, name_id: int | None = None
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if class_id is not None:
            clauses.append("n.class_id = ?")
            parameters.append(class_id)
        if name_id is not None:
            clauses.append("a.name_id = ?")
            parameters.append(name_id)
        sql = """
            SELECT a.*, n.class_id, n.name, n.name_kind
            FROM class_name_assertions a JOIN class_names n USING (name_id)
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY n.class_id, n.name_kind, n.name, a.assertion_id"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["is_primary"] = bool(result["is_primary"])
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def upsert_vtable(
        self,
        vtable_id: str,
        *,
        program_id: str,
        class_id: str,
        address_space: str,
        address: int,
        vfptr_role: str,
        subobject_offset: int | None = None,
        table_index: int | None = None,
        declared_slot_count: int | None = None,
        provenance_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        values = {
            "vtable_id": vtable_id,
            "program_id": program_id,
            "class_id": class_id,
            "address_space": address_space,
            "address": address,
            "vfptr_role": vfptr_role,
            "subobject_offset": subobject_offset,
            "table_index": table_index,
            "declared_slot_count": declared_slot_count,
            "provenance_id": provenance_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "vtables",
                "vtable_id",
                values,
                immutable=(
                    "program_id",
                    "class_id",
                    "address_space",
                    "address",
                    "vfptr_role",
                ),
            )
        return vtable_id

    def upsert_vtable_slot(
        self,
        vtable_id: str,
        slot_index: int,
        *,
        target_address_group_id: str | None = None,
        unresolved_target_id: str | None = None,
        declared_type_index: int | None = None,
        provenance_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> None:
        row = self.connection.execute(
            "SELECT program_id FROM vtables WHERE vtable_id = ?", (vtable_id,)
        ).fetchone()
        if row is None:
            raise AtlasError(f"unknown vtable {vtable_id!r}")
        with self.transaction():
            self.connection.execute(
                """
                INSERT INTO vtable_slots
                    (vtable_id, program_id, slot_index, target_address_group_id,
                     unresolved_target_id, declared_type_index, provenance_id, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vtable_id, slot_index) DO NOTHING
                """,
                (
                    vtable_id,
                    row[0],
                    slot_index,
                    target_address_group_id,
                    unresolved_target_id,
                    declared_type_index,
                    provenance_id,
                    _canonical_json(details),
                ),
            )
            if provenance_id is not None:
                self.add_vtable_slot_assertion(
                    vtable_id,
                    slot_index,
                    target_address_group_id=target_address_group_id,
                    unresolved_target_id=unresolved_target_id,
                    declared_type_index=declared_type_index,
                    provenance_id=provenance_id,
                    details=details,
                )
            self.connection.execute(
                """
                UPDATE vtable_slots
                SET target_address_group_id = ?, unresolved_target_id = ?,
                    declared_type_index = ?, provenance_id = ?, details_json = ?
                WHERE vtable_id = ? AND slot_index = ?
                """,
                (
                    target_address_group_id,
                    unresolved_target_id,
                    declared_type_index,
                    provenance_id,
                    _canonical_json(details),
                    vtable_id,
                    slot_index,
                ),
            )

    def add_vtable_slot_assertion(
        self,
        vtable_id: str,
        slot_index: int,
        *,
        provenance_id: str,
        target_address_group_id: str | None = None,
        unresolved_target_id: str | None = None,
        declared_type_index: int | None = None,
        assertion_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        slot = self.connection.execute(
            """
            SELECT program_id FROM vtable_slots
            WHERE vtable_id = ? AND slot_index = ?
            """,
            (vtable_id, slot_index),
        ).fetchone()
        if slot is None:
            raise AtlasError("unknown canonical vtable slot")
        details_json = _canonical_json(details)
        assertion_id = assertion_id or stable_id(
            "vtable-slot-assertion",
            vtable_id,
            slot_index,
            target_address_group_id,
            unresolved_target_id,
            declared_type_index,
            provenance_id,
            json.loads(details_json),
        )
        values = {
            "assertion_id": assertion_id,
            "vtable_id": vtable_id,
            "program_id": slot["program_id"],
            "slot_index": slot_index,
            "target_address_group_id": target_address_group_id,
            "unresolved_target_id": unresolved_target_id,
            "declared_type_index": declared_type_index,
            "provenance_id": provenance_id,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "vtable_slot_assertions",
                "assertion_id",
                values,
                immutable=tuple(values),
            )
        return assertion_id

    def iter_vtable_slot_assertions(
        self, vtable_id: str, *, slot_index: int | None = None
    ) -> Iterator[dict[str, Any]]:
        sql = "SELECT * FROM vtable_slot_assertions WHERE vtable_id = ?"
        parameters: list[Any] = [vtable_id]
        if slot_index is not None:
            sql += " AND slot_index = ?"
            parameters.append(slot_index)
        sql += " ORDER BY slot_index, provenance_id, assertion_id"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def register_input_bytes(
        self, data: bytes, *, media_type: str | None = None
    ) -> str:
        digest = hashlib.sha256(data).hexdigest()
        content_id = f"sha256:{digest}"
        self._upsert_input_artifact(content_id, digest, len(data), media_type)
        return content_id

    def register_input(
        self,
        path: str | Path,
        *,
        media_type: str | None = None,
        chunk_size: int = 1024 * 1024,
    ) -> str:
        """Hash a file and register its content, without making its path identity."""

        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        digest, size = self._hash_stream(Path(path).open("rb"), chunk_size)
        content_id = f"sha256:{digest}"
        self._upsert_input_artifact(content_id, digest, size, media_type)
        return content_id

    @staticmethod
    def _hash_stream(stream: BinaryIO, chunk_size: int) -> tuple[str, int]:
        hasher = hashlib.sha256()
        size = 0
        with stream:
            while chunk := stream.read(chunk_size):
                hasher.update(chunk)
                size += len(chunk)
        return hasher.hexdigest(), size

    def _upsert_input_artifact(
        self,
        content_id: str,
        digest: str,
        size_bytes: int,
        media_type: str | None,
    ) -> None:
        values = {
            "content_id": content_id,
            "hash_algorithm": "sha256",
            "digest": digest,
            "size_bytes": size_bytes,
            "media_type": media_type,
        }
        with self.transaction():
            self._stable_upsert(
                "input_artifacts",
                "content_id",
                values,
                immutable=("hash_algorithm", "digest", "size_bytes"),
            )

    def create_manifest(self, entries: Iterable[ManifestEntry]) -> str:
        normalized: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for entry in entries:
            key = (entry.role, entry.logical_name)
            if key in seen:
                raise ValueError(f"duplicate manifest role/name pair {key!r}")
            seen.add(key)
            metadata = json.loads(_canonical_json(entry.metadata))
            normalized.append(
                {
                    "content_id": entry.content_id,
                    "role": entry.role,
                    "logical_name": entry.logical_name,
                    "metadata": metadata,
                }
            )
        normalized.sort(
            key=lambda item: (item["role"], item["logical_name"], item["content_id"])
        )
        document = {
            "format": "fnv-source-atlas-input-manifest/v1",
            "entries": normalized,
        }
        canonical = _canonical_json(document)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        manifest_id = f"sha256:{digest}"
        with self.transaction():
            for item in normalized:
                if self.connection.execute(
                    "SELECT 1 FROM input_artifacts WHERE content_id = ?",
                    (item["content_id"],),
                ).fetchone() is None:
                    raise AtlasError(
                        f"manifest references unknown content {item['content_id']!r}"
                    )
            self._stable_upsert(
                "input_manifests",
                "manifest_id",
                {
                    "manifest_id": manifest_id,
                    "hash_algorithm": "sha256",
                    "digest": digest,
                    "canonical_json": canonical,
                },
                immutable=("hash_algorithm", "digest", "canonical_json"),
            )
            for ordinal, item in enumerate(normalized):
                self.connection.execute(
                    """
                    INSERT INTO manifest_entries
                        (manifest_id, ordinal, content_id, role, logical_name, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(manifest_id, ordinal) DO UPDATE SET
                        content_id = excluded.content_id,
                        role = excluded.role,
                        logical_name = excluded.logical_name,
                        metadata_json = excluded.metadata_json
                    """,
                    (
                        manifest_id,
                        ordinal,
                        item["content_id"],
                        item["role"],
                        item["logical_name"],
                        _canonical_json(item["metadata"]),
                    ),
                )
        return manifest_id

    def verify_manifest(self, manifest_id: str) -> bool:
        row = self.connection.execute(
            "SELECT digest, canonical_json FROM input_manifests WHERE manifest_id = ?",
            (manifest_id,),
        ).fetchone()
        if row is None:
            raise ManifestVerificationError(f"unknown manifest {manifest_id!r}")
        actual_digest = hashlib.sha256(row["canonical_json"].encode("utf-8")).hexdigest()
        if manifest_id != f"sha256:{actual_digest}" or row["digest"] != actual_digest:
            raise ManifestVerificationError("manifest JSON does not match its content ID")
        document = json.loads(row["canonical_json"])
        expected = document.get("entries")
        actual_rows = self.connection.execute(
            """
            SELECT ordinal, content_id, role, logical_name, metadata_json
            FROM manifest_entries WHERE manifest_id = ? ORDER BY ordinal
            """,
            (manifest_id,),
        ).fetchall()
        expected_with_ordinals = [
            {"ordinal": ordinal, **item}
            for ordinal, item in enumerate(expected)
        ]
        actual_with_ordinals = [
            {
                "ordinal": item["ordinal"],
                "content_id": item["content_id"],
                "role": item["role"],
                "logical_name": item["logical_name"],
                "metadata": json.loads(item["metadata_json"]),
            }
            for item in actual_rows
        ]
        if actual_with_ordinals != expected_with_ordinals:
            raise ManifestVerificationError(
                "normalized manifest entries do not match the content-addressed JSON"
            )
        return True

    def upsert_provenance(
        self,
        *,
        kind: str,
        producer: str,
        provenance_id: str | None = None,
        producer_version: str | None = None,
        method: str | None = None,
        manifest_id: str | None = None,
        parameters: Mapping[str, Any] = {},
        notes: str | None = None,
    ) -> str:
        parameters_json = _canonical_json(parameters)
        provenance_id = provenance_id or stable_id(
            "provenance",
            kind,
            producer,
            producer_version,
            method,
            manifest_id,
            json.loads(parameters_json),
        )
        values = {
            "provenance_id": provenance_id,
            "kind": kind,
            "producer": producer,
            "producer_version": producer_version,
            "method": method,
            "manifest_id": manifest_id,
            "parameters_json": parameters_json,
            "notes": notes,
        }
        with self.transaction():
            self._stable_upsert(
                "provenance",
                "provenance_id",
                values,
                immutable=(
                    "kind",
                    "producer",
                    "producer_version",
                    "method",
                    "manifest_id",
                    "parameters_json",
                ),
            )
        return provenance_id

    def upsert_unresolved_target(
        self,
        *,
        target_kind: str,
        target_id: str | None = None,
        program_id: str | None = None,
        address_group_id: str | None = None,
        name_hint: str | None = None,
        reason: str | None = None,
        provenance_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        if address_group_id is not None:
            row = self.connection.execute(
                "SELECT program_id FROM address_groups WHERE address_group_id = ?",
                (address_group_id,),
            ).fetchone()
            if row is None:
                raise AtlasError(f"unknown address group {address_group_id!r}")
            if program_id is not None and program_id != row[0]:
                raise IdentityConflictError("target program and address group disagree")
            program_id = row[0]
        if program_id is None:
            raise ValueError("program_id is required for a target without an address group")
        target_id = target_id or stable_id(
            "target", program_id, address_group_id, target_kind, name_hint
        )
        existing_resolution = self.connection.execute(
            """
            SELECT status, resolved_function_id FROM unresolved_targets
            WHERE target_id = ?
            """,
            (target_id,),
        ).fetchone()
        values = {
            "target_id": target_id,
            "program_id": program_id,
            "address_group_id": address_group_id,
            "target_kind": target_kind,
            "name_hint": name_hint,
            "reason": reason,
            "status": existing_resolution["status"] if existing_resolution else "open",
            "resolved_function_id": (
                existing_resolution["resolved_function_id"]
                if existing_resolution
                else None
            ),
            "provenance_id": provenance_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "unresolved_targets",
                "target_id",
                values,
                immutable=(
                    "program_id",
                    "address_group_id",
                    "target_kind",
                    "name_hint",
                ),
            )
        return target_id

    def resolve_target(self, target_id: str, function_id: str) -> None:
        target = self.connection.execute(
            """
            SELECT program_id, address_group_id FROM unresolved_targets
            WHERE target_id = ?
            """,
            (target_id,),
        ).fetchone()
        if target is None:
            raise AtlasError(f"unknown target {target_id!r}")
        function = self.connection.execute(
            """
            SELECT program_id, address_group_id FROM functions
            WHERE function_id = ?
            """,
            (function_id,),
        ).fetchone()
        if function is None:
            raise AtlasError(f"unknown function {function_id!r}")
        if function["program_id"] != target["program_id"]:
            raise IdentityConflictError(
                "unresolved target and resolved function belong to different programs"
            )
        if (
            target["address_group_id"] is not None
            and target["address_group_id"] != function["address_group_id"]
        ):
            raise IdentityConflictError(
                "address-specific target cannot resolve to a different address group"
            )
        with self.transaction():
            cursor = self.connection.execute(
                """
                UPDATE unresolved_targets
                SET status = 'resolved', resolved_function_id = ?
                WHERE target_id = ?
                """,
                (function_id, target_id),
            )
            assert cursor.rowcount == 1

    def upsert_match_claim(
        self,
        *,
        provenance_id: str,
        claim_id: str | None = None,
        pc_function_id: str | None = None,
        pc_target_id: str | None = None,
        xbox_function_id: str | None = None,
        xbox_target_id: str | None = None,
        status: str = "candidate",
        confidence_label: str | None = None,
        confidence_value: float | None = None,
        rationale: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        claim_id = claim_id or stable_id(
            "claim",
            pc_function_id,
            pc_target_id,
            xbox_function_id,
            xbox_target_id,
            provenance_id,
        )
        values = {
            "claim_id": claim_id,
            "pc_function_id": pc_function_id,
            "pc_target_id": pc_target_id,
            "xbox_function_id": xbox_function_id,
            "xbox_target_id": xbox_target_id,
            "status": status,
            "confidence_label": confidence_label,
            "confidence_value": confidence_value,
            "provenance_id": provenance_id,
            "rationale": rationale,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "match_claims",
                "claim_id",
                values,
                immutable=(
                    "pc_function_id",
                    "pc_target_id",
                    "xbox_function_id",
                    "xbox_target_id",
                    "provenance_id",
                ),
            )
            self.connection.execute(
                """
                UPDATE match_claims
                SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE claim_id = ?
                """,
                (claim_id,),
            )
        return claim_id

    def add_claim_evidence(
        self,
        claim_id: str,
        *,
        effect: str,
        evidence_kind: str,
        independence_group: str,
        provenance_id: str,
        evidence_id: str | None = None,
        asserted_strength: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        details_json = _canonical_json(details)
        evidence_id = evidence_id or stable_id(
            "evidence",
            claim_id,
            effect,
            evidence_kind,
            independence_group,
            provenance_id,
            asserted_strength,
            json.loads(details_json),
        )
        values = {
            "evidence_id": evidence_id,
            "claim_id": claim_id,
            "effect": effect,
            "evidence_kind": evidence_kind,
            "independence_group": independence_group,
            "provenance_id": provenance_id,
            "asserted_strength": asserted_strength,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "claim_evidence",
                "evidence_id",
                values,
                immutable=(
                    "claim_id",
                    "effect",
                    "evidence_kind",
                    "independence_group",
                    "provenance_id",
                    "asserted_strength",
                    "details_json",
                ),
            )
        return evidence_id

    def upsert_match_hypothesis_set(
        self,
        *,
        provenance_id: str,
        hypothesis_set_id: str | None = None,
        identity_key: str | None = None,
        pc_function_id: str | None = None,
        pc_target_id: str | None = None,
        status: str = "candidate",
        rationale: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        """Create a producer/occurrence-specific set of viable alternatives.

        A set asserts only that its alternatives remain under consideration.  It
        does not select one, score them, or require exactly one to survive.
        Callers with multiple occurrences from one producer should supply an
        explicit ``hypothesis_set_id`` or distinct ``identity_key``.
        """

        if (pc_function_id is None) == (pc_target_id is None):
            raise ValueError(
                "exactly one of pc_function_id and pc_target_id is required"
            )
        hypothesis_set_id = hypothesis_set_id or stable_id(
            "hypothesis-set",
            pc_function_id,
            pc_target_id,
            provenance_id,
            identity_key,
        )
        values = {
            "hypothesis_set_id": hypothesis_set_id,
            "pc_function_id": pc_function_id,
            "pc_target_id": pc_target_id,
            "status": status,
            "provenance_id": provenance_id,
            "identity_key": identity_key,
            "rationale": rationale,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "match_hypothesis_sets",
                "hypothesis_set_id",
                values,
                immutable=(
                    "pc_function_id",
                    "pc_target_id",
                    "provenance_id",
                    "identity_key",
                ),
            )
            self.connection.execute(
                """
                UPDATE match_hypothesis_sets
                SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE hypothesis_set_id = ?
                """,
                (hypothesis_set_id,),
            )
        return hypothesis_set_id

    def add_match_hypothesis_alternative(
        self,
        hypothesis_set_id: str,
        *,
        claim_id: str | None = None,
        xbox_fold_group_id: str | None = None,
        alternative_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        """Add an unordered scalar claim or one non-expanded Xbox fold bundle."""

        if (claim_id is None) == (xbox_fold_group_id is None):
            raise ValueError(
                "exactly one of claim_id and xbox_fold_group_id is required"
            )
        alternative_id = alternative_id or stable_id(
            "hypothesis-alternative",
            hypothesis_set_id,
            claim_id,
            xbox_fold_group_id,
        )
        values = {
            "alternative_id": alternative_id,
            "hypothesis_set_id": hypothesis_set_id,
            "claim_id": claim_id,
            "xbox_fold_group_id": xbox_fold_group_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "match_hypothesis_alternatives",
                "alternative_id",
                values,
                immutable=(
                    "hypothesis_set_id",
                    "claim_id",
                    "xbox_fold_group_id",
                ),
            )
        return alternative_id

    def add_match_hypothesis_evidence(
        self,
        hypothesis_set_id: str,
        *,
        effect: str,
        evidence_kind: str,
        independence_group: str,
        provenance_id: str,
        evidence_id: str | None = None,
        asserted_strength: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        details_json = _canonical_json(details)
        evidence_id = evidence_id or stable_id(
            "hypothesis-evidence",
            hypothesis_set_id,
            effect,
            evidence_kind,
            independence_group,
            provenance_id,
            asserted_strength,
            json.loads(details_json),
        )
        values = {
            "evidence_id": evidence_id,
            "hypothesis_set_id": hypothesis_set_id,
            "effect": effect,
            "evidence_kind": evidence_kind,
            "independence_group": independence_group,
            "provenance_id": provenance_id,
            "asserted_strength": asserted_strength,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "match_hypothesis_evidence",
                "evidence_id",
                values,
                immutable=(
                    "hypothesis_set_id",
                    "effect",
                    "evidence_kind",
                    "independence_group",
                    "provenance_id",
                    "asserted_strength",
                    "details_json",
                ),
            )
        return evidence_id

    def add_match_hypothesis_alternative_evidence(
        self,
        alternative_id: str,
        *,
        effect: str,
        evidence_kind: str,
        independence_group: str,
        provenance_id: str,
        evidence_id: str | None = None,
        asserted_strength: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        """Attach evidence to exactly one alternative, never its whole set."""

        details_json = _canonical_json(details)
        evidence_id = evidence_id or stable_id(
            "hypothesis-alternative-evidence",
            alternative_id,
            effect,
            evidence_kind,
            independence_group,
            provenance_id,
            asserted_strength,
            json.loads(details_json),
        )
        values = {
            "evidence_id": evidence_id,
            "alternative_id": alternative_id,
            "effect": effect,
            "evidence_kind": evidence_kind,
            "independence_group": independence_group,
            "provenance_id": provenance_id,
            "asserted_strength": asserted_strength,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "match_hypothesis_alternative_evidence",
                "evidence_id",
                values,
                immutable=tuple(values),
            )
        return evidence_id

    def get_match_hypothesis_alternative_evidence(
        self, evidence_id: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT evidence.*, alternative.hypothesis_set_id
            FROM match_hypothesis_alternative_evidence evidence
            JOIN match_hypothesis_alternatives alternative USING (alternative_id)
            WHERE evidence.evidence_id = ?
            """,
            (evidence_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        return result

    def iter_match_hypothesis_alternative_evidence(
        self,
        *,
        alternative_id: str | None = None,
        hypothesis_set_id: str | None = None,
        effect: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("evidence.alternative_id", alternative_id),
            ("alternative.hypothesis_set_id", hypothesis_set_id),
            ("evidence.effect", effect),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        sql = """
            SELECT evidence.*, alternative.hypothesis_set_id
            FROM match_hypothesis_alternative_evidence evidence
            JOIN match_hypothesis_alternatives alternative USING (alternative_id)
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += """
            ORDER BY alternative.hypothesis_set_id, evidence.alternative_id,
                     evidence.independence_group, evidence.evidence_id
        """
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def get_match_hypothesis_set(
        self, hypothesis_set_id: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM match_hypothesis_sets WHERE hypothesis_set_id = ?",
            (hypothesis_set_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        result["alternatives"] = []
        for item in self.connection.execute(
            """
            SELECT * FROM match_hypothesis_alternatives
            WHERE hypothesis_set_id = ? ORDER BY alternative_id
            """,
            (hypothesis_set_id,),
        ):
            alternative = dict(item)
            alternative["details"] = _decode_json(
                alternative.pop("details_json")
            )
            alternative["evidence"] = list(
                self.iter_match_hypothesis_alternative_evidence(
                    alternative_id=alternative["alternative_id"]
                )
            )
            result["alternatives"].append(alternative)
        result["evidence"] = []
        for item in self.connection.execute(
            """
            SELECT * FROM match_hypothesis_evidence
            WHERE hypothesis_set_id = ?
            ORDER BY independence_group, evidence_id
            """,
            (hypothesis_set_id,),
        ):
            evidence = dict(item)
            evidence["details"] = _decode_json(evidence.pop("details_json"))
            result["evidence"].append(evidence)
        return result

    def iter_match_hypothesis_sets(
        self,
        *,
        pc_function_id: str | None = None,
        pc_target_id: str | None = None,
        status: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if pc_function_id is not None:
            clauses.append("pc_function_id = ?")
            parameters.append(pc_function_id)
        if pc_target_id is not None:
            clauses.append("pc_target_id = ?")
            parameters.append(pc_target_id)
        if status is not None:
            clauses.append("status = ?")
            parameters.append(status)
        sql = "SELECT hypothesis_set_id FROM match_hypothesis_sets"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY hypothesis_set_id"
        for row in self.connection.execute(sql, parameters):
            result = self.get_match_hypothesis_set(row[0])
            assert result is not None
            yield result

    def upsert_reviewer(
        self,
        *,
        identity_kind: str,
        identity_key: str,
        display_name: str,
        reviewer_id: str | None = None,
        affiliation: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        """Register the durable identity used to attribute human decisions."""

        reviewer_id = reviewer_id or stable_id(
            "reviewer", identity_kind, identity_key
        )
        values = {
            "reviewer_id": reviewer_id,
            "identity_kind": identity_kind,
            "identity_key": identity_key,
            "display_name": display_name,
            "affiliation": affiliation,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "reviewers",
                "reviewer_id",
                values,
                immutable=("identity_kind", "identity_key"),
            )
        return reviewer_id

    def upsert_review_release(
        self,
        *,
        release_key: str,
        label: str,
        provenance_id: str,
        review_release_id: str | None = None,
        version: str | None = None,
        source_revision: str | None = None,
        manifest_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        """Register an immutable atlas release/build context under review."""

        review_release_id = review_release_id or stable_id(
            "review-release", release_key
        )
        values = {
            "review_release_id": review_release_id,
            "release_key": release_key,
            "label": label,
            "version": version,
            "source_revision": source_revision,
            "manifest_id": manifest_id,
            "provenance_id": provenance_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "review_releases",
                "review_release_id",
                values,
                immutable=tuple(values),
            )
        return review_release_id

    def add_review_decision(
        self,
        *,
        reviewer_id: str,
        action: str,
        decided_at: str | datetime,
        rationale: str,
        provenance_id: str,
        review_release_id: str,
        hypothesis_set_id: str | None = None,
        alternative_id: str | None = None,
        claim_id: str | None = None,
        previous_decision_id: str | None = None,
        decision_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        """Append one reviewer's decision about exactly one stable target.

        ``accept`` on a hypothesis set endorses the set-level proposition only;
        it does not accept every alternative.  Accepting an alternative instead
        endorses that exact scalar claim or fold bundle.  ``reopen`` returns one
        reviewer's stance to an open state.  ``supersede`` records withdrawal or
        replacement without deleting the target or any earlier decision.

        A follow-up names its exact previous decision.  Chains are per reviewer
        and target, may cross release contexts, and never imply consensus with
        another reviewer.
        """

        target_kind, target_column, target_id = _review_target(
            hypothesis_set_id=hypothesis_set_id,
            alternative_id=alternative_id,
            claim_id=claim_id,
        )
        if action not in {"accept", "reject", "defer", "reopen", "supersede"}:
            raise ValueError(f"unsupported review action {action!r}")
        if action == "reopen" and previous_decision_id is None:
            raise ValueError("reopen requires previous_decision_id")
        if not rationale.strip():
            raise ValueError("review rationale must not be empty")
        canonical_timestamp = _canonical_review_timestamp(decided_at)
        details_json = _canonical_json(details)
        decision_id = decision_id or stable_id(
            "review-decision",
            target_kind,
            target_id,
            reviewer_id,
            action,
            canonical_timestamp,
            rationale,
            provenance_id,
            review_release_id,
            previous_decision_id,
            json.loads(details_json),
        )

        target_table = {
            "hypothesis_set": "match_hypothesis_sets",
            "alternative": "match_hypothesis_alternatives",
            "claim": "match_claims",
        }[target_kind]
        if self.connection.execute(
            f"SELECT 1 FROM {target_table} WHERE {target_column} = ?", (target_id,)
        ).fetchone() is None:
            raise AtlasError(f"unknown review {target_kind} target {target_id!r}")
        if self.connection.execute(
            "SELECT 1 FROM reviewers WHERE reviewer_id = ?", (reviewer_id,)
        ).fetchone() is None:
            raise AtlasError(f"unknown reviewer {reviewer_id!r}")
        if self.connection.execute(
            "SELECT 1 FROM review_releases WHERE review_release_id = ?",
            (review_release_id,),
        ).fetchone() is None:
            raise AtlasError(f"unknown review release {review_release_id!r}")

        if previous_decision_id is not None:
            previous = self.connection.execute(
                "SELECT * FROM review_decisions WHERE decision_id = ?",
                (previous_decision_id,),
            ).fetchone()
            if previous is None:
                raise AtlasError(
                    f"unknown previous review decision {previous_decision_id!r}"
                )
            if (
                previous["reviewer_id"] != reviewer_id
                or previous["hypothesis_set_id"] != hypothesis_set_id
                or previous["alternative_id"] != alternative_id
                or previous["claim_id"] != claim_id
            ):
                raise IdentityConflictError(
                    "previous review decision has a different reviewer or target"
                )
            current_time = datetime.fromisoformat(
                canonical_timestamp.replace("Z", "+00:00")
            )
            previous_time = datetime.fromisoformat(
                previous["decided_at"].replace("Z", "+00:00")
            )
            if current_time < previous_time:
                raise ValueError("review decision predates its previous decision")
            successor = self.connection.execute(
                """
                SELECT decision_id FROM review_decisions
                WHERE previous_decision_id = ?
                """,
                (previous_decision_id,),
            ).fetchone()
            if successor is not None and successor["decision_id"] != decision_id:
                raise IdentityConflictError(
                    "previous review decision already has a successor"
                )

        values = {
            "decision_id": decision_id,
            "hypothesis_set_id": hypothesis_set_id,
            "alternative_id": alternative_id,
            "claim_id": claim_id,
            "reviewer_id": reviewer_id,
            "action": action,
            "decided_at": canonical_timestamp,
            "rationale": rationale,
            "provenance_id": provenance_id,
            "review_release_id": review_release_id,
            "previous_decision_id": previous_decision_id,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "review_decisions",
                "decision_id",
                values,
                immutable=tuple(values),
            )
        return decision_id

    def iter_review_history(
        self,
        *,
        hypothesis_set_id: str | None = None,
        alternative_id: str | None = None,
        claim_id: str | None = None,
        reviewer_id: str | None = None,
        review_release_id: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Iterate immutable decisions, optionally restricted to one target."""

        target_values = (hypothesis_set_id, alternative_id, claim_id)
        if sum(value is not None for value in target_values) > 1:
            raise ValueError("review history accepts at most one target filter")
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("hypothesis_set_id", hypothesis_set_id),
            ("alternative_id", alternative_id),
            ("claim_id", claim_id),
            ("reviewer_id", reviewer_id),
            ("review_release_id", review_release_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        sql = """
            WITH RECURSIVE chained AS (
                SELECT d.*, 0 AS chain_depth
                FROM review_decisions d
                WHERE d.previous_decision_id IS NULL
                UNION ALL
                SELECT d.*, chained.chain_depth + 1
                FROM review_decisions d
                JOIN chained ON d.previous_decision_id = chained.decision_id
            )
            SELECT * FROM chained
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += """
            ORDER BY reviewer_id,
                     COALESCE(hypothesis_set_id, alternative_id, claim_id),
                     chain_depth, decided_at, decision_id
        """
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            if result["hypothesis_set_id"] is not None:
                result["target_kind"] = "hypothesis_set"
                result["target_id"] = result["hypothesis_set_id"]
            elif result["alternative_id"] is not None:
                result["target_kind"] = "alternative"
                result["target_id"] = result["alternative_id"]
            else:
                result["target_kind"] = "claim"
                result["target_id"] = result["claim_id"]
            yield result

    def get_current_review_state(
        self,
        *,
        hypothesis_set_id: str | None = None,
        alternative_id: str | None = None,
        claim_id: str | None = None,
    ) -> dict[str, Any]:
        """Return current leaf decisions separately for every reviewer.

        The result deliberately has no consensus or aggregate status field.
        ``status_counts`` is descriptive only and does not choose a winner.
        """

        target_kind, target_column, target_id = _review_target(
            hypothesis_set_id=hypothesis_set_id,
            alternative_id=alternative_id,
            claim_id=claim_id,
        )
        rows = self.connection.execute(
            f"""
            SELECT c.*, r.identity_kind AS reviewer_identity_kind,
                   r.identity_key AS reviewer_identity_key,
                   r.display_name AS reviewer_display_name,
                   release.release_key AS review_release_key,
                   release.label AS review_release_label,
                   release.version AS review_release_version
            FROM current_review_decisions c
            JOIN reviewers r USING (reviewer_id)
            JOIN review_releases release USING (review_release_id)
            WHERE c.{target_column} = ?
            ORDER BY c.reviewer_id, c.decision_id
            """,
            (target_id,),
        ).fetchall()
        current_by_reviewer: list[dict[str, Any]] = []
        status_counts: dict[str, int] = {}
        for row in rows:
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            current_by_reviewer.append(result)
            status = result["derived_status"]
            status_counts[status] = status_counts.get(status, 0) + 1
        return {
            "target_kind": target_kind,
            "target_id": target_id,
            "current_by_reviewer": current_by_reviewer,
            "status_counts": dict(sorted(status_counts.items())),
        }

    def upsert_control_flow_extraction(
        self,
        *,
        program_id: str,
        persistence_policy: str,
        source_physical_site_count: int,
        source_logical_use_count: int,
        persisted_physical_site_count: int,
        persisted_logical_use_count: int,
        triggering_logical_use_count: int,
        procedure_scan_count: int,
        provenance_id: str,
        extraction_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        """Register one immutable, explicitly filtered Xbox extraction run."""

        if persistence_policy not in CONTROL_FLOW_POLICIES:
            raise ValueError(
                f"unsupported control-flow persistence policy {persistence_policy!r}"
            )
        details_json = _canonical_json(details)
        extraction_id = extraction_id or stable_id(
            "control-flow-extraction",
            program_id,
            persistence_policy,
            source_physical_site_count,
            source_logical_use_count,
            persisted_physical_site_count,
            persisted_logical_use_count,
            triggering_logical_use_count,
            procedure_scan_count,
            provenance_id,
            json.loads(details_json),
        )
        values = {
            "extraction_id": extraction_id,
            "program_id": program_id,
            "persistence_policy": persistence_policy,
            "source_physical_site_count": source_physical_site_count,
            "source_logical_use_count": source_logical_use_count,
            "persisted_physical_site_count": persisted_physical_site_count,
            "persisted_logical_use_count": persisted_logical_use_count,
            "triggering_logical_use_count": triggering_logical_use_count,
            "procedure_scan_count": procedure_scan_count,
            "provenance_id": provenance_id,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "control_flow_extractions",
                "extraction_id",
                values,
                immutable=tuple(values),
            )
        return extraction_id

    def upsert_control_flow_site(
        self,
        site_id: str,
        *,
        address_group_id: str,
    ) -> str:
        """Register one physical instruction address, independent of procedures."""

        address = self.connection.execute(
            "SELECT program_id FROM address_groups WHERE address_group_id = ?",
            (address_group_id,),
        ).fetchone()
        if address is None:
            raise AtlasError(f"unknown control-flow site address {address_group_id!r}")
        values = {
            "site_id": site_id,
            "program_id": address["program_id"],
            "address_group_id": address_group_id,
        }
        with self.transaction():
            self._stable_upsert(
                "control_flow_sites",
                "site_id",
                values,
                immutable=tuple(values),
            )
        return site_id

    def add_control_flow_site_assertion(
        self,
        extraction_id: str,
        site_id: str,
        *,
        raw_site_va: int,
        instruction_word: int,
        branch_kind: str,
        raw_target_va: int | None,
        target_kind: str,
        target_record_count: int,
        link: bool,
        absolute: bool,
        conditional: bool,
        indirect: bool,
        bo: int | None = None,
        bi: int | None = None,
        target_address_group_id: str | None = None,
        target_function_id: str | None = None,
        target_fold_group_id: str | None = None,
        assertion_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        extraction = self.connection.execute(
            "SELECT program_id FROM control_flow_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if extraction is None:
            raise AtlasError(f"unknown control-flow extraction {extraction_id!r}")
        details_json = _canonical_json(details)
        assertion_id = assertion_id or stable_id(
            "control-flow-site-assertion",
            extraction_id,
            site_id,
            raw_site_va,
            instruction_word,
            branch_kind,
            raw_target_va,
            target_address_group_id,
            target_function_id,
            target_fold_group_id,
            bool(link),
            bool(absolute),
            bool(conditional),
            bool(indirect),
            bo,
            bi,
            target_kind,
            target_record_count,
            json.loads(details_json),
        )
        values = {
            "assertion_id": assertion_id,
            "extraction_id": extraction_id,
            "program_id": extraction["program_id"],
            "site_id": site_id,
            "raw_site_va": raw_site_va,
            "instruction_word": instruction_word,
            "branch_kind": branch_kind,
            "raw_target_va": raw_target_va,
            "target_address_group_id": target_address_group_id,
            "target_function_id": target_function_id,
            "target_fold_group_id": target_fold_group_id,
            "link": int(link),
            "absolute": int(absolute),
            "conditional": int(conditional),
            "indirect": int(indirect),
            "bo": bo,
            "bi": bi,
            "target_kind": target_kind,
            "target_record_count": target_record_count,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "control_flow_site_assertions",
                "assertion_id",
                values,
                immutable=tuple(values),
            )
        return assertion_id

    def upsert_control_flow_use(
        self,
        use_id: str,
        *,
        procedure_record_id: str,
        function_id: str,
        site_id: str,
    ) -> str:
        function = self.connection.execute(
            "SELECT program_id FROM functions WHERE function_id = ?", (function_id,)
        ).fetchone()
        site = self.connection.execute(
            "SELECT program_id FROM control_flow_sites WHERE site_id = ?", (site_id,)
        ).fetchone()
        if function is None:
            raise AtlasError(f"unknown control-flow procedure {function_id!r}")
        if site is None:
            raise AtlasError(f"unknown control-flow site {site_id!r}")
        if function["program_id"] != site["program_id"]:
            raise IdentityConflictError(
                "control-flow procedure and physical site belong to different programs"
            )
        values = {
            "use_id": use_id,
            "program_id": function["program_id"],
            "procedure_record_id": procedure_record_id,
            "function_id": function_id,
            "site_id": site_id,
        }
        with self.transaction():
            self._stable_upsert(
                "control_flow_uses",
                "use_id",
                values,
                immutable=tuple(values),
            )
        return use_id

    def add_control_flow_use_assertion(
        self,
        extraction_id: str,
        use_id: str,
        *,
        role: str,
        assertion_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        extraction = self.connection.execute(
            "SELECT program_id FROM control_flow_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if extraction is None:
            raise AtlasError(f"unknown control-flow extraction {extraction_id!r}")
        details_json = _canonical_json(details)
        assertion_id = assertion_id or stable_id(
            "control-flow-use-assertion",
            extraction_id,
            use_id,
            role,
            json.loads(details_json),
        )
        values = {
            "assertion_id": assertion_id,
            "extraction_id": extraction_id,
            "program_id": extraction["program_id"],
            "use_id": use_id,
            "role": role,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "control_flow_use_assertions",
                "assertion_id",
                values,
                immutable=tuple(values),
            )
        return assertion_id

    def add_control_flow_scan(
        self,
        extraction_id: str,
        *,
        procedure_record_id: str,
        declared_size: int,
        scanned_size: int,
        unscanned_byte_count: int,
        status: str,
        source_branch_use_count: int,
        persisted_branch_use_count: int,
        function_id: str | None = None,
        unresolved_target_id: str | None = None,
        scan_address_group_id: str | None = None,
        scan_id: str | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        if (function_id is None) == (unresolved_target_id is None):
            raise ValueError(
                "exactly one of function_id and unresolved_target_id is required"
            )
        extraction = self.connection.execute(
            "SELECT program_id FROM control_flow_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if extraction is None:
            raise AtlasError(f"unknown control-flow extraction {extraction_id!r}")
        details_json = _canonical_json(details)
        scan_id = scan_id or stable_id(
            "control-flow-scan",
            extraction_id,
            procedure_record_id,
            function_id,
            unresolved_target_id,
            scan_address_group_id,
            declared_size,
            scanned_size,
            unscanned_byte_count,
            status,
            source_branch_use_count,
            persisted_branch_use_count,
            json.loads(details_json),
        )
        values = {
            "scan_id": scan_id,
            "extraction_id": extraction_id,
            "program_id": extraction["program_id"],
            "procedure_record_id": procedure_record_id,
            "function_id": function_id,
            "unresolved_target_id": unresolved_target_id,
            "scan_address_group_id": scan_address_group_id,
            "declared_size": declared_size,
            "scanned_size": scanned_size,
            "unscanned_byte_count": unscanned_byte_count,
            "status": status,
            "source_branch_use_count": source_branch_use_count,
            "persisted_branch_use_count": persisted_branch_use_count,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "control_flow_scans",
                "scan_id",
                values,
                immutable=tuple(values),
            )
        return scan_id

    def persist_control_flow_extraction(
        self,
        extraction: ControlFlowExtraction,
        *,
        program_id: str,
        provenance_id: str,
        policy: str = "call_relevant_v1",
        extraction_id: str | None = None,
        address_space: str = "xbox-va",
        procedure_function_ids: Mapping[str, str] = {},
        unresolved_target_ids: Mapping[str, str] = {},
        details: Mapping[str, Any] = {},
    ) -> ControlFlowPersistenceResult:
        """Atomically persist an identity-safe, policy-selected Xbox extraction.

        Selection is delegated to :func:`ppc_control_flow.select_control_flow`.
        The call-relevant policy therefore cannot drift from the extractor's
        versioned role predicate.  It retains every logical membership of a
        selected physical site, all procedure scans, and the full-source counts.

        Procedure records resolve by stable record ID, optionally remapped by
        ``procedure_function_ids``.  A scan without a function must be mapped
        explicitly through ``unresolved_target_ids``; names are never consulted.
        This method creates address groups only--never functions, names, match
        claims, confidence, or acceptance state.
        """

        if policy not in CONTROL_FLOW_POLICIES:
            raise ValueError(f"unsupported control-flow persistence policy {policy!r}")
        program = self.connection.execute(
            "SELECT platform FROM programs WHERE program_id = ?", (program_id,)
        ).fetchone()
        if program is None:
            raise AtlasError(f"unknown program {program_id!r}")
        if program["platform"] != "xbox360":
            raise IdentityConflictError(
                "PowerPC control-flow persistence requires an Xbox 360 program"
            )
        if not address_space:
            raise ValueError("control-flow address space must not be empty")

        selected = select_control_flow(extraction, policy=policy)
        source_sites = {site.site_id: site for site in extraction.sites}
        source_uses = {use.use_id: use for use in extraction.uses}
        scans = {scan.record_id: scan for scan in extraction.scans}
        if len(source_sites) != len(extraction.sites):
            raise ValueError("control-flow extraction contains duplicate physical site IDs")
        if len(source_uses) != len(extraction.uses):
            raise ValueError("control-flow extraction contains duplicate logical use IDs")
        if len(scans) != len(extraction.scans):
            raise ValueError("control-flow extraction contains duplicate scan record IDs")

        source_uses_by_site: dict[str, list[Any]] = {}
        source_use_counts_by_record: dict[str, int] = {}
        for use in extraction.uses:
            site = source_sites.get(use.site_id)
            if site is None:
                raise ValueError(f"use {use.use_id!r} references an unknown physical site")
            if use.site_va != site.site_va:
                raise ValueError(f"use {use.use_id!r} disagrees with its physical site VA")
            scan = scans.get(use.record_id)
            if scan is None:
                raise ValueError(f"use {use.use_id!r} has no procedure scan")
            if (
                scan.va is None
                or use.site_va < scan.va
                or use.site_va >= scan.va + scan.scanned_size
            ):
                raise ValueError(
                    f"use {use.use_id!r} lies outside its procedure scan extent"
                )
            source_uses_by_site.setdefault(use.site_id, []).append(use)
            source_use_counts_by_record[use.record_id] = (
                source_use_counts_by_record.get(use.record_id, 0) + 1
            )
        for scan in extraction.scans:
            if source_use_counts_by_record.get(scan.record_id, 0) != scan.branch_use_count:
                raise ValueError(
                    f"scan {scan.record_id!r} branch-use count disagrees with uses"
                )
        if any(site_id not in source_uses_by_site for site_id in source_sites):
            raise ValueError("control-flow extraction contains a physical site with no use")

        selected_site_ids = {site.site_id for site in selected.sites}
        selected_use_ids = {use.use_id for use in selected.uses}
        expected_site_ids = (
            set(source_sites)
            if policy == "all_branches_v1"
            else {
                use.site_id
                for use in extraction.uses
                if use.role in CALL_RELEVANT_V1_ROLES
            }
        )
        expected_use_ids = {
            use.use_id for use in extraction.uses if use.site_id in expected_site_ids
        }
        if selected_site_ids != expected_site_ids or selected_use_ids != expected_use_ids:
            raise AtlasError("shared control-flow selector violated its persistence policy")
        if any(site_id not in source_uses_by_site for site_id in selected_site_ids):
            raise ValueError("selected control-flow site has no logical procedure use")

        triggering_use_count = (
            len(selected.uses)
            if policy == "all_branches_v1"
            else sum(
                use.role in CALL_RELEVANT_V1_ROLES for use in extraction.uses
            )
        )
        persisted_use_counts_by_record: dict[str, int] = {}
        for use in selected.uses:
            persisted_use_counts_by_record[use.record_id] = (
                persisted_use_counts_by_record.get(use.record_id, 0) + 1
            )

        protected_before = self._control_flow_protected_state()
        extraction_details = {
            **dict(details),
            "source_summary": extraction.to_summary(),
            "selection_is_physical_site_if_any_use_matches": True,
            "all_memberships_of_selected_sites_retained": True,
            "full_source_regenerable_from_provenance_manifest": True,
        }
        extraction_id = extraction_id or stable_id(
            "control-flow-extraction",
            program_id,
            policy,
            len(extraction.sites),
            len(extraction.uses),
            len(selected.sites),
            len(selected.uses),
            triggering_use_count,
            len(extraction.scans),
            provenance_id,
            extraction_details,
        )

        with self.batch():
            # Address groups are shared canonical identity rows.  Resolving an
            # existing natural key without calling ``upsert_address_group`` is
            # important: that general API is allowed to refresh its mutable
            # kind/details projection, while this producer must be strictly
            # non-destructive.  The cache also avoids repeated target/scan
            # lookups in the large real corpus.
            address_group_ids = {
                row["address"]: row["address_group_id"]
                for row in self.connection.execute(
                    """
                    SELECT address, address_group_id FROM address_groups
                    WHERE program_id = ? AND address_space = ?
                    """,
                    (program_id, address_space),
                )
            }

            def resolve_address_group(address: int) -> str:
                address_group_id = address_group_ids.get(address)
                if address_group_id is None:
                    address_group_id = self.upsert_address_group(
                        program_id=program_id,
                        address_space=address_space,
                        address=address,
                        kind="code",
                    )
                    address_group_ids[address] = address_group_id
                return address_group_id

            self.upsert_control_flow_extraction(
                extraction_id=extraction_id,
                program_id=program_id,
                persistence_policy=policy,
                source_physical_site_count=len(extraction.sites),
                source_logical_use_count=len(extraction.uses),
                persisted_physical_site_count=len(selected.sites),
                persisted_logical_use_count=len(selected.uses),
                triggering_logical_use_count=triggering_use_count,
                procedure_scan_count=len(extraction.scans),
                provenance_id=provenance_id,
                details=extraction_details,
            )

            for site in selected.sites:
                site_address_group_id = resolve_address_group(site.site_va)
                self.upsert_control_flow_site(
                    site.site_id, address_group_id=site_address_group_id
                )

            for use in selected.uses:
                function_id = procedure_function_ids.get(use.record_id, use.record_id)
                self.upsert_control_flow_use(
                    use.use_id,
                    procedure_record_id=use.record_id,
                    function_id=function_id,
                    site_id=use.site_id,
                )
                self.add_control_flow_use_assertion(
                    extraction_id,
                    use.use_id,
                    role=use.role,
                    details={"raw_site_va": use.site_va},
                )

            for site in selected.sites:
                target_address_group_id: str | None = None
                if site.target_va is not None:
                    target_address_group_id = resolve_address_group(site.target_va)
                self.add_control_flow_site_assertion(
                    extraction_id,
                    site.site_id,
                    raw_site_va=site.site_va,
                    instruction_word=site.instruction_word,
                    branch_kind=site.branch_kind,
                    raw_target_va=site.target_va,
                    target_address_group_id=target_address_group_id,
                    target_function_id=(
                        procedure_function_ids.get(
                            site.target_record_id, site.target_record_id
                        )
                        if site.target_kind == "unique_procedure"
                        else None
                    ),
                    target_fold_group_id=(
                        site.target_fold_group_id
                        if site.target_kind == "fold_group"
                        else None
                    ),
                    link=site.link,
                    absolute=site.absolute,
                    conditional=site.conditional,
                    indirect=site.indirect,
                    bo=site.bo,
                    bi=site.bi,
                    target_kind=site.target_kind,
                    target_record_count=site.target_record_count,
                )

            for scan in extraction.scans:
                scan_address_group_id = None
                if scan.va is not None:
                    scan_address_group_id = resolve_address_group(scan.va)
                function_id = procedure_function_ids.get(
                    scan.record_id, scan.record_id
                )
                function = self.connection.execute(
                    """
                    SELECT 1 FROM functions
                    WHERE function_id = ? AND program_id = ?
                    """,
                    (function_id, program_id),
                ).fetchone()
                unresolved_target_id = None
                if function is None:
                    function_id = None
                    unresolved_target_id = unresolved_target_ids.get(scan.record_id)
                    if unresolved_target_id is None:
                        raise AtlasError(
                            f"scan {scan.record_id!r} has no function or explicit "
                            "unresolved target endpoint"
                        )
                self.add_control_flow_scan(
                    extraction_id,
                    procedure_record_id=scan.record_id,
                    function_id=function_id,
                    unresolved_target_id=unresolved_target_id,
                    scan_address_group_id=scan_address_group_id,
                    declared_size=scan.declared_size,
                    scanned_size=scan.scanned_size,
                    unscanned_byte_count=scan.unscanned_byte_count,
                    status=scan.status,
                    source_branch_use_count=scan.branch_use_count,
                    persisted_branch_use_count=persisted_use_counts_by_record.get(
                        scan.record_id, 0
                    ),
                )

            self.validate_control_flow_extraction(extraction_id)
            if self._control_flow_protected_state() != protected_before:
                raise AtlasError(
                    "control-flow persistence changed functions, names, or mapping state"
                )

        return ControlFlowPersistenceResult(
            extraction_id=extraction_id,
            persistence_policy=policy,
            source_physical_sites=len(extraction.sites),
            source_logical_uses=len(extraction.uses),
            persisted_physical_sites=len(selected.sites),
            persisted_logical_uses=len(selected.uses),
            triggering_logical_uses=triggering_use_count,
            procedure_scans=len(extraction.scans),
        )

    def _control_flow_protected_state(self) -> tuple[tuple[Any, ...], ...]:
        """Snapshot tables control-flow persistence is forbidden to mutate."""

        result: list[tuple[Any, ...]] = []
        for table in ("functions", "function_names"):
            result.append((table, self.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]))
        result.extend(
            ("match_claims", *row)
            for row in self.connection.execute(
                """
                SELECT status, COUNT(*),
                       SUM(confidence_label IS NOT NULL),
                       SUM(confidence_value IS NOT NULL)
                FROM match_claims GROUP BY status ORDER BY status
                """
            )
        )
        result.extend(
            ("match_hypothesis_sets", *row)
            for row in self.connection.execute(
                """
                SELECT status, COUNT(*) FROM match_hypothesis_sets
                GROUP BY status ORDER BY status
                """
            )
        )
        return tuple(result)

    def validate_control_flow_extraction(self, extraction_id: str) -> bool:
        """Validate persisted counts, selection semantics, endpoints, and extents."""

        extraction = self.connection.execute(
            "SELECT * FROM control_flow_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if extraction is None:
            raise AtlasError(f"unknown control-flow extraction {extraction_id!r}")
        site_count = self.connection.execute(
            """
            SELECT COUNT(*) FROM control_flow_site_assertions
            WHERE extraction_id = ?
            """,
            (extraction_id,),
        ).fetchone()[0]
        use_count = self.connection.execute(
            """
            SELECT COUNT(*) FROM control_flow_use_assertions
            WHERE extraction_id = ?
            """,
            (extraction_id,),
        ).fetchone()[0]
        scan_count = self.connection.execute(
            "SELECT COUNT(*) FROM control_flow_scans WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()[0]
        if site_count != extraction["persisted_physical_site_count"]:
            raise AtlasError("persisted control-flow physical-site count is incomplete")
        if use_count != extraction["persisted_logical_use_count"]:
            raise AtlasError("persisted control-flow logical-use count is incomplete")
        if scan_count != extraction["procedure_scan_count"]:
            raise AtlasError("persisted control-flow scan count is incomplete")

        placeholders = ", ".join("?" for _ in CALL_RELEVANT_V1_ROLES)
        if extraction["persistence_policy"] == "all_branches_v1":
            triggering_count = use_count
        else:
            triggering_count = self.connection.execute(
                f"""
                SELECT COUNT(*) FROM control_flow_use_assertions
                WHERE extraction_id = ? AND role IN ({placeholders})
                """,
                (extraction_id, *sorted(CALL_RELEVANT_V1_ROLES)),
            ).fetchone()[0]
        if triggering_count != extraction["triggering_logical_use_count"]:
            raise AtlasError("persisted control-flow triggering-use count is incorrect")

        role_predicate = ""
        role_parameters: tuple[Any, ...] = ()
        if extraction["persistence_policy"] == "call_relevant_v1":
            role_predicate = f" AND assertion.role IN ({placeholders})"
            role_parameters = tuple(sorted(CALL_RELEVANT_V1_ROLES))
        missing_use = self.connection.execute(
            f"""
            SELECT site_assertion.site_id
            FROM control_flow_site_assertions site_assertion
            LEFT JOIN (
                SELECT use.site_id
                FROM control_flow_use_assertions assertion
                JOIN control_flow_uses use USING (use_id, program_id)
                WHERE assertion.extraction_id = ? {role_predicate}
                GROUP BY use.site_id
            ) triggering_site ON triggering_site.site_id = site_assertion.site_id
            WHERE site_assertion.extraction_id = ?
              AND triggering_site.site_id IS NULL
            LIMIT 1
            """,
            (extraction_id, *role_parameters, extraction_id),
        ).fetchone()
        if missing_use is not None:
            raise AtlasError(
                "persisted control-flow site has no policy-triggering logical use"
            )

        orphan_use = self.connection.execute(
            """
            SELECT use_assertion.use_id
            FROM control_flow_use_assertions use_assertion
            JOIN control_flow_uses use USING (use_id, program_id)
            WHERE use_assertion.extraction_id = ?
              AND NOT EXISTS (
                  SELECT 1 FROM control_flow_site_assertions site_assertion
                  WHERE site_assertion.extraction_id = use_assertion.extraction_id
                    AND site_assertion.site_id = use.site_id
              )
            LIMIT 1
            """,
            (extraction_id,),
        ).fetchone()
        if orphan_use is not None:
            raise AtlasError("persisted logical use has no physical-site assertion")

        out_of_extent = self.connection.execute(
            """
            SELECT use.use_id
            FROM control_flow_use_assertions use_assertion
            JOIN control_flow_uses use USING (use_id, program_id)
            JOIN control_flow_sites site USING (site_id, program_id)
            JOIN address_groups site_address
              ON site_address.address_group_id = site.address_group_id
             AND site_address.program_id = site.program_id
            LEFT JOIN control_flow_scans scan
              ON scan.extraction_id = use_assertion.extraction_id
             AND scan.program_id = use.program_id
             AND scan.procedure_record_id = use.procedure_record_id
            LEFT JOIN address_groups scan_address
              ON scan_address.address_group_id = scan.scan_address_group_id
             AND scan_address.program_id = scan.program_id
            WHERE use_assertion.extraction_id = ?
              AND (
                  scan.scan_id IS NULL OR scan_address.address_group_id IS NULL OR
                  site_address.address_space <> scan_address.address_space OR
                  site_address.address < scan_address.address OR
                  site_address.address >= scan_address.address + scan.scanned_size
              )
            LIMIT 1
            """,
            (extraction_id,),
        ).fetchone()
        if out_of_extent is not None:
            raise AtlasError("persisted logical use lies outside its procedure scan extent")

        invalid_endpoint = self.connection.execute(
            """
            SELECT assertion.assertion_id
            FROM control_flow_site_assertions assertion
            JOIN control_flow_sites site USING (site_id, program_id)
            JOIN address_groups site_address
              ON site_address.address_group_id = site.address_group_id
             AND site_address.program_id = site.program_id
            LEFT JOIN address_groups target_address
              ON target_address.address_group_id = assertion.target_address_group_id
             AND target_address.program_id = assertion.program_id
            LEFT JOIN functions target_function
              ON target_function.function_id = assertion.target_function_id
             AND target_function.program_id = assertion.program_id
            WHERE assertion.extraction_id = ?
              AND (
                  site_address.address <> assertion.raw_site_va OR
                  (assertion.target_kind <> 'indirect' AND (
                      target_address.address_group_id IS NULL OR
                      target_address.address <> assertion.raw_target_va OR
                      target_address.address_space <> site_address.address_space
                  )) OR
                  (assertion.target_function_id IS NOT NULL AND
                   target_function.address_group_id IS NOT
                       assertion.target_address_group_id) OR
                  (assertion.target_kind = 'unique_procedure' AND
                   (SELECT COUNT(*) FROM functions function
                    WHERE function.program_id = assertion.program_id
                      AND function.address_group_id =
                          assertion.target_address_group_id) <> 1) OR
                  (assertion.target_fold_group_id IS NOT NULL AND (
                      (SELECT COUNT(*) FROM fold_group_members member
                       WHERE member.fold_group_id = assertion.target_fold_group_id
                         AND member.program_id = assertion.program_id)
                          <> assertion.target_record_count OR
                      (SELECT COUNT(*) FROM functions function
                       WHERE function.program_id = assertion.program_id
                         AND function.address_group_id =
                             assertion.target_address_group_id)
                          <> assertion.target_record_count OR
                      EXISTS (
                          SELECT 1
                          FROM fold_group_members member
                          JOIN functions function USING (function_id, program_id)
                          WHERE member.fold_group_id = assertion.target_fold_group_id
                            AND member.program_id = assertion.program_id
                            AND function.address_group_id IS NOT
                                assertion.target_address_group_id
                      )
                  )) OR
                  (assertion.target_kind IN (
                       'executable_non_entry', 'outside_executable'
                   ) AND EXISTS (
                       SELECT 1 FROM functions function
                       WHERE function.program_id = assertion.program_id
                         AND function.address_group_id =
                             assertion.target_address_group_id
                  ))
              )
            LIMIT 1
            """,
            (extraction_id,),
        ).fetchone()
        if invalid_endpoint is not None:
            raise AtlasError("persisted control-flow raw endpoint is inconsistent")

        scan_totals = self.connection.execute(
            """
            SELECT COALESCE(SUM(source_branch_use_count), 0),
                   COALESCE(SUM(persisted_branch_use_count), 0)
            FROM control_flow_scans WHERE extraction_id = ?
            """,
            (extraction_id,),
        ).fetchone()
        if scan_totals[0] != extraction["source_logical_use_count"]:
            raise AtlasError("procedure scans do not cover every source logical use")
        if scan_totals[1] != extraction["persisted_logical_use_count"]:
            raise AtlasError("procedure scans do not cover every persisted logical use")
        return True

    def get_control_flow_extraction(
        self, extraction_id: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM control_flow_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        return result

    def get_control_flow_site(self, site_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT site.*, address.address_space, address.address
            FROM control_flow_sites site
            JOIN address_groups address USING (address_group_id, program_id)
            WHERE site.site_id = ?
            """,
            (site_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["assertions"] = list(self.iter_control_flow_sites(site_id=site_id))
        result["uses"] = list(self.iter_control_flow_uses(site_id=site_id))
        return result

    def iter_control_flow_sites(
        self,
        *,
        extraction_id: str | None = None,
        site_id: str | None = None,
        target_kind: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("assertion.extraction_id", extraction_id),
            ("assertion.site_id", site_id),
            ("assertion.target_kind", target_kind),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        sql = """
            SELECT assertion.*, site.address_group_id AS site_address_group_id,
                   site_address.address_space, site_address.address AS site_address,
                   target_address.address AS target_address
            FROM control_flow_site_assertions assertion
            JOIN control_flow_sites site USING (site_id, program_id)
            JOIN address_groups site_address
              ON site_address.address_group_id = site.address_group_id
             AND site_address.program_id = site.program_id
            LEFT JOIN address_groups target_address
              ON target_address.address_group_id = assertion.target_address_group_id
             AND target_address.program_id = assertion.program_id
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY assertion.extraction_id, site_address.address, assertion.site_id"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            for field_name in ("link", "absolute", "conditional", "indirect"):
                result[field_name] = bool(result[field_name])
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def iter_control_flow_uses(
        self,
        *,
        extraction_id: str | None = None,
        function_id: str | None = None,
        site_id: str | None = None,
        role: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("assertion.extraction_id", extraction_id),
            ("use.function_id", function_id),
            ("use.site_id", site_id),
            ("assertion.role", role),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        sql = """
            SELECT assertion.*, use.procedure_record_id, use.function_id,
                   use.site_id, address.address_space,
                   address.address AS site_address
            FROM control_flow_use_assertions assertion
            JOIN control_flow_uses use USING (use_id, program_id)
            JOIN control_flow_sites site USING (site_id, program_id)
            JOIN address_groups address USING (address_group_id, program_id)
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += """
            ORDER BY assertion.extraction_id, use.procedure_record_id,
                     address.address, use.use_id
        """
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def iter_control_flow_scans(
        self,
        extraction_id: str,
        *,
        status: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        sql = """
            SELECT scan.*, address.address_space,
                   address.address AS scan_address
            FROM control_flow_scans scan
            LEFT JOIN address_groups address
              ON address.address_group_id = scan.scan_address_group_id
             AND address.program_id = scan.program_id
            WHERE scan.extraction_id = ?
        """
        parameters: list[Any] = [extraction_id]
        if status is not None:
            sql += " AND scan.status = ?"
            parameters.append(status)
        sql += " ORDER BY scan.procedure_record_id, scan.scan_id"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def upsert_vtable_alignment_candidate(
        self,
        alignment_id: str,
        *,
        pc_vtable_id: str,
        xbox_vtable_id: str,
        class_name: str,
        vfptr_role: str,
        subobject_offset: int | None,
        provenance_id: str,
        status: str = "candidate",
        details: Mapping[str, Any] = {},
    ) -> str:
        """Persist a structural table-pair candidate without accepting it."""

        values = {
            "alignment_id": alignment_id,
            "pc_vtable_id": pc_vtable_id,
            "xbox_vtable_id": xbox_vtable_id,
            "class_name": class_name,
            "vfptr_role": vfptr_role,
            "subobject_offset": subobject_offset,
            "status": status,
            "provenance_id": provenance_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "vtable_alignment_candidates",
                "alignment_id",
                values,
                immutable=(
                    "pc_vtable_id",
                    "xbox_vtable_id",
                    "class_name",
                    "vfptr_role",
                    "subobject_offset",
                    "provenance_id",
                ),
            )
        return alignment_id

    def upsert_vtable_slot_alignment(
        self,
        *,
        alignment_id: str,
        pc_slot_index: int,
        xbox_slot_index: int,
        hypothesis_set_id: str,
        provenance_id: str,
        slot_alignment_id: str | None = None,
        status: str = "candidate",
        details: Mapping[str, Any] = {},
    ) -> str:
        """Persist one exact PC/Xbox table-slot occurrence pairing."""

        alignment = self.connection.execute(
            """
            SELECT pc_vtable_id, xbox_vtable_id
            FROM vtable_alignment_candidates WHERE alignment_id = ?
            """,
            (alignment_id,),
        ).fetchone()
        if alignment is None:
            raise AtlasError(f"unknown vtable alignment {alignment_id!r}")
        slot_alignment_id = slot_alignment_id or stable_id(
            "vtable-slot-alignment",
            alignment_id,
            alignment["pc_vtable_id"],
            pc_slot_index,
            alignment["xbox_vtable_id"],
            xbox_slot_index,
            hypothesis_set_id,
            provenance_id,
        )
        values = {
            "slot_alignment_id": slot_alignment_id,
            "alignment_id": alignment_id,
            "pc_vtable_id": alignment["pc_vtable_id"],
            "pc_slot_index": pc_slot_index,
            "xbox_vtable_id": alignment["xbox_vtable_id"],
            "xbox_slot_index": xbox_slot_index,
            "hypothesis_set_id": hypothesis_set_id,
            "status": status,
            "provenance_id": provenance_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "vtable_slot_alignments",
                "slot_alignment_id",
                values,
                immutable=(
                    "alignment_id",
                    "pc_vtable_id",
                    "pc_slot_index",
                    "xbox_vtable_id",
                    "xbox_slot_index",
                    "hypothesis_set_id",
                    "provenance_id",
                ),
            )
        return slot_alignment_id

    def upsert_vtable_alignment_issue(
        self,
        issue_id: str,
        *,
        issue_kind: str,
        class_name: str,
        message: str,
        provenance_id: str,
        vfptr_role: str | None = None,
        subobject_offset: int | None = None,
        details: Mapping[str, Any] = {},
    ) -> str:
        values = {
            "issue_id": issue_id,
            "issue_kind": issue_kind,
            "class_name": class_name,
            "vfptr_role": vfptr_role,
            "subobject_offset": subobject_offset,
            "message": message,
            "provenance_id": provenance_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "vtable_alignment_issues",
                "issue_id",
                values,
                immutable=(
                    "issue_kind",
                    "class_name",
                    "vfptr_role",
                    "subobject_offset",
                    "provenance_id",
                ),
            )
        return issue_id

    def iter_vtable_alignment_candidates(self) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            "SELECT * FROM vtable_alignment_candidates ORDER BY alignment_id"
        ):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def iter_vtable_slot_alignments(
        self, *, alignment_id: str | None = None
    ) -> Iterator[dict[str, Any]]:
        sql = "SELECT * FROM vtable_slot_alignments"
        parameters: tuple[Any, ...] = ()
        if alignment_id is not None:
            sql += " WHERE alignment_id = ?"
            parameters = (alignment_id,)
        sql += " ORDER BY alignment_id, pc_slot_index, xbox_slot_index"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def iter_vtable_alignment_issues(self) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            "SELECT * FROM vtable_alignment_issues ORDER BY class_name, issue_id"
        ):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def upsert_observation(
        self,
        *,
        observation_kind: str,
        independence_group: str,
        provenance_id: str,
        function_id: str | None = None,
        unresolved_target_id: str | None = None,
        observation_id: str | None = None,
        effect: str = "context",
        details: Mapping[str, Any] = {},
    ) -> str:
        """Attach evidence/context to one endpoint without inventing a match.

        This is used for observations such as a public reference or source-file
        mention that describe a PC function/address but do not identify an Xbox
        counterpart.
        """

        if (function_id is None) == (unresolved_target_id is None):
            raise ValueError(
                "exactly one of function_id and unresolved_target_id is required"
            )
        if function_id is not None:
            row = self.connection.execute(
                "SELECT program_id FROM functions WHERE function_id = ?",
                (function_id,),
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT program_id FROM unresolved_targets WHERE target_id = ?",
                (unresolved_target_id,),
            ).fetchone()
        if row is None:
            raise AtlasError("unknown observation subject")
        details_json = _canonical_json(details)
        observation_id = observation_id or stable_id(
            "observation",
            function_id,
            unresolved_target_id,
            observation_kind,
            independence_group,
            effect,
            provenance_id,
            json.loads(details_json),
        )
        values = {
            "observation_id": observation_id,
            "program_id": row[0],
            "function_id": function_id,
            "unresolved_target_id": unresolved_target_id,
            "observation_kind": observation_kind,
            "independence_group": independence_group,
            "effect": effect,
            "provenance_id": provenance_id,
            "details_json": details_json,
        }
        with self.transaction():
            self._stable_upsert(
                "observations",
                "observation_id",
                values,
                immutable=(
                    "program_id",
                    "function_id",
                    "unresolved_target_id",
                    "observation_kind",
                    "independence_group",
                    "effect",
                    "provenance_id",
                    "details_json",
                ),
            )
        return observation_id

    def upsert_call_edge(
        self,
        *,
        caller_function_id: str,
        provenance_id: str,
        edge_id: str | None = None,
        callee_function_id: str | None = None,
        unresolved_target_id: str | None = None,
        call_site_address_space: str | None = None,
        call_site_address: int | None = None,
        edge_kind: str = "call",
        details: Mapping[str, Any] = {},
    ) -> str:
        """Record a call without forcing an unknown callee into a function row.

        Exactly one of ``callee_function_id`` and ``unresolved_target_id`` must
        be supplied.  Composite foreign keys ensure both ends belong to the
        caller's program/address domain.
        """

        caller = self.connection.execute(
            "SELECT program_id FROM functions WHERE function_id = ?",
            (caller_function_id,),
        ).fetchone()
        if caller is None:
            raise AtlasError(f"unknown caller function {caller_function_id!r}")
        edge_id = edge_id or stable_id(
            "call-edge",
            caller_function_id,
            callee_function_id,
            unresolved_target_id,
            call_site_address_space,
            call_site_address,
            edge_kind,
            provenance_id,
        )
        values = {
            "edge_id": edge_id,
            "program_id": caller[0],
            "caller_function_id": caller_function_id,
            "callee_function_id": callee_function_id,
            "unresolved_target_id": unresolved_target_id,
            "call_site_address_space": call_site_address_space,
            "call_site_address": call_site_address,
            "edge_kind": edge_kind,
            "provenance_id": provenance_id,
            "details_json": _canonical_json(details),
        }
        with self.transaction():
            self._stable_upsert(
                "call_edges",
                "edge_id",
                values,
                immutable=(
                    "program_id",
                    "caller_function_id",
                    "callee_function_id",
                    "unresolved_target_id",
                    "call_site_address_space",
                    "call_site_address",
                    "edge_kind",
                    "provenance_id",
                ),
            )
        return edge_id

    def iter_call_edges(
        self, caller_function_id: str
    ) -> Iterator[dict[str, Any]]:
        """Yield calls from a function, including unresolved external targets."""

        for row in self.connection.execute(
            """
            SELECT * FROM call_edges
            WHERE caller_function_id = ?
            ORDER BY call_site_address, edge_id
            """,
            (caller_function_id,),
        ):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def get_function(self, function_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT f.*, a.address_space, a.address, a.kind AS address_kind,
                   p.platform, p.name AS program_name
            FROM functions f
            JOIN address_groups a USING (address_group_id, program_id)
            JOIN programs p USING (program_id)
            WHERE f.function_id = ?
            """,
            (function_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        names = self.connection.execute(
            """
            SELECT name, name_kind, is_primary, provenance_id, details_json
            FROM function_names WHERE function_id = ?
            ORDER BY name_kind, is_primary DESC, name
            """,
            (function_id,),
        ).fetchall()
        result["names"] = [
            {
                **{key: item[key] for key in item.keys() if key != "details_json"},
                "is_primary": bool(item["is_primary"]),
                "details": _decode_json(item["details_json"]),
            }
            for item in names
        ]
        ranges = self.connection.execute(
            """
            SELECT r.*, s.normalized_path
            FROM function_source_ranges r
            JOIN source_files s USING (source_file_id, program_id)
            WHERE r.function_id = ?
            ORDER BY r.is_primary DESC, s.normalized_path, r.line_start, r.column_start
            """,
            (function_id,),
        ).fetchall()
        result["source_ranges"] = [
            {
                **{key: item[key] for key in item.keys() if key != "details_json"},
                "is_primary": bool(item["is_primary"]),
                "details": _decode_json(item["details_json"]),
            }
            for item in ranges
        ]
        result["fold_groups"] = [
            dict(item)
            for item in self.connection.execute(
                """
                SELECT g.fold_group_id, g.kind, m.member_role
                FROM fold_group_members m
                JOIN fold_groups g USING (fold_group_id, program_id)
                WHERE m.function_id = ? ORDER BY g.fold_group_id
                """,
                (function_id,),
            )
        ]
        return result

    def functions_at(
        self, program_id: str, address_space: str, address: int
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT f.function_id FROM functions f
            JOIN address_groups a USING (address_group_id, program_id)
            WHERE f.program_id = ? AND a.address_space = ? AND a.address = ?
            ORDER BY f.identity_key, f.function_id
            """,
            (program_id, address_space, address),
        ).fetchall()
        return [result for row in rows if (result := self.get_function(row[0]))]

    def get_claim(self, claim_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM match_claims WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        evidence_rows = self.connection.execute(
            """
            SELECT * FROM claim_evidence
            WHERE claim_id = ? ORDER BY independence_group, evidence_id
            """,
            (claim_id,),
        ).fetchall()
        result["evidence"] = []
        for item in evidence_rows:
            evidence = dict(item)
            evidence["details"] = _decode_json(evidence.pop("details_json"))
            result["evidence"].append(evidence)
        return result

    def iter_unresolved(
        self, *, program_id: str | None = None, status: str = "open"
    ) -> Iterator[dict[str, Any]]:
        sql = "SELECT * FROM unresolved_targets WHERE status = ?"
        parameters: list[Any] = [status]
        if program_id is not None:
            sql += " AND program_id = ?"
            parameters.append(program_id)
        sql += " ORDER BY program_id, target_id"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["details"] = _decode_json(result.pop("details_json"))
            yield result

    def _require_xbox_program(self, program_id: str) -> None:
        row = self.connection.execute(
            "SELECT platform FROM programs WHERE program_id = ?", (program_id,)
        ).fetchone()
        if row is None:
            raise AtlasError(f"unknown program {program_id!r}")
        if row["platform"] != "xbox360":
            raise AtlasError(f"program {program_id!r} is not an Xbox 360 program")

    def _require_pc_program(self, program_id: str) -> None:
        row = self.connection.execute(
            "SELECT platform FROM programs WHERE program_id = ?", (program_id,)
        ).fetchone()
        if row is None:
            raise AtlasError(f"unknown program {program_id!r}")
        if row["platform"] != "pc":
            raise AtlasError(f"program {program_id!r} is not a PC program")

    def _ensure_address_observations(
        self,
        *,
        program_id: str,
        address_space: str,
        addresses: Iterable[int],
    ) -> dict[int, str]:
        """Reuse address identities and insert only absent neutral observations."""

        requested = set(addresses)
        if any(address < 0 or address > 0xFFFFFFFF for address in requested):
            raise ValueError("observed address is outside uint32")
        existing = {
            row["address"]: row["address_group_id"]
            for row in self.connection.execute(
                """
                SELECT address, address_group_id FROM address_groups
                WHERE program_id = ? AND address_space = ?
                """,
                (program_id, address_space),
            )
            if row["address"] in requested
        }
        missing = sorted(requested - set(existing))
        for address in missing:
            existing[address] = make_address_group_id(
                program_id, address_space, address
            )
        self._bulk_insert_immutable(
            "address_groups",
            "address_group_id",
            (
                {
                    "address_group_id": existing[address],
                    "program_id": program_id,
                    "address_space": address_space,
                    "address": address,
                    "kind": "observed-address",
                    "details_json": "{}",
                }
                for address in missing
            ),
        )
        return existing

    def persist_tpi_layout_corpus(
        self,
        corpus: TpiLayoutCorpus,
        *,
        program_id: str,
        provenance_id: str,
        extraction_id: str | None = None,
        type_namespace: str = "global-tpi",
        details: Mapping[str, Any] = {},
    ) -> TpiLayoutPersistenceResult:
        """Atomically persist every raw TPI record and decoded layout occurrence.

        Raw records use ``(program, namespace, type index)`` as canonical
        physical identity.  Decoded layouts are extraction-scoped producer
        output, so another producer can assert the same bytes without replacing
        lineage.  Referenced type indices intentionally remain scalar values:
        primitive and unavailable indices are valid observations.
        """

        if type_namespace != "global-tpi":
            raise ValueError("only the global-tpi CodeView namespace is supported")
        self._require_xbox_program(program_id)
        if not self.connection.execute(
            "SELECT 1 FROM provenance WHERE provenance_id = ?", (provenance_id,)
        ).fetchone():
            raise AtlasError(f"unknown provenance {provenance_id!r}")

        raw_records = tuple(
            sorted(corpus.type_records.records, key=lambda record: record.type_index)
        )
        raw_by_index: dict[int, Any] = {}
        for record in raw_records:
            if record.type_index in raw_by_index:
                raise ValueError(
                    f"duplicate raw CodeView type index 0x{record.type_index:X}"
                )
            if not 0 <= record.type_index <= 0xFFFFFFFF:
                raise ValueError("CodeView type index is outside uint32")
            if not 0 <= record.leaf_kind <= 0xFFFF:
                raise ValueError("CodeView leaf kind is outside uint16")
            if record.record_length != len(record.body) + 2:
                raise ValueError(
                    f"type 0x{record.type_index:X} record length does not match body"
                )
            if not 2 <= record.record_length <= 0xFFFF:
                raise ValueError("CodeView record length is outside uint16")
            _validated_sha256(
                record.body_sha256,
                record.body,
                label=f"type 0x{record.type_index:X} raw body",
            )
            raw_by_index[record.type_index] = record

        tags = tuple(sorted(corpus.layouts.records, key=lambda record: record.type_index))
        tags_by_index: dict[int, Any] = {}
        physical_members: dict[tuple[int, int], LayoutMember] = {}
        physical_member_payloads: dict[tuple[int, int], str] = {}
        method_lists: dict[int, tuple[Any, ...]] = {}
        physical_overloads: dict[tuple[int, int], Any] = {}
        tag_member_occurrences = 0
        diagnostic_count = 0
        for tag in tags:
            if tag.type_index in tags_by_index:
                raise ValueError(
                    f"duplicate decoded tag type index 0x{tag.type_index:X}"
                )
            raw = raw_by_index.get(tag.type_index)
            if raw is None:
                raise ValueError(
                    f"decoded tag 0x{tag.type_index:X} has no raw type record"
                )
            if raw.leaf_kind != tag.leaf_kind:
                raise ValueError(
                    f"decoded tag 0x{tag.type_index:X} leaf kind conflicts with raw record"
                )
            _validated_sha256(
                tag.record_sha256,
                tag.leaf_kind.to_bytes(2, "little") + raw.body,
                label=f"tag 0x{tag.type_index:X} record",
            )
            if tag.decoded_member_count < 0 or tag.member_count < 0:
                raise ValueError("CodeView tag member counts cannot be negative")
            tags_by_index[tag.type_index] = tag

            ordinals: set[int] = set()
            for member in tag.members:
                if member.ordinal < 0 or member.ordinal in ordinals:
                    raise ValueError(
                        f"tag 0x{tag.type_index:X} has invalid/duplicate member ordinal"
                    )
                ordinals.add(member.ordinal)
                key = member.physical_key
                if not 0 <= key[0] <= 0xFFFFFFFF or key[1] < 0:
                    raise ValueError("physical field-list identity is outside range")
                payload = _physical_member_payload(member)
                previous = physical_member_payloads.get(key)
                if previous is not None and previous != payload:
                    raise ValueError(
                        "physical field-list member was decoded inconsistently at "
                        f"type 0x{key[0]:X} offset 0x{key[1]:X}"
                    )
                physical_member_payloads[key] = payload
                physical_members.setdefault(key, member)

                if member.method_list_type_index is None:
                    if member.overloads:
                        raise ValueError(
                            "field member has overloads without a method-list type index"
                        )
                else:
                    if not 0 <= member.method_list_type_index <= 0xFFFFFFFF:
                        raise ValueError("method-list type index is outside uint32")
                    overloads = tuple(member.overloads)
                    previous_overloads = method_lists.get(member.method_list_type_index)
                    if (
                        previous_overloads is not None
                        and previous_overloads != overloads
                    ):
                        raise ValueError(
                            "method list was decoded inconsistently at type "
                            f"0x{member.method_list_type_index:X}"
                        )
                    method_lists[member.method_list_type_index] = overloads
                    overload_ordinals: set[int] = set()
                    for overload in overloads:
                        if overload.ordinal < 0 or overload.ordinal in overload_ordinals:
                            raise ValueError(
                                "method list has an invalid/duplicate overload ordinal"
                            )
                        overload_ordinals.add(overload.ordinal)
                        if not 0 <= overload.type_index <= 0xFFFFFFFF:
                            raise ValueError("method type index is outside uint32")
                        overload_key = (
                            member.method_list_type_index,
                            overload.ordinal,
                        )
                        previous_overload = physical_overloads.get(overload_key)
                        if (
                            previous_overload is not None
                            and previous_overload != overload
                        ):
                            raise ValueError(
                                "physical method-list overload was decoded inconsistently"
                            )
                        physical_overloads[overload_key] = overload
            tag_member_occurrences += len(tag.members)
            diagnostic_count += len(tag.diagnostics)

        if corpus.type_records.record_count != len(raw_records):
            raise ValueError("raw TPI record count property is inconsistent")
        if corpus.type_records.body_bytes != sum(
            len(record.body) for record in raw_records
        ):
            raise ValueError("raw TPI body-byte count property is inconsistent")
        if corpus.layouts.record_count != len(tags):
            raise ValueError("TPI tag record count property is inconsistent")
        if corpus.layouts.physical_member_count != len(physical_members):
            raise ValueError("TPI physical field-member count property is inconsistent")
        if corpus.layouts.diagnostic_count != diagnostic_count:
            raise ValueError("TPI diagnostic count property is inconsistent")

        details_json = _canonical_json(details)
        raw_fingerprint = _canonical_row_digest(
            (
                record.type_index,
                record.leaf_kind,
                record.record_length,
                record.body_sha256,
                record.leaf_name,
                record.rendered_type,
            )
            for record in raw_records
        )
        layout_fingerprint = _canonical_row_digest(
            tag.to_dict() for tag in tags
        )
        extraction_id = extraction_id or stable_id(
            "codeview-type-extraction",
            program_id,
            type_namespace,
            raw_fingerprint,
            layout_fingerprint,
            provenance_id,
            json.loads(details_json),
        )
        result = TpiLayoutPersistenceResult(
            extraction_id=extraction_id,
            raw_type_records=len(raw_records),
            raw_body_bytes=sum(len(record.body) for record in raw_records),
            tag_records=len(tags),
            definitions=sum(not tag.is_forward_reference for tag in tags),
            forward_references=sum(tag.is_forward_reference for tag in tags),
            tag_member_occurrences=tag_member_occurrences,
            physical_field_members=len(physical_members),
            physical_method_overloads=len(physical_overloads),
            diagnostics=diagnostic_count,
        )

        with self.batch():
            extraction_values = {
                "extraction_id": extraction_id,
                "program_id": program_id,
                "type_namespace": type_namespace,
                "raw_type_record_count": result.raw_type_records,
                "raw_body_byte_count": result.raw_body_bytes,
                "tag_record_count": result.tag_records,
                "definition_count": result.definitions,
                "forward_reference_count": result.forward_references,
                "tag_member_occurrence_count": result.tag_member_occurrences,
                "physical_field_member_count": result.physical_field_members,
                "physical_method_overload_count": result.physical_method_overloads,
                "diagnostic_count": result.diagnostics,
                "provenance_id": provenance_id,
                "details_json": details_json,
            }
            self._stable_upsert(
                "codeview_type_extractions",
                "extraction_id",
                extraction_values,
                immutable=tuple(extraction_values),
            )

            type_record_ids = {
                record.type_index: stable_id(
                    "codeview-type-record",
                    program_id,
                    type_namespace,
                    record.type_index,
                )
                for record in raw_records
            }

            def type_record_rows() -> Iterator[dict[str, Any]]:
                for record in raw_records:
                    yield {
                        "type_record_id": type_record_ids[record.type_index],
                        "program_id": program_id,
                        "type_namespace": type_namespace,
                        "type_index": record.type_index,
                        "leaf_kind": record.leaf_kind,
                        "record_length": record.record_length,
                        "raw_body": record.body,
                        "raw_body_sha256": record.body_sha256,
                    }

            self._bulk_insert_immutable(
                "codeview_type_records",
                "type_record_id",
                type_record_rows(),
            )

            def type_record_assertion_rows() -> Iterator[dict[str, Any]]:
                for record in raw_records:
                    type_record_id = type_record_ids[record.type_index]
                    yield {
                        "assertion_id": stable_id(
                            "codeview-type-record-assertion",
                            extraction_id,
                            type_record_id,
                        ),
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "type_namespace": type_namespace,
                        "type_record_id": type_record_id,
                        "leaf_name": record.leaf_name,
                        "rendered_type": record.rendered_type,
                    }

            self._bulk_insert_immutable(
                "codeview_type_record_assertions",
                "assertion_id",
                type_record_assertion_rows(),
            )

            tag_layout_ids = {
                tag.type_index: stable_id(
                    "codeview-tag-layout", extraction_id, tag.type_index
                )
                for tag in tags
            }

            def tag_layout_rows() -> Iterator[dict[str, Any]]:
                for tag in tags:
                    yield {
                        "tag_layout_id": tag_layout_ids[tag.type_index],
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "type_namespace": type_namespace,
                        "type_record_id": type_record_ids[tag.type_index],
                        "tag_kind": tag.tag_kind,
                        "declared_member_count": tag.member_count,
                        "decoded_member_count": tag.decoded_member_count,
                        "physical_member_occurrence_count": len(tag.members),
                        "properties": tag.properties,
                        "field_list_type_index": tag.field_list_type_index,
                        "derived_type_index": tag.derived_type_index,
                        "vtable_shape_type_index": tag.vtable_shape_type_index,
                        "underlying_type_index": tag.underlying_type_index,
                        "size_value": _integer_text(tag.size),
                        "display_name": tag.name,
                        "unique_name": tag.unique_name,
                        "is_forward_reference": int(tag.is_forward_reference),
                        "record_sha256": tag.record_sha256,
                    }

            self._bulk_insert_immutable(
                "codeview_tag_layouts", "tag_layout_id", tag_layout_rows()
            )

            field_member_ids = {
                key: stable_id(
                    "codeview-field-member", extraction_id, key[0], key[1]
                )
                for key in physical_members
            }

            def field_member_rows() -> Iterator[dict[str, Any]]:
                for key in sorted(physical_members):
                    member = physical_members[key]
                    yield {
                        "field_member_id": field_member_ids[key],
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "source_field_list_type_index":
                            member.source_field_list_type_index,
                        "source_record_offset": member.source_record_offset,
                        "leaf_kind": member.leaf_kind,
                        "member_kind": member.member_kind,
                        "attributes": member.attributes,
                        "access": member.access,
                        "method_kind": member.method_kind,
                        "method_options": member.method_options,
                        "member_name": member.name,
                        "referenced_type_index": member.type_index,
                        "rendered_type": member.rendered_type,
                        "member_offset_value": _integer_text(member.offset),
                        "enum_value": _integer_text(member.value),
                        "base_type_index": member.base_type_index,
                        "vbptr_type_index": member.vbptr_type_index,
                        "vbptr_offset_value": _integer_text(member.vbptr_offset),
                        "vtable_index_value": _integer_text(member.vtable_index),
                        "method_list_type_index": member.method_list_type_index,
                        "declared_overload_count": member.declared_overload_count,
                        "vtable_offset": member.vtable_offset,
                        "continuation_type_index": member.continuation_type_index,
                    }

            self._bulk_insert_immutable(
                "codeview_field_members", "field_member_id", field_member_rows()
            )

            def tag_member_use_rows() -> Iterator[dict[str, Any]]:
                for tag in tags:
                    tag_layout_id = tag_layout_ids[tag.type_index]
                    for member in sorted(tag.members, key=lambda item: item.ordinal):
                        field_member_id = field_member_ids[member.physical_key]
                        yield {
                            "member_use_id": stable_id(
                                "codeview-tag-member-use",
                                tag_layout_id,
                                member.ordinal,
                                field_member_id,
                            ),
                            "extraction_id": extraction_id,
                            "program_id": program_id,
                            "tag_layout_id": tag_layout_id,
                            "ordinal": member.ordinal,
                            "field_member_id": field_member_id,
                        }

            self._bulk_insert_immutable(
                "codeview_tag_member_uses", "member_use_id", tag_member_use_rows()
            )

            def method_overload_rows() -> Iterator[dict[str, Any]]:
                for key in sorted(physical_overloads):
                    overload = physical_overloads[key]
                    yield {
                        "method_overload_id": stable_id(
                            "codeview-method-overload", extraction_id, key[0], key[1]
                        ),
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "method_list_type_index": key[0],
                        "ordinal": overload.ordinal,
                        "attributes": overload.attributes,
                        "access": overload.access,
                        "method_kind": overload.method_kind,
                        "method_options": overload.method_options,
                        "method_type_index": overload.type_index,
                        "rendered_type": overload.rendered_type,
                        "vtable_offset": overload.vtable_offset,
                    }

            self._bulk_insert_immutable(
                "codeview_method_overloads",
                "method_overload_id",
                method_overload_rows(),
            )

            def diagnostic_rows() -> Iterator[dict[str, Any]]:
                for tag in tags:
                    tag_layout_id = tag_layout_ids[tag.type_index]
                    for ordinal, diagnostic in enumerate(tag.diagnostics):
                        yield {
                            "diagnostic_id": stable_id(
                                "codeview-layout-diagnostic",
                                tag_layout_id,
                                ordinal,
                                diagnostic.code,
                                diagnostic.type_index,
                                diagnostic.offset,
                                diagnostic.message,
                                diagnostic.remaining_hex,
                            ),
                            "extraction_id": extraction_id,
                            "program_id": program_id,
                            "tag_layout_id": tag_layout_id,
                            "ordinal": ordinal,
                            "code": diagnostic.code,
                            "source_type_index": diagnostic.type_index,
                            "source_record_offset": diagnostic.offset,
                            "message": diagnostic.message,
                            "remaining_hex": diagnostic.remaining_hex,
                        }

            self._bulk_insert_immutable(
                "codeview_layout_diagnostics", "diagnostic_id", diagnostic_rows()
            )

            self.validate_tpi_layout_extraction(extraction_id)

        return result

    def validate_tpi_layout_extraction(self, extraction_id: str) -> bool:
        """Validate a persisted TPI run with a bounded set of aggregate queries."""

        extraction = self.connection.execute(
            "SELECT * FROM codeview_type_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if extraction is None:
            raise AtlasError(f"unknown CodeView type extraction {extraction_id!r}")
        counts = self.connection.execute(
            """
            SELECT
                (SELECT COUNT(*)
                 FROM codeview_type_record_assertions
                 WHERE extraction_id = ?) AS raw_records,
                (SELECT COALESCE(SUM(length(record.raw_body)), 0)
                 FROM codeview_type_record_assertions assertion
                 JOIN codeview_type_records record USING (type_record_id)
                 WHERE assertion.extraction_id = ?) AS raw_body_bytes,
                (SELECT COUNT(*) FROM codeview_tag_layouts
                 WHERE extraction_id = ?) AS tags,
                (SELECT COUNT(*) FROM codeview_tag_layouts
                 WHERE extraction_id = ? AND is_forward_reference = 0) AS definitions,
                (SELECT COUNT(*) FROM codeview_tag_layouts
                 WHERE extraction_id = ? AND is_forward_reference = 1) AS forwards,
                (SELECT COUNT(*) FROM codeview_tag_member_uses
                 WHERE extraction_id = ?) AS member_uses,
                (SELECT COUNT(*) FROM codeview_field_members
                 WHERE extraction_id = ?) AS physical_members,
                (SELECT COUNT(*) FROM codeview_method_overloads
                 WHERE extraction_id = ?) AS overloads,
                (SELECT COUNT(*) FROM codeview_layout_diagnostics
                 WHERE extraction_id = ?) AS diagnostics
            """,
            (extraction_id,) * 9,
        ).fetchone()
        expected = {
            "raw_records": extraction["raw_type_record_count"],
            "raw_body_bytes": extraction["raw_body_byte_count"],
            "tags": extraction["tag_record_count"],
            "definitions": extraction["definition_count"],
            "forwards": extraction["forward_reference_count"],
            "member_uses": extraction["tag_member_occurrence_count"],
            "physical_members": extraction["physical_field_member_count"],
            "overloads": extraction["physical_method_overload_count"],
            "diagnostics": extraction["diagnostic_count"],
        }
        mismatches = [
            name for name, value in expected.items() if counts[name] != value
        ]
        if mismatches:
            raise AtlasError(
                f"CodeView extraction {extraction_id!r} count mismatch: "
                + ", ".join(mismatches)
            )

        anomalies = self.connection.execute(
            """
            SELECT
                (SELECT COUNT(*)
                 FROM codeview_tag_layouts tag
                 LEFT JOIN codeview_type_record_assertions assertion
                   ON assertion.extraction_id = tag.extraction_id
                  AND assertion.type_record_id = tag.type_record_id
                 WHERE tag.extraction_id = ? AND assertion.assertion_id IS NULL)
                    AS tags_without_raw_assertion,
                (SELECT COUNT(*)
                 FROM codeview_field_members member
                 WHERE member.extraction_id = ? AND NOT EXISTS (
                     SELECT 1 FROM codeview_tag_member_uses use
                     WHERE use.extraction_id = member.extraction_id
                       AND use.field_member_id = member.field_member_id
                 )) AS unused_physical_members,
                (SELECT COUNT(*)
                 FROM codeview_method_overloads overload
                 WHERE overload.extraction_id = ? AND NOT EXISTS (
                     SELECT 1 FROM codeview_field_members member
                     WHERE member.extraction_id = overload.extraction_id
                       AND member.method_list_type_index =
                           overload.method_list_type_index
                 )) AS unreferenced_method_lists,
                (SELECT COUNT(*)
                 FROM codeview_tag_layouts tag
                 WHERE tag.extraction_id = ? AND
                       tag.physical_member_occurrence_count <> (
                           SELECT COUNT(*) FROM codeview_tag_member_uses use
                           WHERE use.tag_layout_id = tag.tag_layout_id
                       )) AS tag_member_count_mismatches
            """,
            (extraction_id, extraction_id, extraction_id, extraction_id),
        ).fetchone()
        anomaly_names = [name for name in anomalies.keys() if anomalies[name]]
        if anomaly_names:
            raise AtlasError(
                f"CodeView extraction {extraction_id!r} structural anomaly: "
                + ", ".join(anomaly_names)
            )
        return True

    def get_tpi_layout_extraction(
        self, extraction_id: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM codeview_type_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        return result

    def iter_codeview_type_records(
        self,
        *,
        extraction_id: str | None = None,
        program_id: str | None = None,
        leaf_kind: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("assertion.extraction_id", extraction_id),
            ("record.program_id", program_id),
            ("record.leaf_kind", leaf_kind),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        sql = """
            SELECT record.*, assertion.assertion_id, assertion.extraction_id,
                   assertion.leaf_name, assertion.rendered_type
            FROM codeview_type_record_assertions assertion
            JOIN codeview_type_records record USING (type_record_id)
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY assertion.extraction_id, record.type_index"
        for row in self.connection.execute(sql, parameters):
            yield dict(row)

    def iter_codeview_tag_layouts(
        self,
        extraction_id: str,
        *,
        display_name: str | None = None,
        include_forward_references: bool = True,
    ) -> Iterator[dict[str, Any]]:
        sql = """
            SELECT tag.*, record.type_index, record.leaf_kind
            FROM codeview_tag_layouts tag
            JOIN codeview_type_records record USING (type_record_id)
            WHERE tag.extraction_id = ?
        """
        parameters: list[Any] = [extraction_id]
        if display_name is not None:
            sql += " AND tag.display_name = ?"
            parameters.append(display_name)
        if not include_forward_references:
            sql += " AND tag.is_forward_reference = 0"
        sql += " ORDER BY record.type_index"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["is_forward_reference"] = bool(result["is_forward_reference"])
            result["size"] = _decode_integer_text(result.pop("size_value"))
            yield result

    def iter_codeview_method_overloads(
        self,
        extraction_id: str,
        *,
        method_list_type_index: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        sql = """
            SELECT * FROM codeview_method_overloads WHERE extraction_id = ?
        """
        parameters: list[Any] = [extraction_id]
        if method_list_type_index is not None:
            sql += " AND method_list_type_index = ?"
            parameters.append(method_list_type_index)
        sql += " ORDER BY method_list_type_index, ordinal"
        for row in self.connection.execute(sql, parameters):
            yield dict(row)

    def iter_codeview_tag_members(
        self, tag_layout_id: str
    ) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            """
            SELECT use.ordinal AS tag_ordinal, member.*
            FROM codeview_tag_member_uses use
            JOIN codeview_field_members member USING (field_member_id)
            WHERE use.tag_layout_id = ?
            ORDER BY use.ordinal
            """,
            (tag_layout_id,),
        ):
            result = dict(row)
            result["offset"] = _decode_integer_text(
                result.pop("member_offset_value")
            )
            result["value"] = _decode_integer_text(result.pop("enum_value"))
            result["vbptr_offset"] = _decode_integer_text(
                result.pop("vbptr_offset_value")
            )
            result["vtable_index"] = _decode_integer_text(
                result.pop("vtable_index_value")
            )
            result["type_index"] = result.pop("referenced_type_index")
            method_list_type_index = result["method_list_type_index"]
            result["overloads"] = (
                list(
                    self.iter_codeview_method_overloads(
                        result["extraction_id"],
                        method_list_type_index=method_list_type_index,
                    )
                )
                if method_list_type_index is not None
                else []
            )
            yield result

    def iter_codeview_layout_diagnostics(
        self,
        extraction_id: str,
        *,
        code: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        sql = """
            SELECT diagnostic.*, record.type_index AS tag_type_index
            FROM codeview_layout_diagnostics diagnostic
            JOIN codeview_tag_layouts tag USING (tag_layout_id)
            JOIN codeview_type_records record USING (type_record_id)
            WHERE diagnostic.extraction_id = ?
        """
        parameters: list[Any] = [extraction_id]
        if code is not None:
            sql += " AND diagnostic.code = ?"
            parameters.append(code)
        sql += " ORDER BY record.type_index, diagnostic.ordinal"
        for row in self.connection.execute(sql, parameters):
            yield dict(row)

    def persist_data_symbol_extraction(
        self,
        extraction: DataSymbolExtraction,
        *,
        program_id: str,
        provenance_id: str,
        extraction_id: str | None = None,
        address_space: str = "xbox-va",
        details: Mapping[str, Any] = {},
    ) -> DataSymbolPersistenceResult:
        """Atomically persist typed data records without inventing code facts."""

        if address_space != "xbox-va":
            raise ValueError("Xbox data symbols require the xbox-va address space")
        self._require_xbox_program(program_id)
        if not self.connection.execute(
            "SELECT 1 FROM provenance WHERE provenance_id = ?", (provenance_id,)
        ).fetchone():
            raise AtlasError(f"unknown provenance {provenance_id!r}")

        records = tuple(
            sorted(
                extraction.records,
                key=lambda record: (
                    record.module_index,
                    record.symbol_stream,
                    record.record_offset,
                    record.record_id,
                ),
            )
        )
        seen_source_ids: set[str] = set()
        seen_physical_keys: set[tuple[int, int, int]] = set()
        for record in records:
            expected_source_id = make_data_record_id(
                record.module_index, record.symbol_stream, record.record_offset
            )
            if record.record_id != expected_source_id:
                raise ValueError(
                    f"data record {record.record_id!r} does not match physical identity "
                    f"{expected_source_id!r}"
                )
            if record.record_id in seen_source_ids:
                raise ValueError(f"duplicate data-symbol record ID {record.record_id!r}")
            seen_source_ids.add(record.record_id)
            physical_key = (
                record.module_index,
                record.symbol_stream,
                record.record_offset,
            )
            if physical_key in seen_physical_keys:
                raise ValueError("duplicate data-symbol physical stream location")
            seen_physical_keys.add(physical_key)
            if min(physical_key) < 0:
                raise ValueError("data-symbol physical identity cannot be negative")
            if not 2 <= record.record_length <= 0xFFFF:
                raise ValueError("data-symbol record length is outside uint16")
            expected_kind = {0x110C: "S_LDATA32", 0x110D: "S_GDATA32"}.get(
                record.record_kind_code
            )
            if expected_kind != record.record_kind:
                raise ValueError("data-symbol record kind/code pair is inconsistent")
            if not 0 <= record.section <= 0xFFFF:
                raise ValueError("data-symbol section is outside uint16")
            if not 0 <= record.section_offset <= 0xFFFFFFFF:
                raise ValueError("data-symbol section offset is outside uint32")
            if not 0 <= record.type_index <= 0xFFFFFFFF:
                raise ValueError("data-symbol type index is outside uint32")
            if record.va is not None and not 0 <= record.va <= 0xFFFFFFFF:
                raise ValueError("resolved data-symbol VA is outside Xbox uint32")
            try:
                record.raw_name.encode("latin-1")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    "data-symbol raw name is not a reversible Latin-1 string"
                ) from exc

        expected_groups = build_data_address_groups(records)
        if extraction.address_groups != expected_groups:
            raise ValueError(
                "data-symbol address groups are not the complete deterministic "
                "grouping of physical records"
            )
        if extraction.record_count != len(records):
            raise ValueError("data-symbol record count property is inconsistent")
        resolved_count = sum(record.va is not None for record in records)
        unresolved_count = len(records) - resolved_count
        if extraction.unresolved_va_count != unresolved_count:
            raise ValueError("data-symbol unresolved count property is inconsistent")
        if extraction.unique_va_count != len(expected_groups):
            raise ValueError("data-symbol unique-address count property is inconsistent")

        details_json = _canonical_json(details)
        fingerprint = _canonical_row_digest(
            record.to_dict() for record in records
        )
        extraction_id = extraction_id or stable_id(
            "data-symbol-extraction",
            program_id,
            address_space,
            fingerprint,
            provenance_id,
            json.loads(details_json),
        )
        result = DataSymbolPersistenceResult(
            extraction_id=extraction_id,
            records=len(records),
            resolved_records=resolved_count,
            unresolved_records=unresolved_count,
            unique_addresses=len(expected_groups),
        )

        with self.batch():
            extraction_values = {
                "extraction_id": extraction_id,
                "program_id": program_id,
                "address_space": address_space,
                "record_count": result.records,
                "resolved_record_count": result.resolved_records,
                "unresolved_record_count": result.unresolved_records,
                "unique_address_count": result.unique_addresses,
                "provenance_id": provenance_id,
                "details_json": details_json,
            }
            self._stable_upsert(
                "data_symbol_extractions",
                "extraction_id",
                extraction_values,
                immutable=tuple(extraction_values),
            )

            # Preserve any existing address-group projection (including a code
            # kind) at a shared VA.  Only absent canonical Xbox VAs are added.
            address_group_ids = {
                row["address"]: row["address_group_id"]
                for row in self.connection.execute(
                    """
                    SELECT address, address_group_id FROM address_groups
                    WHERE program_id = ? AND address_space = 'xbox-va'
                    """,
                    (program_id,),
                )
            }

            new_addresses: list[tuple[int, str]] = []
            for group in expected_groups:
                if group.va not in address_group_ids:
                    address_group_id = make_address_group_id(
                        program_id, "xbox-va", group.va
                    )
                    address_group_ids[group.va] = address_group_id
                    new_addresses.append((group.va, address_group_id))

            self._bulk_insert_immutable(
                "address_groups",
                "address_group_id",
                (
                    {
                        "address_group_id": address_group_id,
                        "program_id": program_id,
                        "address_space": "xbox-va",
                        "address": va,
                        "kind": "data",
                        "details_json": "{}",
                    }
                    for va, address_group_id in new_addresses
                ),
            )

            data_record_ids = {
                record.record_id: stable_id(
                    "data-symbol-record", program_id, record.record_id
                )
                for record in records
            }

            def data_record_rows() -> Iterator[dict[str, Any]]:
                for record in records:
                    yield {
                        "data_record_id": data_record_ids[record.record_id],
                        "program_id": program_id,
                        "source_record_id": record.record_id,
                        "module_index": record.module_index,
                        "symbol_stream": record.symbol_stream,
                        "record_offset": record.record_offset,
                    }

            self._bulk_insert_immutable(
                "data_symbol_records", "data_record_id", data_record_rows()
            )

            def data_assertion_rows() -> Iterator[dict[str, Any]]:
                for record in records:
                    data_record_id = data_record_ids[record.record_id]
                    yield {
                        "assertion_id": stable_id(
                            "data-symbol-record-assertion",
                            extraction_id,
                            data_record_id,
                        ),
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "data_record_id": data_record_id,
                        "module_name": record.module_name,
                        "record_length": record.record_length,
                        "record_kind": record.record_kind,
                        "record_kind_code": record.record_kind_code,
                        "resolved_va": record.va,
                        "address_group_id": (
                            address_group_ids[record.va]
                            if record.va is not None
                            else None
                        ),
                        "section": record.section,
                        "section_offset": record.section_offset,
                        "type_index": record.type_index,
                        "raw_name": record.raw_name,
                    }

            self._bulk_insert_immutable(
                "data_symbol_record_assertions",
                "assertion_id",
                data_assertion_rows(),
            )

            self.validate_data_symbol_extraction(extraction_id)

        return result

    def validate_data_symbol_extraction(self, extraction_id: str) -> bool:
        """Validate typed-data counts and address domains with set queries."""

        extraction = self.connection.execute(
            "SELECT * FROM data_symbol_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if extraction is None:
            raise AtlasError(f"unknown data-symbol extraction {extraction_id!r}")
        counts = self.connection.execute(
            """
            SELECT
                COUNT(*) AS records,
                COUNT(assertion.address_group_id) AS resolved_records,
                COALESCE(SUM(assertion.address_group_id IS NULL), 0)
                    AS unresolved_records,
                COUNT(DISTINCT assertion.address_group_id) AS unique_addresses,
                COALESCE(SUM(
                    assertion.address_group_id IS NOT NULL AND NOT EXISTS (
                        SELECT 1 FROM address_groups address
                        WHERE address.address_group_id = assertion.address_group_id
                          AND address.program_id = assertion.program_id
                          AND address.address_space = 'xbox-va'
                          AND address.address = assertion.resolved_va
                          AND address.address >= 0
                          AND address.address <= 4294967295
                    )
                ), 0) AS invalid_addresses
            FROM data_symbol_record_assertions assertion
            WHERE assertion.extraction_id = ?
            """,
            (extraction_id,),
        ).fetchone()
        expected = {
            "records": extraction["record_count"],
            "resolved_records": extraction["resolved_record_count"],
            "unresolved_records": extraction["unresolved_record_count"],
            "unique_addresses": extraction["unique_address_count"],
        }
        mismatches = [
            name for name, value in expected.items() if counts[name] != value
        ]
        if counts["invalid_addresses"]:
            mismatches.append("invalid_addresses")
        if mismatches:
            raise AtlasError(
                f"data-symbol extraction {extraction_id!r} validation mismatch: "
                + ", ".join(mismatches)
            )
        return True

    def get_data_symbol_extraction(
        self, extraction_id: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM data_symbol_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        return result

    def iter_data_symbols(
        self,
        *,
        extraction_id: str | None = None,
        program_id: str | None = None,
        raw_name: str | None = None,
        resolved: bool | None = None,
        address: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("assertion.extraction_id", extraction_id),
            ("record.program_id", program_id),
            ("assertion.raw_name", raw_name),
            ("assertion.resolved_va", address),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        if resolved is True:
            clauses.append("assertion.address_group_id IS NOT NULL")
        elif resolved is False:
            clauses.append("assertion.address_group_id IS NULL")
        sql = """
            SELECT record.*, assertion.assertion_id, assertion.extraction_id,
                   assertion.module_name, assertion.record_length,
                   assertion.record_kind, assertion.record_kind_code,
                   assertion.resolved_va, assertion.address_group_id,
                   assertion.section, assertion.section_offset,
                   assertion.type_index, assertion.raw_name,
                   address.address_space, address.kind AS address_kind
            FROM data_symbol_record_assertions assertion
            JOIN data_symbol_records record USING (data_record_id)
            LEFT JOIN address_groups address
              ON address.address_group_id = assertion.address_group_id
             AND address.program_id = assertion.program_id
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += """
            ORDER BY assertion.extraction_id, record.module_index,
                     record.symbol_stream, record.record_offset
        """
        for row in self.connection.execute(sql, parameters):
            yield dict(row)

    def data_symbols_at(
        self,
        program_id: str,
        address: int,
        *,
        extraction_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return list(
            self.iter_data_symbols(
                extraction_id=extraction_id,
                program_id=program_id,
                address=address,
                resolved=True,
            )
        )

    def persist_vftable_corpus(
        self,
        extraction_id: str,
        corpus: VftableCorpus,
        *,
        program_id: str,
        provenance_id: str,
        scan_max_slots: int = 4096,
        details: Mapping[str, Any] = {},
    ) -> VftablePersistenceResult:
        """Persist physical vftable records and non-declarative pointer runs.

        The method deliberately creates only neutral address identities needed
        by foreign keys.  It never creates a function, name, vtable, extent,
        match, confidence, or review decision.
        """

        if not extraction_id:
            raise ValueError("vftable extraction_id must not be empty")
        if scan_max_slots <= 0:
            raise ValueError("vftable scan_max_slots must be positive")
        self._require_xbox_program(program_id)
        if not self.connection.execute(
            "SELECT 1 FROM provenance WHERE provenance_id = ?", (provenance_id,)
        ).fetchone():
            raise AtlasError(f"unknown provenance {provenance_id!r}")

        symbols = corpus.symbols
        stream = symbols.stream_reference
        records = tuple(
            sorted(
                symbols.records,
                key=lambda item: (
                    item.symbol_record_stream,
                    item.record_offset,
                    item.record_id,
                ),
            )
        )
        record_by_source_id: dict[str, Any] = {}
        name_by_id: dict[str, tuple[str, bytes]] = {}
        physical_locations: set[tuple[int, int]] = set()
        for record in records:
            expected_id = make_vftable_record_id(
                record.symbol_record_stream, record.record_offset
            )
            if record.record_id != expected_id:
                raise ValueError(
                    f"vftable record {record.record_id!r} disagrees with physical identity"
                )
            if record.record_id in record_by_source_id:
                raise ValueError(f"duplicate vftable record ID {record.record_id!r}")
            location = (record.symbol_record_stream, record.record_offset)
            if location in physical_locations:
                raise ValueError("duplicate vftable symbol-stream location")
            physical_locations.add(location)
            record_by_source_id[record.record_id] = record
            if record.symbol_record_stream != stream.symbol_record_stream:
                raise ValueError("vftable record is from the wrong DBI symbol stream")
            if min(location) < 0:
                raise ValueError("vftable physical identity cannot be negative")
            if record.record_kind != "S_PUB32" or record.record_kind_code != S_PUB32:
                raise ValueError("vftable record kind/code is not S_PUB32")
            if not 0 <= record.public_flags <= 0xFFFFFFFF:
                raise ValueError("vftable public flags are outside uint32")
            if not 0 <= record.section <= 0xFFFF:
                raise ValueError("vftable section is outside uint16")
            if not 0 <= record.section_offset <= 0xFFFFFFFF:
                raise ValueError("vftable section offset is outside uint32")
            if record.va is not None and not 0 <= record.va <= 0xFFFFFFFF:
                raise ValueError("vftable VA is outside Xbox uint32")
            if not 2 <= record.record_length <= 0xFFFF:
                raise ValueError("vftable record length is outside uint16")
            raw = record.raw_record
            if len(raw) != record.record_length + 2:
                raise ValueError("vftable raw-record length is inconsistent")
            if int.from_bytes(raw[0:2], "little") != record.record_length:
                raise ValueError("vftable raw-record prefix disagrees with record length")
            if int.from_bytes(raw[2:4], "little") != record.record_kind_code:
                raise ValueError("vftable raw-record kind disagrees with decoded kind")
            if len(raw) < 15:
                raise ValueError("vftable raw S_PUB32 record is truncated")
            if int.from_bytes(raw[4:8], "little") != record.public_flags:
                raise ValueError("vftable raw flags disagree with decoded flags")
            if int.from_bytes(raw[8:12], "little") != record.section_offset:
                raise ValueError("vftable raw offset disagrees with decoded offset")
            if int.from_bytes(raw[12:14], "little") != record.section:
                raise ValueError("vftable raw section disagrees with decoded section")
            nul = raw.find(b"\0", 14)
            if nul < 0:
                raise ValueError("vftable raw decorated name is unterminated")
            decorated_bytes = record.decorated_name.encode("latin-1")
            if raw[14:nul] != decorated_bytes:
                raise ValueError("vftable raw decorated name disagrees with decoded name")
            expected_name_id = make_canonical_name_id(record.decorated_name)
            if record.canonical_name_id != expected_name_id:
                raise ValueError("vftable canonical-name identity is inconsistent")
            previous_name = name_by_id.get(expected_name_id)
            name_payload = (record.decorated_name, decorated_bytes)
            if previous_name is not None and previous_name != name_payload:
                raise ValueError("vftable canonical-name ID has conflicting content")
            name_by_id[expected_name_id] = name_payload

        expected_groups = build_vftable_address_groups(records)
        if symbols.address_groups != expected_groups:
            raise ValueError(
                "vftable same-address groups are not the complete deterministic grouping"
            )
        if symbols.record_count != len(records):
            raise ValueError("vftable physical-record count property is inconsistent")
        unresolved_count = sum(record.va is None for record in records)
        resolved_count = len(records) - unresolved_count
        if symbols.unresolved_va_count != unresolved_count:
            raise ValueError("vftable unresolved-record count property is inconsistent")
        if symbols.unique_va_count != len(expected_groups):
            raise ValueError("vftable unique-address count property is inconsistent")
        if stream.dbi_stream < 0 or stream.symbol_record_stream < 0:
            raise ValueError("vftable DBI stream references cannot be negative")
        if any(
            value is not None and value < 0
            for value in (
                stream.global_symbol_hash_stream,
                stream.public_symbol_hash_stream,
            )
        ):
            raise ValueError("vftable DBI hash-stream references cannot be negative")

        group_by_source_id = {group.group_id: group for group in expected_groups}
        if len(group_by_source_id) != len(expected_groups):
            raise ValueError("duplicate vftable source address-group identity")
        group_by_va = {group.va: group for group in expected_groups}
        runs = tuple(sorted(corpus.pointer_runs.runs, key=lambda item: item.run_id))
        run_by_source_id: dict[str, Any] = {}
        seen_slot_ids: set[str] = set()
        pointer_slot_count = 0
        run_diagnostic_count = 0
        for run in runs:
            if run.run_id in run_by_source_id:
                raise ValueError(f"duplicate vftable pointer-run ID {run.run_id!r}")
            run_by_source_id[run.run_id] = run
            group = group_by_source_id.get(run.address_group_id)
            if group is None or group.va != run.table_va:
                raise ValueError("vftable pointer run does not identify its table group")
            if tuple(run.symbol_record_ids) != group.record_ids:
                raise ValueError("vftable pointer-run table membership is incomplete")
            if run.observed_pointer_count != len(run.slots):
                raise ValueError("vftable pointer-run slot count property is inconsistent")
            if len(run.slots) > scan_max_slots:
                raise ValueError("vftable pointer run exceeds the declared scan cap")
            # This is the table-relative coordinate of the next known symbol,
            # not necessarily an index in the observed pointer prefix.
            if (
                run.known_boundary_slot_index is not None
                and run.known_boundary_slot_index < 0
            ):
                raise ValueError(
                    "vftable known-boundary slot index cannot be negative"
                )
            if run.next_vftable_va is None:
                if run.next_vftable_record_ids:
                    raise ValueError("vftable next-symbol membership has no next address")
            else:
                next_group = group_by_va.get(run.next_vftable_va)
                if next_group is None:
                    raise ValueError("vftable pointer run names an unknown next table")
                if tuple(run.next_vftable_record_ids) != next_group.record_ids:
                    raise ValueError("vftable next-table membership is incomplete")
            if (run.termination_word_hex is None) != (run.termination_va is None):
                if run.termination_kind not in {
                    "unmapped_table_address",
                    "ambiguous_table_mapping",
                    "mapped_section_end",
                    "max_slots_reached",
                }:
                    raise ValueError("vftable termination address/word pairing is inconsistent")
            if run.termination_word_hex is not None:
                try:
                    termination_word = bytes.fromhex(run.termination_word_hex)
                except ValueError as exc:
                    raise ValueError("invalid vftable termination word") from exc
                if len(termination_word) != 4:
                    raise ValueError("vftable termination word must be four bytes")
            for ordinal, slot in enumerate(run.slots):
                if slot.slot_id in seen_slot_ids:
                    raise ValueError(f"duplicate vftable pointer-slot ID {slot.slot_id!r}")
                seen_slot_ids.add(slot.slot_id)
                if slot.run_id != run.run_id or slot.slot_index != ordinal:
                    raise ValueError("vftable slot identity/order disagrees with its run")
                if slot.slot_va != run.table_va + ordinal * 4:
                    raise ValueError("vftable slot VA is not contiguous from its table")
                if not 0 <= slot.target_va <= 0xFFFFFFFF:
                    raise ValueError("vftable slot target is outside Xbox uint32")
                try:
                    raw_word = bytes.fromhex(slot.raw_word_hex)
                except ValueError as exc:
                    raise ValueError("invalid vftable slot raw word") from exc
                if raw_word != slot.target_va.to_bytes(4, "big"):
                    raise ValueError("vftable raw pointer word disagrees with target VA")
            pointer_slot_count += len(run.slots)
            run_diagnostic_count += len(run.diagnostics)

        if corpus.pointer_runs.run_count != len(runs):
            raise ValueError("vftable pointer-run count property is inconsistent")
        if corpus.pointer_runs.slot_count != pointer_slot_count:
            raise ValueError("vftable pointer-slot count property is inconsistent")
        if len(runs) != len(expected_groups) or set(run.address_group_id for run in runs) != set(
            group_by_source_id
        ):
            raise ValueError("vftable pointer runs are not complete for address groups")

        symbol_diagnostic_count = len(symbols.diagnostics)
        scan_diagnostic_count = len(corpus.pointer_runs.diagnostics)
        result = VftablePersistenceResult(
            extraction_id=extraction_id,
            physical_records=len(records),
            resolved_records=resolved_count,
            unresolved_records=unresolved_count,
            canonical_names=len(name_by_id),
            address_groups=len(expected_groups),
            pointer_runs=len(runs),
            pointer_slots=pointer_slot_count,
            diagnostics=(
                symbol_diagnostic_count
                + run_diagnostic_count
                + scan_diagnostic_count
            ),
        )
        details_json = _canonical_json(details)

        all_addresses: set[int] = set(group_by_va)
        for run in runs:
            all_addresses.add(run.table_va)
            if run.next_vftable_va is not None:
                all_addresses.add(run.next_vftable_va)
            for slot in run.slots:
                all_addresses.add(slot.slot_va)
                all_addresses.add(slot.target_va)

        with self.batch():
            self._bulk_insert_immutable(
                "xbox_vftable_extractions",
                "extraction_id",
                ({
                    "extraction_id": extraction_id,
                    "program_id": program_id,
                    "address_space": "xbox-va",
                    "dbi_stream": stream.dbi_stream,
                    "global_symbol_hash_stream": stream.global_symbol_hash_stream,
                    "public_symbol_hash_stream": stream.public_symbol_hash_stream,
                    "symbol_record_stream": stream.symbol_record_stream,
                    "scan_max_slots": scan_max_slots,
                    "physical_record_count": result.physical_records,
                    "resolved_record_count": result.resolved_records,
                    "unresolved_record_count": result.unresolved_records,
                    "canonical_name_count": result.canonical_names,
                    "source_address_group_count": result.address_groups,
                    "pointer_run_count": result.pointer_runs,
                    "pointer_slot_count": result.pointer_slots,
                    "symbol_diagnostic_count": symbol_diagnostic_count,
                    "run_diagnostic_count": run_diagnostic_count,
                    "scan_diagnostic_count": scan_diagnostic_count,
                    "provenance_id": provenance_id,
                    "details_json": details_json,
                },),
            )
            address_group_ids = self._ensure_address_observations(
                program_id=program_id,
                address_space="xbox-va",
                addresses=all_addresses,
            )
            self._bulk_insert_immutable(
                "xbox_vftable_name_identities",
                "canonical_name_id",
                (
                    {
                        "canonical_name_id": canonical_name_id,
                        "decorated_name": decorated_name,
                        "decorated_name_bytes": decorated_bytes,
                        "decorated_name_sha256": hashlib.sha256(
                            decorated_bytes
                        ).hexdigest(),
                    }
                    for canonical_name_id, (
                        decorated_name,
                        decorated_bytes,
                    ) in sorted(name_by_id.items())
                ),
            )
            db_record_ids = {
                record.record_id: stable_id(
                    "xbox-vftable-record", program_id, record.record_id
                )
                for record in records
            }
            self._bulk_insert_immutable(
                "xbox_vftable_symbol_records",
                "vftable_record_id",
                (
                    {
                        "vftable_record_id": db_record_ids[record.record_id],
                        "program_id": program_id,
                        "source_record_id": record.record_id,
                        "symbol_record_stream": record.symbol_record_stream,
                        "record_offset": record.record_offset,
                        "record_length": record.record_length,
                        "raw_record": record.raw_record,
                        "raw_record_sha256": hashlib.sha256(
                            record.raw_record
                        ).hexdigest(),
                    }
                    for record in records
                ),
            )
            self._bulk_insert_immutable(
                "xbox_vftable_symbol_assertions",
                "assertion_id",
                (
                    {
                        "assertion_id": stable_id(
                            "xbox-vftable-symbol-assertion",
                            extraction_id,
                            db_record_ids[record.record_id],
                        ),
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "vftable_record_id": db_record_ids[record.record_id],
                        "canonical_name_id": record.canonical_name_id,
                        "record_kind": record.record_kind,
                        "record_kind_code": record.record_kind_code,
                        "public_flags": record.public_flags,
                        "section": record.section,
                        "section_offset": record.section_offset,
                        "resolved_va": record.va,
                        "address_group_id": (
                            address_group_ids[record.va]
                            if record.va is not None
                            else None
                        ),
                        "owner_encoding": record.name_parts.owner_encoding,
                        "qualifier_encoding": record.name_parts.qualifier_encoding,
                        "role_encoding": record.name_parts.role_encoding,
                        "parse_status": record.name_parts.parse_status,
                        "is_template_owner": int(
                            record.name_parts.is_template_owner
                        ),
                        "is_template_qualifier": int(
                            record.name_parts.is_template_qualifier
                        ),
                    }
                    for record in records
                ),
            )
            address_observation_ids = {
                group.group_id: stable_id(
                    "xbox-vftable-address-observation",
                    extraction_id,
                    group.group_id,
                )
                for group in expected_groups
            }
            self._bulk_insert_immutable(
                "xbox_vftable_address_observations",
                "address_observation_id",
                (
                    {
                        "address_observation_id": address_observation_ids[group.group_id],
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "source_address_group_id": group.group_id,
                        "address_group_id": address_group_ids[group.va],
                        "table_va": group.va,
                        "member_count": group.count,
                    }
                    for group in expected_groups
                ),
            )
            self._bulk_insert_immutable(
                "xbox_vftable_address_members",
                "membership_id",
                (
                    {
                        "membership_id": stable_id(
                            "xbox-vftable-address-member",
                            address_observation_ids[group.group_id],
                            ordinal,
                        ),
                        "address_observation_id": address_observation_ids[group.group_id],
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "source_ordinal": ordinal,
                        "is_ranked": 0,
                        "vftable_record_id": db_record_ids[source_record_id],
                        "canonical_name_id": group.canonical_name_ids[ordinal],
                    }
                    for group in expected_groups
                    for ordinal, source_record_id in enumerate(group.record_ids)
                ),
            )
            db_run_ids = {
                run.run_id: stable_id(
                    "xbox-vftable-pointer-run", extraction_id, run.run_id
                )
                for run in runs
            }
            self._bulk_insert_immutable(
                "xbox_vftable_pointer_runs",
                "pointer_run_id",
                (
                    {
                        "pointer_run_id": db_run_ids[run.run_id],
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "source_run_id": run.run_id,
                        "address_observation_id": address_observation_ids[
                            run.address_group_id
                        ],
                        "table_address_group_id": address_group_ids[run.table_va],
                        "table_va": run.table_va,
                        "observed_pointer_count": len(run.slots),
                        "termination_kind": run.termination_kind,
                        "termination_va": run.termination_va,
                        "termination_word": (
                            bytes.fromhex(run.termination_word_hex)
                            if run.termination_word_hex is not None
                            else None
                        ),
                        "next_vftable_address_group_id": (
                            address_group_ids[run.next_vftable_va]
                            if run.next_vftable_va is not None
                            else None
                        ),
                        "next_vftable_va": run.next_vftable_va,
                        "known_boundary_slot_index": run.known_boundary_slot_index,
                        "boundary_relation": run.boundary_relation,
                        "extent_semantics": (
                            "observed_pointer_prefix_not_declared_extent"
                        ),
                    }
                    for run in runs
                ),
            )
            self._bulk_insert_immutable(
                "xbox_vftable_pointer_run_symbols",
                "run_symbol_id",
                (
                    {
                        "run_symbol_id": stable_id(
                            "xbox-vftable-run-symbol",
                            db_run_ids[run.run_id],
                            role,
                            ordinal,
                        ),
                        "pointer_run_id": db_run_ids[run.run_id],
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "membership_role": role,
                        "source_ordinal": ordinal,
                        "vftable_record_id": db_record_ids[source_record_id],
                    }
                    for run in runs
                    for role, source_ids in (
                        ("table", run.symbol_record_ids),
                        ("next", run.next_vftable_record_ids),
                    )
                    for ordinal, source_record_id in enumerate(source_ids)
                ),
            )
            self._bulk_insert_immutable(
                "xbox_vftable_pointer_slots",
                "pointer_slot_id",
                (
                    {
                        "pointer_slot_id": stable_id(
                            "xbox-vftable-pointer-slot",
                            extraction_id,
                            slot.slot_id,
                        ),
                        "source_slot_id": slot.slot_id,
                        "pointer_run_id": db_run_ids[run.run_id],
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "slot_index": slot.slot_index,
                        "slot_va": slot.slot_va,
                        "slot_address_group_id": address_group_ids[slot.slot_va],
                        "target_va": slot.target_va,
                        "target_address_group_id": address_group_ids[slot.target_va],
                        "raw_word": bytes.fromhex(slot.raw_word_hex),
                    }
                    for run in runs
                    for slot in run.slots
                ),
            )

            def diagnostic_rows() -> Iterator[dict[str, Any]]:
                for ordinal, diagnostic in enumerate(symbols.diagnostics):
                    yield {
                        "diagnostic_id": stable_id(
                            "xbox-vftable-diagnostic",
                            extraction_id,
                            "symbol_extraction",
                            ordinal,
                            diagnostic.code,
                            diagnostic.subject_id,
                            diagnostic.message,
                        ),
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "diagnostic_scope": "symbol_extraction",
                        "pointer_run_id": None,
                        "source_ordinal": ordinal,
                        "subject_id": diagnostic.subject_id,
                        "code": diagnostic.code,
                        "message": diagnostic.message,
                    }
                for run in runs:
                    for ordinal, diagnostic in enumerate(run.diagnostics):
                        yield {
                            "diagnostic_id": stable_id(
                                "xbox-vftable-diagnostic",
                                extraction_id,
                                run.run_id,
                                ordinal,
                                diagnostic.code,
                                diagnostic.subject_id,
                                diagnostic.message,
                            ),
                            "extraction_id": extraction_id,
                            "program_id": program_id,
                            "diagnostic_scope": "pointer_run",
                            "pointer_run_id": db_run_ids[run.run_id],
                            "source_ordinal": ordinal,
                            "subject_id": diagnostic.subject_id,
                            "code": diagnostic.code,
                            "message": diagnostic.message,
                        }
                for ordinal, diagnostic in enumerate(corpus.pointer_runs.diagnostics):
                    yield {
                        "diagnostic_id": stable_id(
                            "xbox-vftable-diagnostic",
                            extraction_id,
                            "pointer_scan",
                            ordinal,
                            diagnostic.code,
                            diagnostic.subject_id,
                            diagnostic.message,
                        ),
                        "extraction_id": extraction_id,
                        "program_id": program_id,
                        "diagnostic_scope": "pointer_scan",
                        "pointer_run_id": None,
                        "source_ordinal": ordinal,
                        "subject_id": diagnostic.subject_id,
                        "code": diagnostic.code,
                        "message": diagnostic.message,
                    }

            self._bulk_insert_immutable(
                "xbox_vftable_diagnostics", "diagnostic_id", diagnostic_rows()
            )
            self.validate_vftable_extraction(extraction_id)
        return result

    def validate_vftable_extraction(self, extraction_id: str) -> bool:
        """Validate vftable counts, complete memberships, and Xbox VA domains."""

        extraction = self.connection.execute(
            "SELECT * FROM xbox_vftable_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if extraction is None:
            raise AtlasError(f"unknown vftable extraction {extraction_id!r}")
        counts = self.connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM xbox_vftable_symbol_assertions
                 WHERE extraction_id = :id) AS physical_records,
                (SELECT COUNT(*) FROM xbox_vftable_symbol_assertions
                 WHERE extraction_id = :id AND address_group_id IS NOT NULL)
                    AS resolved_records,
                (SELECT COUNT(*) FROM xbox_vftable_symbol_assertions
                 WHERE extraction_id = :id AND address_group_id IS NULL)
                    AS unresolved_records,
                (SELECT COUNT(DISTINCT canonical_name_id)
                 FROM xbox_vftable_symbol_assertions
                 WHERE extraction_id = :id) AS canonical_names,
                (SELECT COUNT(*) FROM xbox_vftable_address_observations
                 WHERE extraction_id = :id) AS address_groups,
                (SELECT COUNT(*) FROM xbox_vftable_pointer_runs
                 WHERE extraction_id = :id) AS pointer_runs,
                (SELECT COUNT(*) FROM xbox_vftable_pointer_slots
                 WHERE extraction_id = :id) AS pointer_slots,
                (SELECT COUNT(*) FROM xbox_vftable_diagnostics
                 WHERE extraction_id = :id
                   AND diagnostic_scope = 'symbol_extraction')
                    AS symbol_diagnostics,
                (SELECT COUNT(*) FROM xbox_vftable_diagnostics
                 WHERE extraction_id = :id
                   AND diagnostic_scope = 'pointer_run') AS run_diagnostics,
                (SELECT COUNT(*) FROM xbox_vftable_diagnostics
                 WHERE extraction_id = :id
                   AND diagnostic_scope = 'pointer_scan') AS scan_diagnostics,
                (
                    EXISTS (
                        SELECT 1
                        FROM xbox_vftable_address_observations observation
                        WHERE observation.extraction_id = :id
                          AND observation.member_count <> (
                              SELECT COUNT(*)
                              FROM xbox_vftable_address_members member
                              WHERE member.address_observation_id =
                                    observation.address_observation_id
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM xbox_vftable_address_members member
                        JOIN xbox_vftable_symbol_assertions assertion
                          ON assertion.extraction_id = member.extraction_id
                         AND assertion.vftable_record_id = member.vftable_record_id
                        WHERE member.extraction_id = :id
                          AND member.canonical_name_id <> assertion.canonical_name_id
                    ) OR EXISTS (
                        SELECT 1
                        FROM xbox_vftable_address_members member
                        JOIN xbox_vftable_address_observations observation
                          USING (address_observation_id, extraction_id, program_id)
                        JOIN xbox_vftable_symbol_assertions assertion
                          ON assertion.extraction_id = member.extraction_id
                         AND assertion.vftable_record_id = member.vftable_record_id
                        WHERE member.extraction_id = :id
                          AND (
                              assertion.address_group_id IS NULL OR
                              assertion.address_group_id <>
                                  observation.address_group_id
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM xbox_vftable_symbol_assertions assertion
                        WHERE assertion.extraction_id = :id
                          AND assertion.address_group_id IS NOT NULL
                          AND NOT EXISTS (
                              SELECT 1
                              FROM xbox_vftable_address_members member
                              WHERE member.extraction_id = assertion.extraction_id
                                AND member.vftable_record_id =
                                    assertion.vftable_record_id
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM xbox_vftable_pointer_runs run
                        JOIN xbox_vftable_address_observations observation
                          USING (address_observation_id, extraction_id, program_id)
                        WHERE run.extraction_id = :id
                          AND (
                              run.table_address_group_id <>
                                  observation.address_group_id OR
                              run.table_va <> observation.table_va OR
                              run.observed_pointer_count <> (
                                  SELECT COUNT(*)
                                  FROM xbox_vftable_pointer_slots slot
                                  WHERE slot.pointer_run_id = run.pointer_run_id
                              ) OR
                              observation.member_count <> (
                                  SELECT COUNT(*)
                                  FROM xbox_vftable_pointer_run_symbols symbol
                                  WHERE symbol.pointer_run_id = run.pointer_run_id
                                    AND symbol.membership_role = 'table'
                              ) OR EXISTS (
                                  SELECT 1
                                  FROM xbox_vftable_address_members member
                                  WHERE member.address_observation_id =
                                        observation.address_observation_id
                                    AND NOT EXISTS (
                                        SELECT 1
                                        FROM xbox_vftable_pointer_run_symbols symbol
                                        WHERE symbol.pointer_run_id = run.pointer_run_id
                                          AND symbol.membership_role = 'table'
                                          AND symbol.vftable_record_id =
                                              member.vftable_record_id
                                    )
                              ) OR EXISTS (
                                  SELECT 1
                                  FROM xbox_vftable_pointer_slots slot
                                  WHERE slot.pointer_run_id = run.pointer_run_id
                                    AND slot.slot_va <> run.table_va + slot.slot_index * 4
                              )
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM xbox_vftable_pointer_runs run
                        WHERE run.extraction_id = :id
                          AND run.next_vftable_va IS NULL
                          AND EXISTS (
                              SELECT 1
                              FROM xbox_vftable_pointer_run_symbols symbol
                              WHERE symbol.pointer_run_id = run.pointer_run_id
                                AND symbol.membership_role = 'next'
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM xbox_vftable_pointer_runs run
                        WHERE run.extraction_id = :id
                          AND run.next_vftable_va IS NOT NULL
                          AND (
                              NOT EXISTS (
                                  SELECT 1
                                  FROM xbox_vftable_address_observations next_observation
                                  WHERE next_observation.extraction_id = run.extraction_id
                                    AND next_observation.table_va = run.next_vftable_va
                              ) OR EXISTS (
                                  SELECT 1
                                  FROM xbox_vftable_address_observations next_observation
                                  JOIN xbox_vftable_address_members member
                                    USING (address_observation_id)
                                  WHERE next_observation.extraction_id = run.extraction_id
                                    AND next_observation.table_va = run.next_vftable_va
                                    AND NOT EXISTS (
                                        SELECT 1
                                        FROM xbox_vftable_pointer_run_symbols symbol
                                        WHERE symbol.pointer_run_id = run.pointer_run_id
                                          AND symbol.membership_role = 'next'
                                          AND symbol.vftable_record_id =
                                              member.vftable_record_id
                                    )
                              ) OR (
                                  SELECT COUNT(*)
                                  FROM xbox_vftable_pointer_run_symbols symbol
                                  WHERE symbol.pointer_run_id = run.pointer_run_id
                                    AND symbol.membership_role = 'next'
                              ) <> (
                                  SELECT next_observation.member_count
                                  FROM xbox_vftable_address_observations next_observation
                                  WHERE next_observation.extraction_id = run.extraction_id
                                    AND next_observation.table_va = run.next_vftable_va
                              )
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM xbox_vftable_symbol_assertions assertion
                        LEFT JOIN address_groups address
                          ON address.address_group_id = assertion.address_group_id
                         AND address.program_id = assertion.program_id
                        WHERE assertion.extraction_id = :id
                          AND assertion.address_group_id IS NOT NULL
                          AND (
                              address.address_group_id IS NULL OR
                              address.address_space <> 'xbox-va' OR
                              address.address <> assertion.resolved_va
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM xbox_vftable_pointer_slots slot
                        LEFT JOIN address_groups slot_address
                          ON slot_address.address_group_id = slot.slot_address_group_id
                        LEFT JOIN address_groups target_address
                          ON target_address.address_group_id = slot.target_address_group_id
                        WHERE slot.extraction_id = :id
                          AND (
                              slot_address.program_id <> slot.program_id OR
                              slot_address.address_space <> 'xbox-va' OR
                              slot_address.address <> slot.slot_va OR
                              target_address.program_id <> slot.program_id OR
                              target_address.address_space <> 'xbox-va' OR
                              target_address.address <> slot.target_va
                          )
                    )
                ) AS invalid_structure
            """,
            {"id": extraction_id},
        ).fetchone()
        expected = {
            "physical_records": extraction["physical_record_count"],
            "resolved_records": extraction["resolved_record_count"],
            "unresolved_records": extraction["unresolved_record_count"],
            "canonical_names": extraction["canonical_name_count"],
            "address_groups": extraction["source_address_group_count"],
            "pointer_runs": extraction["pointer_run_count"],
            "pointer_slots": extraction["pointer_slot_count"],
            "symbol_diagnostics": extraction["symbol_diagnostic_count"],
            "run_diagnostics": extraction["run_diagnostic_count"],
            "scan_diagnostics": extraction["scan_diagnostic_count"],
        }
        mismatches = [
            name for name, expected_value in expected.items()
            if counts[name] != expected_value
        ]
        if counts["invalid_structure"]:
            mismatches.append("invalid_structure")
        if mismatches:
            raise AtlasError(
                f"vftable extraction {extraction_id!r} validation mismatch: "
                + ", ".join(mismatches)
            )
        return True

    def get_vftable_extraction(
        self, extraction_id: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM xbox_vftable_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        return result

    def iter_vftable_symbol_records(
        self,
        *,
        extraction_id: str | None = None,
        program_id: str | None = None,
        address: int | None = None,
        canonical_name_id: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("assertion.extraction_id", extraction_id),
            ("record.program_id", program_id),
            ("assertion.resolved_va", address),
            ("assertion.canonical_name_id", canonical_name_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        sql = """
            SELECT record.*, assertion.assertion_id, assertion.extraction_id,
                   assertion.canonical_name_id, assertion.record_kind,
                   assertion.record_kind_code, assertion.public_flags,
                   assertion.section, assertion.section_offset,
                   assertion.resolved_va, assertion.address_group_id,
                   assertion.owner_encoding, assertion.qualifier_encoding,
                   assertion.role_encoding, assertion.parse_status,
                   assertion.is_template_owner,
                   assertion.is_template_qualifier,
                   name.decorated_name, name.decorated_name_bytes,
                   name.decorated_name_sha256
            FROM xbox_vftable_symbol_assertions assertion
            JOIN xbox_vftable_symbol_records record USING (vftable_record_id)
            JOIN xbox_vftable_name_identities name USING (canonical_name_id)
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += (
            " ORDER BY assertion.extraction_id, record.symbol_record_stream, "
            "record.record_offset"
        )
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["is_template_owner"] = bool(result["is_template_owner"])
            result["is_template_qualifier"] = bool(
                result["is_template_qualifier"]
            )
            yield result

    def iter_vftable_address_observations(
        self, extraction_id: str
    ) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            """
            SELECT * FROM xbox_vftable_address_observations
            WHERE extraction_id = ? ORDER BY table_va
            """,
            (extraction_id,),
        ):
            result = dict(row)
            result["members"] = [
                dict(member)
                for member in self.connection.execute(
                    """
                    SELECT member.*, name.decorated_name
                    FROM xbox_vftable_address_members member
                    JOIN xbox_vftable_name_identities name USING (canonical_name_id)
                    WHERE member.address_observation_id = ?
                    ORDER BY member.source_ordinal
                    """,
                    (row["address_observation_id"],),
                )
            ]
            yield result

    def iter_vftable_pointer_runs(
        self, extraction_id: str
    ) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            """
            SELECT * FROM xbox_vftable_pointer_runs
            WHERE extraction_id = ? ORDER BY table_va, source_run_id
            """,
            (extraction_id,),
        ):
            result = dict(row)
            termination_word = result.pop("termination_word")
            result["termination_word_hex"] = (
                bytes(termination_word).hex()
                if termination_word is not None
                else None
            )
            result["symbols"] = [
                dict(symbol)
                for symbol in self.connection.execute(
                    """
                    SELECT membership_role, source_ordinal, vftable_record_id
                    FROM xbox_vftable_pointer_run_symbols
                    WHERE pointer_run_id = ?
                    ORDER BY membership_role, source_ordinal
                    """,
                    (row["pointer_run_id"],),
                )
            ]
            yield result

    def iter_vftable_pointer_slots(
        self,
        *,
        extraction_id: str | None = None,
        pointer_run_id: str | None = None,
        target_address: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("extraction_id", extraction_id),
            ("pointer_run_id", pointer_run_id),
            ("target_va", target_address),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        sql = "SELECT * FROM xbox_vftable_pointer_slots"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY extraction_id, pointer_run_id, slot_index"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            result["raw_word_hex"] = bytes(result.pop("raw_word")).hex()
            yield result

    def iter_vftable_diagnostics(
        self,
        extraction_id: str,
        *,
        code: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        sql = "SELECT * FROM xbox_vftable_diagnostics WHERE extraction_id = ?"
        parameters: list[Any] = [extraction_id]
        if code is not None:
            sql += " AND code = ?"
            parameters.append(code)
        sql += " ORDER BY diagnostic_scope, pointer_run_id, source_ordinal"
        for row in self.connection.execute(sql, parameters):
            yield dict(row)

    def persist_sdk_extraction(
        self,
        extraction_id: str,
        extraction: SdkPrototypeExtraction,
        inventory_join: SdkPcInventoryJoin,
        *,
        pc_program_id: str,
        provenance_id: str,
        pc_address_space: str = "ram",
        details: Mapping[str, Any] = {},
    ) -> SdkPersistenceResult:
        """Persist portable SDK observations and a non-promoting PC join."""

        if not extraction_id:
            raise ValueError("SDK extraction_id must not be empty")
        if not pc_address_space:
            raise ValueError("SDK PC address space must not be empty")
        self._require_pc_program(pc_program_id)
        if not self.connection.execute(
            "SELECT 1 FROM provenance WHERE provenance_id = ?", (provenance_id,)
        ).fetchone():
            raise AtlasError(f"unknown provenance {provenance_id!r}")
        source_tree_sha256, source_files = _validated_sdk_source_manifest(extraction)
        manifest_by_path = {item.relative_path: item for item in source_files}
        source_file_ids = {
            item.relative_path: stable_id(
                "sdk-source-file", source_tree_sha256, item.relative_path
            )
            for item in source_files
        }

        prototypes = tuple(extraction.observations)
        calls = tuple(extraction.call_targets)
        data_observations = tuple(extraction.data_addresses)
        variants = {"game", "geck", "unspecified_pc"}

        def validate_source_observation(
            observation: Any,
            *,
            seen: set[str],
            line_fields: tuple[str, ...],
        ) -> None:
            if observation.observation_id in seen:
                raise ValueError(
                    f"duplicate SDK source observation ID {observation.observation_id!r}"
                )
            seen.add(observation.observation_id)
            if observation.program_variant not in variants:
                raise ValueError("unknown SDK program variant")
            if not 0 <= observation.address <= 0xFFFFFFFF:
                raise ValueError("SDK source observation address is outside uint32")
            _portable_sdk_path(observation.source_path)
            source_file = manifest_by_path.get(observation.source_path)
            if source_file is None:
                raise ValueError("SDK observation source path is absent from manifest")
            if source_file.sha256 != observation.source_file_sha256:
                raise ValueError("SDK observation source hash disagrees with manifest")
            for field_name in line_fields:
                value = getattr(observation, field_name)
                if value is not None and value <= 0:
                    raise ValueError("SDK observation source lines must be positive")

        seen_prototypes: set[str] = set()
        for observation in prototypes:
            validate_source_observation(
                observation,
                seen=seen_prototypes,
                line_fields=("address_line", "declaration_line"),
            )
            if not observation.declared_name or not observation.evidence_kind:
                raise ValueError("SDK prototype has an empty typed identity field")
            if observation.address_ordinal < 0:
                raise ValueError("SDK prototype address ordinal cannot be negative")

        seen_calls: set[str] = set()
        for observation in calls:
            validate_source_observation(
                observation,
                seen=seen_calls,
                line_fields=("call_line", "declaration_line"),
            )
            if not observation.invocation_kind or observation.address_ordinal < 0:
                raise ValueError("SDK call target has an invalid typed identity field")

        seen_data: set[str] = set()
        for observation in data_observations:
            validate_source_observation(
                observation,
                seen=seen_data,
                line_fields=("declaration_line",),
            )
            if not observation.data_kind or not observation.declared_name:
                raise ValueError("SDK data observation has an empty typed identity field")

        diagnostics = tuple(extraction.diagnostics)
        for diagnostic in diagnostics:
            path = _portable_sdk_path(diagnostic.source_path)
            if path not in manifest_by_path:
                raise ValueError("SDK diagnostic source path is absent from manifest")
            if not diagnostic.code or diagnostic.line <= 0:
                raise ValueError("SDK diagnostic code/line is invalid")

        pc_function_rows = tuple(
            self.connection.execute(
                """
                SELECT function.function_id, address.address,
                       address.address_group_id
                FROM functions function
                JOIN address_groups address
                  ON address.address_group_id = function.address_group_id
                 AND address.program_id = function.program_id
                WHERE function.program_id = ? AND address.address_space = ?
                """,
                (pc_program_id, pc_address_space),
            )
        )
        pc_functions = {
            row["function_id"]: (row["address"], row["address_group_id"])
            for row in pc_function_rows
        }
        pc_entry_groups: dict[int, str] = {}
        for row in pc_function_rows:
            prior = pc_entry_groups.get(row["address"])
            if prior is not None and prior != row["address_group_id"]:
                raise AtlasError("PC functions at one entry disagree on address identity")
            pc_entry_groups[row["address"]] = row["address_group_id"]

        prototype_joins = tuple(inventory_join.prototype_joins)
        call_joins = tuple(inventory_join.call_target_joins)
        data_joins = tuple(inventory_join.data_joins)
        if len(prototype_joins) != len(prototypes):
            raise ValueError("SDK prototype inventory join is incomplete")
        if len(call_joins) != len(calls):
            raise ValueError("SDK call-target inventory join is incomplete")
        if len(data_joins) != len(data_observations):
            raise ValueError("SDK data inventory join is incomplete")

        game_classifications = {
            "pc_function_entry",
            "pc_executable_non_entry",
            "pc_non_executable_section",
            "outside_pc_image_sections",
        }
        unspecified_classifications = {
            "pc_function_entry_variant_unspecified",
            "pc_executable_non_entry_variant_unspecified",
            "pc_non_executable_section_variant_unspecified",
            "outside_pc_image_sections_variant_unspecified",
        }
        definitive_links: list[tuple[str, str]] = []
        candidate_links: list[tuple[str, str]] = []

        def validate_code_join(
            joined: Any,
            observation: Any,
            *,
            observation_kind: str,
            source_ordinal: int,
        ) -> None:
            if (
                joined.observation_kind != observation_kind
                or joined.observation_id != observation.observation_id
                or joined.program_variant != observation.program_variant
                or joined.address != observation.address
            ):
                raise ValueError("SDK code join disagrees with its source observation")
            if (joined.section_name is None) != (joined.section_executable is None):
                raise ValueError("SDK code join section metadata is incomplete")
            if observation.program_variant == "geck":
                if (
                    joined.classification != "non_game_variant"
                    or joined.pc_function_id is not None
                    or joined.candidate_pc_function_id is not None
                ):
                    raise ValueError("GECK observation was linked into the PC domain")
                return
            if observation.program_variant == "game":
                if joined.classification not in game_classifications:
                    raise ValueError("invalid GAME SDK code classification")
                if joined.candidate_pc_function_id is not None:
                    raise ValueError("GAME SDK observation cannot use a candidate link")
                if joined.classification == "pc_function_entry":
                    if joined.pc_function_id is None:
                        raise ValueError("GAME exact entry lacks a definitive function link")
                    endpoint = pc_functions.get(joined.pc_function_id)
                    if endpoint is None or endpoint[0] != joined.address:
                        raise ValueError("GAME SDK link is not an exact canonical PC entry")
                    definitive_links.append(
                        (f"{observation_kind}:{source_ordinal}", joined.pc_function_id)
                    )
                elif joined.pc_function_id is not None:
                    raise ValueError("non-entry GAME observation has a function link")
                return
            if joined.classification not in unspecified_classifications:
                raise ValueError("invalid unspecified-PC SDK code classification")
            if joined.pc_function_id is not None:
                raise ValueError("unspecified SDK observation cannot be definitive")
            if joined.classification == "pc_function_entry_variant_unspecified":
                if joined.candidate_pc_function_id is None:
                    raise ValueError("unspecified exact entry lacks a candidate link")
                endpoint = pc_functions.get(joined.candidate_pc_function_id)
                if endpoint is None or endpoint[0] != joined.address:
                    raise ValueError(
                        "unspecified SDK candidate is not an exact canonical PC entry"
                    )
                candidate_links.append(
                    (
                        f"{observation_kind}:{source_ordinal}",
                        joined.candidate_pc_function_id,
                    )
                )
            elif joined.candidate_pc_function_id is not None:
                raise ValueError("non-entry unspecified observation has a candidate link")

        for ordinal, (observation, joined) in enumerate(
            zip(prototypes, prototype_joins)
        ):
            validate_code_join(
                joined,
                observation,
                observation_kind="prototype",
                source_ordinal=ordinal,
            )
        for ordinal, (observation, joined) in enumerate(zip(calls, call_joins)):
            validate_code_join(
                joined,
                observation,
                observation_kind="call_target",
                source_ordinal=ordinal,
            )

        game_data_classifications = {
            "pc_executable_section",
            "pc_data_section",
            "outside_pc_image_sections",
        }
        unspecified_data_classifications = {
            "pc_executable_section_variant_unspecified",
            "pc_data_section_variant_unspecified",
            "outside_pc_image_sections_variant_unspecified",
        }
        for observation, joined in zip(data_observations, data_joins):
            if (
                joined.observation_id != observation.observation_id
                or joined.program_variant != observation.program_variant
                or joined.address != observation.address
                or joined.data_kind != observation.data_kind
            ):
                raise ValueError("SDK data join disagrees with its source observation")
            if (joined.section_name is None) != (joined.section_executable is None):
                raise ValueError("SDK data join section metadata is incomplete")
            allowed = (
                {"non_game_variant"}
                if observation.program_variant == "geck"
                else game_data_classifications
                if observation.program_variant == "game"
                else unspecified_data_classifications
            )
            if joined.classification not in allowed:
                raise ValueError("invalid SDK data inventory classification")

        prototype_by_source_id = {
            observation.observation_id: observation for observation in prototypes
        }
        prototype_ordinal_by_source_id = {
            observation.observation_id: ordinal
            for ordinal, observation in enumerate(prototypes)
        }
        prototype_join_by_source_id = {
            joined.observation_id: joined for joined in prototype_joins
        }
        expected_boundary_sources = {
            observation.observation_id
            for observation in prototypes
            if observation.evidence_kind == "create_object_macro"
            and prototype_join_by_source_id[observation.observation_id].classification
            in {
                "pc_executable_non_entry",
                "pc_executable_non_entry_variant_unspecified",
            }
        }
        boundary_candidates = tuple(inventory_join.boundary_candidates)
        boundary_by_source: dict[str, Any] = {}
        seen_candidate_ids: set[str] = set()
        boundary_container_count = 0
        for candidate in boundary_candidates:
            source_id = candidate.source_observation.observation_id
            if candidate.candidate_id in seen_candidate_ids or source_id in boundary_by_source:
                raise ValueError("duplicate SDK boundary-candidate identity")
            seen_candidate_ids.add(candidate.candidate_id)
            boundary_by_source[source_id] = candidate
            source_observation = prototype_by_source_id.get(source_id)
            source_join = prototype_join_by_source_id.get(source_id)
            if (
                source_observation is None
                or candidate.source_observation != source_observation
                or source_join is None
                or candidate.inventory_classification != source_join.classification
                or candidate.candidate_reason
                != "sdk_create_object_target_is_executable_non_entry"
            ):
                raise ValueError("SDK boundary candidate disagrees with source/join")
            entries = tuple(candidate.containing_function_entries)
            if entries != tuple(sorted(set(entries))):
                raise ValueError("SDK boundary container entries are not unique/sorted")
            for entry in entries:
                if entry not in pc_entry_groups:
                    raise ValueError(
                        "SDK boundary container is not an existing canonical PC entry"
                    )
            boundary_container_count += len(entries)
        if set(boundary_by_source) != expected_boundary_sources:
            raise ValueError("SDK boundary-candidate set is incomplete or contains extras")

        prototype_db_ids = {
            item.observation_id: stable_id(
                "sdk-prototype-observation", source_tree_sha256, item.observation_id
            )
            for item in prototypes
        }
        call_db_ids = {
            item.observation_id: stable_id(
                "sdk-call-target-observation",
                source_tree_sha256,
                item.observation_id,
            )
            for item in calls
        }
        data_db_ids = {
            item.observation_id: stable_id(
                "sdk-data-observation", source_tree_sha256, item.observation_id
            )
            for item in data_observations
        }
        prototype_join_ids = {
            ordinal: stable_id(
                "sdk-code-inventory-join",
                extraction_id,
                "prototype",
                ordinal,
                observation.observation_id,
            )
            for ordinal, observation in enumerate(prototypes)
        }
        call_join_ids = {
            ordinal: stable_id(
                "sdk-code-inventory-join",
                extraction_id,
                "call_target",
                ordinal,
                observation.observation_id,
            )
            for ordinal, observation in enumerate(calls)
        }
        boundary_db_ids = {
            candidate.candidate_id: stable_id(
                "sdk-boundary-candidate", extraction_id, candidate.candidate_id
            )
            for candidate in boundary_candidates
        }
        result = SdkPersistenceResult(
            extraction_id=extraction_id,
            source_tree_sha256=source_tree_sha256,
            source_files=len(source_files),
            prototypes=len(prototypes),
            call_targets=len(calls),
            data_addresses=len(data_observations),
            diagnostics=len(diagnostics),
            code_joins=len(prototype_joins) + len(call_joins),
            data_joins=len(data_joins),
            definitive_game_links=len(definitive_links),
            unspecified_entry_candidates=len(candidate_links),
            boundary_candidates=len(boundary_candidates),
            boundary_containers=boundary_container_count,
        )
        details_json = _canonical_json(details)

        with self.batch():
            self._bulk_insert_immutable(
                "sdk_source_trees",
                "source_tree_sha256",
                ({
                    "source_tree_sha256": source_tree_sha256,
                    "file_count": len(source_files),
                    "total_byte_count": sum(item.byte_length for item in source_files),
                },),
            )
            self._bulk_insert_immutable(
                "sdk_source_tree_files",
                "source_file_id",
                (
                    {
                        "source_file_id": source_file_ids[item.relative_path],
                        "source_tree_sha256": source_tree_sha256,
                        "relative_path": item.relative_path,
                        "relative_path_casefold": item.relative_path.casefold(),
                        "source_file_sha256": item.sha256,
                        "byte_length": item.byte_length,
                    }
                    for item in source_files
                ),
            )
            self._bulk_insert_immutable(
                "sdk_extractions",
                "extraction_id",
                ({
                    "extraction_id": extraction_id,
                    "source_tree_sha256": source_tree_sha256,
                    "pc_program_id": pc_program_id,
                    "pc_address_space": pc_address_space,
                    "files_scanned": extraction.files_scanned,
                    "prototype_count": len(prototypes),
                    "unique_prototype_address_count": len(extraction.unique_addresses),
                    "game_prototype_address_count": len(extraction.game_addresses),
                    "geck_prototype_address_count": len(extraction.geck_addresses),
                    "call_target_count": len(calls),
                    "data_address_count": len(data_observations),
                    "diagnostic_count": len(diagnostics),
                    "prototype_join_count": len(prototype_joins),
                    "call_target_join_count": len(call_joins),
                    "data_join_count": len(data_joins),
                    "definitive_game_link_count": len(definitive_links),
                    "unspecified_entry_candidate_count": len(candidate_links),
                    "boundary_candidate_count": len(boundary_candidates),
                    "boundary_container_count": boundary_container_count,
                    "provenance_id": provenance_id,
                    "details_json": details_json,
                },),
            )

            self._bulk_insert_immutable(
                "sdk_prototype_observations",
                "prototype_observation_id",
                (
                    {
                        "prototype_observation_id": prototype_db_ids[
                            item.observation_id
                        ],
                        "source_tree_sha256": source_tree_sha256,
                        "source_observation_id": item.observation_id,
                        "source_file_id": source_file_ids[item.source_path],
                        "program_variant": item.program_variant,
                        "address": item.address,
                        "declared_name": item.declared_name,
                        "signature": item.signature,
                        "evidence_kind": item.evidence_kind,
                        "source_path": item.source_path,
                        "source_file_sha256": item.source_file_sha256,
                        "address_line": item.address_line,
                        "declaration_line": item.declaration_line,
                        "source_text": item.source_text,
                        "address_ordinal": item.address_ordinal,
                        "declaration_text": item.declaration_text,
                    }
                    for item in prototypes
                ),
            )
            self._bulk_insert_immutable(
                "sdk_call_target_observations",
                "call_target_observation_id",
                (
                    {
                        "call_target_observation_id": call_db_ids[item.observation_id],
                        "source_tree_sha256": source_tree_sha256,
                        "source_observation_id": item.observation_id,
                        "source_file_id": source_file_ids[item.source_path],
                        "program_variant": item.program_variant,
                        "address": item.address,
                        "invocation_kind": item.invocation_kind,
                        "helper_name": item.helper_name,
                        "calling_convention": item.calling_convention,
                        "rendered_return_type": item.rendered_return_type,
                        "parameter_types_known": int(item.parameter_types is not None),
                        "rendered_target_type": item.rendered_target_type,
                        "enclosing_declared_name": item.enclosing_declared_name,
                        "enclosing_owner_hint": item.enclosing_owner_hint,
                        "enclosing_signature": item.enclosing_signature,
                        "declaration_text": item.declaration_text,
                        "source_path": item.source_path,
                        "source_file_sha256": item.source_file_sha256,
                        "call_line": item.call_line,
                        "declaration_line": item.declaration_line,
                        "source_text": item.source_text,
                        "address_ordinal": item.address_ordinal,
                    }
                    for item in calls
                ),
            )
            self._bulk_insert_immutable(
                "sdk_call_parameter_types",
                "parameter_type_id",
                (
                    {
                        "parameter_type_id": stable_id(
                            "sdk-call-parameter-type",
                            call_db_ids[item.observation_id],
                            ordinal,
                        ),
                        "call_target_observation_id": call_db_ids[
                            item.observation_id
                        ],
                        "ordinal": ordinal,
                        "rendered_type": rendered_type,
                    }
                    for item in calls
                    for ordinal, rendered_type in enumerate(item.parameter_types or ())
                ),
            )
            self._bulk_insert_immutable(
                "sdk_call_argument_expressions",
                "argument_expression_id",
                (
                    {
                        "argument_expression_id": stable_id(
                            "sdk-call-argument-expression",
                            call_db_ids[item.observation_id],
                            ordinal,
                        ),
                        "call_target_observation_id": call_db_ids[
                            item.observation_id
                        ],
                        "ordinal": ordinal,
                        "expression": expression,
                    }
                    for item in calls
                    for ordinal, expression in enumerate(item.argument_expressions)
                ),
            )
            self._bulk_insert_immutable(
                "sdk_data_observations",
                "data_observation_id",
                (
                    {
                        "data_observation_id": data_db_ids[item.observation_id],
                        "source_tree_sha256": source_tree_sha256,
                        "source_observation_id": item.observation_id,
                        "source_file_id": source_file_ids[item.source_path],
                        "program_variant": item.program_variant,
                        "address": item.address,
                        "data_kind": item.data_kind,
                        "declared_name": item.declared_name,
                        "member_name": item.member_name,
                        "declared_type": item.declared_type,
                        "owner_name": item.owner_name,
                        "owner_basis": item.owner_basis,
                        "declaration_text": item.declaration_text,
                        "source_path": item.source_path,
                        "source_file_sha256": item.source_file_sha256,
                        "declaration_line": item.declaration_line,
                    }
                    for item in data_observations
                ),
            )

            self._bulk_insert_immutable(
                "sdk_prototype_extraction_assertions",
                "assertion_id",
                (
                    {
                        "assertion_id": stable_id(
                            "sdk-prototype-extraction-assertion",
                            extraction_id,
                            prototype_db_ids[item.observation_id],
                        ),
                        "extraction_id": extraction_id,
                        "source_tree_sha256": source_tree_sha256,
                        "prototype_observation_id": prototype_db_ids[
                            item.observation_id
                        ],
                        "source_ordinal": ordinal,
                    }
                    for ordinal, item in enumerate(prototypes)
                ),
            )
            self._bulk_insert_immutable(
                "sdk_call_target_extraction_assertions",
                "assertion_id",
                (
                    {
                        "assertion_id": stable_id(
                            "sdk-call-target-extraction-assertion",
                            extraction_id,
                            call_db_ids[item.observation_id],
                        ),
                        "extraction_id": extraction_id,
                        "source_tree_sha256": source_tree_sha256,
                        "call_target_observation_id": call_db_ids[
                            item.observation_id
                        ],
                        "source_ordinal": ordinal,
                    }
                    for ordinal, item in enumerate(calls)
                ),
            )
            self._bulk_insert_immutable(
                "sdk_data_extraction_assertions",
                "assertion_id",
                (
                    {
                        "assertion_id": stable_id(
                            "sdk-data-extraction-assertion",
                            extraction_id,
                            data_db_ids[item.observation_id],
                        ),
                        "extraction_id": extraction_id,
                        "source_tree_sha256": source_tree_sha256,
                        "data_observation_id": data_db_ids[item.observation_id],
                        "source_ordinal": ordinal,
                    }
                    for ordinal, item in enumerate(data_observations)
                ),
            )
            self._bulk_insert_immutable(
                "sdk_diagnostics",
                "diagnostic_id",
                (
                    {
                        "diagnostic_id": stable_id(
                            "sdk-diagnostic",
                            extraction_id,
                            ordinal,
                            item.code,
                            item.source_path,
                            item.line,
                            item.message,
                        ),
                        "extraction_id": extraction_id,
                        "source_tree_sha256": source_tree_sha256,
                        "source_file_id": source_file_ids[item.source_path],
                        "source_path": item.source_path,
                        "source_file_sha256": manifest_by_path[
                            item.source_path
                        ].sha256,
                        "source_ordinal": ordinal,
                        "code": item.code,
                        "line": item.line,
                        "message": item.message,
                    }
                    for ordinal, item in enumerate(diagnostics)
                ),
            )

            def code_join_rows() -> Iterator[dict[str, Any]]:
                for ordinal, (item, joined) in enumerate(
                    zip(prototypes, prototype_joins)
                ):
                    yield {
                        "code_join_id": prototype_join_ids[ordinal],
                        "extraction_id": extraction_id,
                        "source_tree_sha256": source_tree_sha256,
                        "observation_kind": "prototype",
                        "prototype_observation_id": prototype_db_ids[
                            item.observation_id
                        ],
                        "call_target_observation_id": None,
                        "source_ordinal": ordinal,
                        "program_variant": joined.program_variant,
                        "address": joined.address,
                        "classification": joined.classification,
                        "section_name": joined.section_name,
                        "section_executable": (
                            int(joined.section_executable)
                            if joined.section_executable is not None
                            else None
                        ),
                    }
                for ordinal, (item, joined) in enumerate(zip(calls, call_joins)):
                    yield {
                        "code_join_id": call_join_ids[ordinal],
                        "extraction_id": extraction_id,
                        "source_tree_sha256": source_tree_sha256,
                        "observation_kind": "call_target",
                        "prototype_observation_id": None,
                        "call_target_observation_id": call_db_ids[
                            item.observation_id
                        ],
                        "source_ordinal": ordinal,
                        "program_variant": joined.program_variant,
                        "address": joined.address,
                        "classification": joined.classification,
                        "section_name": joined.section_name,
                        "section_executable": (
                            int(joined.section_executable)
                            if joined.section_executable is not None
                            else None
                        ),
                    }

            self._bulk_insert_immutable(
                "sdk_code_inventory_joins", "code_join_id", code_join_rows()
            )

            definitive_by_key = dict(definitive_links)
            candidate_by_key = dict(candidate_links)
            self._bulk_insert_immutable(
                "sdk_game_exact_entry_links",
                "code_join_id",
                (
                    {
                        "code_join_id": (
                            prototype_join_ids[ordinal]
                            if kind == "prototype"
                            else call_join_ids[ordinal]
                        ),
                        "function_id": function_id,
                    }
                    for key, function_id in sorted(definitive_by_key.items())
                    for kind, ordinal_text in (key.split(":"),)
                    for ordinal in (int(ordinal_text),)
                ),
            )
            self._bulk_insert_immutable(
                "sdk_unspecified_exact_entry_candidates",
                "code_join_id",
                (
                    {
                        "code_join_id": (
                            prototype_join_ids[ordinal]
                            if kind == "prototype"
                            else call_join_ids[ordinal]
                        ),
                        "candidate_function_id": function_id,
                    }
                    for key, function_id in sorted(candidate_by_key.items())
                    for kind, ordinal_text in (key.split(":"),)
                    for ordinal in (int(ordinal_text),)
                ),
            )
            self._bulk_insert_immutable(
                "sdk_data_inventory_joins",
                "data_join_id",
                (
                    {
                        "data_join_id": stable_id(
                            "sdk-data-inventory-join",
                            extraction_id,
                            ordinal,
                            item.observation_id,
                        ),
                        "extraction_id": extraction_id,
                        "source_tree_sha256": source_tree_sha256,
                        "data_observation_id": data_db_ids[item.observation_id],
                        "source_ordinal": ordinal,
                        "program_variant": joined.program_variant,
                        "address": joined.address,
                        "data_kind": joined.data_kind,
                        "classification": joined.classification,
                        "section_name": joined.section_name,
                        "section_executable": (
                            int(joined.section_executable)
                            if joined.section_executable is not None
                            else None
                        ),
                    }
                    for ordinal, (item, joined) in enumerate(
                        zip(data_observations, data_joins)
                    )
                ),
            )
            self._bulk_insert_immutable(
                "sdk_boundary_candidates",
                "boundary_candidate_id",
                (
                    {
                        "boundary_candidate_id": boundary_db_ids[
                            candidate.candidate_id
                        ],
                        "source_candidate_id": candidate.candidate_id,
                        "extraction_id": extraction_id,
                        "source_tree_sha256": source_tree_sha256,
                        "code_join_id": prototype_join_ids[
                            prototype_ordinal_by_source_id[
                                candidate.source_observation.observation_id
                            ]
                        ],
                        "prototype_observation_id": prototype_db_ids[
                            candidate.source_observation.observation_id
                        ],
                        "source_ordinal": ordinal,
                        "address": candidate.source_observation.address,
                        "inventory_classification": (
                            candidate.inventory_classification
                        ),
                        "candidate_reason": candidate.candidate_reason,
                        "containing_entry_count": len(
                            candidate.containing_function_entries
                        ),
                    }
                    for ordinal, candidate in enumerate(boundary_candidates)
                ),
            )
            self._bulk_insert_immutable(
                "sdk_boundary_candidate_containers",
                "container_id",
                (
                    {
                        "container_id": stable_id(
                            "sdk-boundary-container",
                            boundary_db_ids[candidate.candidate_id],
                            ordinal,
                            entry,
                        ),
                        "boundary_candidate_id": boundary_db_ids[
                            candidate.candidate_id
                        ],
                        "source_ordinal": ordinal,
                        "entry_address": entry,
                        "address_group_id": pc_entry_groups[entry],
                    }
                    for candidate in boundary_candidates
                    for ordinal, entry in enumerate(
                        candidate.containing_function_entries
                    )
                ),
            )
            self.validate_sdk_extraction(extraction_id)
        return result

    def validate_sdk_extraction(self, extraction_id: str) -> bool:
        """Validate SDK corpus counts, variant links, and PC endpoint domains."""

        extraction = self.connection.execute(
            "SELECT * FROM sdk_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if extraction is None:
            raise AtlasError(f"unknown SDK extraction {extraction_id!r}")
        counts = self.connection.execute(
            """
            SELECT
                (SELECT COUNT(*)
                 FROM sdk_source_tree_files file
                 WHERE file.source_tree_sha256 = extraction.source_tree_sha256)
                    AS source_files,
                (SELECT COUNT(*) FROM sdk_prototype_extraction_assertions
                 WHERE extraction_id = extraction.extraction_id) AS prototypes,
                (SELECT COUNT(DISTINCT observation.address)
                 FROM sdk_prototype_extraction_assertions membership
                 JOIN sdk_prototype_observations observation
                   USING (prototype_observation_id, source_tree_sha256)
                 WHERE membership.extraction_id = extraction.extraction_id)
                    AS unique_prototype_addresses,
                (SELECT COUNT(DISTINCT observation.address)
                 FROM sdk_prototype_extraction_assertions membership
                 JOIN sdk_prototype_observations observation
                   USING (prototype_observation_id, source_tree_sha256)
                 WHERE membership.extraction_id = extraction.extraction_id
                   AND observation.program_variant = 'game')
                    AS game_prototype_addresses,
                (SELECT COUNT(DISTINCT observation.address)
                 FROM sdk_prototype_extraction_assertions membership
                 JOIN sdk_prototype_observations observation
                   USING (prototype_observation_id, source_tree_sha256)
                 WHERE membership.extraction_id = extraction.extraction_id
                   AND observation.program_variant = 'geck')
                    AS geck_prototype_addresses,
                (SELECT COUNT(*) FROM sdk_call_target_extraction_assertions
                 WHERE extraction_id = extraction.extraction_id) AS call_targets,
                (SELECT COUNT(*) FROM sdk_data_extraction_assertions
                 WHERE extraction_id = extraction.extraction_id) AS data_addresses,
                (SELECT COUNT(*) FROM sdk_diagnostics
                 WHERE extraction_id = extraction.extraction_id) AS diagnostics,
                (SELECT COUNT(*) FROM sdk_code_inventory_joins
                 WHERE extraction_id = extraction.extraction_id
                   AND observation_kind = 'prototype') AS prototype_joins,
                (SELECT COUNT(*) FROM sdk_code_inventory_joins
                 WHERE extraction_id = extraction.extraction_id
                   AND observation_kind = 'call_target') AS call_target_joins,
                (SELECT COUNT(*) FROM sdk_data_inventory_joins
                 WHERE extraction_id = extraction.extraction_id) AS data_joins,
                (SELECT COUNT(*)
                 FROM sdk_game_exact_entry_links link
                 JOIN sdk_code_inventory_joins joined USING (code_join_id)
                 WHERE joined.extraction_id = extraction.extraction_id)
                    AS definitive_links,
                (SELECT COUNT(*)
                 FROM sdk_unspecified_exact_entry_candidates candidate
                 JOIN sdk_code_inventory_joins joined USING (code_join_id)
                 WHERE joined.extraction_id = extraction.extraction_id)
                    AS unspecified_candidates,
                (SELECT COUNT(*) FROM sdk_boundary_candidates
                 WHERE extraction_id = extraction.extraction_id)
                    AS boundary_candidates,
                (SELECT COUNT(*)
                 FROM sdk_boundary_candidate_containers container
                 JOIN sdk_boundary_candidates candidate
                   USING (boundary_candidate_id)
                 WHERE candidate.extraction_id = extraction.extraction_id)
                    AS boundary_containers,
                (
                    EXISTS (
                        SELECT 1 FROM sdk_source_trees tree
                        WHERE tree.source_tree_sha256 = extraction.source_tree_sha256
                          AND (
                              tree.file_count <> extraction.files_scanned OR
                              tree.file_count <> (
                                  SELECT COUNT(*) FROM sdk_source_tree_files file
                                  WHERE file.source_tree_sha256 = tree.source_tree_sha256
                              ) OR tree.total_byte_count <> (
                                  SELECT COALESCE(SUM(file.byte_length), 0)
                                  FROM sdk_source_tree_files file
                                  WHERE file.source_tree_sha256 = tree.source_tree_sha256
                              )
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM sdk_call_target_observations observation
                        WHERE observation.source_tree_sha256 = extraction.source_tree_sha256
                          AND observation.parameter_types_known = 0
                          AND EXISTS (
                              SELECT 1 FROM sdk_call_parameter_types parameter
                              WHERE parameter.call_target_observation_id =
                                    observation.call_target_observation_id
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM sdk_call_target_extraction_assertions membership
                        JOIN sdk_call_target_observations observation
                          USING (call_target_observation_id, source_tree_sha256)
                        WHERE membership.extraction_id = extraction.extraction_id
                          AND (
                              EXISTS (
                                  SELECT COUNT(*)
                                  FROM sdk_call_parameter_types parameter
                                  WHERE parameter.call_target_observation_id =
                                        observation.call_target_observation_id
                                  HAVING COUNT(*) > 0 AND (
                                      MIN(parameter.ordinal) <> 0 OR
                                      MAX(parameter.ordinal) + 1 <> COUNT(*)
                                  )
                              ) OR EXISTS (
                                  SELECT COUNT(*)
                                  FROM sdk_call_argument_expressions argument
                                  WHERE argument.call_target_observation_id =
                                        observation.call_target_observation_id
                                  HAVING COUNT(*) > 0 AND (
                                      MIN(argument.ordinal) <> 0 OR
                                      MAX(argument.ordinal) + 1 <> COUNT(*)
                                  )
                              )
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM sdk_code_inventory_joins joined
                        LEFT JOIN sdk_game_exact_entry_links definitive
                          USING (code_join_id)
                        LEFT JOIN sdk_unspecified_exact_entry_candidates candidate
                          USING (code_join_id)
                        WHERE joined.extraction_id = extraction.extraction_id
                          AND (
                              (joined.program_variant = 'geck' AND
                               (joined.classification <> 'non_game_variant' OR
                                definitive.code_join_id IS NOT NULL OR
                                candidate.code_join_id IS NOT NULL)) OR
                              (joined.program_variant = 'game' AND
                               (joined.classification NOT IN (
                                    'pc_function_entry',
                                    'pc_executable_non_entry',
                                    'pc_non_executable_section',
                                    'outside_pc_image_sections'
                                ) OR
                                (joined.classification = 'pc_function_entry') <>
                                (definitive.code_join_id IS NOT NULL) OR
                                candidate.code_join_id IS NOT NULL)) OR
                              (joined.program_variant = 'unspecified_pc' AND
                               (joined.classification NOT IN (
                                    'pc_function_entry_variant_unspecified',
                                    'pc_executable_non_entry_variant_unspecified',
                                    'pc_non_executable_section_variant_unspecified',
                                    'outside_pc_image_sections_variant_unspecified'
                                ) OR
                                (joined.classification =
                                 'pc_function_entry_variant_unspecified') <>
                                (candidate.code_join_id IS NOT NULL) OR
                                definitive.code_join_id IS NOT NULL))
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM sdk_data_inventory_joins joined
                        WHERE joined.extraction_id = extraction.extraction_id
                          AND (
                              (joined.program_variant = 'geck' AND
                               joined.classification <> 'non_game_variant') OR
                              (joined.program_variant = 'game' AND
                               joined.classification NOT IN (
                                   'pc_executable_section',
                                   'pc_data_section',
                                   'outside_pc_image_sections'
                               )) OR
                              (joined.program_variant = 'unspecified_pc' AND
                               joined.classification NOT IN (
                                   'pc_executable_section_variant_unspecified',
                                   'pc_data_section_variant_unspecified',
                                   'outside_pc_image_sections_variant_unspecified'
                               ))
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM sdk_game_exact_entry_links link
                        JOIN sdk_code_inventory_joins joined USING (code_join_id)
                        JOIN functions function ON function.function_id = link.function_id
                        JOIN address_groups address
                          ON address.address_group_id = function.address_group_id
                         AND address.program_id = function.program_id
                        JOIN programs program ON program.program_id = function.program_id
                        WHERE joined.extraction_id = extraction.extraction_id
                          AND (
                              function.program_id <> extraction.pc_program_id OR
                              address.address_space <> extraction.pc_address_space OR
                              address.address <> joined.address OR
                              program.platform <> 'pc'
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM sdk_unspecified_exact_entry_candidates link
                        JOIN sdk_code_inventory_joins joined USING (code_join_id)
                        JOIN functions function
                          ON function.function_id = link.candidate_function_id
                        JOIN address_groups address
                          ON address.address_group_id = function.address_group_id
                         AND address.program_id = function.program_id
                        JOIN programs program ON program.program_id = function.program_id
                        WHERE joined.extraction_id = extraction.extraction_id
                          AND (
                              function.program_id <> extraction.pc_program_id OR
                              address.address_space <> extraction.pc_address_space OR
                              address.address <> joined.address OR
                              program.platform <> 'pc'
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM sdk_boundary_candidates candidate
                        WHERE candidate.extraction_id = extraction.extraction_id
                          AND candidate.containing_entry_count <> (
                              SELECT COUNT(*)
                              FROM sdk_boundary_candidate_containers container
                              WHERE container.boundary_candidate_id =
                                    candidate.boundary_candidate_id
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM sdk_prototype_extraction_assertions membership
                        JOIN sdk_prototype_observations observation
                          USING (prototype_observation_id, source_tree_sha256)
                        JOIN sdk_code_inventory_joins joined
                          ON joined.extraction_id = membership.extraction_id
                         AND joined.observation_kind = 'prototype'
                         AND joined.prototype_observation_id =
                             membership.prototype_observation_id
                        WHERE membership.extraction_id = extraction.extraction_id
                          AND observation.evidence_kind = 'create_object_macro'
                          AND joined.classification IN (
                              'pc_executable_non_entry',
                              'pc_executable_non_entry_variant_unspecified'
                          )
                          AND NOT EXISTS (
                              SELECT 1 FROM sdk_boundary_candidates candidate
                              WHERE candidate.extraction_id = membership.extraction_id
                                AND candidate.prototype_observation_id =
                                    membership.prototype_observation_id
                          )
                    ) OR EXISTS (
                        SELECT 1
                        FROM sdk_boundary_candidate_containers container
                        JOIN sdk_boundary_candidates candidate
                          USING (boundary_candidate_id)
                        JOIN address_groups address
                          ON address.address_group_id = container.address_group_id
                        JOIN programs program ON program.program_id = address.program_id
                        WHERE candidate.extraction_id = extraction.extraction_id
                          AND (
                              address.program_id <> extraction.pc_program_id OR
                              address.address_space <> extraction.pc_address_space OR
                              address.address <> container.entry_address OR
                              program.platform <> 'pc' OR
                              NOT EXISTS (
                                  SELECT 1 FROM functions function
                                  WHERE function.program_id = extraction.pc_program_id
                                    AND function.address_group_id =
                                        container.address_group_id
                              )
                          )
                    ) OR EXISTS (
                        SELECT 1 FROM programs program
                        WHERE program.program_id = extraction.pc_program_id
                          AND program.platform <> 'pc'
                    )
                ) AS invalid_structure
            FROM sdk_extractions extraction
            WHERE extraction.extraction_id = ?
            """,
            (extraction_id,),
        ).fetchone()
        expected = {
            "source_files": extraction["files_scanned"],
            "prototypes": extraction["prototype_count"],
            "unique_prototype_addresses": extraction[
                "unique_prototype_address_count"
            ],
            "game_prototype_addresses": extraction[
                "game_prototype_address_count"
            ],
            "geck_prototype_addresses": extraction[
                "geck_prototype_address_count"
            ],
            "call_targets": extraction["call_target_count"],
            "data_addresses": extraction["data_address_count"],
            "diagnostics": extraction["diagnostic_count"],
            "prototype_joins": extraction["prototype_join_count"],
            "call_target_joins": extraction["call_target_join_count"],
            "data_joins": extraction["data_join_count"],
            "definitive_links": extraction["definitive_game_link_count"],
            "unspecified_candidates": extraction[
                "unspecified_entry_candidate_count"
            ],
            "boundary_candidates": extraction["boundary_candidate_count"],
            "boundary_containers": extraction["boundary_container_count"],
        }
        mismatches = [
            name for name, expected_value in expected.items()
            if counts[name] != expected_value
        ]
        if counts["invalid_structure"]:
            mismatches.append("invalid_structure")
        if mismatches:
            raise AtlasError(
                f"SDK extraction {extraction_id!r} validation mismatch: "
                + ", ".join(mismatches)
            )
        return True

    def get_sdk_extraction(self, extraction_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM sdk_extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _decode_json(result.pop("details_json"))
        result["source_files"] = [
            dict(item)
            for item in self.connection.execute(
                """
                SELECT relative_path, source_file_sha256 AS sha256, byte_length
                FROM sdk_source_tree_files
                WHERE source_tree_sha256 = ? ORDER BY relative_path_casefold
                """,
                (row["source_tree_sha256"],),
            )
        ]
        return result

    def iter_sdk_prototype_observations(
        self,
        *,
        extraction_id: str | None = None,
        program_variant: str | None = None,
        address: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if extraction_id is not None:
            clauses.append("membership.extraction_id = ?")
            parameters.append(extraction_id)
        if program_variant is not None:
            clauses.append("observation.program_variant = ?")
            parameters.append(program_variant)
        if address is not None:
            clauses.append("observation.address = ?")
            parameters.append(address)
        sql = """
            SELECT membership.assertion_id, membership.extraction_id,
                   membership.source_ordinal, observation.*
            FROM sdk_prototype_extraction_assertions membership
            JOIN sdk_prototype_observations observation
              USING (prototype_observation_id, source_tree_sha256)
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY membership.extraction_id, membership.source_ordinal"
        for row in self.connection.execute(sql, parameters):
            yield dict(row)

    def iter_sdk_call_target_observations(
        self,
        *,
        extraction_id: str | None = None,
        program_variant: str | None = None,
        address: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if extraction_id is not None:
            clauses.append("membership.extraction_id = ?")
            parameters.append(extraction_id)
        if program_variant is not None:
            clauses.append("observation.program_variant = ?")
            parameters.append(program_variant)
        if address is not None:
            clauses.append("observation.address = ?")
            parameters.append(address)
        sql = """
            SELECT membership.assertion_id, membership.extraction_id,
                   membership.source_ordinal, observation.*
            FROM sdk_call_target_extraction_assertions membership
            JOIN sdk_call_target_observations observation
              USING (call_target_observation_id, source_tree_sha256)
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY membership.extraction_id, membership.source_ordinal"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            known = bool(result.pop("parameter_types_known"))
            parameter_types = [
                item["rendered_type"]
                for item in self.connection.execute(
                    """
                    SELECT rendered_type FROM sdk_call_parameter_types
                    WHERE call_target_observation_id = ? ORDER BY ordinal
                    """,
                    (row["call_target_observation_id"],),
                )
            ]
            result["parameter_types"] = parameter_types if known else None
            result["argument_expressions"] = [
                item["expression"]
                for item in self.connection.execute(
                    """
                    SELECT expression FROM sdk_call_argument_expressions
                    WHERE call_target_observation_id = ? ORDER BY ordinal
                    """,
                    (row["call_target_observation_id"],),
                )
            ]
            yield result

    def iter_sdk_data_observations(
        self,
        *,
        extraction_id: str | None = None,
        program_variant: str | None = None,
        address: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if extraction_id is not None:
            clauses.append("membership.extraction_id = ?")
            parameters.append(extraction_id)
        if program_variant is not None:
            clauses.append("observation.program_variant = ?")
            parameters.append(program_variant)
        if address is not None:
            clauses.append("observation.address = ?")
            parameters.append(address)
        sql = """
            SELECT membership.assertion_id, membership.extraction_id,
                   membership.source_ordinal, observation.*
            FROM sdk_data_extraction_assertions membership
            JOIN sdk_data_observations observation
              USING (data_observation_id, source_tree_sha256)
        """
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY membership.extraction_id, membership.source_ordinal"
        for row in self.connection.execute(sql, parameters):
            yield dict(row)

    def iter_sdk_code_inventory_joins(
        self,
        extraction_id: str,
        *,
        observation_kind: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        sql = """
            SELECT joined.*, definitive.function_id AS definitive_pc_function_id,
                   candidate.candidate_function_id
            FROM sdk_code_inventory_joins joined
            LEFT JOIN sdk_game_exact_entry_links definitive USING (code_join_id)
            LEFT JOIN sdk_unspecified_exact_entry_candidates candidate
              USING (code_join_id)
            WHERE joined.extraction_id = ?
        """
        parameters: list[Any] = [extraction_id]
        if observation_kind is not None:
            sql += " AND joined.observation_kind = ?"
            parameters.append(observation_kind)
        sql += " ORDER BY joined.observation_kind, joined.source_ordinal"
        for row in self.connection.execute(sql, parameters):
            result = dict(row)
            if result["section_executable"] is not None:
                result["section_executable"] = bool(result["section_executable"])
            yield result

    def iter_sdk_data_inventory_joins(
        self, extraction_id: str
    ) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            """
            SELECT * FROM sdk_data_inventory_joins
            WHERE extraction_id = ? ORDER BY source_ordinal
            """,
            (extraction_id,),
        ):
            result = dict(row)
            if result["section_executable"] is not None:
                result["section_executable"] = bool(result["section_executable"])
            yield result

    def iter_sdk_boundary_candidates(
        self, extraction_id: str
    ) -> Iterator[dict[str, Any]]:
        for row in self.connection.execute(
            """
            SELECT * FROM sdk_boundary_candidates
            WHERE extraction_id = ? ORDER BY source_ordinal
            """,
            (extraction_id,),
        ):
            result = dict(row)
            result["containing_entries"] = [
                dict(container)
                for container in self.connection.execute(
                    """
                    SELECT source_ordinal, entry_address, address_group_id
                    FROM sdk_boundary_candidate_containers
                    WHERE boundary_candidate_id = ? ORDER BY source_ordinal
                    """,
                    (row["boundary_candidate_id"],),
                )
            ]
            yield result

    def iter_sdk_diagnostics(
        self, extraction_id: str, *, code: str | None = None
    ) -> Iterator[dict[str, Any]]:
        sql = "SELECT * FROM sdk_diagnostics WHERE extraction_id = ?"
        parameters: list[Any] = [extraction_id]
        if code is not None:
            sql += " AND code = ?"
            parameters.append(code)
        sql += " ORDER BY source_ordinal"
        for row in self.connection.execute(sql, parameters):
            yield dict(row)
