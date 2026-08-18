"""SQLite schema for the lossless Fallout: New Vegas source atlas.

The schema deliberately separates logical functions from code addresses.  More
than one logical function may occupy an address (for example after identical
COMDAT folding), and every function may have more than one name.  Match claims,
sets of alternative claims/fold bundles, and the observations supporting them
are separate records: the database does not convert a number of channels into
confidence.  Producer assertions and human review decisions are append-only
facts; the older canonical tables remain convenient materialized projections
and never replace assertion or adjudication history.  Human review state is
derived per reviewer and never silently promoted to a global consensus.
Xbox control-flow persistence likewise separates physical instruction sites
from logical PDB procedure membership and keeps producer decode assertions
append-only; folded targets remain one address/fold bundle rather than fan-out.
Global CodeView types and typed data symbols follow the same rule: raw physical
identity is canonical, decoded producer assertions are append-only, and raw
type references never require a fabricated resolution row.  Evidence that
supports one hypothesis alternative is stored on that alternative, not its
whole disjunction.  Raw Xbox vftable symbols/pointer runs and portable SDK
source observations are also evidence corpora: their physical/source identity
is immutable, producer membership is append-only, and inventory joins never
promote an observation into a canonical function, name, vtable, or match.
"""

from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import sqlite3


SCHEMA_VERSION = 8
APPLICATION_ID = 0x464E5641  # "FNVA"


class SchemaError(RuntimeError):
    """Raised when a database is not a compatible source-atlas database."""


_JSON_OBJECT = "CHECK (json_valid(details_json) AND json_type(details_json) = 'object')"


SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE atlas_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE programs (
        program_id TEXT PRIMARY KEY,
        platform TEXT NOT NULL CHECK (platform IN ('pc', 'xbox360')),
        name TEXT NOT NULL CHECK (length(name) > 0),
        architecture TEXT,
        image_base INTEGER CHECK (image_base IS NULL OR image_base >= 0),
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (program_id, platform)
    )
    """,
    """
    CREATE TABLE input_artifacts (
        content_id TEXT PRIMARY KEY,
        hash_algorithm TEXT NOT NULL DEFAULT 'sha256'
            CHECK (hash_algorithm = 'sha256'),
        digest TEXT NOT NULL UNIQUE
            CHECK (length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'),
        size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
        media_type TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        CHECK (content_id = 'sha256:' || digest)
    )
    """,
    """
    CREATE TABLE input_manifests (
        manifest_id TEXT PRIMARY KEY,
        hash_algorithm TEXT NOT NULL DEFAULT 'sha256'
            CHECK (hash_algorithm = 'sha256'),
        digest TEXT NOT NULL UNIQUE
            CHECK (length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'),
        canonical_json TEXT NOT NULL
            CHECK (json_valid(canonical_json) AND json_type(canonical_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        CHECK (manifest_id = 'sha256:' || digest)
    )
    """,
    """
    CREATE TABLE manifest_entries (
        manifest_id TEXT NOT NULL REFERENCES input_manifests(manifest_id)
            ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        content_id TEXT NOT NULL REFERENCES input_artifacts(content_id)
            ON DELETE RESTRICT,
        role TEXT NOT NULL CHECK (length(role) > 0),
        logical_name TEXT NOT NULL CHECK (length(logical_name) > 0),
        metadata_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(metadata_json) AND json_type(metadata_json) = 'object'),
        PRIMARY KEY (manifest_id, ordinal),
        UNIQUE (manifest_id, role, logical_name)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE provenance (
        provenance_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (length(kind) > 0),
        producer TEXT NOT NULL CHECK (length(producer) > 0),
        producer_version TEXT,
        method TEXT,
        manifest_id TEXT REFERENCES input_manifests(manifest_id)
            ON DELETE RESTRICT,
        parameters_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(parameters_json) AND json_type(parameters_json) = 'object'),
        notes TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE TABLE modules (
        module_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        name TEXT NOT NULL CHECK (length(name) > 0),
        object_path TEXT,
        compiland_index INTEGER CHECK (compiland_index IS NULL OR compiland_index >= 0),
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        UNIQUE (module_id, program_id),
        UNIQUE (program_id, name, compiland_index)
    )
    """,
    """
    CREATE TABLE source_files (
        source_file_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        normalized_path TEXT NOT NULL CHECK (length(normalized_path) > 0),
        checksum_kind TEXT,
        checksum TEXT,
        language TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        UNIQUE (source_file_id, program_id),
        UNIQUE (program_id, normalized_path)
    )
    """,
    """
    CREATE TABLE address_groups (
        address_group_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        address_space TEXT NOT NULL CHECK (length(address_space) > 0),
        address INTEGER NOT NULL CHECK (address >= 0),
        kind TEXT NOT NULL DEFAULT 'code' CHECK (length(kind) > 0),
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        UNIQUE (address_group_id, program_id),
        UNIQUE (program_id, address_space, address)
    )
    """,
    """
    CREATE TABLE functions (
        function_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        address_group_id TEXT NOT NULL,
        identity_key TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'function' CHECK (length(kind) > 0),
        type_index INTEGER CHECK (type_index IS NULL OR type_index >= 0),
        module_id TEXT,
        symbol_record_kind TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id) ON DELETE CASCADE,
        FOREIGN KEY (module_id, program_id)
            REFERENCES modules(module_id, program_id) ON DELETE RESTRICT,
        UNIQUE (function_id, program_id),
        UNIQUE (address_group_id, identity_key)
    )
    """,
    """
    CREATE TABLE function_assertions (
        assertion_id TEXT PRIMARY KEY,
        function_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (length(kind) > 0),
        type_index INTEGER CHECK (type_index IS NULL OR type_index >= 0),
        module_id TEXT,
        symbol_record_kind TEXT,
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE CASCADE,
        FOREIGN KEY (module_id, program_id)
            REFERENCES modules(module_id, program_id) ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE function_names (
        name_id INTEGER PRIMARY KEY,
        function_id TEXT NOT NULL REFERENCES functions(function_id) ON DELETE CASCADE,
        name TEXT NOT NULL CHECK (length(name) > 0),
        name_kind TEXT NOT NULL CHECK (length(name_kind) > 0),
        is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
        provenance_id TEXT REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        UNIQUE (function_id, name_kind, name)
    )
    """,
    """
    CREATE TABLE function_name_assertions (
        assertion_id TEXT PRIMARY KEY,
        name_id INTEGER NOT NULL REFERENCES function_names(name_id) ON DELETE CASCADE,
        is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE UNIQUE INDEX one_primary_function_name_per_kind
        ON function_names(function_id, name_kind) WHERE is_primary = 1
    """,
    """
    CREATE INDEX function_names_by_name ON function_names(name)
    """,
    """
    CREATE TABLE function_source_ranges (
        function_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        source_file_id TEXT NOT NULL,
        line_start INTEGER NOT NULL DEFAULT 0 CHECK (line_start >= 0),
        line_end INTEGER CHECK (line_end IS NULL OR line_end >= line_start),
        column_start INTEGER NOT NULL DEFAULT 0 CHECK (column_start >= 0),
        column_end INTEGER CHECK (column_end IS NULL OR column_end >= 0),
        is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
        provenance_id TEXT REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        FOREIGN KEY (function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE CASCADE,
        FOREIGN KEY (source_file_id, program_id)
            REFERENCES source_files(source_file_id, program_id) ON DELETE CASCADE,
        PRIMARY KEY (function_id, source_file_id, line_start, column_start)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE function_source_range_assertions (
        assertion_id TEXT PRIMARY KEY,
        function_id TEXT NOT NULL,
        source_file_id TEXT NOT NULL,
        line_start INTEGER NOT NULL DEFAULT 0 CHECK (line_start >= 0),
        column_start INTEGER NOT NULL DEFAULT 0 CHECK (column_start >= 0),
        line_end INTEGER CHECK (line_end IS NULL OR line_end >= line_start),
        column_end INTEGER CHECK (column_end IS NULL OR column_end >= 0),
        is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (function_id, source_file_id, line_start, column_start)
            REFERENCES function_source_ranges(
                function_id, source_file_id, line_start, column_start
            ) ON DELETE CASCADE
    )
    """,
    """
    CREATE UNIQUE INDEX one_primary_source_range
        ON function_source_ranges(function_id) WHERE is_primary = 1
    """,
    """
    CREATE TABLE function_signatures (
        function_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL,
        type_index INTEGER NOT NULL CHECK (type_index >= 0),
        resolution_status TEXT NOT NULL
            CHECK (resolution_status IN ('resolved', 'unresolved')),
        error_code TEXT,
        error_message TEXT,
        leaf_kind INTEGER CHECK (leaf_kind IS NULL OR (leaf_kind >= 0 AND leaf_kind <= 65535)),
        leaf_name TEXT,
        return_type_index INTEGER
            CHECK (return_type_index IS NULL OR return_type_index >= 0),
        class_type_index INTEGER
            CHECK (class_type_index IS NULL OR class_type_index >= 0),
        this_type_index INTEGER
            CHECK (this_type_index IS NULL OR this_type_index >= 0),
        calling_convention INTEGER
            CHECK (calling_convention IS NULL OR
                   (calling_convention >= 0 AND calling_convention <= 255)),
        calling_convention_name TEXT,
        attributes INTEGER
            CHECK (attributes IS NULL OR (attributes >= 0 AND attributes <= 255)),
        this_adjustment INTEGER,
        parameter_count INTEGER
            CHECK (parameter_count IS NULL OR parameter_count >= 0),
        argument_list_type_index INTEGER
            CHECK (argument_list_type_index IS NULL OR argument_list_type_index >= 0),
        argument_list_count INTEGER
            CHECK (argument_list_count IS NULL OR argument_list_count >= 0),
        is_variadic INTEGER CHECK (is_variadic IS NULL OR is_variadic IN (0, 1)),
        rendered_return_type TEXT,
        rendered_class_type TEXT,
        rendered_this_type TEXT,
        rendered_signature TEXT,
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE CASCADE,
        CHECK (
            (resolution_status = 'resolved' AND
             error_code IS NULL AND error_message IS NULL AND
             leaf_kind IN (4104, 4105) AND leaf_name IS NOT NULL AND
             return_type_index IS NOT NULL AND
             calling_convention IS NOT NULL AND calling_convention_name IS NOT NULL AND
             attributes IS NOT NULL AND parameter_count IS NOT NULL AND
             argument_list_type_index IS NOT NULL AND argument_list_count IS NOT NULL AND
             is_variadic IS NOT NULL AND rendered_return_type IS NOT NULL AND
             rendered_signature IS NOT NULL)
            OR
            (resolution_status = 'unresolved' AND error_code IS NOT NULL AND
             return_type_index IS NULL AND class_type_index IS NULL AND
             this_type_index IS NULL AND calling_convention IS NULL AND
             calling_convention_name IS NULL AND attributes IS NULL AND
             this_adjustment IS NULL AND parameter_count IS NULL AND
             argument_list_type_index IS NULL AND argument_list_count IS NULL AND
             is_variadic IS NULL AND rendered_return_type IS NULL AND
             rendered_class_type IS NULL AND rendered_this_type IS NULL AND
             rendered_signature IS NULL)
        ),
        CHECK (
            resolution_status <> 'resolved' OR
            (leaf_kind = 4104 AND class_type_index IS NULL AND
             this_type_index IS NULL AND this_adjustment IS NULL AND
             rendered_class_type IS NULL AND rendered_this_type IS NULL) OR
            (leaf_kind = 4105 AND class_type_index IS NOT NULL AND
             this_type_index IS NOT NULL AND this_adjustment IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE function_signature_arguments (
        function_id TEXT NOT NULL REFERENCES function_signatures(function_id)
            ON DELETE CASCADE,
        position INTEGER NOT NULL CHECK (position >= 0),
        type_index INTEGER NOT NULL CHECK (type_index >= 0),
        is_vararg_marker INTEGER NOT NULL DEFAULT 0
            CHECK (is_vararg_marker IN (0, 1)),
        rendered_type TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        PRIMARY KEY (function_id, position),
        CHECK (is_vararg_marker = 0 OR type_index = 0)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE fold_groups (
        fold_group_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        kind TEXT NOT NULL DEFAULT 'icf' CHECK (length(kind) > 0),
        provenance_id TEXT REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        UNIQUE (fold_group_id, program_id)
    )
    """,
    """
    CREATE TABLE fold_group_members (
        fold_group_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        function_id TEXT NOT NULL,
        member_role TEXT NOT NULL DEFAULT 'member' CHECK (length(member_role) > 0),
        FOREIGN KEY (fold_group_id, program_id)
            REFERENCES fold_groups(fold_group_id, program_id) ON DELETE CASCADE,
        FOREIGN KEY (function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE CASCADE,
        PRIMARY KEY (fold_group_id, function_id)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE classes (
        class_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        identity_key TEXT NOT NULL,
        type_index INTEGER CHECK (type_index IS NULL OR type_index >= 0),
        size_bytes INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
        module_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        FOREIGN KEY (module_id, program_id)
            REFERENCES modules(module_id, program_id) ON DELETE RESTRICT,
        UNIQUE (class_id, program_id),
        UNIQUE (program_id, identity_key)
    )
    """,
    """
    CREATE TABLE class_names (
        name_id INTEGER PRIMARY KEY,
        class_id TEXT NOT NULL REFERENCES classes(class_id) ON DELETE CASCADE,
        name TEXT NOT NULL CHECK (length(name) > 0),
        name_kind TEXT NOT NULL CHECK (length(name_kind) > 0),
        is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
        provenance_id TEXT REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        UNIQUE (class_id, name_kind, name)
    )
    """,
    """
    CREATE TABLE class_name_assertions (
        assertion_id TEXT PRIMARY KEY,
        name_id INTEGER NOT NULL REFERENCES class_names(name_id) ON DELETE CASCADE,
        is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE UNIQUE INDEX one_primary_class_name_per_kind
        ON class_names(class_id, name_kind) WHERE is_primary = 1
    """,
    """
    CREATE INDEX class_names_by_name ON class_names(name)
    """,
    """
    CREATE TABLE vtables (
        vtable_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        class_id TEXT NOT NULL,
        address_space TEXT NOT NULL CHECK (length(address_space) > 0),
        address INTEGER NOT NULL CHECK (address >= 0),
        vfptr_role TEXT NOT NULL CHECK (length(vfptr_role) > 0),
        subobject_offset INTEGER,
        table_index INTEGER CHECK (table_index IS NULL OR table_index >= 0),
        declared_slot_count INTEGER
            CHECK (declared_slot_count IS NULL OR declared_slot_count >= 0),
        provenance_id TEXT REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        FOREIGN KEY (class_id, program_id)
            REFERENCES classes(class_id, program_id) ON DELETE CASCADE,
        UNIQUE (vtable_id, program_id),
        UNIQUE (class_id, vfptr_role, address_space, address)
    )
    """,
    """
    CREATE TABLE unresolved_targets (
        target_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        address_group_id TEXT,
        target_kind TEXT NOT NULL CHECK (length(target_kind) > 0),
        name_hint TEXT,
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'open'
            CHECK (status IN ('open', 'resolved', 'invalid')),
        resolved_function_id TEXT,
        provenance_id TEXT REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id) ON DELETE CASCADE,
        FOREIGN KEY (resolved_function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE RESTRICT,
        UNIQUE (target_id, program_id),
        CHECK (address_group_id IS NOT NULL OR name_hint IS NOT NULL),
        CHECK ((status = 'resolved') = (resolved_function_id IS NOT NULL))
    )
    """,
    """
    CREATE TABLE vtable_slots (
        vtable_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        slot_index INTEGER NOT NULL CHECK (slot_index >= 0),
        target_address_group_id TEXT,
        unresolved_target_id TEXT,
        declared_type_index INTEGER
            CHECK (declared_type_index IS NULL OR declared_type_index >= 0),
        provenance_id TEXT REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        FOREIGN KEY (vtable_id, program_id)
            REFERENCES vtables(vtable_id, program_id) ON DELETE CASCADE,
        FOREIGN KEY (target_address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id) ON DELETE RESTRICT,
        FOREIGN KEY (unresolved_target_id, program_id)
            REFERENCES unresolved_targets(target_id, program_id) ON DELETE RESTRICT,
        PRIMARY KEY (vtable_id, slot_index),
        CHECK ((target_address_group_id IS NOT NULL) !=
               (unresolved_target_id IS NOT NULL))
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE vtable_slot_assertions (
        assertion_id TEXT PRIMARY KEY,
        vtable_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        slot_index INTEGER NOT NULL CHECK (slot_index >= 0),
        target_address_group_id TEXT,
        unresolved_target_id TEXT,
        declared_type_index INTEGER
            CHECK (declared_type_index IS NULL OR declared_type_index >= 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (vtable_id, slot_index)
            REFERENCES vtable_slots(vtable_id, slot_index) ON DELETE CASCADE,
        FOREIGN KEY (vtable_id, program_id)
            REFERENCES vtables(vtable_id, program_id) ON DELETE CASCADE,
        FOREIGN KEY (target_address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id) ON DELETE RESTRICT,
        FOREIGN KEY (unresolved_target_id, program_id)
            REFERENCES unresolved_targets(target_id, program_id) ON DELETE RESTRICT,
        CHECK ((target_address_group_id IS NOT NULL) !=
               (unresolved_target_id IS NOT NULL))
    )
    """,
    """
    CREATE TABLE match_claims (
        claim_id TEXT PRIMARY KEY,
        pc_function_id TEXT REFERENCES functions(function_id) ON DELETE RESTRICT,
        pc_target_id TEXT REFERENCES unresolved_targets(target_id) ON DELETE RESTRICT,
        xbox_function_id TEXT REFERENCES functions(function_id) ON DELETE RESTRICT,
        xbox_target_id TEXT REFERENCES unresolved_targets(target_id) ON DELETE RESTRICT,
        status TEXT NOT NULL DEFAULT 'candidate'
            CHECK (status IN ('candidate', 'accepted', 'rejected', 'conflicted', 'superseded')),
        confidence_label TEXT,
        confidence_value REAL
            CHECK (confidence_value IS NULL OR (confidence_value >= 0.0 AND confidence_value <= 1.0)),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        rationale TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        CHECK ((pc_function_id IS NOT NULL) != (pc_target_id IS NOT NULL)),
        CHECK ((xbox_function_id IS NOT NULL) != (xbox_target_id IS NOT NULL))
    )
    """,
    """
    CREATE TABLE match_hypothesis_sets (
        hypothesis_set_id TEXT PRIMARY KEY,
        pc_function_id TEXT REFERENCES functions(function_id) ON DELETE RESTRICT,
        pc_target_id TEXT REFERENCES unresolved_targets(target_id) ON DELETE RESTRICT,
        status TEXT NOT NULL DEFAULT 'candidate'
            CHECK (status IN ('candidate', 'accepted', 'rejected', 'conflicted', 'superseded')),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        identity_key TEXT,
        rationale TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        CHECK ((pc_function_id IS NOT NULL) != (pc_target_id IS NOT NULL))
    )
    """,
    """
    CREATE TABLE match_hypothesis_alternatives (
        alternative_id TEXT PRIMARY KEY,
        hypothesis_set_id TEXT NOT NULL
            REFERENCES match_hypothesis_sets(hypothesis_set_id) ON DELETE CASCADE,
        claim_id TEXT REFERENCES match_claims(claim_id) ON DELETE RESTRICT,
        xbox_fold_group_id TEXT REFERENCES fold_groups(fold_group_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        CHECK ((claim_id IS NOT NULL) != (xbox_fold_group_id IS NOT NULL)),
        UNIQUE (hypothesis_set_id, claim_id),
        UNIQUE (hypothesis_set_id, xbox_fold_group_id)
    )
    """,
    """
    CREATE TABLE match_hypothesis_evidence (
        evidence_id TEXT PRIMARY KEY,
        hypothesis_set_id TEXT NOT NULL
            REFERENCES match_hypothesis_sets(hypothesis_set_id) ON DELETE CASCADE,
        effect TEXT NOT NULL CHECK (effect IN ('supports', 'contradicts', 'context')),
        evidence_kind TEXT NOT NULL CHECK (length(evidence_kind) > 0),
        independence_group TEXT NOT NULL CHECK (length(independence_group) > 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        asserted_strength TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE TABLE reviewers (
        reviewer_id TEXT PRIMARY KEY,
        identity_kind TEXT NOT NULL CHECK (length(identity_kind) > 0),
        identity_key TEXT NOT NULL CHECK (length(identity_key) > 0),
        display_name TEXT NOT NULL CHECK (length(display_name) > 0),
        affiliation TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (identity_kind, identity_key)
    )
    """,
    """
    CREATE TABLE review_releases (
        review_release_id TEXT PRIMARY KEY,
        release_key TEXT NOT NULL UNIQUE CHECK (length(release_key) > 0),
        label TEXT NOT NULL CHECK (length(label) > 0),
        version TEXT,
        source_revision TEXT,
        manifest_id TEXT REFERENCES input_manifests(manifest_id) ON DELETE RESTRICT,
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE TABLE review_decisions (
        decision_id TEXT PRIMARY KEY,
        hypothesis_set_id TEXT
            REFERENCES match_hypothesis_sets(hypothesis_set_id) ON DELETE RESTRICT,
        alternative_id TEXT
            REFERENCES match_hypothesis_alternatives(alternative_id) ON DELETE RESTRICT,
        claim_id TEXT REFERENCES match_claims(claim_id) ON DELETE RESTRICT,
        reviewer_id TEXT NOT NULL REFERENCES reviewers(reviewer_id) ON DELETE RESTRICT,
        action TEXT NOT NULL
            CHECK (action IN ('accept', 'reject', 'defer', 'reopen', 'supersede')),
        decided_at TEXT NOT NULL CHECK (
            length(decided_at) = 27 AND
            decided_at GLOB '????-??-??T??:??:??.??????Z' AND
            julianday(decided_at) IS NOT NULL
        ),
        rationale TEXT NOT NULL CHECK (length(trim(rationale)) > 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        review_release_id TEXT NOT NULL
            REFERENCES review_releases(review_release_id) ON DELETE RESTRICT,
        previous_decision_id TEXT UNIQUE
            REFERENCES review_decisions(decision_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        CHECK (
            (hypothesis_set_id IS NOT NULL) +
            (alternative_id IS NOT NULL) +
            (claim_id IS NOT NULL) = 1
        ),
        CHECK (action <> 'reopen' OR previous_decision_id IS NOT NULL)
    )
    """,
    """
    CREATE TABLE control_flow_extractions (
        extraction_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE RESTRICT,
        persistence_policy TEXT NOT NULL
            CHECK (persistence_policy IN ('call_relevant_v1', 'all_branches_v1')),
        source_physical_site_count INTEGER NOT NULL
            CHECK (source_physical_site_count >= 0),
        source_logical_use_count INTEGER NOT NULL
            CHECK (source_logical_use_count >= 0),
        persisted_physical_site_count INTEGER NOT NULL
            CHECK (persisted_physical_site_count >= 0 AND
                   persisted_physical_site_count <= source_physical_site_count),
        persisted_logical_use_count INTEGER NOT NULL
            CHECK (persisted_logical_use_count >= 0 AND
                   persisted_logical_use_count <= source_logical_use_count),
        triggering_logical_use_count INTEGER NOT NULL
            CHECK (triggering_logical_use_count >= 0 AND
                   triggering_logical_use_count <= persisted_logical_use_count),
        procedure_scan_count INTEGER NOT NULL CHECK (procedure_scan_count >= 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (extraction_id, program_id),
        CHECK (
            persistence_policy <> 'all_branches_v1' OR
            (persisted_physical_site_count = source_physical_site_count AND
             persisted_logical_use_count = source_logical_use_count AND
             triggering_logical_use_count = source_logical_use_count)
        )
    )
    """,
    """
    CREATE TABLE control_flow_sites (
        site_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL,
        address_group_id TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id) ON DELETE RESTRICT,
        UNIQUE (site_id, program_id),
        UNIQUE (program_id, address_group_id)
    )
    """,
    """
    CREATE TABLE control_flow_site_assertions (
        assertion_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        raw_site_va INTEGER NOT NULL CHECK (raw_site_va >= 0 AND raw_site_va <= 4294967295),
        instruction_word INTEGER NOT NULL
            CHECK (instruction_word >= 0 AND instruction_word <= 4294967295),
        branch_kind TEXT NOT NULL CHECK (
            branch_kind IN (
                'branch_immediate', 'branch_conditional',
                'branch_to_link_register', 'branch_to_count_register'
            )
        ),
        raw_target_va INTEGER
            CHECK (raw_target_va IS NULL OR
                   (raw_target_va >= 0 AND raw_target_va <= 4294967295)),
        target_address_group_id TEXT,
        target_function_id TEXT,
        target_fold_group_id TEXT,
        link INTEGER NOT NULL CHECK (link IN (0, 1)),
        absolute INTEGER NOT NULL CHECK (absolute IN (0, 1)),
        conditional INTEGER NOT NULL CHECK (conditional IN (0, 1)),
        indirect INTEGER NOT NULL CHECK (indirect IN (0, 1)),
        bo INTEGER CHECK (bo IS NULL OR (bo >= 0 AND bo <= 31)),
        bi INTEGER CHECK (bi IS NULL OR (bi >= 0 AND bi <= 31)),
        target_kind TEXT NOT NULL CHECK (
            target_kind IN (
                'indirect', 'unique_procedure', 'fold_group',
                'executable_non_entry', 'outside_executable'
            )
        ),
        target_record_count INTEGER NOT NULL CHECK (target_record_count >= 0),
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id)
            REFERENCES control_flow_extractions(extraction_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (site_id, program_id)
            REFERENCES control_flow_sites(site_id, program_id) ON DELETE RESTRICT,
        FOREIGN KEY (target_address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id) ON DELETE RESTRICT,
        FOREIGN KEY (target_function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE RESTRICT,
        FOREIGN KEY (target_fold_group_id, program_id)
            REFERENCES fold_groups(fold_group_id, program_id) ON DELETE RESTRICT,
        UNIQUE (extraction_id, site_id),
        CHECK ((conditional = 1) = (bo IS NOT NULL AND bi IS NOT NULL)),
        CHECK (
            (indirect = 1) =
            (branch_kind IN ('branch_to_link_register', 'branch_to_count_register'))
        ),
        CHECK (
            (target_kind = 'indirect' AND indirect = 1 AND
             raw_target_va IS NULL AND target_address_group_id IS NULL AND
             target_function_id IS NULL AND target_fold_group_id IS NULL AND
             target_record_count = 0) OR
            (target_kind = 'unique_procedure' AND indirect = 0 AND
             raw_target_va IS NOT NULL AND target_address_group_id IS NOT NULL AND
             target_function_id IS NOT NULL AND target_fold_group_id IS NULL AND
             target_record_count = 1) OR
            (target_kind = 'fold_group' AND indirect = 0 AND
             raw_target_va IS NOT NULL AND target_address_group_id IS NOT NULL AND
             target_function_id IS NULL AND target_fold_group_id IS NOT NULL AND
             target_record_count > 1) OR
            (target_kind IN ('executable_non_entry', 'outside_executable') AND
             indirect = 0 AND raw_target_va IS NOT NULL AND
             target_address_group_id IS NOT NULL AND target_function_id IS NULL AND
             target_fold_group_id IS NULL AND target_record_count = 0)
        )
    )
    """,
    """
    CREATE TABLE control_flow_uses (
        use_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL,
        procedure_record_id TEXT NOT NULL CHECK (length(procedure_record_id) > 0),
        function_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE RESTRICT,
        FOREIGN KEY (site_id, program_id)
            REFERENCES control_flow_sites(site_id, program_id) ON DELETE RESTRICT,
        UNIQUE (use_id, program_id),
        UNIQUE (program_id, procedure_record_id, site_id)
    )
    """,
    """
    CREATE TABLE control_flow_use_assertions (
        assertion_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        use_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK (
            role IN (
                'link_register_setup', 'local_direct_call', 'direct_call',
                'local_branch', 'tail_transfer',
                'conditional_link_register_setup', 'local_conditional_call',
                'conditional_call', 'local_conditional_branch',
                'conditional_transfer', 'indirect_call',
                'indirect_tail_or_switch', 'indirect_link_register_call',
                'return_or_indirect_branch'
            )
        ),
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id)
            REFERENCES control_flow_extractions(extraction_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (use_id, program_id)
            REFERENCES control_flow_uses(use_id, program_id) ON DELETE RESTRICT,
        UNIQUE (extraction_id, use_id)
    )
    """,
    """
    CREATE TABLE control_flow_scans (
        scan_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        procedure_record_id TEXT NOT NULL CHECK (length(procedure_record_id) > 0),
        function_id TEXT,
        unresolved_target_id TEXT,
        scan_address_group_id TEXT,
        declared_size INTEGER NOT NULL CHECK (declared_size >= 0),
        scanned_size INTEGER NOT NULL CHECK (scanned_size >= 0),
        unscanned_byte_count INTEGER NOT NULL CHECK (unscanned_byte_count >= 0),
        status TEXT NOT NULL CHECK (
            status IN (
                'ok', 'empty', 'unresolved_va', 'unmapped_va',
                'non_executable_section', 'truncated_raw_extent', 'unaligned_size'
            )
        ),
        source_branch_use_count INTEGER NOT NULL CHECK (source_branch_use_count >= 0),
        persisted_branch_use_count INTEGER NOT NULL CHECK (
            persisted_branch_use_count >= 0 AND
            persisted_branch_use_count <= source_branch_use_count
        ),
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id)
            REFERENCES control_flow_extractions(extraction_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE RESTRICT,
        FOREIGN KEY (unresolved_target_id, program_id)
            REFERENCES unresolved_targets(target_id, program_id) ON DELETE RESTRICT,
        FOREIGN KEY (scan_address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id) ON DELETE RESTRICT,
        UNIQUE (extraction_id, procedure_record_id),
        CHECK ((function_id IS NOT NULL) != (unresolved_target_id IS NOT NULL)),
        CHECK (declared_size = scanned_size + unscanned_byte_count),
        CHECK ((status = 'unresolved_va') = (scan_address_group_id IS NULL)),
        CHECK (function_id IS NULL OR scan_address_group_id IS NOT NULL)
    )
    """,
    """
    CREATE TABLE vtable_alignment_candidates (
        alignment_id TEXT PRIMARY KEY,
        pc_vtable_id TEXT NOT NULL REFERENCES vtables(vtable_id) ON DELETE RESTRICT,
        xbox_vtable_id TEXT NOT NULL REFERENCES vtables(vtable_id) ON DELETE RESTRICT,
        class_name TEXT NOT NULL CHECK (length(class_name) > 0),
        vfptr_role TEXT NOT NULL CHECK (length(vfptr_role) > 0),
        subobject_offset INTEGER,
        status TEXT NOT NULL DEFAULT 'candidate' CHECK (status = 'candidate'),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (alignment_id, pc_vtable_id, xbox_vtable_id)
    )
    """,
    """
    CREATE TABLE vtable_slot_alignments (
        slot_alignment_id TEXT PRIMARY KEY,
        alignment_id TEXT NOT NULL,
        pc_vtable_id TEXT NOT NULL,
        pc_slot_index INTEGER NOT NULL CHECK (pc_slot_index >= 0),
        xbox_vtable_id TEXT NOT NULL,
        xbox_slot_index INTEGER NOT NULL CHECK (xbox_slot_index >= 0),
        hypothesis_set_id TEXT NOT NULL
            REFERENCES match_hypothesis_sets(hypothesis_set_id) ON DELETE RESTRICT,
        status TEXT NOT NULL DEFAULT 'candidate' CHECK (status = 'candidate'),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (alignment_id, pc_vtable_id, xbox_vtable_id)
            REFERENCES vtable_alignment_candidates(
                alignment_id, pc_vtable_id, xbox_vtable_id
            ) ON DELETE CASCADE,
        FOREIGN KEY (pc_vtable_id, pc_slot_index)
            REFERENCES vtable_slots(vtable_id, slot_index) ON DELETE RESTRICT,
        FOREIGN KEY (xbox_vtable_id, xbox_slot_index)
            REFERENCES vtable_slots(vtable_id, slot_index) ON DELETE RESTRICT,
        UNIQUE (alignment_id, pc_slot_index, xbox_slot_index),
        UNIQUE (hypothesis_set_id),
        CHECK (pc_slot_index = xbox_slot_index)
    )
    """,
    """
    CREATE TABLE vtable_alignment_issues (
        issue_id TEXT PRIMARY KEY,
        issue_kind TEXT NOT NULL CHECK (length(issue_kind) > 0),
        class_name TEXT NOT NULL CHECK (length(class_name) > 0),
        vfptr_role TEXT,
        subobject_offset INTEGER,
        message TEXT NOT NULL CHECK (length(message) > 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE TABLE claim_evidence (
        evidence_id TEXT PRIMARY KEY,
        claim_id TEXT NOT NULL REFERENCES match_claims(claim_id) ON DELETE CASCADE,
        effect TEXT NOT NULL CHECK (effect IN ('supports', 'contradicts', 'context')),
        evidence_kind TEXT NOT NULL CHECK (length(evidence_kind) > 0),
        independence_group TEXT NOT NULL CHECK (length(independence_group) > 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        asserted_strength TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE TABLE observations (
        observation_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        function_id TEXT,
        unresolved_target_id TEXT,
        observation_kind TEXT NOT NULL CHECK (length(observation_kind) > 0),
        independence_group TEXT NOT NULL CHECK (length(independence_group) > 0),
        effect TEXT NOT NULL DEFAULT 'context'
            CHECK (effect IN ('supports', 'contradicts', 'context')),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE CASCADE,
        FOREIGN KEY (unresolved_target_id, program_id)
            REFERENCES unresolved_targets(target_id, program_id) ON DELETE CASCADE,
        CHECK ((function_id IS NOT NULL) != (unresolved_target_id IS NOT NULL))
    )
    """,
    """
    CREATE TABLE call_edges (
        edge_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE CASCADE,
        caller_function_id TEXT NOT NULL,
        callee_function_id TEXT,
        unresolved_target_id TEXT,
        call_site_address_space TEXT,
        call_site_address INTEGER
            CHECK (call_site_address IS NULL OR call_site_address >= 0),
        edge_kind TEXT NOT NULL DEFAULT 'call' CHECK (length(edge_kind) > 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        FOREIGN KEY (caller_function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE CASCADE,
        FOREIGN KEY (callee_function_id, program_id)
            REFERENCES functions(function_id, program_id) ON DELETE RESTRICT,
        FOREIGN KEY (unresolved_target_id, program_id)
            REFERENCES unresolved_targets(target_id, program_id) ON DELETE RESTRICT,
        CHECK ((callee_function_id IS NOT NULL) != (unresolved_target_id IS NOT NULL)),
        CHECK ((call_site_address_space IS NULL) = (call_site_address IS NULL))
    )
    """,
    """
    CREATE INDEX functions_by_program_address
        ON functions(program_id, address_group_id)
    """,
    """
    CREATE INDEX function_assertions_by_function
        ON function_assertions(function_id, provenance_id)
    """,
    """
    CREATE INDEX function_name_assertions_by_name
        ON function_name_assertions(name_id, provenance_id)
    """,
    """
    CREATE INDEX function_source_range_assertions_by_range
        ON function_source_range_assertions(
            function_id, source_file_id, line_start, column_start, provenance_id
        )
    """,
    """
    CREATE INDEX function_signatures_by_status
        ON function_signatures(program_id, resolution_status, type_index)
    """,
    """
    CREATE INDEX vtable_slots_by_target
        ON vtable_slots(target_address_group_id)
    """,
    """
    CREATE INDEX class_name_assertions_by_name
        ON class_name_assertions(name_id, provenance_id)
    """,
    """
    CREATE INDEX vtable_slot_assertions_by_slot
        ON vtable_slot_assertions(vtable_id, slot_index, provenance_id)
    """,
    """
    CREATE INDEX unresolved_targets_by_status
        ON unresolved_targets(program_id, status)
    """,
    """
    CREATE INDEX match_claims_by_pc ON match_claims(pc_function_id, pc_target_id)
    """,
    """
    CREATE INDEX match_claims_by_xbox ON match_claims(xbox_function_id, xbox_target_id)
    """,
    """
    CREATE INDEX match_hypothesis_sets_by_pc
        ON match_hypothesis_sets(pc_function_id, pc_target_id, status)
    """,
    """
    CREATE INDEX match_hypothesis_alternatives_by_set
        ON match_hypothesis_alternatives(hypothesis_set_id, alternative_id)
    """,
    """
    CREATE INDEX match_hypothesis_evidence_by_set
        ON match_hypothesis_evidence(hypothesis_set_id, independence_group)
    """,
    """
    CREATE UNIQUE INDEX one_root_set_review_per_reviewer
        ON review_decisions(hypothesis_set_id, reviewer_id)
        WHERE previous_decision_id IS NULL AND hypothesis_set_id IS NOT NULL
    """,
    """
    CREATE UNIQUE INDEX one_root_alternative_review_per_reviewer
        ON review_decisions(alternative_id, reviewer_id)
        WHERE previous_decision_id IS NULL AND alternative_id IS NOT NULL
    """,
    """
    CREATE UNIQUE INDEX one_root_claim_review_per_reviewer
        ON review_decisions(claim_id, reviewer_id)
        WHERE previous_decision_id IS NULL AND claim_id IS NOT NULL
    """,
    """
    CREATE INDEX review_decisions_by_reviewer
        ON review_decisions(reviewer_id, decided_at, decision_id)
    """,
    """
    CREATE INDEX review_decisions_by_release
        ON review_decisions(review_release_id, decided_at, decision_id)
    """,
    """
    CREATE VIEW current_review_decisions AS
        SELECT
            d.decision_id,
            CASE
                WHEN d.hypothesis_set_id IS NOT NULL THEN 'hypothesis_set'
                WHEN d.alternative_id IS NOT NULL THEN 'alternative'
                ELSE 'claim'
            END AS target_kind,
            COALESCE(d.hypothesis_set_id, d.alternative_id, d.claim_id) AS target_id,
            d.hypothesis_set_id,
            d.alternative_id,
            d.claim_id,
            d.reviewer_id,
            d.action,
            CASE d.action
                WHEN 'accept' THEN 'accepted'
                WHEN 'reject' THEN 'rejected'
                WHEN 'defer' THEN 'deferred'
                WHEN 'reopen' THEN 'open'
                WHEN 'supersede' THEN 'superseded'
            END AS derived_status,
            d.decided_at,
            d.rationale,
            d.provenance_id,
            d.review_release_id,
            d.previous_decision_id,
            d.details_json,
            d.created_at
        FROM review_decisions d
        WHERE NOT EXISTS (
            SELECT 1 FROM review_decisions successor
            WHERE successor.previous_decision_id = d.decision_id
        )
    """,
    """
    CREATE INDEX control_flow_extractions_by_program_policy
        ON control_flow_extractions(program_id, persistence_policy, extraction_id)
    """,
    """
    CREATE INDEX control_flow_site_assertions_by_extraction
        ON control_flow_site_assertions(extraction_id, target_kind, site_id)
    """,
    """
    CREATE INDEX control_flow_site_assertions_by_direct_target
        ON control_flow_site_assertions(target_address_group_id, target_kind)
    """,
    """
    CREATE INDEX control_flow_uses_by_function
        ON control_flow_uses(function_id, site_id)
    """,
    """
    CREATE INDEX control_flow_uses_by_site
        ON control_flow_uses(site_id, function_id)
    """,
    """
    CREATE INDEX control_flow_use_assertions_by_extraction_role
        ON control_flow_use_assertions(extraction_id, role, use_id)
    """,
    """
    CREATE INDEX control_flow_scans_by_extraction_status
        ON control_flow_scans(extraction_id, status, procedure_record_id)
    """,
    """
    CREATE INDEX vtable_alignment_candidates_by_pair
        ON vtable_alignment_candidates(pc_vtable_id, xbox_vtable_id)
    """,
    """
    CREATE INDEX vtable_slot_alignments_by_hypothesis
        ON vtable_slot_alignments(hypothesis_set_id, alignment_id)
    """,
    """
    CREATE INDEX vtable_alignment_issues_by_class
        ON vtable_alignment_issues(class_name, issue_kind)
    """,
    """
    CREATE INDEX claim_evidence_by_claim
        ON claim_evidence(claim_id, independence_group)
    """,
    """
    CREATE INDEX observations_by_subject
        ON observations(program_id, function_id, unresolved_target_id, observation_kind)
    """,
    """
    CREATE INDEX call_edges_by_caller
        ON call_edges(caller_function_id, edge_kind)
    """,
    """
    CREATE INDEX call_edges_by_callee
        ON call_edges(callee_function_id, unresolved_target_id)
    """,
    """
    CREATE TRIGGER validate_function_signature_type_insert
    BEFORE INSERT ON function_signatures
    WHEN NOT EXISTS (
        SELECT 1 FROM functions f
        WHERE f.function_id = NEW.function_id
          AND f.program_id = NEW.program_id
          AND f.type_index = NEW.type_index
    )
    BEGIN
        SELECT RAISE(ABORT, 'signature type index does not match logical function');
    END
    """,
    """
    CREATE TRIGGER validate_function_signature_type_update
    BEFORE UPDATE OF function_id, program_id, type_index ON function_signatures
    WHEN NOT EXISTS (
        SELECT 1 FROM functions f
        WHERE f.function_id = NEW.function_id
          AND f.program_id = NEW.program_id
          AND f.type_index = NEW.type_index
    )
    BEGIN
        SELECT RAISE(ABORT, 'signature type index does not match logical function');
    END
    """,
    """
    CREATE TRIGGER protect_function_type_with_signature
    BEFORE UPDATE OF type_index ON functions
    WHEN EXISTS (
        SELECT 1 FROM function_signatures s
        WHERE s.function_id = OLD.function_id
          AND s.type_index IS NOT NEW.type_index
    )
    BEGIN
        SELECT RAISE(ABORT, 'cannot change a function type index with a signature record');
    END
    """,
    """
    CREATE TRIGGER validate_signature_argument_insert
    BEFORE INSERT ON function_signature_arguments
    WHEN NOT EXISTS (
        SELECT 1 FROM function_signatures s
        WHERE s.function_id = NEW.function_id
          AND s.resolution_status = 'resolved'
          AND NEW.position < s.argument_list_count
          AND (NEW.is_vararg_marker = 0 OR NEW.position = s.argument_list_count - 1)
    )
    BEGIN
        SELECT RAISE(ABORT, 'signature argument is outside a resolved argument list');
    END
    """,
    """
    CREATE TRIGGER validate_signature_argument_update
    BEFORE UPDATE ON function_signature_arguments
    WHEN NOT EXISTS (
        SELECT 1 FROM function_signatures s
        WHERE s.function_id = NEW.function_id
          AND s.resolution_status = 'resolved'
          AND NEW.position < s.argument_list_count
          AND (NEW.is_vararg_marker = 0 OR NEW.position = s.argument_list_count - 1)
    )
    BEGIN
        SELECT RAISE(ABORT, 'signature argument is outside a resolved argument list');
    END
    """,
    """
    CREATE TRIGGER protect_resolved_signature_arguments
    BEFORE UPDATE OF resolution_status, argument_list_count ON function_signatures
    WHEN EXISTS (SELECT 1 FROM function_signature_arguments a
                WHERE a.function_id = OLD.function_id)
         AND (NEW.resolution_status <> 'resolved' OR
              NEW.argument_list_count <> OLD.argument_list_count)
    BEGIN
        SELECT RAISE(ABORT, 'delete signature arguments before changing resolution shape');
    END
    """,
    """
    CREATE TRIGGER validate_target_resolution_address_insert
    BEFORE INSERT ON unresolved_targets
    WHEN NEW.resolved_function_id IS NOT NULL
         AND NEW.address_group_id IS NOT NULL
         AND NOT EXISTS (
             SELECT 1 FROM functions f
             WHERE f.function_id = NEW.resolved_function_id
               AND f.program_id = NEW.program_id
               AND f.address_group_id = NEW.address_group_id
         )
    BEGIN
        SELECT RAISE(ABORT, 'resolved function is at a different address group');
    END
    """,
    """
    CREATE TRIGGER validate_target_resolution_address_update
    BEFORE UPDATE OF resolved_function_id, address_group_id, program_id
    ON unresolved_targets
    WHEN NEW.resolved_function_id IS NOT NULL
         AND NEW.address_group_id IS NOT NULL
         AND NOT EXISTS (
             SELECT 1 FROM functions f
             WHERE f.function_id = NEW.resolved_function_id
               AND f.program_id = NEW.program_id
               AND f.address_group_id = NEW.address_group_id
         )
    BEGIN
        SELECT RAISE(ABORT, 'resolved function is at a different address group');
    END
    """,
    """
    CREATE TRIGGER validate_match_claim_platforms_insert
    BEFORE INSERT ON match_claims
    BEGIN
        SELECT CASE WHEN NEW.pc_function_id IS NOT NULL AND
            (SELECT p.platform FROM functions f JOIN programs p USING (program_id)
             WHERE f.function_id = NEW.pc_function_id) <> 'pc'
            THEN RAISE(ABORT, 'pc_function_id does not identify a PC function') END;
        SELECT CASE WHEN NEW.pc_target_id IS NOT NULL AND
            (SELECT p.platform FROM unresolved_targets t JOIN programs p USING (program_id)
             WHERE t.target_id = NEW.pc_target_id) <> 'pc'
            THEN RAISE(ABORT, 'pc_target_id does not identify a PC target') END;
        SELECT CASE WHEN NEW.xbox_function_id IS NOT NULL AND
            (SELECT p.platform FROM functions f JOIN programs p USING (program_id)
             WHERE f.function_id = NEW.xbox_function_id) <> 'xbox360'
            THEN RAISE(ABORT, 'xbox_function_id does not identify an Xbox 360 function') END;
        SELECT CASE WHEN NEW.xbox_target_id IS NOT NULL AND
            (SELECT p.platform FROM unresolved_targets t JOIN programs p USING (program_id)
             WHERE t.target_id = NEW.xbox_target_id) <> 'xbox360'
            THEN RAISE(ABORT, 'xbox_target_id does not identify an Xbox 360 target') END;
    END
    """,
    """
    CREATE TRIGGER validate_match_claim_platforms_update
    BEFORE UPDATE OF pc_function_id, pc_target_id, xbox_function_id, xbox_target_id
    ON match_claims
    BEGIN
        SELECT CASE WHEN NEW.pc_function_id IS NOT NULL AND
            (SELECT p.platform FROM functions f JOIN programs p USING (program_id)
             WHERE f.function_id = NEW.pc_function_id) <> 'pc'
            THEN RAISE(ABORT, 'pc_function_id does not identify a PC function') END;
        SELECT CASE WHEN NEW.pc_target_id IS NOT NULL AND
            (SELECT p.platform FROM unresolved_targets t JOIN programs p USING (program_id)
             WHERE t.target_id = NEW.pc_target_id) <> 'pc'
            THEN RAISE(ABORT, 'pc_target_id does not identify a PC target') END;
        SELECT CASE WHEN NEW.xbox_function_id IS NOT NULL AND
            (SELECT p.platform FROM functions f JOIN programs p USING (program_id)
             WHERE f.function_id = NEW.xbox_function_id) <> 'xbox360'
            THEN RAISE(ABORT, 'xbox_function_id does not identify an Xbox 360 function') END;
        SELECT CASE WHEN NEW.xbox_target_id IS NOT NULL AND
            (SELECT p.platform FROM unresolved_targets t JOIN programs p USING (program_id)
             WHERE t.target_id = NEW.xbox_target_id) <> 'xbox360'
            THEN RAISE(ABORT, 'xbox_target_id does not identify an Xbox 360 target') END;
    END
    """,
    """
    CREATE TRIGGER validate_match_hypothesis_set_platform_insert
    BEFORE INSERT ON match_hypothesis_sets
    BEGIN
        SELECT CASE WHEN NEW.pc_function_id IS NOT NULL AND
            (SELECT p.platform FROM functions f JOIN programs p USING (program_id)
             WHERE f.function_id = NEW.pc_function_id) <> 'pc'
            THEN RAISE(ABORT, 'hypothesis pc_function_id is not a PC function') END;
        SELECT CASE WHEN NEW.pc_target_id IS NOT NULL AND
            (SELECT p.platform FROM unresolved_targets t JOIN programs p USING (program_id)
             WHERE t.target_id = NEW.pc_target_id) <> 'pc'
            THEN RAISE(ABORT, 'hypothesis pc_target_id is not a PC target') END;
    END
    """,
    """
    CREATE TRIGGER validate_match_hypothesis_set_platform_update
    BEFORE UPDATE OF pc_function_id, pc_target_id ON match_hypothesis_sets
    BEGIN
        SELECT CASE WHEN NEW.pc_function_id IS NOT NULL AND
            (SELECT p.platform FROM functions f JOIN programs p USING (program_id)
             WHERE f.function_id = NEW.pc_function_id) <> 'pc'
            THEN RAISE(ABORT, 'hypothesis pc_function_id is not a PC function') END;
        SELECT CASE WHEN NEW.pc_target_id IS NOT NULL AND
            (SELECT p.platform FROM unresolved_targets t JOIN programs p USING (program_id)
             WHERE t.target_id = NEW.pc_target_id) <> 'pc'
            THEN RAISE(ABORT, 'hypothesis pc_target_id is not a PC target') END;
        SELECT CASE WHEN EXISTS (
            SELECT 1
            FROM match_hypothesis_alternatives a
            JOIN match_claims c ON c.claim_id = a.claim_id
            WHERE a.hypothesis_set_id = OLD.hypothesis_set_id
              AND NOT (
                  c.pc_function_id IS NEW.pc_function_id AND
                  c.pc_target_id IS NEW.pc_target_id
              )
        ) THEN RAISE(ABORT, 'hypothesis subject disagrees with a scalar alternative') END;
    END
    """,
    """
    CREATE TRIGGER validate_match_hypothesis_alternative_insert
    BEFORE INSERT ON match_hypothesis_alternatives
    BEGIN
        SELECT CASE WHEN NEW.claim_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM match_hypothesis_sets s
            JOIN match_claims c ON c.claim_id = NEW.claim_id
            WHERE s.hypothesis_set_id = NEW.hypothesis_set_id
              AND c.pc_function_id IS s.pc_function_id
              AND c.pc_target_id IS s.pc_target_id
        ) THEN RAISE(ABORT, 'scalar alternative has a different PC subject') END;
        SELECT CASE WHEN NEW.xbox_fold_group_id IS NOT NULL AND
            (SELECT p.platform
             FROM fold_groups g JOIN programs p USING (program_id)
             WHERE g.fold_group_id = NEW.xbox_fold_group_id) <> 'xbox360'
            THEN RAISE(ABORT, 'fold alternative is not an Xbox 360 fold group') END;
    END
    """,
    """
    CREATE TRIGGER validate_match_hypothesis_alternative_update
    BEFORE UPDATE OF hypothesis_set_id, claim_id, xbox_fold_group_id
    ON match_hypothesis_alternatives
    BEGIN
        SELECT CASE WHEN NEW.claim_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM match_hypothesis_sets s
            JOIN match_claims c ON c.claim_id = NEW.claim_id
            WHERE s.hypothesis_set_id = NEW.hypothesis_set_id
              AND c.pc_function_id IS s.pc_function_id
              AND c.pc_target_id IS s.pc_target_id
        ) THEN RAISE(ABORT, 'scalar alternative has a different PC subject') END;
        SELECT CASE WHEN NEW.xbox_fold_group_id IS NOT NULL AND
            (SELECT p.platform
             FROM fold_groups g JOIN programs p USING (program_id)
             WHERE g.fold_group_id = NEW.xbox_fold_group_id) <> 'xbox360'
            THEN RAISE(ABORT, 'fold alternative is not an Xbox 360 fold group') END;
    END
    """,
    """
    CREATE TRIGGER protect_hypothesis_subject_on_claim_update
    BEFORE UPDATE OF pc_function_id, pc_target_id ON match_claims
    WHEN EXISTS (
        SELECT 1
        FROM match_hypothesis_alternatives a
        JOIN match_hypothesis_sets s USING (hypothesis_set_id)
        WHERE a.claim_id = OLD.claim_id
          AND NOT (
              NEW.pc_function_id IS s.pc_function_id AND
              NEW.pc_target_id IS s.pc_target_id
          )
    )
    BEGIN
        SELECT RAISE(ABORT, 'updated claim would disagree with its hypothesis subject');
    END
    """,
    """
    CREATE TRIGGER protect_hypothesis_fold_platform_on_group_update
    BEFORE UPDATE OF program_id ON fold_groups
    WHEN EXISTS (
        SELECT 1 FROM match_hypothesis_alternatives a
        WHERE a.xbox_fold_group_id = OLD.fold_group_id
    ) AND (
        SELECT platform FROM programs WHERE program_id = NEW.program_id
    ) <> 'xbox360'
    BEGIN
        SELECT RAISE(ABORT, 'updated fold alternative would not be Xbox 360');
    END
    """,
    """
    CREATE TRIGGER validate_vtable_alignment_candidate_platform_insert
    BEFORE INSERT ON vtable_alignment_candidates
    BEGIN
        SELECT CASE WHEN
            (SELECT p.platform FROM vtables v JOIN programs p USING (program_id)
             WHERE v.vtable_id = NEW.pc_vtable_id) <> 'pc'
            THEN RAISE(ABORT, 'alignment pc_vtable_id is not a PC vtable') END;
        SELECT CASE WHEN
            (SELECT p.platform FROM vtables v JOIN programs p USING (program_id)
             WHERE v.vtable_id = NEW.xbox_vtable_id) <> 'xbox360'
            THEN RAISE(ABORT, 'alignment xbox_vtable_id is not an Xbox 360 vtable') END;
    END
    """,
    """
    CREATE TRIGGER validate_vtable_alignment_candidate_platform_update
    BEFORE UPDATE OF pc_vtable_id, xbox_vtable_id ON vtable_alignment_candidates
    BEGIN
        SELECT CASE WHEN
            (SELECT p.platform FROM vtables v JOIN programs p USING (program_id)
             WHERE v.vtable_id = NEW.pc_vtable_id) <> 'pc'
            THEN RAISE(ABORT, 'alignment pc_vtable_id is not a PC vtable') END;
        SELECT CASE WHEN
            (SELECT p.platform FROM vtables v JOIN programs p USING (program_id)
             WHERE v.vtable_id = NEW.xbox_vtable_id) <> 'xbox360'
            THEN RAISE(ABORT, 'alignment xbox_vtable_id is not an Xbox 360 vtable') END;
    END
    """,
    """
    CREATE TRIGGER validate_vtable_slot_alignment_hypothesis_insert
    BEFORE INSERT ON vtable_slot_alignments
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1
            FROM vtable_slots vs
            JOIN match_hypothesis_sets s
              ON s.hypothesis_set_id = NEW.hypothesis_set_id
            LEFT JOIN functions f ON f.function_id = s.pc_function_id
            LEFT JOIN unresolved_targets t ON t.target_id = s.pc_target_id
            WHERE vs.vtable_id = NEW.pc_vtable_id
              AND vs.slot_index = NEW.pc_slot_index
              AND (
                  (s.pc_function_id IS NOT NULL AND
                   vs.target_address_group_id IS f.address_group_id) OR
                  (s.pc_target_id IS NOT NULL AND (
                       vs.unresolved_target_id IS s.pc_target_id OR
                       (vs.target_address_group_id IS NOT NULL AND
                        vs.target_address_group_id IS t.address_group_id)
                  ))
              )
        ) THEN RAISE(ABORT, 'slot hypothesis has a different PC endpoint') END;
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM match_hypothesis_alternatives a
            WHERE a.hypothesis_set_id = NEW.hypothesis_set_id
        ) THEN RAISE(ABORT, 'slot hypothesis has no Xbox alternative') END;
        SELECT CASE WHEN EXISTS (
            SELECT 1
            FROM match_hypothesis_alternatives a
            WHERE a.hypothesis_set_id = NEW.hypothesis_set_id
              AND NOT (
                  (a.claim_id IS NOT NULL AND EXISTS (
                      SELECT 1
                      FROM match_claims c
                      JOIN vtable_slots vs
                        ON vs.vtable_id = NEW.xbox_vtable_id
                       AND vs.slot_index = NEW.xbox_slot_index
                      LEFT JOIN functions f ON f.function_id = c.xbox_function_id
                      LEFT JOIN unresolved_targets t ON t.target_id = c.xbox_target_id
                      WHERE c.claim_id = a.claim_id
                        AND (
                            (c.xbox_function_id IS NOT NULL AND
                             vs.target_address_group_id = f.address_group_id) OR
                            (c.xbox_target_id IS NOT NULL AND (
                                vs.unresolved_target_id = c.xbox_target_id OR
                                (vs.target_address_group_id IS NOT NULL AND
                                 vs.target_address_group_id = t.address_group_id)
                            ))
                        )
                  )) OR
                  (a.xbox_fold_group_id IS NOT NULL AND EXISTS (
                      SELECT 1
                      FROM vtable_slots vs
                      JOIN fold_group_members m
                        ON m.fold_group_id = a.xbox_fold_group_id
                      JOIN functions f USING (function_id, program_id)
                      WHERE vs.vtable_id = NEW.xbox_vtable_id
                        AND vs.slot_index = NEW.xbox_slot_index
                        AND vs.target_address_group_id IS f.address_group_id
                  ) AND NOT EXISTS (
                      SELECT 1
                      FROM fold_group_members m
                      JOIN functions f USING (function_id, program_id)
                      JOIN vtable_slots vs
                        ON vs.vtable_id = NEW.xbox_vtable_id
                       AND vs.slot_index = NEW.xbox_slot_index
                      WHERE m.fold_group_id = a.xbox_fold_group_id
                        AND f.address_group_id IS NOT vs.target_address_group_id
                  ))
              )
        ) THEN RAISE(ABORT, 'slot hypothesis has a different Xbox endpoint') END;
    END
    """,
    """
    CREATE TRIGGER validate_vtable_slot_alignment_hypothesis_update
    BEFORE UPDATE OF pc_vtable_id, pc_slot_index, xbox_vtable_id,
                     xbox_slot_index, hypothesis_set_id
    ON vtable_slot_alignments
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1
            FROM vtable_slots vs
            JOIN match_hypothesis_sets s
              ON s.hypothesis_set_id = NEW.hypothesis_set_id
            LEFT JOIN functions f ON f.function_id = s.pc_function_id
            LEFT JOIN unresolved_targets t ON t.target_id = s.pc_target_id
            WHERE vs.vtable_id = NEW.pc_vtable_id
              AND vs.slot_index = NEW.pc_slot_index
              AND (
                  (s.pc_function_id IS NOT NULL AND
                   vs.target_address_group_id IS f.address_group_id) OR
                  (s.pc_target_id IS NOT NULL AND (
                       vs.unresolved_target_id IS s.pc_target_id OR
                       (vs.target_address_group_id IS NOT NULL AND
                        vs.target_address_group_id IS t.address_group_id)
                  ))
              )
        ) THEN RAISE(ABORT, 'slot hypothesis has a different PC endpoint') END;
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM match_hypothesis_alternatives a
            WHERE a.hypothesis_set_id = NEW.hypothesis_set_id
        ) THEN RAISE(ABORT, 'slot hypothesis has no Xbox alternative') END;
        SELECT CASE WHEN EXISTS (
            SELECT 1
            FROM match_hypothesis_alternatives a
            WHERE a.hypothesis_set_id = NEW.hypothesis_set_id
              AND NOT (
                  (a.claim_id IS NOT NULL AND EXISTS (
                      SELECT 1
                      FROM match_claims c
                      JOIN vtable_slots vs
                        ON vs.vtable_id = NEW.xbox_vtable_id
                       AND vs.slot_index = NEW.xbox_slot_index
                      LEFT JOIN functions f ON f.function_id = c.xbox_function_id
                      LEFT JOIN unresolved_targets t ON t.target_id = c.xbox_target_id
                      WHERE c.claim_id = a.claim_id
                        AND (
                            (c.xbox_function_id IS NOT NULL AND
                             vs.target_address_group_id = f.address_group_id) OR
                            (c.xbox_target_id IS NOT NULL AND (
                                vs.unresolved_target_id = c.xbox_target_id OR
                                (vs.target_address_group_id IS NOT NULL AND
                                 vs.target_address_group_id = t.address_group_id)
                            ))
                        )
                  )) OR
                  (a.xbox_fold_group_id IS NOT NULL AND EXISTS (
                      SELECT 1
                      FROM vtable_slots vs
                      JOIN fold_group_members m
                        ON m.fold_group_id = a.xbox_fold_group_id
                      JOIN functions f USING (function_id, program_id)
                      WHERE vs.vtable_id = NEW.xbox_vtable_id
                        AND vs.slot_index = NEW.xbox_slot_index
                        AND vs.target_address_group_id IS f.address_group_id
                  ) AND NOT EXISTS (
                      SELECT 1
                      FROM fold_group_members m
                      JOIN functions f USING (function_id, program_id)
                      JOIN vtable_slots vs
                        ON vs.vtable_id = NEW.xbox_vtable_id
                       AND vs.slot_index = NEW.xbox_slot_index
                      WHERE m.fold_group_id = a.xbox_fold_group_id
                        AND f.address_group_id IS NOT vs.target_address_group_id
                  ))
              )
        ) THEN RAISE(ABORT, 'slot hypothesis has a different Xbox endpoint') END;
    END
    """,
    """
    CREATE TRIGGER validate_control_flow_extraction_platform_insert
    BEFORE INSERT ON control_flow_extractions
    WHEN NOT EXISTS (
        SELECT 1 FROM programs p
        WHERE p.program_id = NEW.program_id AND p.platform = 'xbox360'
    )
    BEGIN
        SELECT RAISE(ABORT, 'control-flow extraction program is not Xbox 360');
    END
    """,
    """
    CREATE TRIGGER validate_control_flow_site_platform_insert
    BEFORE INSERT ON control_flow_sites
    WHEN NOT EXISTS (
        SELECT 1 FROM programs p
        WHERE p.program_id = NEW.program_id AND p.platform = 'xbox360'
    )
    BEGIN
        SELECT RAISE(ABORT, 'control-flow site program is not Xbox 360');
    END
    """,
    """
    CREATE TRIGGER validate_control_flow_site_platform_update
    BEFORE UPDATE OF program_id, address_group_id ON control_flow_sites
    WHEN NOT EXISTS (
        SELECT 1 FROM programs p
        WHERE p.program_id = NEW.program_id AND p.platform = 'xbox360'
    )
    BEGIN
        SELECT RAISE(ABORT, 'control-flow site program is not Xbox 360');
    END
    """,
    """
    CREATE TRIGGER validate_control_flow_site_assertion_insert
    BEFORE INSERT ON control_flow_site_assertions
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1
            FROM control_flow_sites site
            JOIN address_groups site_address
              ON site_address.address_group_id = site.address_group_id
             AND site_address.program_id = site.program_id
            WHERE site.site_id = NEW.site_id
              AND site.program_id = NEW.program_id
              AND site_address.address = NEW.raw_site_va
        ) THEN RAISE(ABORT, 'control-flow raw site address disagrees with endpoint') END;
        SELECT CASE WHEN NEW.target_address_group_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM control_flow_sites site
            JOIN address_groups site_address
              ON site_address.address_group_id = site.address_group_id
             AND site_address.program_id = site.program_id
            JOIN address_groups target_address
              ON target_address.address_group_id = NEW.target_address_group_id
             AND target_address.program_id = NEW.program_id
            WHERE site.site_id = NEW.site_id
              AND site.program_id = NEW.program_id
              AND target_address.address_space = site_address.address_space
              AND target_address.address = NEW.raw_target_va
        ) THEN RAISE(ABORT, 'control-flow raw target/address space disagrees with endpoint') END;
        SELECT CASE WHEN NEW.target_function_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM functions function
            WHERE function.function_id = NEW.target_function_id
              AND function.program_id = NEW.program_id
              AND function.address_group_id = NEW.target_address_group_id
        ) THEN RAISE(ABORT, 'control-flow unique target is at a different address') END;
        SELECT CASE WHEN NEW.target_kind = 'unique_procedure' AND (
            SELECT COUNT(*) FROM functions function
            WHERE function.program_id = NEW.program_id
              AND function.address_group_id = NEW.target_address_group_id
        ) <> 1 THEN RAISE(ABORT, 'control-flow unique target address is not unique') END;
        SELECT CASE WHEN NEW.target_fold_group_id IS NOT NULL AND (
            NOT EXISTS (
                SELECT 1 FROM fold_group_members member
                WHERE member.fold_group_id = NEW.target_fold_group_id
                  AND member.program_id = NEW.program_id
            ) OR EXISTS (
                SELECT 1
                FROM fold_group_members member
                JOIN functions function USING (function_id, program_id)
                WHERE member.fold_group_id = NEW.target_fold_group_id
                  AND member.program_id = NEW.program_id
                  AND function.address_group_id IS NOT NEW.target_address_group_id
            ) OR (
                SELECT COUNT(*) FROM fold_group_members member
                WHERE member.fold_group_id = NEW.target_fold_group_id
                  AND member.program_id = NEW.program_id
            ) <> NEW.target_record_count OR (
                SELECT COUNT(*) FROM functions function
                WHERE function.program_id = NEW.program_id
                  AND function.address_group_id = NEW.target_address_group_id
            ) <> NEW.target_record_count
        ) THEN RAISE(ABORT, 'control-flow fold target is incomplete or at a different address') END;
        SELECT CASE WHEN NEW.target_kind IN (
            'executable_non_entry', 'outside_executable'
        ) AND EXISTS (
            SELECT 1 FROM functions function
            WHERE function.program_id = NEW.program_id
              AND function.address_group_id = NEW.target_address_group_id
        ) THEN RAISE(ABORT, 'control-flow non-entry target address has a function') END;
    END
    """,
    """
    CREATE TRIGGER validate_control_flow_scan_insert
    BEFORE INSERT ON control_flow_scans
    BEGIN
        SELECT CASE WHEN NEW.function_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM functions function
            WHERE function.function_id = NEW.function_id
              AND function.program_id = NEW.program_id
              AND function.address_group_id = NEW.scan_address_group_id
        ) THEN RAISE(ABORT, 'control-flow scan function is at a different address') END;
        SELECT CASE WHEN NEW.unresolved_target_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM unresolved_targets target
            WHERE target.target_id = NEW.unresolved_target_id
              AND target.program_id = NEW.program_id
              AND target.address_group_id IS NEW.scan_address_group_id
        ) THEN RAISE(ABORT, 'control-flow scan target is at a different address') END;
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_extraction_update
    BEFORE UPDATE ON control_flow_extractions
    BEGIN
        SELECT RAISE(ABORT, 'control-flow extractions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_extraction_delete
    BEFORE DELETE ON control_flow_extractions
    BEGIN
        SELECT RAISE(ABORT, 'control-flow extractions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_site_update
    BEFORE UPDATE ON control_flow_sites
    BEGIN
        SELECT RAISE(ABORT, 'control-flow physical sites are immutable');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_site_delete
    BEFORE DELETE ON control_flow_sites
    BEGIN
        SELECT RAISE(ABORT, 'control-flow physical sites are immutable');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_use_update
    BEFORE UPDATE ON control_flow_uses
    BEGIN
        SELECT RAISE(ABORT, 'control-flow logical uses are immutable');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_use_delete
    BEFORE DELETE ON control_flow_uses
    BEGIN
        SELECT RAISE(ABORT, 'control-flow logical uses are immutable');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_site_assertion_update
    BEFORE UPDATE ON control_flow_site_assertions
    BEGIN
        SELECT RAISE(ABORT, 'control-flow site assertions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_site_assertion_delete
    BEFORE DELETE ON control_flow_site_assertions
    BEGIN
        SELECT RAISE(ABORT, 'control-flow site assertions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_use_assertion_update
    BEFORE UPDATE ON control_flow_use_assertions
    BEGIN
        SELECT RAISE(ABORT, 'control-flow use assertions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_use_assertion_delete
    BEFORE DELETE ON control_flow_use_assertions
    BEGIN
        SELECT RAISE(ABORT, 'control-flow use assertions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_scan_update
    BEFORE UPDATE ON control_flow_scans
    BEGIN
        SELECT RAISE(ABORT, 'control-flow scans are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_control_flow_scan_delete
    BEFORE DELETE ON control_flow_scans
    BEGIN
        SELECT RAISE(ABORT, 'control-flow scans are append-only');
    END
    """,
    """
    CREATE TRIGGER validate_review_decision_successor_insert
    BEFORE INSERT ON review_decisions
    WHEN NEW.previous_decision_id IS NOT NULL
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1
            FROM review_decisions previous
            WHERE previous.decision_id = NEW.previous_decision_id
              AND previous.reviewer_id = NEW.reviewer_id
              AND previous.hypothesis_set_id IS NEW.hypothesis_set_id
              AND previous.alternative_id IS NEW.alternative_id
              AND previous.claim_id IS NEW.claim_id
        ) THEN RAISE(ABORT, 'previous review decision has a different reviewer or target') END;
        SELECT CASE WHEN EXISTS (
            SELECT 1
            FROM review_decisions previous
            WHERE previous.decision_id = NEW.previous_decision_id
              AND NEW.decided_at < previous.decided_at
        ) THEN RAISE(ABORT, 'review decision predates its previous decision') END;
    END
    """,
    """
    CREATE TRIGGER reject_review_decision_update
    BEFORE UPDATE ON review_decisions
    BEGIN
        SELECT RAISE(ABORT, 'review decisions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_review_decision_delete
    BEFORE DELETE ON review_decisions
    BEGIN
        SELECT RAISE(ABORT, 'review decisions are append-only');
    END
    """,
    """
    CREATE TRIGGER protect_referenced_review_release_update
    BEFORE UPDATE ON review_releases
    WHEN EXISTS (
        SELECT 1 FROM review_decisions d
        WHERE d.review_release_id = OLD.review_release_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'referenced review release context is immutable');
    END
    """,
    """
    CREATE TRIGGER protect_referenced_reviewer_identity_update
    BEFORE UPDATE OF reviewer_id, identity_kind, identity_key ON reviewers
    WHEN EXISTS (
        SELECT 1 FROM review_decisions d WHERE d.reviewer_id = OLD.reviewer_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'referenced reviewer identity is immutable');
    END
    """,
    """
    CREATE TABLE match_hypothesis_alternative_evidence (
        evidence_id TEXT PRIMARY KEY,
        alternative_id TEXT NOT NULL
            REFERENCES match_hypothesis_alternatives(alternative_id) ON DELETE RESTRICT,
        effect TEXT NOT NULL CHECK (effect IN ('supports', 'contradicts', 'context')),
        evidence_kind TEXT NOT NULL CHECK (length(evidence_kind) > 0),
        independence_group TEXT NOT NULL CHECK (length(independence_group) > 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id) ON DELETE RESTRICT,
        asserted_strength TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE TABLE codeview_type_extractions (
        extraction_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE RESTRICT,
        type_namespace TEXT NOT NULL DEFAULT 'global-tpi'
            CHECK (type_namespace = 'global-tpi'),
        raw_type_record_count INTEGER NOT NULL CHECK (raw_type_record_count >= 0),
        raw_body_byte_count INTEGER NOT NULL CHECK (raw_body_byte_count >= 0),
        tag_record_count INTEGER NOT NULL CHECK (tag_record_count >= 0),
        definition_count INTEGER NOT NULL CHECK (definition_count >= 0),
        forward_reference_count INTEGER NOT NULL
            CHECK (forward_reference_count >= 0),
        tag_member_occurrence_count INTEGER NOT NULL
            CHECK (tag_member_occurrence_count >= 0),
        physical_field_member_count INTEGER NOT NULL
            CHECK (physical_field_member_count >= 0 AND
                   physical_field_member_count <= tag_member_occurrence_count),
        physical_method_overload_count INTEGER NOT NULL
            CHECK (physical_method_overload_count >= 0),
        diagnostic_count INTEGER NOT NULL CHECK (diagnostic_count >= 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id)
            ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (extraction_id, program_id),
        UNIQUE (extraction_id, program_id, type_namespace),
        CHECK (tag_record_count = definition_count + forward_reference_count)
    )
    """,
    """
    CREATE TABLE codeview_type_records (
        type_record_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE RESTRICT,
        type_namespace TEXT NOT NULL DEFAULT 'global-tpi'
            CHECK (type_namespace = 'global-tpi'),
        type_index INTEGER NOT NULL
            CHECK (type_index >= 0 AND type_index <= 4294967295),
        leaf_kind INTEGER NOT NULL
            CHECK (leaf_kind >= 0 AND leaf_kind <= 65535),
        record_length INTEGER NOT NULL
            CHECK (record_length >= 2 AND record_length <= 65535),
        raw_body BLOB NOT NULL CHECK (typeof(raw_body) = 'blob'),
        raw_body_sha256 TEXT NOT NULL CHECK (
            length(raw_body_sha256) = 64 AND
            raw_body_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (type_record_id, program_id, type_namespace),
        UNIQUE (type_record_id, program_id, type_namespace, type_index),
        UNIQUE (program_id, type_namespace, type_index),
        CHECK (record_length = length(raw_body) + 2)
    )
    """,
    """
    CREATE TABLE codeview_type_record_assertions (
        assertion_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        type_namespace TEXT NOT NULL,
        type_record_id TEXT NOT NULL,
        leaf_name TEXT NOT NULL CHECK (length(leaf_name) > 0),
        rendered_type TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id, type_namespace)
            REFERENCES codeview_type_extractions(
                extraction_id, program_id, type_namespace
            ) ON DELETE RESTRICT,
        FOREIGN KEY (type_record_id, program_id, type_namespace)
            REFERENCES codeview_type_records(
                type_record_id, program_id, type_namespace
            ) ON DELETE RESTRICT,
        UNIQUE (extraction_id, type_record_id)
    )
    """,
    """
    CREATE TABLE codeview_tag_layouts (
        tag_layout_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        type_namespace TEXT NOT NULL,
        type_record_id TEXT NOT NULL,
        tag_kind TEXT NOT NULL
            CHECK (tag_kind IN ('class', 'structure', 'union', 'enum')),
        declared_member_count INTEGER NOT NULL CHECK (declared_member_count >= 0),
        decoded_member_count INTEGER NOT NULL CHECK (decoded_member_count >= 0),
        physical_member_occurrence_count INTEGER NOT NULL
            CHECK (physical_member_occurrence_count >= 0),
        properties INTEGER NOT NULL
            CHECK (properties >= 0 AND properties <= 65535),
        field_list_type_index INTEGER NOT NULL
            CHECK (field_list_type_index >= 0 AND field_list_type_index <= 4294967295),
        derived_type_index INTEGER
            CHECK (derived_type_index IS NULL OR
                   (derived_type_index >= 0 AND derived_type_index <= 4294967295)),
        vtable_shape_type_index INTEGER
            CHECK (vtable_shape_type_index IS NULL OR
                   (vtable_shape_type_index >= 0 AND
                    vtable_shape_type_index <= 4294967295)),
        underlying_type_index INTEGER
            CHECK (underlying_type_index IS NULL OR
                   (underlying_type_index >= 0 AND
                    underlying_type_index <= 4294967295)),
        size_value TEXT,
        display_name TEXT NOT NULL,
        unique_name TEXT,
        is_forward_reference INTEGER NOT NULL
            CHECK (is_forward_reference IN (0, 1)),
        record_sha256 TEXT NOT NULL CHECK (
            length(record_sha256) = 64 AND
            record_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id, type_namespace)
            REFERENCES codeview_type_extractions(
                extraction_id, program_id, type_namespace
            ) ON DELETE RESTRICT,
        FOREIGN KEY (
            type_record_id, program_id, type_namespace
        ) REFERENCES codeview_type_records(
            type_record_id, program_id, type_namespace
        ) ON DELETE RESTRICT,
        UNIQUE (tag_layout_id, extraction_id, program_id),
        UNIQUE (extraction_id, type_record_id)
    )
    """,
    """
    CREATE TABLE codeview_field_members (
        field_member_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        source_field_list_type_index INTEGER NOT NULL
            CHECK (source_field_list_type_index >= 0 AND
                   source_field_list_type_index <= 4294967295),
        source_record_offset INTEGER NOT NULL CHECK (source_record_offset >= 0),
        leaf_kind INTEGER NOT NULL
            CHECK (leaf_kind >= 0 AND leaf_kind <= 65535),
        member_kind TEXT NOT NULL CHECK (length(member_kind) > 0),
        attributes INTEGER
            CHECK (attributes IS NULL OR (attributes >= 0 AND attributes <= 65535)),
        access TEXT,
        method_kind TEXT,
        method_options INTEGER CHECK (method_options IS NULL OR method_options >= 0),
        member_name TEXT,
        referenced_type_index INTEGER
            CHECK (referenced_type_index IS NULL OR
                   (referenced_type_index >= 0 AND
                    referenced_type_index <= 4294967295)),
        rendered_type TEXT,
        member_offset_value TEXT,
        enum_value TEXT,
        base_type_index INTEGER
            CHECK (base_type_index IS NULL OR
                   (base_type_index >= 0 AND base_type_index <= 4294967295)),
        vbptr_type_index INTEGER
            CHECK (vbptr_type_index IS NULL OR
                   (vbptr_type_index >= 0 AND vbptr_type_index <= 4294967295)),
        vbptr_offset_value TEXT,
        vtable_index_value TEXT,
        method_list_type_index INTEGER
            CHECK (method_list_type_index IS NULL OR
                   (method_list_type_index >= 0 AND
                    method_list_type_index <= 4294967295)),
        declared_overload_count INTEGER
            CHECK (declared_overload_count IS NULL OR declared_overload_count >= 0),
        vtable_offset INTEGER,
        continuation_type_index INTEGER
            CHECK (continuation_type_index IS NULL OR
                   (continuation_type_index >= 0 AND
                    continuation_type_index <= 4294967295)),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id)
            REFERENCES codeview_type_extractions(extraction_id, program_id)
            ON DELETE RESTRICT,
        UNIQUE (field_member_id, extraction_id, program_id),
        UNIQUE (
            extraction_id, source_field_list_type_index, source_record_offset
        )
    )
    """,
    """
    CREATE TABLE codeview_tag_member_uses (
        member_use_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        tag_layout_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        field_member_id TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (tag_layout_id, extraction_id, program_id)
            REFERENCES codeview_tag_layouts(
                tag_layout_id, extraction_id, program_id
            ) ON DELETE RESTRICT,
        FOREIGN KEY (field_member_id, extraction_id, program_id)
            REFERENCES codeview_field_members(
                field_member_id, extraction_id, program_id
            ) ON DELETE RESTRICT,
        UNIQUE (tag_layout_id, ordinal)
    )
    """,
    """
    CREATE TABLE codeview_method_overloads (
        method_overload_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        method_list_type_index INTEGER NOT NULL
            CHECK (method_list_type_index >= 0 AND
                   method_list_type_index <= 4294967295),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        attributes INTEGER NOT NULL
            CHECK (attributes >= 0 AND attributes <= 65535),
        access TEXT NOT NULL CHECK (length(access) > 0),
        method_kind TEXT NOT NULL CHECK (length(method_kind) > 0),
        method_options INTEGER NOT NULL CHECK (method_options >= 0),
        method_type_index INTEGER NOT NULL
            CHECK (method_type_index >= 0 AND method_type_index <= 4294967295),
        rendered_type TEXT NOT NULL,
        vtable_offset INTEGER,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id)
            REFERENCES codeview_type_extractions(extraction_id, program_id)
            ON DELETE RESTRICT,
        UNIQUE (method_overload_id, extraction_id, program_id),
        UNIQUE (extraction_id, method_list_type_index, ordinal)
    )
    """,
    """
    CREATE TABLE codeview_layout_diagnostics (
        diagnostic_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        tag_layout_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        code TEXT NOT NULL CHECK (length(code) > 0),
        source_type_index INTEGER NOT NULL
            CHECK (source_type_index >= 0 AND source_type_index <= 4294967295),
        source_record_offset INTEGER NOT NULL CHECK (source_record_offset >= 0),
        message TEXT NOT NULL,
        remaining_hex TEXT NOT NULL DEFAULT '' CHECK (
            length(remaining_hex) % 2 = 0 AND
            remaining_hex NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (tag_layout_id, extraction_id, program_id)
            REFERENCES codeview_tag_layouts(
                tag_layout_id, extraction_id, program_id
            ) ON DELETE RESTRICT,
        UNIQUE (tag_layout_id, ordinal)
    )
    """,
    """
    CREATE TABLE data_symbol_extractions (
        extraction_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE RESTRICT,
        address_space TEXT NOT NULL DEFAULT 'xbox-va'
            CHECK (address_space = 'xbox-va'),
        record_count INTEGER NOT NULL CHECK (record_count >= 0),
        resolved_record_count INTEGER NOT NULL
            CHECK (resolved_record_count >= 0 AND resolved_record_count <= record_count),
        unresolved_record_count INTEGER NOT NULL
            CHECK (unresolved_record_count >= 0 AND
                   unresolved_record_count <= record_count),
        unique_address_count INTEGER NOT NULL CHECK (unique_address_count >= 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id)
            ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (extraction_id, program_id),
        CHECK (record_count = resolved_record_count + unresolved_record_count)
    )
    """,
    """
    CREATE TABLE data_symbol_records (
        data_record_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE RESTRICT,
        source_record_id TEXT NOT NULL CHECK (length(source_record_id) > 0),
        module_index INTEGER NOT NULL CHECK (module_index >= 0),
        symbol_stream INTEGER NOT NULL CHECK (symbol_stream >= 0),
        record_offset INTEGER NOT NULL CHECK (record_offset >= 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (data_record_id, program_id),
        UNIQUE (program_id, source_record_id),
        UNIQUE (program_id, module_index, symbol_stream, record_offset)
    )
    """,
    """
    CREATE TABLE data_symbol_record_assertions (
        assertion_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        data_record_id TEXT NOT NULL,
        module_name TEXT NOT NULL,
        record_length INTEGER NOT NULL
            CHECK (record_length >= 2 AND record_length <= 65535),
        record_kind TEXT NOT NULL CHECK (record_kind IN ('S_LDATA32', 'S_GDATA32')),
        record_kind_code INTEGER NOT NULL
            CHECK (record_kind_code IN (4364, 4365)),
        resolved_va INTEGER
            CHECK (resolved_va IS NULL OR
                   (resolved_va >= 0 AND resolved_va <= 4294967295)),
        address_group_id TEXT,
        section INTEGER NOT NULL CHECK (section >= 0 AND section <= 65535),
        section_offset INTEGER NOT NULL
            CHECK (section_offset >= 0 AND section_offset <= 4294967295),
        type_index INTEGER NOT NULL
            CHECK (type_index >= 0 AND type_index <= 4294967295),
        raw_name TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id)
            REFERENCES data_symbol_extractions(extraction_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (data_record_id, program_id)
            REFERENCES data_symbol_records(data_record_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id)
            ON DELETE RESTRICT,
        UNIQUE (extraction_id, data_record_id),
        CHECK ((resolved_va IS NULL) = (address_group_id IS NULL)),
        CHECK (
            (record_kind = 'S_LDATA32' AND record_kind_code = 4364) OR
            (record_kind = 'S_GDATA32' AND record_kind_code = 4365)
        )
    )
    """,
    """
    CREATE INDEX codeview_type_record_assertions_by_extraction
        ON codeview_type_record_assertions(extraction_id, type_record_id)
    """,
    """
    CREATE INDEX codeview_type_records_by_leaf
        ON codeview_type_records(program_id, type_namespace, leaf_kind, type_index)
    """,
    """
    CREATE INDEX codeview_tag_layouts_by_name
        ON codeview_tag_layouts(program_id, display_name, unique_name)
    """,
    """
    CREATE INDEX codeview_tag_member_uses_by_member
        ON codeview_tag_member_uses(field_member_id, tag_layout_id, ordinal)
    """,
    """
    CREATE INDEX codeview_field_members_by_method_list
        ON codeview_field_members(extraction_id, method_list_type_index)
        WHERE method_list_type_index IS NOT NULL
    """,
    """
    CREATE INDEX codeview_method_overloads_by_type
        ON codeview_method_overloads(extraction_id, method_type_index)
    """,
    """
    CREATE INDEX codeview_layout_diagnostics_by_code
        ON codeview_layout_diagnostics(extraction_id, code, diagnostic_id)
    """,
    """
    CREATE INDEX data_symbol_record_assertions_by_address
        ON data_symbol_record_assertions(program_id, address_group_id, data_record_id)
    """,
    """
    CREATE INDEX data_symbol_record_assertions_by_name
        ON data_symbol_record_assertions(program_id, raw_name, data_record_id)
    """,
    """
    CREATE INDEX match_hypothesis_alternative_evidence_by_alternative
        ON match_hypothesis_alternative_evidence(
            alternative_id, independence_group, evidence_id
        )
    """,
    """
    CREATE TRIGGER validate_codeview_type_extraction_platform_insert
    BEFORE INSERT ON codeview_type_extractions
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM programs
            WHERE program_id = NEW.program_id AND platform = 'xbox360'
        ) THEN RAISE(ABORT, 'CodeView type extraction program is not Xbox 360') END;
    END
    """,
    """
    CREATE TRIGGER reject_match_hypothesis_alternative_evidence_update
    BEFORE UPDATE ON match_hypothesis_alternative_evidence
    BEGIN
        SELECT RAISE(ABORT, 'match alternative evidence is append-only');
    END
    """,
    """
    CREATE TRIGGER reject_match_hypothesis_alternative_evidence_delete
    BEFORE DELETE ON match_hypothesis_alternative_evidence
    BEGIN
        SELECT RAISE(ABORT, 'match alternative evidence is append-only');
    END
    """,
    """
    CREATE TRIGGER protect_evidenced_match_hypothesis_alternative_update
    BEFORE UPDATE OF hypothesis_set_id, claim_id, xbox_fold_group_id
    ON match_hypothesis_alternatives
    WHEN EXISTS (
        SELECT 1 FROM match_hypothesis_alternative_evidence evidence
        WHERE evidence.alternative_id = OLD.alternative_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'evidenced match alternative identity is immutable');
    END
    """,
    """
    CREATE TRIGGER protect_evidenced_match_claim_endpoint_update
    BEFORE UPDATE OF pc_function_id, pc_target_id, xbox_function_id, xbox_target_id
    ON match_claims
    WHEN EXISTS (
        SELECT 1
        FROM match_hypothesis_alternatives alternative
        JOIN match_hypothesis_alternative_evidence evidence
          USING (alternative_id)
        WHERE alternative.claim_id = OLD.claim_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'evidenced match claim endpoints are immutable');
    END
    """,
    """
    CREATE TRIGGER protect_evidenced_fold_group_update
    BEFORE UPDATE OF program_id, kind ON fold_groups
    WHEN EXISTS (
        SELECT 1
        FROM match_hypothesis_alternatives alternative
        JOIN match_hypothesis_alternative_evidence evidence
          USING (alternative_id)
        WHERE alternative.xbox_fold_group_id = OLD.fold_group_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'evidenced fold-group identity is immutable');
    END
    """,
    """
    CREATE TRIGGER protect_evidenced_fold_member_insert
    BEFORE INSERT ON fold_group_members
    WHEN EXISTS (
        SELECT 1
        FROM match_hypothesis_alternatives alternative
        JOIN match_hypothesis_alternative_evidence evidence
          USING (alternative_id)
        WHERE alternative.xbox_fold_group_id = NEW.fold_group_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'evidenced fold-group membership is immutable');
    END
    """,
    """
    CREATE TRIGGER protect_evidenced_fold_member_update
    BEFORE UPDATE OF fold_group_id, function_id ON fold_group_members
    WHEN EXISTS (
        SELECT 1
        FROM match_hypothesis_alternatives alternative
        JOIN match_hypothesis_alternative_evidence evidence
          USING (alternative_id)
        WHERE alternative.xbox_fold_group_id IN (
            OLD.fold_group_id, NEW.fold_group_id
        )
    )
    BEGIN
        SELECT RAISE(ABORT, 'evidenced fold-group membership is immutable');
    END
    """,
    """
    CREATE TRIGGER protect_evidenced_fold_member_delete
    BEFORE DELETE ON fold_group_members
    WHEN EXISTS (
        SELECT 1
        FROM match_hypothesis_alternatives alternative
        JOIN match_hypothesis_alternative_evidence evidence
          USING (alternative_id)
        WHERE alternative.xbox_fold_group_id = OLD.fold_group_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'evidenced fold-group membership is immutable');
    END
    """,
    """
    CREATE TRIGGER validate_codeview_type_record_platform_insert
    BEFORE INSERT ON codeview_type_records
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM programs
            WHERE program_id = NEW.program_id AND platform = 'xbox360'
        ) THEN RAISE(ABORT, 'CodeView type record program is not Xbox 360') END;
    END
    """,
    """
    CREATE TRIGGER validate_data_symbol_extraction_platform_insert
    BEFORE INSERT ON data_symbol_extractions
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM programs
            WHERE program_id = NEW.program_id AND platform = 'xbox360'
        ) THEN RAISE(ABORT, 'data-symbol extraction program is not Xbox 360') END;
    END
    """,
    """
    CREATE TRIGGER validate_data_symbol_record_platform_insert
    BEFORE INSERT ON data_symbol_records
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM programs
            WHERE program_id = NEW.program_id AND platform = 'xbox360'
        ) THEN RAISE(ABORT, 'data-symbol record program is not Xbox 360') END;
    END
    """,
    """
    CREATE TRIGGER validate_data_symbol_assertion_address_insert
    BEFORE INSERT ON data_symbol_record_assertions
    WHEN NEW.address_group_id IS NOT NULL
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM address_groups address
            WHERE address.address_group_id = NEW.address_group_id
              AND address.program_id = NEW.program_id
              AND address.address_space = 'xbox-va'
              AND address.address = NEW.resolved_va
              AND address.address >= 0
              AND address.address <= 4294967295
        ) THEN RAISE(ABORT, 'data-symbol resolved address is not matching Xbox VA') END;
    END
    """,
    """
    CREATE TRIGGER protect_type_data_program_platform_update
    BEFORE UPDATE OF platform ON programs
    WHEN NEW.platform <> 'xbox360' AND (
        EXISTS (
            SELECT 1 FROM codeview_type_extractions extraction
            WHERE extraction.program_id = OLD.program_id
        ) OR EXISTS (
            SELECT 1 FROM codeview_type_records record
            WHERE record.program_id = OLD.program_id
        ) OR EXISTS (
            SELECT 1 FROM data_symbol_extractions extraction
            WHERE extraction.program_id = OLD.program_id
        ) OR EXISTS (
            SELECT 1 FROM data_symbol_records record
            WHERE record.program_id = OLD.program_id
        )
    )
    BEGIN
        SELECT RAISE(ABORT, 'program with Xbox type/data records must remain Xbox 360');
    END
    """,
    """
    CREATE TRIGGER protect_data_symbol_address_identity_update
    BEFORE UPDATE OF program_id, address_space, address ON address_groups
    WHEN EXISTS (
        SELECT 1 FROM data_symbol_record_assertions assertion
        WHERE assertion.address_group_id = OLD.address_group_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'data-symbol resolved address identity is immutable');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_type_extraction_update
    BEFORE UPDATE ON codeview_type_extractions
    BEGIN
        SELECT RAISE(ABORT, 'CodeView type extractions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_type_extraction_delete
    BEFORE DELETE ON codeview_type_extractions
    BEGIN
        SELECT RAISE(ABORT, 'CodeView type extractions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_type_record_update
    BEFORE UPDATE ON codeview_type_records
    BEGIN
        SELECT RAISE(ABORT, 'CodeView type records are immutable');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_type_record_delete
    BEFORE DELETE ON codeview_type_records
    BEGIN
        SELECT RAISE(ABORT, 'CodeView type records are immutable');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_type_record_assertion_update
    BEFORE UPDATE ON codeview_type_record_assertions
    BEGIN
        SELECT RAISE(ABORT, 'CodeView type record assertions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_type_record_assertion_delete
    BEFORE DELETE ON codeview_type_record_assertions
    BEGIN
        SELECT RAISE(ABORT, 'CodeView type record assertions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_tag_layout_update
    BEFORE UPDATE ON codeview_tag_layouts
    BEGIN
        SELECT RAISE(ABORT, 'CodeView tag layouts are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_tag_layout_delete
    BEFORE DELETE ON codeview_tag_layouts
    BEGIN
        SELECT RAISE(ABORT, 'CodeView tag layouts are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_field_member_update
    BEFORE UPDATE ON codeview_field_members
    BEGIN
        SELECT RAISE(ABORT, 'CodeView field members are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_field_member_delete
    BEFORE DELETE ON codeview_field_members
    BEGIN
        SELECT RAISE(ABORT, 'CodeView field members are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_tag_member_use_update
    BEFORE UPDATE ON codeview_tag_member_uses
    BEGIN
        SELECT RAISE(ABORT, 'CodeView tag-member uses are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_tag_member_use_delete
    BEFORE DELETE ON codeview_tag_member_uses
    BEGIN
        SELECT RAISE(ABORT, 'CodeView tag-member uses are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_method_overload_update
    BEFORE UPDATE ON codeview_method_overloads
    BEGIN
        SELECT RAISE(ABORT, 'CodeView method overloads are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_method_overload_delete
    BEFORE DELETE ON codeview_method_overloads
    BEGIN
        SELECT RAISE(ABORT, 'CodeView method overloads are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_layout_diagnostic_update
    BEFORE UPDATE ON codeview_layout_diagnostics
    BEGIN
        SELECT RAISE(ABORT, 'CodeView layout diagnostics are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_codeview_layout_diagnostic_delete
    BEFORE DELETE ON codeview_layout_diagnostics
    BEGIN
        SELECT RAISE(ABORT, 'CodeView layout diagnostics are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_data_symbol_extraction_update
    BEFORE UPDATE ON data_symbol_extractions
    BEGIN
        SELECT RAISE(ABORT, 'data-symbol extractions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_data_symbol_extraction_delete
    BEFORE DELETE ON data_symbol_extractions
    BEGIN
        SELECT RAISE(ABORT, 'data-symbol extractions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_data_symbol_record_update
    BEFORE UPDATE ON data_symbol_records
    BEGIN
        SELECT RAISE(ABORT, 'data-symbol records are immutable');
    END
    """,
    """
    CREATE TRIGGER reject_data_symbol_record_delete
    BEFORE DELETE ON data_symbol_records
    BEGIN
        SELECT RAISE(ABORT, 'data-symbol records are immutable');
    END
    """,
    """
    CREATE TRIGGER reject_data_symbol_record_assertion_update
    BEFORE UPDATE ON data_symbol_record_assertions
    BEGIN
        SELECT RAISE(ABORT, 'data-symbol record assertions are append-only');
    END
    """,
    """
    CREATE TRIGGER reject_data_symbol_record_assertion_delete
    BEFORE DELETE ON data_symbol_record_assertions
    BEGIN
        SELECT RAISE(ABORT, 'data-symbol record assertions are append-only');
    END
    """,
    """
    CREATE TABLE xbox_vftable_extractions (
        extraction_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE RESTRICT,
        address_space TEXT NOT NULL DEFAULT 'xbox-va'
            CHECK (address_space = 'xbox-va'),
        dbi_stream INTEGER NOT NULL CHECK (dbi_stream >= 0),
        global_symbol_hash_stream INTEGER
            CHECK (global_symbol_hash_stream IS NULL OR global_symbol_hash_stream >= 0),
        public_symbol_hash_stream INTEGER
            CHECK (public_symbol_hash_stream IS NULL OR public_symbol_hash_stream >= 0),
        symbol_record_stream INTEGER NOT NULL CHECK (symbol_record_stream >= 0),
        scan_max_slots INTEGER NOT NULL CHECK (scan_max_slots > 0),
        physical_record_count INTEGER NOT NULL CHECK (physical_record_count >= 0),
        resolved_record_count INTEGER NOT NULL CHECK (
            resolved_record_count >= 0 AND
            resolved_record_count <= physical_record_count
        ),
        unresolved_record_count INTEGER NOT NULL CHECK (
            unresolved_record_count >= 0 AND
            unresolved_record_count <= physical_record_count
        ),
        canonical_name_count INTEGER NOT NULL CHECK (
            canonical_name_count >= 0 AND
            canonical_name_count <= physical_record_count
        ),
        source_address_group_count INTEGER NOT NULL CHECK (
            source_address_group_count >= 0 AND
            source_address_group_count <= resolved_record_count
        ),
        pointer_run_count INTEGER NOT NULL CHECK (pointer_run_count >= 0),
        pointer_slot_count INTEGER NOT NULL CHECK (pointer_slot_count >= 0),
        symbol_diagnostic_count INTEGER NOT NULL CHECK (symbol_diagnostic_count >= 0),
        run_diagnostic_count INTEGER NOT NULL CHECK (run_diagnostic_count >= 0),
        scan_diagnostic_count INTEGER NOT NULL CHECK (scan_diagnostic_count >= 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id)
            ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (extraction_id, program_id),
        CHECK (physical_record_count = resolved_record_count + unresolved_record_count)
    )
    """,
    """
    CREATE TABLE xbox_vftable_name_identities (
        canonical_name_id TEXT PRIMARY KEY,
        decorated_name TEXT NOT NULL,
        decorated_name_bytes BLOB NOT NULL CHECK (typeof(decorated_name_bytes) = 'blob'),
        decorated_name_sha256 TEXT NOT NULL UNIQUE CHECK (
            length(decorated_name_sha256) = 64 AND
            decorated_name_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (decorated_name),
        UNIQUE (decorated_name_bytes),
        CHECK (
            canonical_name_id =
            'x360-msvc-vftable-name:sha256:' || decorated_name_sha256
        )
    )
    """,
    """
    CREATE TABLE xbox_vftable_symbol_records (
        vftable_record_id TEXT PRIMARY KEY,
        program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE RESTRICT,
        source_record_id TEXT NOT NULL CHECK (length(source_record_id) > 0),
        symbol_record_stream INTEGER NOT NULL CHECK (symbol_record_stream >= 0),
        record_offset INTEGER NOT NULL CHECK (record_offset >= 0),
        record_length INTEGER NOT NULL CHECK (
            record_length >= 2 AND record_length <= 65535
        ),
        raw_record BLOB NOT NULL CHECK (typeof(raw_record) = 'blob'),
        raw_record_sha256 TEXT NOT NULL CHECK (
            length(raw_record_sha256) = 64 AND
            raw_record_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (vftable_record_id, program_id),
        UNIQUE (program_id, source_record_id),
        UNIQUE (program_id, symbol_record_stream, record_offset),
        CHECK (length(raw_record) = record_length + 2)
    )
    """,
    """
    CREATE TABLE xbox_vftable_symbol_assertions (
        assertion_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        vftable_record_id TEXT NOT NULL,
        canonical_name_id TEXT NOT NULL
            REFERENCES xbox_vftable_name_identities(canonical_name_id)
            ON DELETE RESTRICT,
        record_kind TEXT NOT NULL CHECK (record_kind = 'S_PUB32'),
        record_kind_code INTEGER NOT NULL CHECK (record_kind_code = 4366),
        public_flags INTEGER NOT NULL CHECK (
            public_flags >= 0 AND public_flags <= 4294967295
        ),
        section INTEGER NOT NULL CHECK (section >= 0 AND section <= 65535),
        section_offset INTEGER NOT NULL CHECK (
            section_offset >= 0 AND section_offset <= 4294967295
        ),
        resolved_va INTEGER CHECK (
            resolved_va IS NULL OR (resolved_va >= 0 AND resolved_va <= 4294967295)
        ),
        address_group_id TEXT,
        owner_encoding TEXT,
        qualifier_encoding TEXT,
        role_encoding TEXT NOT NULL CHECK (length(role_encoding) > 0),
        parse_status TEXT NOT NULL CHECK (length(parse_status) > 0),
        is_template_owner INTEGER NOT NULL CHECK (is_template_owner IN (0, 1)),
        is_template_qualifier INTEGER NOT NULL CHECK (is_template_qualifier IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id)
            REFERENCES xbox_vftable_extractions(extraction_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (vftable_record_id, program_id)
            REFERENCES xbox_vftable_symbol_records(vftable_record_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id)
            ON DELETE RESTRICT,
        UNIQUE (assertion_id, extraction_id, program_id),
        UNIQUE (extraction_id, vftable_record_id),
        CHECK ((resolved_va IS NULL) = (address_group_id IS NULL))
    )
    """,
    """
    CREATE TABLE xbox_vftable_address_observations (
        address_observation_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        source_address_group_id TEXT NOT NULL CHECK (length(source_address_group_id) > 0),
        address_group_id TEXT NOT NULL,
        table_va INTEGER NOT NULL CHECK (table_va >= 0 AND table_va <= 4294967295),
        member_count INTEGER NOT NULL CHECK (member_count > 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id)
            REFERENCES xbox_vftable_extractions(extraction_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id)
            ON DELETE RESTRICT,
        UNIQUE (address_observation_id, extraction_id, program_id),
        UNIQUE (extraction_id, source_address_group_id),
        UNIQUE (extraction_id, table_va)
    )
    """,
    """
    CREATE TABLE xbox_vftable_address_members (
        membership_id TEXT PRIMARY KEY,
        address_observation_id TEXT NOT NULL,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        is_ranked INTEGER NOT NULL DEFAULT 0 CHECK (is_ranked = 0),
        vftable_record_id TEXT NOT NULL,
        canonical_name_id TEXT NOT NULL
            REFERENCES xbox_vftable_name_identities(canonical_name_id)
            ON DELETE RESTRICT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (address_observation_id, extraction_id, program_id)
            REFERENCES xbox_vftable_address_observations(
                address_observation_id, extraction_id, program_id
            ) ON DELETE RESTRICT,
        FOREIGN KEY (extraction_id, vftable_record_id)
            REFERENCES xbox_vftable_symbol_assertions(
                extraction_id, vftable_record_id
            ) ON DELETE RESTRICT,
        UNIQUE (address_observation_id, source_ordinal),
        UNIQUE (address_observation_id, vftable_record_id)
    )
    """,
    """
    CREATE TABLE xbox_vftable_pointer_runs (
        pointer_run_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        source_run_id TEXT NOT NULL CHECK (length(source_run_id) > 0),
        address_observation_id TEXT NOT NULL,
        table_address_group_id TEXT NOT NULL,
        table_va INTEGER NOT NULL CHECK (table_va >= 0 AND table_va <= 4294967295),
        observed_pointer_count INTEGER NOT NULL CHECK (observed_pointer_count >= 0),
        termination_kind TEXT NOT NULL CHECK (length(termination_kind) > 0),
        termination_va INTEGER CHECK (
            termination_va IS NULL OR
            (termination_va >= 0 AND termination_va <= 4294967295)
        ),
        termination_word BLOB CHECK (
            termination_word IS NULL OR
            (typeof(termination_word) = 'blob' AND length(termination_word) = 4)
        ),
        next_vftable_address_group_id TEXT,
        next_vftable_va INTEGER CHECK (
            next_vftable_va IS NULL OR
            (next_vftable_va >= 0 AND next_vftable_va <= 4294967295)
        ),
        known_boundary_slot_index INTEGER CHECK (
            known_boundary_slot_index IS NULL OR known_boundary_slot_index >= 0
        ),
        boundary_relation TEXT NOT NULL CHECK (length(boundary_relation) > 0),
        extent_semantics TEXT NOT NULL DEFAULT
            'observed_pointer_prefix_not_declared_extent'
            CHECK (extent_semantics = 'observed_pointer_prefix_not_declared_extent'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (address_observation_id, extraction_id, program_id)
            REFERENCES xbox_vftable_address_observations(
                address_observation_id, extraction_id, program_id
            ) ON DELETE RESTRICT,
        FOREIGN KEY (table_address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (next_vftable_address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id)
            ON DELETE RESTRICT,
        UNIQUE (pointer_run_id, extraction_id, program_id),
        UNIQUE (extraction_id, source_run_id),
        UNIQUE (extraction_id, address_observation_id),
        CHECK (
            (next_vftable_va IS NULL) =
            (next_vftable_address_group_id IS NULL)
        )
    )
    """,
    """
    CREATE TABLE xbox_vftable_pointer_run_symbols (
        run_symbol_id TEXT PRIMARY KEY,
        pointer_run_id TEXT NOT NULL,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        membership_role TEXT NOT NULL CHECK (membership_role IN ('table', 'next')),
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        vftable_record_id TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (pointer_run_id, extraction_id, program_id)
            REFERENCES xbox_vftable_pointer_runs(
                pointer_run_id, extraction_id, program_id
            ) ON DELETE RESTRICT,
        FOREIGN KEY (extraction_id, vftable_record_id)
            REFERENCES xbox_vftable_symbol_assertions(
                extraction_id, vftable_record_id
            ) ON DELETE RESTRICT,
        UNIQUE (pointer_run_id, membership_role, source_ordinal),
        UNIQUE (pointer_run_id, membership_role, vftable_record_id)
    )
    """,
    """
    CREATE TABLE xbox_vftable_pointer_slots (
        pointer_slot_id TEXT PRIMARY KEY,
        source_slot_id TEXT NOT NULL CHECK (length(source_slot_id) > 0),
        pointer_run_id TEXT NOT NULL,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        slot_index INTEGER NOT NULL CHECK (slot_index >= 0),
        slot_va INTEGER NOT NULL CHECK (slot_va >= 0 AND slot_va <= 4294967295),
        slot_address_group_id TEXT NOT NULL,
        target_va INTEGER NOT NULL CHECK (target_va >= 0 AND target_va <= 4294967295),
        target_address_group_id TEXT NOT NULL,
        raw_word BLOB NOT NULL CHECK (
            typeof(raw_word) = 'blob' AND length(raw_word) = 4
        ),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (pointer_run_id, extraction_id, program_id)
            REFERENCES xbox_vftable_pointer_runs(
                pointer_run_id, extraction_id, program_id
            ) ON DELETE RESTRICT,
        FOREIGN KEY (slot_address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (target_address_group_id, program_id)
            REFERENCES address_groups(address_group_id, program_id)
            ON DELETE RESTRICT,
        UNIQUE (extraction_id, source_slot_id),
        UNIQUE (pointer_run_id, slot_index)
    )
    """,
    """
    CREATE TABLE xbox_vftable_diagnostics (
        diagnostic_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        program_id TEXT NOT NULL,
        diagnostic_scope TEXT NOT NULL CHECK (
            diagnostic_scope IN ('symbol_extraction', 'pointer_run', 'pointer_scan')
        ),
        pointer_run_id TEXT,
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        subject_id TEXT,
        code TEXT NOT NULL CHECK (length(code) > 0),
        message TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, program_id)
            REFERENCES xbox_vftable_extractions(extraction_id, program_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (pointer_run_id, extraction_id, program_id)
            REFERENCES xbox_vftable_pointer_runs(
                pointer_run_id, extraction_id, program_id
            ) ON DELETE RESTRICT,
        CHECK (
            (diagnostic_scope = 'pointer_run') = (pointer_run_id IS NOT NULL)
        )
    )
    """,
    """
    CREATE INDEX xbox_vftable_symbol_assertions_by_address
        ON xbox_vftable_symbol_assertions(
            program_id, address_group_id, extraction_id, vftable_record_id
        )
    """,
    """
    CREATE INDEX xbox_vftable_address_members_by_record
        ON xbox_vftable_address_members(
            extraction_id, vftable_record_id, address_observation_id
        )
    """,
    """
    CREATE INDEX xbox_vftable_pointer_slots_by_target
        ON xbox_vftable_pointer_slots(
            program_id, target_address_group_id, extraction_id, pointer_slot_id
        )
    """,
    """
    CREATE INDEX xbox_vftable_diagnostics_by_code
        ON xbox_vftable_diagnostics(extraction_id, code, diagnostic_id)
    """,
    """
    CREATE TABLE sdk_source_trees (
        source_tree_sha256 TEXT PRIMARY KEY CHECK (
            length(source_tree_sha256) = 71 AND
            substr(source_tree_sha256, 1, 7) = 'sha256:' AND
            substr(source_tree_sha256, 8) NOT GLOB '*[^0-9a-f]*'
        ),
        file_count INTEGER NOT NULL CHECK (file_count >= 0),
        total_byte_count INTEGER NOT NULL CHECK (total_byte_count >= 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE TABLE sdk_source_tree_files (
        source_file_id TEXT PRIMARY KEY,
        source_tree_sha256 TEXT NOT NULL
            REFERENCES sdk_source_trees(source_tree_sha256) ON DELETE RESTRICT,
        relative_path TEXT NOT NULL CHECK (length(relative_path) > 0),
        relative_path_casefold TEXT NOT NULL CHECK (length(relative_path_casefold) > 0),
        source_file_sha256 TEXT NOT NULL CHECK (
            length(source_file_sha256) = 64 AND
            source_file_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (
            source_file_id, source_tree_sha256, relative_path,
            source_file_sha256
        ),
        UNIQUE (source_tree_sha256, relative_path),
        UNIQUE (source_tree_sha256, relative_path_casefold)
    )
    """,
    """
    CREATE TABLE sdk_extractions (
        extraction_id TEXT PRIMARY KEY,
        source_tree_sha256 TEXT NOT NULL
            REFERENCES sdk_source_trees(source_tree_sha256) ON DELETE RESTRICT,
        pc_program_id TEXT NOT NULL REFERENCES programs(program_id) ON DELETE RESTRICT,
        pc_address_space TEXT NOT NULL DEFAULT 'ram'
            CHECK (length(pc_address_space) > 0),
        files_scanned INTEGER NOT NULL CHECK (files_scanned >= 0),
        prototype_count INTEGER NOT NULL CHECK (prototype_count >= 0),
        unique_prototype_address_count INTEGER NOT NULL CHECK (
            unique_prototype_address_count >= 0 AND
            unique_prototype_address_count <= prototype_count
        ),
        game_prototype_address_count INTEGER NOT NULL CHECK (
            game_prototype_address_count >= 0 AND
            game_prototype_address_count <= prototype_count
        ),
        geck_prototype_address_count INTEGER NOT NULL CHECK (
            geck_prototype_address_count >= 0 AND
            geck_prototype_address_count <= prototype_count
        ),
        call_target_count INTEGER NOT NULL CHECK (call_target_count >= 0),
        data_address_count INTEGER NOT NULL CHECK (data_address_count >= 0),
        diagnostic_count INTEGER NOT NULL CHECK (diagnostic_count >= 0),
        prototype_join_count INTEGER NOT NULL CHECK (prototype_join_count >= 0),
        call_target_join_count INTEGER NOT NULL CHECK (call_target_join_count >= 0),
        data_join_count INTEGER NOT NULL CHECK (data_join_count >= 0),
        definitive_game_link_count INTEGER NOT NULL CHECK (
            definitive_game_link_count >= 0
        ),
        unspecified_entry_candidate_count INTEGER NOT NULL CHECK (
            unspecified_entry_candidate_count >= 0
        ),
        boundary_candidate_count INTEGER NOT NULL CHECK (boundary_candidate_count >= 0),
        boundary_container_count INTEGER NOT NULL CHECK (boundary_container_count >= 0),
        provenance_id TEXT NOT NULL REFERENCES provenance(provenance_id)
            ON DELETE RESTRICT,
        details_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (extraction_id, source_tree_sha256),
        UNIQUE (extraction_id, pc_program_id)
    )
    """,
    """
    CREATE TABLE sdk_prototype_observations (
        prototype_observation_id TEXT PRIMARY KEY,
        source_tree_sha256 TEXT NOT NULL,
        source_observation_id TEXT NOT NULL CHECK (length(source_observation_id) > 0),
        source_file_id TEXT NOT NULL,
        program_variant TEXT NOT NULL CHECK (
            program_variant IN ('game', 'geck', 'unspecified_pc')
        ),
        address INTEGER NOT NULL CHECK (address >= 0 AND address <= 4294967295),
        declared_name TEXT NOT NULL CHECK (length(declared_name) > 0),
        signature TEXT NOT NULL,
        evidence_kind TEXT NOT NULL CHECK (length(evidence_kind) > 0),
        source_path TEXT NOT NULL CHECK (length(source_path) > 0),
        source_file_sha256 TEXT NOT NULL CHECK (
            length(source_file_sha256) = 64 AND
            source_file_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        address_line INTEGER NOT NULL CHECK (address_line > 0),
        declaration_line INTEGER NOT NULL CHECK (declaration_line > 0),
        source_text TEXT NOT NULL,
        address_ordinal INTEGER NOT NULL CHECK (address_ordinal >= 0),
        declaration_text TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (
            source_file_id, source_tree_sha256, source_path, source_file_sha256
        ) REFERENCES sdk_source_tree_files(
            source_file_id, source_tree_sha256, relative_path, source_file_sha256
        ) ON DELETE RESTRICT,
        UNIQUE (prototype_observation_id, source_tree_sha256),
        UNIQUE (source_tree_sha256, source_observation_id)
    )
    """,
    """
    CREATE TABLE sdk_call_target_observations (
        call_target_observation_id TEXT PRIMARY KEY,
        source_tree_sha256 TEXT NOT NULL,
        source_observation_id TEXT NOT NULL CHECK (length(source_observation_id) > 0),
        source_file_id TEXT NOT NULL,
        program_variant TEXT NOT NULL CHECK (
            program_variant IN ('game', 'geck', 'unspecified_pc')
        ),
        address INTEGER NOT NULL CHECK (address >= 0 AND address <= 4294967295),
        invocation_kind TEXT NOT NULL CHECK (length(invocation_kind) > 0),
        helper_name TEXT,
        calling_convention TEXT,
        rendered_return_type TEXT,
        parameter_types_known INTEGER NOT NULL CHECK (parameter_types_known IN (0, 1)),
        rendered_target_type TEXT,
        enclosing_declared_name TEXT,
        enclosing_owner_hint TEXT,
        enclosing_signature TEXT,
        declaration_text TEXT,
        source_path TEXT NOT NULL CHECK (length(source_path) > 0),
        source_file_sha256 TEXT NOT NULL CHECK (
            length(source_file_sha256) = 64 AND
            source_file_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        call_line INTEGER NOT NULL CHECK (call_line > 0),
        declaration_line INTEGER CHECK (declaration_line IS NULL OR declaration_line > 0),
        source_text TEXT NOT NULL,
        address_ordinal INTEGER NOT NULL CHECK (address_ordinal >= 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (
            source_file_id, source_tree_sha256, source_path, source_file_sha256
        ) REFERENCES sdk_source_tree_files(
            source_file_id, source_tree_sha256, relative_path, source_file_sha256
        ) ON DELETE RESTRICT,
        UNIQUE (call_target_observation_id, source_tree_sha256),
        UNIQUE (source_tree_sha256, source_observation_id)
    )
    """,
    """
    CREATE TABLE sdk_call_parameter_types (
        parameter_type_id TEXT PRIMARY KEY,
        call_target_observation_id TEXT NOT NULL
            REFERENCES sdk_call_target_observations(call_target_observation_id)
            ON DELETE RESTRICT,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        rendered_type TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (call_target_observation_id, ordinal)
    )
    """,
    """
    CREATE TABLE sdk_call_argument_expressions (
        argument_expression_id TEXT PRIMARY KEY,
        call_target_observation_id TEXT NOT NULL
            REFERENCES sdk_call_target_observations(call_target_observation_id)
            ON DELETE RESTRICT,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        expression TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (call_target_observation_id, ordinal)
    )
    """,
    """
    CREATE TABLE sdk_data_observations (
        data_observation_id TEXT PRIMARY KEY,
        source_tree_sha256 TEXT NOT NULL,
        source_observation_id TEXT NOT NULL CHECK (length(source_observation_id) > 0),
        source_file_id TEXT NOT NULL,
        program_variant TEXT NOT NULL CHECK (
            program_variant IN ('game', 'geck', 'unspecified_pc')
        ),
        address INTEGER NOT NULL CHECK (address >= 0 AND address <= 4294967295),
        data_kind TEXT NOT NULL CHECK (length(data_kind) > 0),
        declared_name TEXT NOT NULL CHECK (length(declared_name) > 0),
        member_name TEXT NOT NULL CHECK (length(member_name) > 0),
        declared_type TEXT NOT NULL,
        owner_name TEXT,
        owner_basis TEXT,
        declaration_text TEXT NOT NULL,
        source_path TEXT NOT NULL CHECK (length(source_path) > 0),
        source_file_sha256 TEXT NOT NULL CHECK (
            length(source_file_sha256) = 64 AND
            source_file_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        declaration_line INTEGER NOT NULL CHECK (declaration_line > 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (
            source_file_id, source_tree_sha256, source_path, source_file_sha256
        ) REFERENCES sdk_source_tree_files(
            source_file_id, source_tree_sha256, relative_path, source_file_sha256
        ) ON DELETE RESTRICT,
        UNIQUE (data_observation_id, source_tree_sha256),
        UNIQUE (source_tree_sha256, source_observation_id)
    )
    """,
    """
    CREATE TABLE sdk_prototype_extraction_assertions (
        assertion_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        source_tree_sha256 TEXT NOT NULL,
        prototype_observation_id TEXT NOT NULL,
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, source_tree_sha256)
            REFERENCES sdk_extractions(extraction_id, source_tree_sha256)
            ON DELETE RESTRICT,
        FOREIGN KEY (prototype_observation_id, source_tree_sha256)
            REFERENCES sdk_prototype_observations(
                prototype_observation_id, source_tree_sha256
            ) ON DELETE RESTRICT,
        UNIQUE (extraction_id, source_ordinal),
        UNIQUE (extraction_id, prototype_observation_id)
    )
    """,
    """
    CREATE TABLE sdk_call_target_extraction_assertions (
        assertion_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        source_tree_sha256 TEXT NOT NULL,
        call_target_observation_id TEXT NOT NULL,
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, source_tree_sha256)
            REFERENCES sdk_extractions(extraction_id, source_tree_sha256)
            ON DELETE RESTRICT,
        FOREIGN KEY (call_target_observation_id, source_tree_sha256)
            REFERENCES sdk_call_target_observations(
                call_target_observation_id, source_tree_sha256
            ) ON DELETE RESTRICT,
        UNIQUE (extraction_id, source_ordinal),
        UNIQUE (extraction_id, call_target_observation_id)
    )
    """,
    """
    CREATE TABLE sdk_data_extraction_assertions (
        assertion_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        source_tree_sha256 TEXT NOT NULL,
        data_observation_id TEXT NOT NULL,
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, source_tree_sha256)
            REFERENCES sdk_extractions(extraction_id, source_tree_sha256)
            ON DELETE RESTRICT,
        FOREIGN KEY (data_observation_id, source_tree_sha256)
            REFERENCES sdk_data_observations(data_observation_id, source_tree_sha256)
            ON DELETE RESTRICT,
        UNIQUE (extraction_id, source_ordinal),
        UNIQUE (extraction_id, data_observation_id)
    )
    """,
    """
    CREATE TABLE sdk_diagnostics (
        diagnostic_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        source_tree_sha256 TEXT NOT NULL,
        source_file_id TEXT NOT NULL,
        source_path TEXT NOT NULL CHECK (length(source_path) > 0),
        source_file_sha256 TEXT NOT NULL CHECK (
            length(source_file_sha256) = 64 AND
            source_file_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        code TEXT NOT NULL CHECK (length(code) > 0),
        line INTEGER NOT NULL CHECK (line > 0),
        message TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, source_tree_sha256)
            REFERENCES sdk_extractions(extraction_id, source_tree_sha256)
            ON DELETE RESTRICT,
        FOREIGN KEY (
            source_file_id, source_tree_sha256, source_path, source_file_sha256
        ) REFERENCES sdk_source_tree_files(
            source_file_id, source_tree_sha256, relative_path, source_file_sha256
        ) ON DELETE RESTRICT,
        UNIQUE (extraction_id, source_ordinal)
    )
    """,
    """
    CREATE TABLE sdk_code_inventory_joins (
        code_join_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        source_tree_sha256 TEXT NOT NULL,
        observation_kind TEXT NOT NULL CHECK (
            observation_kind IN ('prototype', 'call_target')
        ),
        prototype_observation_id TEXT,
        call_target_observation_id TEXT,
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        program_variant TEXT NOT NULL CHECK (
            program_variant IN ('game', 'geck', 'unspecified_pc')
        ),
        address INTEGER NOT NULL CHECK (address >= 0 AND address <= 4294967295),
        classification TEXT NOT NULL CHECK (length(classification) > 0),
        section_name TEXT,
        section_executable INTEGER CHECK (section_executable IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, source_tree_sha256)
            REFERENCES sdk_extractions(extraction_id, source_tree_sha256)
            ON DELETE RESTRICT,
        FOREIGN KEY (prototype_observation_id, source_tree_sha256)
            REFERENCES sdk_prototype_observations(
                prototype_observation_id, source_tree_sha256
            ) ON DELETE RESTRICT,
        FOREIGN KEY (call_target_observation_id, source_tree_sha256)
            REFERENCES sdk_call_target_observations(
                call_target_observation_id, source_tree_sha256
            ) ON DELETE RESTRICT,
        UNIQUE (extraction_id, observation_kind, source_ordinal),
        CHECK (
            (observation_kind = 'prototype' AND
             prototype_observation_id IS NOT NULL AND
             call_target_observation_id IS NULL) OR
            (observation_kind = 'call_target' AND
             prototype_observation_id IS NULL AND
             call_target_observation_id IS NOT NULL)
        ),
        CHECK ((section_name IS NULL) = (section_executable IS NULL))
    )
    """,
    """
    CREATE TABLE sdk_game_exact_entry_links (
        code_join_id TEXT PRIMARY KEY
            REFERENCES sdk_code_inventory_joins(code_join_id) ON DELETE RESTRICT,
        function_id TEXT NOT NULL REFERENCES functions(function_id) ON DELETE RESTRICT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE TABLE sdk_unspecified_exact_entry_candidates (
        code_join_id TEXT PRIMARY KEY
            REFERENCES sdk_code_inventory_joins(code_join_id) ON DELETE RESTRICT,
        candidate_function_id TEXT NOT NULL
            REFERENCES functions(function_id) ON DELETE RESTRICT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
    """,
    """
    CREATE TABLE sdk_data_inventory_joins (
        data_join_id TEXT PRIMARY KEY,
        extraction_id TEXT NOT NULL,
        source_tree_sha256 TEXT NOT NULL,
        data_observation_id TEXT NOT NULL,
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        program_variant TEXT NOT NULL CHECK (
            program_variant IN ('game', 'geck', 'unspecified_pc')
        ),
        address INTEGER NOT NULL CHECK (address >= 0 AND address <= 4294967295),
        data_kind TEXT NOT NULL CHECK (length(data_kind) > 0),
        classification TEXT NOT NULL CHECK (length(classification) > 0),
        section_name TEXT,
        section_executable INTEGER CHECK (section_executable IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, source_tree_sha256)
            REFERENCES sdk_extractions(extraction_id, source_tree_sha256)
            ON DELETE RESTRICT,
        FOREIGN KEY (data_observation_id, source_tree_sha256)
            REFERENCES sdk_data_observations(data_observation_id, source_tree_sha256)
            ON DELETE RESTRICT,
        UNIQUE (extraction_id, source_ordinal),
        UNIQUE (extraction_id, data_observation_id),
        CHECK ((section_name IS NULL) = (section_executable IS NULL))
    )
    """,
    """
    CREATE TABLE sdk_boundary_candidates (
        boundary_candidate_id TEXT PRIMARY KEY,
        source_candidate_id TEXT NOT NULL CHECK (length(source_candidate_id) > 0),
        extraction_id TEXT NOT NULL,
        source_tree_sha256 TEXT NOT NULL,
        code_join_id TEXT NOT NULL
            REFERENCES sdk_code_inventory_joins(code_join_id) ON DELETE RESTRICT,
        prototype_observation_id TEXT NOT NULL,
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        address INTEGER NOT NULL CHECK (address >= 0 AND address <= 4294967295),
        inventory_classification TEXT NOT NULL
            CHECK (length(inventory_classification) > 0),
        candidate_reason TEXT NOT NULL CHECK (length(candidate_reason) > 0),
        containing_entry_count INTEGER NOT NULL CHECK (containing_entry_count >= 0),
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (extraction_id, source_tree_sha256)
            REFERENCES sdk_extractions(extraction_id, source_tree_sha256)
            ON DELETE RESTRICT,
        FOREIGN KEY (prototype_observation_id, source_tree_sha256)
            REFERENCES sdk_prototype_observations(
                prototype_observation_id, source_tree_sha256
            ) ON DELETE RESTRICT,
        UNIQUE (extraction_id, source_candidate_id),
        UNIQUE (extraction_id, source_ordinal),
        UNIQUE (extraction_id, code_join_id)
    )
    """,
    """
    CREATE TABLE sdk_boundary_candidate_containers (
        container_id TEXT PRIMARY KEY,
        boundary_candidate_id TEXT NOT NULL
            REFERENCES sdk_boundary_candidates(boundary_candidate_id)
            ON DELETE RESTRICT,
        source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
        entry_address INTEGER NOT NULL CHECK (
            entry_address >= 0 AND entry_address <= 4294967295
        ),
        address_group_id TEXT NOT NULL REFERENCES address_groups(address_group_id)
            ON DELETE RESTRICT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (boundary_candidate_id, source_ordinal),
        UNIQUE (boundary_candidate_id, entry_address)
    )
    """,
    """
    CREATE INDEX sdk_prototype_observations_by_address
        ON sdk_prototype_observations(
            program_variant, address, source_tree_sha256, prototype_observation_id
        )
    """,
    """
    CREATE INDEX sdk_call_target_observations_by_address
        ON sdk_call_target_observations(
            program_variant, address, source_tree_sha256, call_target_observation_id
        )
    """,
    """
    CREATE INDEX sdk_data_observations_by_address
        ON sdk_data_observations(
            program_variant, address, source_tree_sha256, data_observation_id
        )
    """,
    """
    CREATE INDEX sdk_code_inventory_joins_by_classification
        ON sdk_code_inventory_joins(
            extraction_id, classification, observation_kind, source_ordinal
        )
    """,
    """
    CREATE INDEX sdk_data_inventory_joins_by_classification
        ON sdk_data_inventory_joins(extraction_id, classification, source_ordinal)
    """,
    """
    CREATE INDEX sdk_diagnostics_by_code
        ON sdk_diagnostics(extraction_id, code, source_ordinal)
    """,
    """
    CREATE TRIGGER validate_xbox_vftable_extraction_platform_insert
    BEFORE INSERT ON xbox_vftable_extractions
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM programs
            WHERE program_id = NEW.program_id AND platform = 'xbox360'
        ) THEN RAISE(ABORT, 'vftable extraction program is not Xbox 360') END;
    END
    """,
    """
    CREATE TRIGGER validate_xbox_vftable_record_platform_insert
    BEFORE INSERT ON xbox_vftable_symbol_records
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM programs
            WHERE program_id = NEW.program_id AND platform = 'xbox360'
        ) THEN RAISE(ABORT, 'vftable record program is not Xbox 360') END;
    END
    """,
    """
    CREATE TRIGGER validate_xbox_vftable_assertion_address_insert
    BEFORE INSERT ON xbox_vftable_symbol_assertions
    WHEN NEW.address_group_id IS NOT NULL
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM address_groups address
            JOIN programs program USING (program_id)
            WHERE address.address_group_id = NEW.address_group_id
              AND address.program_id = NEW.program_id
              AND address.address_space = 'xbox-va'
              AND address.address = NEW.resolved_va
              AND program.platform = 'xbox360'
        ) THEN RAISE(ABORT, 'vftable symbol address is not matching Xbox VA') END;
    END
    """,
    """
    CREATE TRIGGER validate_xbox_vftable_address_observation_insert
    BEFORE INSERT ON xbox_vftable_address_observations
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM address_groups address
            JOIN programs program USING (program_id)
            WHERE address.address_group_id = NEW.address_group_id
              AND address.program_id = NEW.program_id
              AND address.address_space = 'xbox-va'
              AND address.address = NEW.table_va
              AND program.platform = 'xbox360'
        ) THEN RAISE(ABORT, 'vftable table address is not matching Xbox VA') END;
    END
    """,
    """
    CREATE TRIGGER validate_xbox_vftable_pointer_run_addresses_insert
    BEFORE INSERT ON xbox_vftable_pointer_runs
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM address_groups address
            JOIN programs program USING (program_id)
            WHERE address.address_group_id = NEW.table_address_group_id
              AND address.program_id = NEW.program_id
              AND address.address_space = 'xbox-va'
              AND address.address = NEW.table_va
              AND program.platform = 'xbox360'
        ) THEN RAISE(ABORT, 'vftable pointer-run table is not matching Xbox VA') END;
        SELECT CASE WHEN NEW.next_vftable_address_group_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM address_groups address
            WHERE address.address_group_id = NEW.next_vftable_address_group_id
              AND address.program_id = NEW.program_id
              AND address.address_space = 'xbox-va'
              AND address.address = NEW.next_vftable_va
        ) THEN RAISE(ABORT, 'vftable pointer-run boundary is not matching Xbox VA') END;
    END
    """,
    """
    CREATE TRIGGER validate_xbox_vftable_pointer_slot_addresses_insert
    BEFORE INSERT ON xbox_vftable_pointer_slots
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM address_groups address
            JOIN programs program USING (program_id)
            WHERE address.address_group_id = NEW.slot_address_group_id
              AND address.program_id = NEW.program_id
              AND address.address_space = 'xbox-va'
              AND address.address = NEW.slot_va
              AND program.platform = 'xbox360'
        ) THEN RAISE(ABORT, 'vftable slot is not matching Xbox VA') END;
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM address_groups address
            WHERE address.address_group_id = NEW.target_address_group_id
              AND address.program_id = NEW.program_id
              AND address.address_space = 'xbox-va'
              AND address.address = NEW.target_va
        ) THEN RAISE(ABORT, 'vftable slot target is not matching Xbox VA') END;
    END
    """,
    """
    CREATE TRIGGER protect_vftable_program_platform_update
    BEFORE UPDATE OF platform ON programs
    WHEN NEW.platform <> 'xbox360' AND (
        EXISTS (
            SELECT 1 FROM xbox_vftable_extractions extraction
            WHERE extraction.program_id = OLD.program_id
        ) OR EXISTS (
            SELECT 1 FROM xbox_vftable_symbol_records record
            WHERE record.program_id = OLD.program_id
        )
    )
    BEGIN
        SELECT RAISE(ABORT, 'program with vftable evidence must remain Xbox 360');
    END
    """,
    """
    CREATE TRIGGER protect_vftable_address_identity_update
    BEFORE UPDATE OF program_id, address_space, address ON address_groups
    WHEN EXISTS (
        SELECT 1 FROM xbox_vftable_symbol_assertions item
        WHERE item.address_group_id = OLD.address_group_id
    ) OR EXISTS (
        SELECT 1 FROM xbox_vftable_address_observations item
        WHERE item.address_group_id = OLD.address_group_id
    ) OR EXISTS (
        SELECT 1 FROM xbox_vftable_pointer_runs item
        WHERE item.table_address_group_id = OLD.address_group_id
           OR item.next_vftable_address_group_id = OLD.address_group_id
    ) OR EXISTS (
        SELECT 1 FROM xbox_vftable_pointer_slots item
        WHERE item.slot_address_group_id = OLD.address_group_id
           OR item.target_address_group_id = OLD.address_group_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'vftable address identity is immutable');
    END
    """,
    """
    CREATE TRIGGER validate_sdk_extraction_platform_insert
    BEFORE INSERT ON sdk_extractions
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM programs
            WHERE program_id = NEW.pc_program_id AND platform = 'pc'
        ) THEN RAISE(ABORT, 'SDK inventory program is not PC') END;
    END
    """,
    """
    CREATE TRIGGER validate_sdk_code_join_observation_insert
    BEFORE INSERT ON sdk_code_inventory_joins
    BEGIN
        SELECT CASE WHEN NOT (
            (NEW.observation_kind = 'prototype' AND EXISTS (
                SELECT 1
                FROM sdk_prototype_extraction_assertions membership
                JOIN sdk_prototype_observations observation
                  USING (prototype_observation_id, source_tree_sha256)
                WHERE membership.extraction_id = NEW.extraction_id
                  AND membership.source_tree_sha256 = NEW.source_tree_sha256
                  AND membership.prototype_observation_id = NEW.prototype_observation_id
                  AND membership.source_ordinal = NEW.source_ordinal
                  AND observation.program_variant = NEW.program_variant
                  AND observation.address = NEW.address
            )) OR
            (NEW.observation_kind = 'call_target' AND EXISTS (
                SELECT 1
                FROM sdk_call_target_extraction_assertions membership
                JOIN sdk_call_target_observations observation
                  USING (call_target_observation_id, source_tree_sha256)
                WHERE membership.extraction_id = NEW.extraction_id
                  AND membership.source_tree_sha256 = NEW.source_tree_sha256
                  AND membership.call_target_observation_id = NEW.call_target_observation_id
                  AND membership.source_ordinal = NEW.source_ordinal
                  AND observation.program_variant = NEW.program_variant
                  AND observation.address = NEW.address
            ))
        ) THEN RAISE(ABORT, 'SDK code join disagrees with source observation') END;
    END
    """,
    """
    CREATE TRIGGER validate_sdk_data_join_observation_insert
    BEFORE INSERT ON sdk_data_inventory_joins
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1
            FROM sdk_data_extraction_assertions membership
            JOIN sdk_data_observations observation
              USING (data_observation_id, source_tree_sha256)
            WHERE membership.extraction_id = NEW.extraction_id
              AND membership.source_tree_sha256 = NEW.source_tree_sha256
              AND membership.data_observation_id = NEW.data_observation_id
              AND membership.source_ordinal = NEW.source_ordinal
              AND observation.program_variant = NEW.program_variant
              AND observation.address = NEW.address
              AND observation.data_kind = NEW.data_kind
        ) THEN RAISE(ABORT, 'SDK data join disagrees with source observation') END;
    END
    """,
    """
    CREATE TRIGGER validate_sdk_game_exact_entry_link_insert
    BEFORE INSERT ON sdk_game_exact_entry_links
    BEGIN
        SELECT CASE WHEN EXISTS (
            SELECT 1 FROM sdk_unspecified_exact_entry_candidates candidate
            WHERE candidate.code_join_id = NEW.code_join_id
        ) OR NOT EXISTS (
            SELECT 1
            FROM sdk_code_inventory_joins joined
            JOIN sdk_extractions extraction USING (extraction_id)
            JOIN functions function ON function.function_id = NEW.function_id
            JOIN address_groups address
              ON address.address_group_id = function.address_group_id
             AND address.program_id = function.program_id
            JOIN programs program ON program.program_id = function.program_id
            WHERE joined.code_join_id = NEW.code_join_id
              AND joined.program_variant = 'game'
              AND joined.classification = 'pc_function_entry'
              AND function.program_id = extraction.pc_program_id
              AND address.address_space = extraction.pc_address_space
              AND address.address = joined.address
              AND program.platform = 'pc'
        ) THEN RAISE(ABORT, 'invalid definitive GAME SDK entry link') END;
    END
    """,
    """
    CREATE TRIGGER validate_sdk_unspecified_entry_candidate_insert
    BEFORE INSERT ON sdk_unspecified_exact_entry_candidates
    BEGIN
        SELECT CASE WHEN EXISTS (
            SELECT 1 FROM sdk_game_exact_entry_links definitive
            WHERE definitive.code_join_id = NEW.code_join_id
        ) OR NOT EXISTS (
            SELECT 1
            FROM sdk_code_inventory_joins joined
            JOIN sdk_extractions extraction USING (extraction_id)
            JOIN functions function
              ON function.function_id = NEW.candidate_function_id
            JOIN address_groups address
              ON address.address_group_id = function.address_group_id
             AND address.program_id = function.program_id
            JOIN programs program ON program.program_id = function.program_id
            WHERE joined.code_join_id = NEW.code_join_id
              AND joined.program_variant = 'unspecified_pc'
              AND joined.classification = 'pc_function_entry_variant_unspecified'
              AND function.program_id = extraction.pc_program_id
              AND address.address_space = extraction.pc_address_space
              AND address.address = joined.address
              AND program.platform = 'pc'
        ) THEN RAISE(ABORT, 'invalid unspecified SDK entry candidate') END;
    END
    """,
    """
    CREATE TRIGGER validate_sdk_boundary_candidate_insert
    BEFORE INSERT ON sdk_boundary_candidates
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1
            FROM sdk_code_inventory_joins joined
            JOIN sdk_prototype_observations observation
              ON observation.prototype_observation_id = NEW.prototype_observation_id
             AND observation.source_tree_sha256 = NEW.source_tree_sha256
            WHERE joined.code_join_id = NEW.code_join_id
              AND joined.extraction_id = NEW.extraction_id
              AND joined.source_tree_sha256 = NEW.source_tree_sha256
              AND joined.observation_kind = 'prototype'
              AND joined.prototype_observation_id = NEW.prototype_observation_id
              AND joined.address = NEW.address
              AND joined.program_variant IN ('game', 'unspecified_pc')
              AND joined.classification = NEW.inventory_classification
              AND joined.classification IN (
                  'pc_executable_non_entry',
                  'pc_executable_non_entry_variant_unspecified'
              )
              AND observation.evidence_kind = 'create_object_macro'
              AND NEW.candidate_reason =
                  'sdk_create_object_target_is_executable_non_entry'
        ) THEN RAISE(ABORT, 'invalid SDK boundary candidate') END;
    END
    """,
    """
    CREATE TRIGGER validate_sdk_boundary_container_insert
    BEFORE INSERT ON sdk_boundary_candidate_containers
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1
            FROM sdk_boundary_candidates candidate
            JOIN sdk_extractions extraction USING (extraction_id)
            JOIN address_groups address
              ON address.address_group_id = NEW.address_group_id
            JOIN programs program ON program.program_id = address.program_id
            WHERE candidate.boundary_candidate_id = NEW.boundary_candidate_id
              AND address.program_id = extraction.pc_program_id
              AND address.address_space = extraction.pc_address_space
              AND address.address = NEW.entry_address
              AND program.platform = 'pc'
              AND EXISTS (
                  SELECT 1 FROM functions function
                  WHERE function.program_id = extraction.pc_program_id
                    AND function.address_group_id = address.address_group_id
              )
        ) THEN RAISE(ABORT, 'SDK boundary container is not an existing PC entry') END;
    END
    """,
    """
    CREATE TRIGGER protect_sdk_program_platform_update
    BEFORE UPDATE OF platform ON programs
    WHEN NEW.platform <> 'pc' AND EXISTS (
        SELECT 1 FROM sdk_extractions extraction
        WHERE extraction.pc_program_id = OLD.program_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'program with SDK inventory joins must remain PC');
    END
    """,
    """
    CREATE TRIGGER protect_sdk_linked_function_endpoint_update
    BEFORE UPDATE OF program_id, address_group_id ON functions
    WHEN EXISTS (
        SELECT 1 FROM sdk_game_exact_entry_links link
        WHERE link.function_id = OLD.function_id
    ) OR EXISTS (
        SELECT 1 FROM sdk_unspecified_exact_entry_candidates candidate
        WHERE candidate.candidate_function_id = OLD.function_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'SDK-linked function endpoint is immutable');
    END
    """,
    """
    CREATE TRIGGER protect_sdk_address_identity_update
    BEFORE UPDATE OF program_id, address_space, address ON address_groups
    WHEN EXISTS (
        SELECT 1 FROM sdk_boundary_candidate_containers container
        WHERE container.address_group_id = OLD.address_group_id
    ) OR EXISTS (
        SELECT 1
        FROM functions function
        LEFT JOIN sdk_game_exact_entry_links definitive
          ON definitive.function_id = function.function_id
        LEFT JOIN sdk_unspecified_exact_entry_candidates candidate
          ON candidate.candidate_function_id = function.function_id
        WHERE function.address_group_id = OLD.address_group_id
          AND (definitive.code_join_id IS NOT NULL OR candidate.code_join_id IS NOT NULL)
    )
    BEGIN
        SELECT RAISE(ABORT, 'SDK-linked PC address identity is immutable');
    END
    """,
) + tuple(
    f"""
    CREATE TRIGGER reject_{table}_update
    BEFORE UPDATE ON {table}
    BEGIN
        SELECT RAISE(ABORT, '{label} are immutable');
    END
    """
    for table, label in (
        ('xbox_vftable_extractions', 'vftable extractions'),
        ('xbox_vftable_name_identities', 'vftable name identities'),
        ('xbox_vftable_symbol_records', 'vftable symbol records'),
        ('xbox_vftable_symbol_assertions', 'vftable symbol assertions'),
        ('xbox_vftable_address_observations', 'vftable address observations'),
        ('xbox_vftable_address_members', 'vftable address memberships'),
        ('xbox_vftable_pointer_runs', 'vftable pointer runs'),
        ('xbox_vftable_pointer_run_symbols', 'vftable pointer-run memberships'),
        ('xbox_vftable_pointer_slots', 'vftable pointer slots'),
        ('xbox_vftable_diagnostics', 'vftable diagnostics'),
        ('sdk_source_trees', 'SDK source trees'),
        ('sdk_source_tree_files', 'SDK source-tree files'),
        ('sdk_extractions', 'SDK extractions'),
        ('sdk_prototype_observations', 'SDK prototype observations'),
        ('sdk_call_target_observations', 'SDK call-target observations'),
        ('sdk_call_parameter_types', 'SDK call parameter types'),
        ('sdk_call_argument_expressions', 'SDK call arguments'),
        ('sdk_data_observations', 'SDK data observations'),
        ('sdk_prototype_extraction_assertions', 'SDK prototype assertions'),
        ('sdk_call_target_extraction_assertions', 'SDK call-target assertions'),
        ('sdk_data_extraction_assertions', 'SDK data assertions'),
        ('sdk_diagnostics', 'SDK diagnostics'),
        ('sdk_code_inventory_joins', 'SDK code joins'),
        ('sdk_game_exact_entry_links', 'SDK definitive GAME links'),
        ('sdk_unspecified_exact_entry_candidates', 'SDK unspecified candidates'),
        ('sdk_data_inventory_joins', 'SDK data joins'),
        ('sdk_boundary_candidates', 'SDK boundary candidates'),
        ('sdk_boundary_candidate_containers', 'SDK boundary containers'),
    )
) + tuple(
    f"""
    CREATE TRIGGER reject_{table}_delete
    BEFORE DELETE ON {table}
    BEGIN
        SELECT RAISE(ABORT, '{label} are immutable');
    END
    """
    for table, label in (
        ('xbox_vftable_extractions', 'vftable extractions'),
        ('xbox_vftable_name_identities', 'vftable name identities'),
        ('xbox_vftable_symbol_records', 'vftable symbol records'),
        ('xbox_vftable_symbol_assertions', 'vftable symbol assertions'),
        ('xbox_vftable_address_observations', 'vftable address observations'),
        ('xbox_vftable_address_members', 'vftable address memberships'),
        ('xbox_vftable_pointer_runs', 'vftable pointer runs'),
        ('xbox_vftable_pointer_run_symbols', 'vftable pointer-run memberships'),
        ('xbox_vftable_pointer_slots', 'vftable pointer slots'),
        ('xbox_vftable_diagnostics', 'vftable diagnostics'),
        ('sdk_source_trees', 'SDK source trees'),
        ('sdk_source_tree_files', 'SDK source-tree files'),
        ('sdk_extractions', 'SDK extractions'),
        ('sdk_prototype_observations', 'SDK prototype observations'),
        ('sdk_call_target_observations', 'SDK call-target observations'),
        ('sdk_call_parameter_types', 'SDK call parameter types'),
        ('sdk_call_argument_expressions', 'SDK call arguments'),
        ('sdk_data_observations', 'SDK data observations'),
        ('sdk_prototype_extraction_assertions', 'SDK prototype assertions'),
        ('sdk_call_target_extraction_assertions', 'SDK call-target assertions'),
        ('sdk_data_extraction_assertions', 'SDK data assertions'),
        ('sdk_diagnostics', 'SDK diagnostics'),
        ('sdk_code_inventory_joins', 'SDK code joins'),
        ('sdk_game_exact_entry_links', 'SDK definitive GAME links'),
        ('sdk_unspecified_exact_entry_candidates', 'SDK unspecified candidates'),
        ('sdk_data_inventory_joins', 'SDK data joins'),
        ('sdk_boundary_candidates', 'SDK boundary candidates'),
        ('sdk_boundary_candidate_containers', 'SDK boundary containers'),
    )
)


def _canonical_schema_sql(sql: str) -> tuple[str, ...]:
    """Tokenize schema SQL while ignoring presentation-only differences.

    SQLite retains much of the original DDL formatting in ``sqlite_schema``.
    Comparing raw SQL would therefore reject harmless whitespace, comments,
    keyword case, or a trailing semicolon.  This small tokenizer canonicalizes
    those features while preserving quoted string contents and every structural
    token in tables, indexes, and triggers.
    """

    tokens: list[str] = []
    index = 0
    length = len(sql)
    while index < length:
        character = sql[index]
        if character.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if sql.startswith("/*", index):
            close = sql.find("*/", index + 2)
            index = length if close < 0 else close + 2
            continue

        if character == "'":
            index += 1
            value: list[str] = []
            while index < length:
                if sql[index] == "'":
                    if index + 1 < length and sql[index + 1] == "'":
                        value.append("'")
                        index += 2
                        continue
                    index += 1
                    break
                value.append(sql[index])
                index += 1
            tokens.append("string:" + "".join(value))
            continue

        if character in {'"', "`", "["}:
            close_character = "]" if character == "[" else character
            index += 1
            value = []
            while index < length:
                if sql[index] == close_character:
                    if (
                        index + 1 < length
                        and sql[index + 1] == close_character
                    ):
                        value.append(close_character)
                        index += 2
                        continue
                    index += 1
                    break
                value.append(sql[index])
                index += 1
            tokens.append("word:" + "".join(value).casefold())
            continue

        if character.isalpha() or character in {"_", "$"}:
            end = index + 1
            while end < length and (
                sql[end].isalnum() or sql[end] in {"_", "$"}
            ):
                end += 1
            tokens.append("word:" + sql[index:end].casefold())
            index = end
            continue

        if character.isdigit():
            end = index + 1
            while end < length and (
                sql[end].isalnum() or sql[end] in {".", "_"}
            ):
                end += 1
            tokens.append("number:" + sql[index:end].casefold())
            index = end
            continue

        operator = next(
            (
                candidate
                for candidate in ("->>", "||", "<<", ">>", "<=", ">=", "<>", "!=", "==", "->")
                if sql.startswith(candidate, index)
            ),
            None,
        )
        if operator is not None:
            tokens.append("symbol:" + operator)
            index += len(operator)
            continue
        tokens.append("symbol:" + character)
        index += 1

    # A final statement terminator is presentation, whereas semicolons inside a
    # trigger body remain structural tokens.
    while tokens and tokens[-1] == "symbol:;":
        tokens.pop()
    return tuple(tokens)


def _schema_catalog(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, str, str, tuple[str, ...]], ...]:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, sql
        FROM main.sqlite_schema
        WHERE type IN ('table', 'index', 'trigger', 'view')
          AND name NOT GLOB 'sqlite_*'
        """
    ).fetchall()
    catalog = []
    for object_type, name, table_name, sql in rows:
        catalog.append(
            (
                str(object_type).casefold(),
                str(name).casefold(),
                str(table_name).casefold(),
                _canonical_schema_sql(str(sql)) if sql is not None else (),
            )
        )
    return tuple(sorted(catalog))


def _schema_catalog_fingerprint(
    catalog: tuple[tuple[str, str, str, tuple[str, ...]], ...]
) -> str:
    encoded = json.dumps(catalog, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _expected_schema_catalog() -> tuple[
    tuple[str, str, str, tuple[str, ...]], ...
]:
    expected = sqlite3.connect(":memory:")
    try:
        for statement in SCHEMA_STATEMENTS:
            expected.execute(statement)
        return _schema_catalog(expected)
    finally:
        expected.close()


def _validate_schema_shape(connection: sqlite3.Connection) -> None:
    expected = _expected_schema_catalog()
    actual = _schema_catalog(connection)
    if actual == expected:
        return

    expected_by_key = {(item[0], item[1]): item for item in expected}
    actual_by_key = {(item[0], item[1]): item for item in actual}
    missing = sorted(set(expected_by_key) - set(actual_by_key))
    unexpected = sorted(set(actual_by_key) - set(expected_by_key))
    changed = sorted(
        key
        for key in set(expected_by_key) & set(actual_by_key)
        if expected_by_key[key] != actual_by_key[key]
    )

    def labels(items: list[tuple[str, str]]) -> str:
        return ", ".join(f"{kind}:{name}" for kind, name in items) or "none"

    raise SchemaError(
        f"schema v{SCHEMA_VERSION} shape mismatch "
        f"(expected sha256:{_schema_catalog_fingerprint(expected)}, "
        f"actual sha256:{_schema_catalog_fingerprint(actual)}; "
        f"missing={labels(missing)}; changed={labels(changed)}; "
        f"unexpected={labels(unexpected)})"
    )


def _user_version(connection: sqlite3.Connection) -> int:
    return int(connection.execute("PRAGMA user_version").fetchone()[0])


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Create the current schema in an empty database, atomically.

    Existing current-version databases are only validated.  A database with user
    tables but no atlas version is rejected instead of being overwritten.
    """

    version = _user_version(connection)
    if version > SCHEMA_VERSION:
        raise SchemaError(
            f"database schema version {version} is newer than supported "
            f"version {SCHEMA_VERSION}"
        )
    if version == SCHEMA_VERSION:
        validate_schema(connection)
        return
    if version != 0:
        raise SchemaError(f"no migration is available from schema version {version}")

    user_tables = connection.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        """
    ).fetchall()
    if user_tables:
        raise SchemaError("refusing to initialize a non-empty, unversioned database")

    try:
        connection.execute("BEGIN IMMEDIATE")
        for statement in SCHEMA_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO atlas_meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


def validate_schema(connection: sqlite3.Connection) -> None:
    """Reject databases with an incompatible identity, version, or shape."""

    version = _user_version(connection)
    if version != SCHEMA_VERSION:
        raise SchemaError(
            f"expected schema version {SCHEMA_VERSION}, found {version}"
        )
    application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
    if application_id != APPLICATION_ID:
        raise SchemaError(
            f"unexpected SQLite application_id 0x{application_id:08x}"
        )
    _validate_schema_shape(connection)
    row = connection.execute(
        "SELECT value FROM atlas_meta WHERE key = 'schema_version'"
    ).fetchone()
    if row is None or row[0] != str(SCHEMA_VERSION):
        raise SchemaError("atlas_meta schema version does not match PRAGMA user_version")
