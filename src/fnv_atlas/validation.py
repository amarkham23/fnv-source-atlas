"""Cross-table semantic validation for a completed source-atlas database."""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import sqlite3

from .ppc_control_flow import CALL_RELEVANT_V1_ROLES


_CALL_RELEVANT_SQL = ", ".join(
    f"'{role}'" for role in sorted(CALL_RELEVANT_V1_ROLES)
)
_CALL_RELEVANT_SOURCE_COUNT_SQL = " + ".join(
    "COALESCE(CAST(json_extract(e.details_json, "
    f"'$.source_summary.use_roles.{role}') AS INTEGER), 0)"
    for role in sorted(CALL_RELEVANT_V1_ROLES)
)


def _sha256_hex(value: object) -> str | None:
    """SQLite scalar used to audit stored opaque CodeView bytes."""

    if value is None:
        return None
    try:
        payload = bytes(value)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(payload).hexdigest()


def _codeview_record_sha256(leaf_kind: object, body: object) -> str | None:
    """Return the lossless tag-record digest used by ``tpi_layouts``."""

    try:
        leaf_bytes = int(leaf_kind).to_bytes(2, "little", signed=False)
        payload = bytes(body)
    except (OverflowError, TypeError, ValueError):
        return None
    return hashlib.sha256(leaf_bytes + payload).hexdigest()


def _latin1_bytes(value: object) -> bytes | None:
    """Return the byte-preserving encoding used by CodeView symbol names."""

    try:
        return str(value).encode("latin-1")
    except (UnicodeEncodeError, ValueError):
        return None


def _vftable_record_matches(
    raw_record: object,
    record_length: object,
    record_kind_code: object,
    public_flags: object,
    section_offset: object,
    section: object,
    decorated_name_bytes: object,
) -> int:
    """Audit the decoded fields of one losslessly stored S_PUB32 record."""

    try:
        raw = bytes(raw_record)
        name = bytes(decorated_name_bytes)
        length = int(record_length)
        nul = raw.find(b"\0", 14)
        valid = (
            len(raw) == length + 2
            and len(raw) >= 15
            and int.from_bytes(raw[0:2], "little") == length
            and int.from_bytes(raw[2:4], "little") == int(record_kind_code)
            and int.from_bytes(raw[4:8], "little") == int(public_flags)
            and int.from_bytes(raw[8:12], "little") == int(section_offset)
            and int.from_bytes(raw[12:14], "little") == int(section)
            and nul >= 14
            and raw[14:nul] == name
        )
    except (OverflowError, TypeError, ValueError):
        return 0
    return int(valid)


def _big_endian_u32_matches(raw_word: object, value: object) -> int:
    try:
        raw = bytes(raw_word)
        expected = int(value)
    except (TypeError, ValueError):
        return 0
    return int(
        len(raw) == 4
        and 0 <= expected <= 0xFFFFFFFF
        and raw == expected.to_bytes(4, "big")
    )


def _unicode_casefold(value: object) -> str | None:
    return value.casefold() if isinstance(value, str) else None


def _sdk_relative_path_valid(value: object) -> int:
    if not isinstance(value, str):
        return 0
    parsed = PurePosixPath(value)
    return int(
        bool(value)
        and "\\" not in value
        and not value.startswith("/")
        and parsed.as_posix() == value
        and all(part not in {"", ".", ".."} for part in parsed.parts)
        and not (parsed.parts and ":" in parsed.parts[0])
    )


class _SdkSourceTreeSha256:
    """Order-independent SQLite aggregate for the canonical SDK tree ID."""

    def __init__(self) -> None:
        self._files: list[tuple[str, int, str]] = []
        self._invalid = False

    def step(self, path: object, byte_length: object, digest: object) -> None:
        # LEFT JOIN supplies one all-NULL row for a legitimately empty tree.
        if path is None and byte_length is None and digest is None:
            return
        try:
            path_text = str(path)
            length = int(byte_length)
            digest_text = str(digest)
            if (
                not _sdk_relative_path_valid(path_text)
                or length < 0
                or len(digest_text) != 64
                or digest_text != digest_text.lower()
                or any(character not in "0123456789abcdef" for character in digest_text)
            ):
                raise ValueError
            bytes.fromhex(digest_text)
        except (TypeError, ValueError):
            self._invalid = True
            return
        self._files.append((path_text, length, digest_text))

    def finalize(self) -> str | None:
        if self._invalid:
            return None
        ordered = sorted(self._files, key=lambda item: item[0].casefold())
        folded_paths: set[str] = set()
        digest = hashlib.sha256()
        for path, byte_length, file_digest in ordered:
            folded = path.casefold()
            if folded in folded_paths:
                return None
            folded_paths.add(folded)
            path_bytes = path.encode("utf-8")
            digest.update(len(path_bytes).to_bytes(4, "big"))
            digest.update(path_bytes)
            digest.update(byte_length.to_bytes(8, "big"))
            digest.update(bytes.fromhex(file_digest))
        return f"sha256:{digest.hexdigest()}"


SEMANTIC_CHECKS: tuple[tuple[str, str], ...] = (
    (
        "functions_without_assertions",
        """
        SELECT COUNT(*)
        FROM functions f
        WHERE NOT EXISTS (
            SELECT 1 FROM function_assertions a
            WHERE a.function_id = f.function_id
        )
        """,
    ),
    (
        "function_projection_without_matching_assertion",
        """
        SELECT COUNT(*)
        FROM functions f
        WHERE NOT EXISTS (
            SELECT 1 FROM function_assertions a
            WHERE a.function_id = f.function_id
              AND a.kind = f.kind
              AND a.type_index IS f.type_index
              AND a.module_id IS f.module_id
              AND a.symbol_record_kind IS f.symbol_record_kind
              AND a.details_json = f.details_json
        )
        """,
    ),
    (
        "function_names_without_assertions",
        """
        SELECT COUNT(*)
        FROM function_names n
        WHERE NOT EXISTS (
            SELECT 1 FROM function_name_assertions a
            WHERE a.name_id = n.name_id
        )
        """,
    ),
    (
        "function_name_projection_without_matching_assertion",
        """
        SELECT COUNT(*)
        FROM function_names n
        WHERE NOT EXISTS (
            SELECT 1 FROM function_name_assertions a
            WHERE a.name_id = n.name_id
              AND a.is_primary = n.is_primary
              AND a.provenance_id IS n.provenance_id
              AND a.details_json = n.details_json
        )
        """,
    ),
    (
        "function_source_ranges_without_assertions",
        """
        SELECT COUNT(*)
        FROM function_source_ranges r
        WHERE NOT EXISTS (
            SELECT 1 FROM function_source_range_assertions a
            WHERE a.function_id = r.function_id
              AND a.source_file_id = r.source_file_id
              AND a.line_start = r.line_start
              AND a.column_start = r.column_start
        )
        """,
    ),
    (
        "source_range_projection_without_matching_assertion",
        """
        SELECT COUNT(*)
        FROM function_source_ranges r
        WHERE NOT EXISTS (
            SELECT 1 FROM function_source_range_assertions a
            WHERE a.function_id = r.function_id
              AND a.source_file_id = r.source_file_id
              AND a.line_start = r.line_start
              AND a.column_start = r.column_start
              AND a.line_end IS r.line_end
              AND a.column_end IS r.column_end
              AND a.is_primary = r.is_primary
              AND a.provenance_id IS r.provenance_id
              AND a.details_json = r.details_json
        )
        """,
    ),
    (
        "class_names_without_assertions",
        """
        SELECT COUNT(*)
        FROM class_names n
        WHERE NOT EXISTS (
            SELECT 1 FROM class_name_assertions a
            WHERE a.name_id = n.name_id
        )
        """,
    ),
    (
        "class_name_projection_without_matching_assertion",
        """
        SELECT COUNT(*)
        FROM class_names n
        WHERE NOT EXISTS (
            SELECT 1 FROM class_name_assertions a
            WHERE a.name_id = n.name_id
              AND a.is_primary = n.is_primary
              AND a.provenance_id IS n.provenance_id
              AND a.details_json = n.details_json
        )
        """,
    ),
    (
        "vtable_slots_without_assertions",
        """
        SELECT COUNT(*)
        FROM vtable_slots s
        WHERE NOT EXISTS (
            SELECT 1 FROM vtable_slot_assertions a
            WHERE a.vtable_id = s.vtable_id
              AND a.slot_index = s.slot_index
        )
        """,
    ),
    (
        "vtable_slot_projection_without_matching_assertion",
        """
        SELECT COUNT(*)
        FROM vtable_slots s
        WHERE NOT EXISTS (
            SELECT 1 FROM vtable_slot_assertions a
            WHERE a.vtable_id = s.vtable_id
              AND a.slot_index = s.slot_index
              AND a.target_address_group_id IS s.target_address_group_id
              AND a.unresolved_target_id IS s.unresolved_target_id
              AND a.declared_type_index IS s.declared_type_index
              AND a.provenance_id IS s.provenance_id
              AND a.details_json = s.details_json
        )
        """,
    ),
    (
        "xbox_functions_missing_signature",
        """
        SELECT COUNT(*)
        FROM functions f
        LEFT JOIN function_signatures s USING (function_id)
        JOIN programs p ON p.program_id = f.program_id
        WHERE p.platform = 'xbox360' AND f.type_index IS NOT NULL
          AND s.function_id IS NULL
        """,
    ),
    (
        "signature_argument_count_mismatch",
        """
        SELECT COUNT(*) FROM (
            SELECT s.function_id
            FROM function_signatures s
            LEFT JOIN function_signature_arguments a USING (function_id)
            WHERE s.resolution_status = 'resolved'
            GROUP BY s.function_id, s.argument_list_count
            HAVING COUNT(a.position) <> s.argument_list_count
        )
        """,
    ),
    (
        "unresolved_signature_has_arguments",
        """
        SELECT COUNT(*)
        FROM function_signatures s
        JOIN function_signature_arguments a USING (function_id)
        WHERE s.resolution_status = 'unresolved'
        """,
    ),
    (
        "vtable_observed_slot_count_mismatch",
        """
        SELECT COUNT(*) FROM (
            SELECT v.vtable_id,
                   CAST(json_extract(v.details_json, '$.observed_slot_count') AS INTEGER)
                       AS observed,
                   COUNT(vs.slot_index) AS stored
            FROM vtables v
            LEFT JOIN vtable_slots vs USING (vtable_id)
            GROUP BY v.vtable_id
            HAVING observed IS NULL OR observed <> stored
        )
        """,
    ),
    (
        "vtable_slot_indices_noncontiguous",
        """
        SELECT COUNT(*) FROM (
            SELECT v.vtable_id,
                   CAST(json_extract(v.details_json, '$.observed_slot_count') AS INTEGER)
                       AS observed,
                   COUNT(vs.slot_index) AS stored,
                   MIN(vs.slot_index) AS first_index,
                   MAX(vs.slot_index) AS last_index
            FROM vtables v
            LEFT JOIN vtable_slots vs USING (vtable_id)
            GROUP BY v.vtable_id
            HAVING (observed = 0 AND stored <> 0)
                OR (observed > 0 AND
                    (stored <> observed OR first_index <> 0 OR last_index <> observed - 1))
        )
        """,
    ),
    (
        "variadic_signature_marker_mismatch",
        """
        SELECT COUNT(*) FROM (
            SELECT s.function_id, s.is_variadic, s.argument_list_count,
                   COALESCE(SUM(a.is_vararg_marker), 0) AS marker_count,
                   MAX(CASE WHEN a.is_vararg_marker = 1 THEN a.position END)
                       AS marker_position
            FROM function_signatures s
            LEFT JOIN function_signature_arguments a USING (function_id)
            WHERE s.resolution_status = 'resolved'
            GROUP BY s.function_id, s.is_variadic, s.argument_list_count
            HAVING marker_count <> s.is_variadic
                OR (s.is_variadic = 1 AND
                    marker_position <> s.argument_list_count - 1)
        )
        """,
    ),
    (
        "match_claims_without_evidence",
        """
        SELECT COUNT(*)
        FROM match_claims c
        WHERE NOT EXISTS (
                  SELECT 1 FROM claim_evidence e
                  WHERE e.claim_id = c.claim_id
              )
          AND NOT EXISTS (
                  SELECT 1
                  FROM match_hypothesis_alternatives a
                  JOIN match_hypothesis_evidence e
                    USING (hypothesis_set_id)
                  WHERE a.claim_id = c.claim_id
              )
          AND NOT EXISTS (
                  SELECT 1
                  FROM match_hypothesis_alternatives a
                  JOIN match_hypothesis_alternative_evidence e
                    USING (alternative_id)
                  WHERE a.claim_id = c.claim_id
              )
        """,
    ),
    (
        "hypothesis_sets_without_alternatives",
        """
        SELECT COUNT(*)
        FROM match_hypothesis_sets h
        WHERE NOT EXISTS (
            SELECT 1 FROM match_hypothesis_alternatives a
            WHERE a.hypothesis_set_id = h.hypothesis_set_id
        )
        """,
    ),
    (
        "hypothesis_sets_without_evidence",
        """
        SELECT COUNT(*)
        FROM match_hypothesis_sets h
        WHERE NOT EXISTS (
            SELECT 1 FROM match_hypothesis_evidence e
            WHERE e.hypothesis_set_id = h.hypothesis_set_id
        )
          AND NOT EXISTS (
            SELECT 1
            FROM match_hypothesis_alternatives a
            JOIN match_hypothesis_alternative_evidence e
              USING (alternative_id)
            WHERE a.hypothesis_set_id = h.hypothesis_set_id
        )
        """,
    ),
    (
        "fold_groups_with_fewer_than_two_members",
        """
        SELECT COUNT(*) FROM (
            SELECT g.fold_group_id, COUNT(m.function_id) AS members
            FROM fold_groups g
            LEFT JOIN fold_group_members m USING (fold_group_id)
            GROUP BY g.fold_group_id HAVING members < 2
        )
        """,
    ),
    (
        "vtable_slot_alignments_without_structural_evidence",
        """
        SELECT COUNT(*)
        FROM vtable_slot_alignments a
        WHERE NOT EXISTS (
            SELECT 1
            FROM match_hypothesis_evidence e
            WHERE e.hypothesis_set_id = a.hypothesis_set_id
              AND e.independence_group = 'class_slot_alignment'
        )
        """,
    ),
    (
        "vtable_slot_alignment_alternative_count_mismatch",
        """
        SELECT COUNT(*) FROM (
            SELECT a.slot_alignment_id,
                   COUNT(h.alternative_id) AS alternatives
            FROM vtable_slot_alignments a
            LEFT JOIN match_hypothesis_alternatives h
              USING (hypothesis_set_id)
            GROUP BY a.slot_alignment_id
            HAVING alternatives <> 1
        )
        """,
    ),
    (
        "vtable_slot_alignment_index_mismatch",
        """
        SELECT COUNT(*)
        FROM vtable_slot_alignments
        WHERE pc_slot_index <> xbox_slot_index
        """,
    ),
    (
        "vtable_slot_alignment_pc_endpoint_mismatch",
        """
        SELECT COUNT(*)
        FROM vtable_slot_alignments a
        JOIN vtable_slots s
          ON s.vtable_id = a.pc_vtable_id
         AND s.slot_index = a.pc_slot_index
        JOIN match_hypothesis_sets h USING (hypothesis_set_id)
        LEFT JOIN functions f ON f.function_id = h.pc_function_id
        LEFT JOIN unresolved_targets u ON u.target_id = h.pc_target_id
        WHERE s.target_address_group_id IS NULL
           OR COALESCE(f.address_group_id, u.address_group_id)
                <> s.target_address_group_id
        """,
    ),
    (
        "vtable_slot_alignment_pc_endpoint_classification_mismatch",
        """
        SELECT COUNT(*)
        FROM vtable_slot_alignments a
        JOIN vtable_slots s
          ON s.vtable_id = a.pc_vtable_id
         AND s.slot_index = a.pc_slot_index
        JOIN match_hypothesis_sets h USING (hypothesis_set_id)
        LEFT JOIN (
            SELECT address_group_id, COUNT(*) AS function_count
            FROM functions GROUP BY address_group_id
        ) f ON f.address_group_id = s.target_address_group_id
        WHERE (h.pc_function_id IS NOT NULL AND
               COALESCE(f.function_count, 0) <> 1)
           OR (h.pc_target_id IS NOT NULL AND
               COALESCE(f.function_count, 0) <> 0)
        """,
    ),
    (
        "vtable_slot_alignment_scalar_xbox_endpoint_mismatch",
        """
        SELECT COUNT(*)
        FROM vtable_slot_alignments a
        JOIN vtable_slots s
          ON s.vtable_id = a.xbox_vtable_id
         AND s.slot_index = a.xbox_slot_index
        JOIN match_hypothesis_alternatives h
          USING (hypothesis_set_id)
        JOIN match_claims c ON c.claim_id = h.claim_id
        LEFT JOIN functions f ON f.function_id = c.xbox_function_id
        LEFT JOIN unresolved_targets u ON u.target_id = c.xbox_target_id
        WHERE s.target_address_group_id IS NULL
           OR COALESCE(f.address_group_id, u.address_group_id)
                <> s.target_address_group_id
        """,
    ),
    (
        "vtable_slot_alignment_scalar_xbox_classification_mismatch",
        """
        SELECT COUNT(*)
        FROM vtable_slot_alignments a
        JOIN vtable_slots s
          ON s.vtable_id = a.xbox_vtable_id
         AND s.slot_index = a.xbox_slot_index
        JOIN match_hypothesis_alternatives h
          USING (hypothesis_set_id)
        JOIN match_claims c ON c.claim_id = h.claim_id
        LEFT JOIN (
            SELECT address_group_id, COUNT(*) AS function_count
            FROM functions GROUP BY address_group_id
        ) f ON f.address_group_id = s.target_address_group_id
        WHERE (c.xbox_function_id IS NOT NULL AND
               COALESCE(f.function_count, 0) <> 1)
           OR (c.xbox_target_id IS NOT NULL AND
               COALESCE(f.function_count, 0) <> 0)
        """,
    ),
    (
        "vtable_slot_alignment_fold_xbox_endpoint_mismatch",
        """
        SELECT COUNT(*)
        FROM vtable_slot_alignments a
        JOIN vtable_slots s
          ON s.vtable_id = a.xbox_vtable_id
         AND s.slot_index = a.xbox_slot_index
        JOIN match_hypothesis_alternatives h
          USING (hypothesis_set_id)
        WHERE h.xbox_fold_group_id IS NOT NULL
          AND (
              s.target_address_group_id IS NULL
              OR NOT EXISTS (
                  SELECT 1
                  FROM fold_group_members m
                  WHERE m.fold_group_id = h.xbox_fold_group_id
              )
              OR EXISTS (
                  SELECT 1
                  FROM fold_group_members m
                  JOIN functions f USING (function_id, program_id)
                  WHERE m.fold_group_id = h.xbox_fold_group_id
                    AND f.address_group_id <> s.target_address_group_id
              )
          )
        """,
    ),
    (
        "vtable_slot_alignment_fold_xbox_membership_incomplete",
        """
        SELECT COUNT(*)
        FROM vtable_slot_alignments a
        JOIN vtable_slots s
          ON s.vtable_id = a.xbox_vtable_id
         AND s.slot_index = a.xbox_slot_index
        JOIN match_hypothesis_alternatives h
          USING (hypothesis_set_id)
        LEFT JOIN (
            SELECT address_group_id, COUNT(*) AS function_count
            FROM functions GROUP BY address_group_id
        ) f ON f.address_group_id = s.target_address_group_id
        LEFT JOIN (
            SELECT fold_group_id, COUNT(*) AS member_count
            FROM fold_group_members GROUP BY fold_group_id
        ) m ON m.fold_group_id = h.xbox_fold_group_id
        WHERE h.xbox_fold_group_id IS NOT NULL
          AND (COALESCE(f.function_count, 0) <= 1
               OR COALESCE(m.member_count, 0) <> f.function_count)
        """,
    ),
    (
        "vtable_slot_alignment_non_candidate_mapping",
        """
        SELECT COUNT(*)
        FROM vtable_slot_alignments a
        JOIN match_hypothesis_sets h USING (hypothesis_set_id)
        JOIN match_hypothesis_alternatives x USING (hypothesis_set_id)
        LEFT JOIN match_claims c ON c.claim_id = x.claim_id
        WHERE a.status <> 'candidate'
           OR h.status <> 'candidate'
           OR (c.claim_id IS NOT NULL AND
               (c.status <> 'candidate'
                OR c.confidence_label IS NOT NULL
                OR c.confidence_value IS NOT NULL))
        """,
    ),
    (
        "vtable_alignment_provenance_created_function_or_name",
        """
        SELECT
            (SELECT COUNT(*)
             FROM function_assertions a
             JOIN provenance p USING (provenance_id)
             WHERE p.producer = 'fnv_atlas.vtable_hypotheses')
          + (SELECT COUNT(*)
             FROM function_name_assertions a
             JOIN provenance p USING (provenance_id)
             WHERE p.producer = 'fnv_atlas.vtable_hypotheses')
        """,
    ),
    (
        "codeview_type_extraction_summary_mismatch",
        """
        WITH raw_counts AS (
            SELECT assertion.extraction_id,
                   COUNT(*) AS record_count,
                   COALESCE(SUM(length(record.raw_body)), 0) AS body_bytes
            FROM codeview_type_record_assertions assertion
            LEFT JOIN codeview_type_records record
              ON record.type_record_id = assertion.type_record_id
            GROUP BY assertion.extraction_id
        ), tag_counts AS (
            SELECT extraction_id,
                   COUNT(*) AS tag_count,
                   COALESCE(SUM(is_forward_reference = 0), 0) AS definitions,
                   COALESCE(SUM(is_forward_reference = 1), 0) AS forwards
            FROM codeview_tag_layouts
            GROUP BY extraction_id
        ), member_use_counts AS (
            SELECT extraction_id, COUNT(*) AS row_count
            FROM codeview_tag_member_uses
            GROUP BY extraction_id
        ), field_member_counts AS (
            SELECT extraction_id, COUNT(*) AS row_count
            FROM codeview_field_members
            GROUP BY extraction_id
        ), method_overload_counts AS (
            SELECT extraction_id, COUNT(*) AS row_count
            FROM codeview_method_overloads
            GROUP BY extraction_id
        ), diagnostic_counts AS (
            SELECT extraction_id, COUNT(*) AS row_count
            FROM codeview_layout_diagnostics
            GROUP BY extraction_id
        )
        SELECT COUNT(*)
        FROM codeview_type_extractions extraction
        LEFT JOIN raw_counts raw USING (extraction_id)
        LEFT JOIN tag_counts tag USING (extraction_id)
        LEFT JOIN member_use_counts member_use USING (extraction_id)
        LEFT JOIN field_member_counts field_member USING (extraction_id)
        LEFT JOIN method_overload_counts method USING (extraction_id)
        LEFT JOIN diagnostic_counts diagnostic USING (extraction_id)
        WHERE extraction.raw_type_record_count <>
                  COALESCE(raw.record_count, 0)
           OR extraction.raw_body_byte_count <>
                  COALESCE(raw.body_bytes, 0)
           OR extraction.tag_record_count <> COALESCE(tag.tag_count, 0)
           OR extraction.definition_count <> COALESCE(tag.definitions, 0)
           OR extraction.forward_reference_count <> COALESCE(tag.forwards, 0)
           OR extraction.tag_member_occurrence_count <>
                  COALESCE(member_use.row_count, 0)
           OR extraction.physical_field_member_count <>
                  COALESCE(field_member.row_count, 0)
           OR extraction.physical_method_overload_count <>
                  COALESCE(method.row_count, 0)
           OR extraction.diagnostic_count <>
                  COALESCE(diagnostic.row_count, 0)
        """,
    ),
    (
        "codeview_type_record_integrity_mismatch",
        """
        SELECT COUNT(*)
        FROM codeview_type_records record
        WHERE typeof(record.raw_body) <> 'blob'
           OR record.record_length <> length(record.raw_body) + 2
           OR record.raw_body_sha256 IS NOT sha256_hex(record.raw_body)
        """,
    ),
    (
        "codeview_type_records_without_assertions",
        """
        SELECT COUNT(*) FROM (
            SELECT type_record_id FROM codeview_type_records
            EXCEPT
            SELECT type_record_id FROM codeview_type_record_assertions
        ) orphan
        """,
    ),
    (
        "codeview_type_assertion_identity_mismatch",
        """
        SELECT COUNT(*)
        FROM codeview_type_record_assertions assertion
        LEFT JOIN codeview_type_extractions extraction
          ON extraction.extraction_id = assertion.extraction_id
        LEFT JOIN codeview_type_records record
          ON record.type_record_id = assertion.type_record_id
        WHERE extraction.extraction_id IS NULL
           OR record.type_record_id IS NULL
           OR assertion.program_id IS NOT extraction.program_id
           OR assertion.type_namespace IS NOT extraction.type_namespace
           OR assertion.program_id IS NOT record.program_id
           OR assertion.type_namespace IS NOT record.type_namespace
        """,
    ),
    (
        "codeview_tag_record_identity_mismatch",
        """
        SELECT COUNT(*)
        FROM codeview_tag_layouts tag
        LEFT JOIN codeview_type_extractions extraction
          ON extraction.extraction_id = tag.extraction_id
        LEFT JOIN codeview_type_records record
          ON record.type_record_id = tag.type_record_id
        LEFT JOIN codeview_type_record_assertions assertion
          ON assertion.extraction_id = tag.extraction_id
         AND assertion.type_record_id = tag.type_record_id
        WHERE extraction.extraction_id IS NULL
           OR record.type_record_id IS NULL
           OR assertion.assertion_id IS NULL
           OR tag.program_id IS NOT extraction.program_id
           OR tag.type_namespace IS NOT extraction.type_namespace
           OR tag.program_id IS NOT record.program_id
           OR tag.type_namespace IS NOT record.type_namespace
           OR record.leaf_kind IS NOT CASE tag.tag_kind
                  WHEN 'class' THEN 5380
                  WHEN 'structure' THEN 5381
                  WHEN 'union' THEN 5382
                  WHEN 'enum' THEN 5383
              END
           OR tag.record_sha256 IS NOT codeview_record_sha256(
                  record.leaf_kind, record.raw_body
              )
           OR tag.is_forward_reference <> ((tag.properties & 128) <> 0)
        """,
    ),
    (
        "codeview_tag_member_shape_mismatch",
        """
        WITH tag_shapes AS (
            SELECT tag.tag_layout_id,
                   tag.physical_member_occurrence_count AS expected_physical,
                   tag.decoded_member_count AS expected_decoded,
                   tag.is_forward_reference,
                   COUNT(use.member_use_id) AS physical_count,
                   MIN(use.ordinal) AS first_ordinal,
                   MAX(use.ordinal) AS last_ordinal,
                   COALESCE(SUM(CASE
                       WHEN member.member_kind = 'overloaded_method'
                           THEN COALESCE(member.declared_overload_count, 0)
                       WHEN member.member_kind = 'continuation' THEN 0
                       WHEN member.field_member_id IS NOT NULL THEN 1
                       ELSE 0
                   END), 0) AS decoded_count
            FROM codeview_tag_layouts tag
            LEFT JOIN codeview_tag_member_uses use
              ON use.tag_layout_id = tag.tag_layout_id
            LEFT JOIN codeview_field_members member
              ON member.field_member_id = use.field_member_id
            GROUP BY tag.tag_layout_id
        )
        SELECT COUNT(*)
        FROM tag_shapes
        WHERE expected_physical <> physical_count
           OR expected_decoded <> decoded_count
           OR (physical_count > 0 AND (
                  first_ordinal <> 0 OR last_ordinal <> physical_count - 1
              ))
           OR (is_forward_reference = 1 AND physical_count <> 0)
        """,
    ),
    (
        "codeview_field_member_identity_mismatch",
        """
        SELECT COUNT(*)
        FROM codeview_field_members member
        LEFT JOIN codeview_type_extractions extraction
          ON extraction.extraction_id = member.extraction_id
        WHERE extraction.extraction_id IS NULL
           OR member.program_id IS NOT extraction.program_id
           OR NOT EXISTS (
                  SELECT 1
                  FROM codeview_tag_member_uses use
                  WHERE use.extraction_id = member.extraction_id
                    AND use.program_id = member.program_id
                    AND use.field_member_id = member.field_member_id
              )
           OR NOT EXISTS (
                  SELECT 1
                  FROM codeview_type_record_assertions assertion
                  JOIN codeview_type_records record
                    ON record.type_record_id = assertion.type_record_id
                   AND record.program_id = assertion.program_id
                   AND record.type_namespace = assertion.type_namespace
                  WHERE assertion.extraction_id = member.extraction_id
                    AND assertion.program_id = member.program_id
                    AND assertion.type_namespace = 'global-tpi'
                    AND record.type_namespace = 'global-tpi'
                    AND record.type_index =
                        member.source_field_list_type_index
                    AND record.leaf_kind = 4611
              )
        """,
    ),
    (
        "codeview_tag_member_identity_mismatch",
        """
        SELECT COUNT(*)
        FROM codeview_tag_member_uses use
        LEFT JOIN codeview_type_extractions extraction
          ON extraction.extraction_id = use.extraction_id
        LEFT JOIN codeview_tag_layouts tag
          ON tag.tag_layout_id = use.tag_layout_id
        LEFT JOIN codeview_field_members member
          ON member.field_member_id = use.field_member_id
        WHERE extraction.extraction_id IS NULL
           OR tag.tag_layout_id IS NULL
           OR member.field_member_id IS NULL
           OR use.program_id IS NOT extraction.program_id
           OR use.extraction_id IS NOT tag.extraction_id
           OR use.program_id IS NOT tag.program_id
           OR use.extraction_id IS NOT member.extraction_id
           OR use.program_id IS NOT member.program_id
        """,
    ),
    (
        "codeview_method_overload_identity_mismatch",
        """
        WITH method_lists AS (
            SELECT overload.extraction_id, overload.program_id,
                   overload.method_list_type_index,
                   COUNT(*) AS overload_count,
                   MIN(overload.ordinal) AS first_ordinal,
                   MAX(overload.ordinal) AS last_ordinal
            FROM codeview_method_overloads overload
            GROUP BY overload.extraction_id, overload.program_id,
                     overload.method_list_type_index
        )
        SELECT COUNT(*)
        FROM method_lists method
        LEFT JOIN codeview_type_extractions extraction
          ON extraction.extraction_id = method.extraction_id
        WHERE extraction.extraction_id IS NULL
           OR method.program_id IS NOT extraction.program_id
           OR method.first_ordinal <> 0
           OR method.last_ordinal <> method.overload_count - 1
           OR NOT EXISTS (
                  SELECT 1
                  FROM codeview_field_members member
                  WHERE member.extraction_id = method.extraction_id
                    AND member.program_id = method.program_id
                    AND member.method_list_type_index =
                        method.method_list_type_index
              )
           OR NOT EXISTS (
                  SELECT 1
                  FROM codeview_type_record_assertions assertion
                  JOIN codeview_type_records record
                    ON record.type_record_id = assertion.type_record_id
                   AND record.program_id = assertion.program_id
                   AND record.type_namespace = assertion.type_namespace
                  WHERE assertion.extraction_id = method.extraction_id
                    AND assertion.program_id = method.program_id
                    AND assertion.type_namespace = 'global-tpi'
                    AND record.type_namespace = 'global-tpi'
                    AND record.type_index = method.method_list_type_index
                    AND record.leaf_kind = 4614
              )
        """,
    ),
    (
        "codeview_layout_diagnostic_identity_mismatch",
        """
        WITH diagnostic_groups AS (
            SELECT diagnostic.extraction_id, diagnostic.program_id,
                   diagnostic.tag_layout_id,
                   COUNT(*) AS diagnostic_count,
                   MIN(diagnostic.ordinal) AS first_ordinal,
                   MAX(diagnostic.ordinal) AS last_ordinal
            FROM codeview_layout_diagnostics diagnostic
            GROUP BY diagnostic.extraction_id, diagnostic.program_id,
                     diagnostic.tag_layout_id
        )
        SELECT COUNT(*)
        FROM diagnostic_groups diagnostic
        LEFT JOIN codeview_type_extractions extraction
          ON extraction.extraction_id = diagnostic.extraction_id
        LEFT JOIN codeview_tag_layouts tag
          ON tag.tag_layout_id = diagnostic.tag_layout_id
        WHERE extraction.extraction_id IS NULL
           OR tag.tag_layout_id IS NULL
           OR diagnostic.program_id IS NOT extraction.program_id
           OR diagnostic.extraction_id IS NOT tag.extraction_id
           OR diagnostic.program_id IS NOT tag.program_id
           OR diagnostic.first_ordinal <> 0
           OR diagnostic.last_ordinal <> diagnostic.diagnostic_count - 1
        """,
    ),
    (
        "codeview_type_non_xbox_identity",
        """
        SELECT COUNT(*) FROM (
            SELECT extraction.extraction_id AS row_id
            FROM codeview_type_extractions extraction
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
               OR extraction.type_namespace IS NOT 'global-tpi'
            UNION ALL
            SELECT record.type_record_id
            FROM codeview_type_records record
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
               OR record.type_namespace IS NOT 'global-tpi'
            UNION ALL
            SELECT assertion.assertion_id
            FROM codeview_type_record_assertions assertion
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
               OR assertion.type_namespace IS NOT 'global-tpi'
            UNION ALL
            SELECT tag.tag_layout_id
            FROM codeview_tag_layouts tag
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
               OR tag.type_namespace IS NOT 'global-tpi'
            UNION ALL
            SELECT member.field_member_id
            FROM codeview_field_members member
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
            UNION ALL
            SELECT use.member_use_id
            FROM codeview_tag_member_uses use
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
            UNION ALL
            SELECT overload.method_overload_id
            FROM codeview_method_overloads overload
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
            UNION ALL
            SELECT diagnostic.diagnostic_id
            FROM codeview_layout_diagnostics diagnostic
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
        ) violation
        """,
    ),
    (
        "data_symbol_extraction_summary_mismatch",
        """
        WITH assertion_counts AS (
            SELECT assertion.extraction_id,
                   COUNT(*) AS record_count,
                   COALESCE(SUM(assertion.address_group_id IS NOT NULL), 0)
                       AS resolved_count,
                   COALESCE(SUM(assertion.address_group_id IS NULL), 0)
                       AS unresolved_count,
                   COUNT(DISTINCT assertion.address_group_id)
                       AS unique_address_count
            FROM data_symbol_record_assertions assertion
            GROUP BY assertion.extraction_id
        )
        SELECT COUNT(*)
        FROM data_symbol_extractions extraction
        LEFT JOIN assertion_counts actual USING (extraction_id)
        WHERE extraction.record_count <> COALESCE(actual.record_count, 0)
           OR extraction.resolved_record_count <>
                  COALESCE(actual.resolved_count, 0)
           OR extraction.unresolved_record_count <>
                  COALESCE(actual.unresolved_count, 0)
           OR extraction.unique_address_count <>
                  COALESCE(actual.unique_address_count, 0)
        """,
    ),
    (
        "data_symbol_records_without_assertions",
        """
        SELECT COUNT(*) FROM (
            SELECT data_record_id FROM data_symbol_records
            EXCEPT
            SELECT data_record_id FROM data_symbol_record_assertions
        ) orphan
        """,
    ),
    (
        "data_symbol_record_identity_mismatch",
        """
        SELECT COUNT(*)
        FROM data_symbol_records record
        WHERE record.source_record_id IS NOT printf(
                  'x360-data:m%04d:s%04d:o%08X',
                  record.module_index,
                  record.symbol_stream,
                  record.record_offset
              )
        """,
    ),
    (
        "data_symbol_assertion_identity_mismatch",
        """
        SELECT COUNT(*)
        FROM data_symbol_record_assertions assertion
        LEFT JOIN data_symbol_extractions extraction
          ON extraction.extraction_id = assertion.extraction_id
        LEFT JOIN data_symbol_records record
          ON record.data_record_id = assertion.data_record_id
        WHERE extraction.extraction_id IS NULL
           OR record.data_record_id IS NULL
           OR assertion.program_id IS NOT extraction.program_id
           OR assertion.program_id IS NOT record.program_id
        """,
    ),
    (
        "data_symbol_non_xbox_addressing",
        """
        SELECT COUNT(*) FROM (
            SELECT extraction.extraction_id AS row_id
            FROM data_symbol_extractions extraction
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
               OR extraction.address_space IS NOT 'xbox-va'
            UNION ALL
            SELECT record.data_record_id
            FROM data_symbol_records record
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
            UNION ALL
            SELECT assertion.assertion_id
            FROM data_symbol_record_assertions assertion
            LEFT JOIN programs program USING (program_id)
            LEFT JOIN address_groups address
              ON address.address_group_id = assertion.address_group_id
            WHERE program.platform IS NOT 'xbox360'
               OR (assertion.resolved_va IS NULL) <>
                  (assertion.address_group_id IS NULL)
               OR (assertion.address_group_id IS NOT NULL AND (
                      address.address_group_id IS NULL
                      OR address.program_id IS NOT assertion.program_id
                      OR address.address_space IS NOT 'xbox-va'
                      OR address.address IS NOT assertion.resolved_va
                      OR address.address < 0
                      OR address.address > 4294967295
                  ))
        ) violation
        """,
    ),
    (
        "type_data_provenance_created_function_or_name",
        """
        WITH type_data_provenance AS (
            SELECT provenance_id FROM codeview_type_extractions
            UNION
            SELECT provenance_id FROM data_symbol_extractions
        )
        SELECT
            (SELECT COUNT(*)
             FROM function_assertions assertion
             JOIN type_data_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM function_names name
             JOIN type_data_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM function_name_assertions assertion
             JOIN type_data_provenance producer USING (provenance_id))
        """,
    ),
    (
        "type_data_provenance_created_match_state",
        """
        WITH type_data_provenance AS (
            SELECT provenance_id FROM codeview_type_extractions
            UNION
            SELECT provenance_id FROM data_symbol_extractions
        )
        SELECT
            (SELECT COUNT(*)
             FROM match_claims claim
             JOIN type_data_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM match_hypothesis_sets hypothesis
             JOIN type_data_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM claim_evidence evidence
             JOIN type_data_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM match_hypothesis_evidence evidence
             JOIN type_data_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM match_hypothesis_alternative_evidence evidence
             JOIN type_data_provenance producer USING (provenance_id))
        """,
    ),
    (
        "control_flow_source_summary_metadata_mismatch",
        """
        SELECT COUNT(*)
        FROM control_flow_extractions e
        WHERE json_type(e.details_json, '$.source_summary') IS NOT 'object'
           OR CAST(json_extract(
                  e.details_json, '$.source_summary.physical_sites'
              ) AS INTEGER) IS NOT e.source_physical_site_count
           OR CAST(json_extract(
                  e.details_json, '$.source_summary.logical_uses'
              ) AS INTEGER) IS NOT e.source_logical_use_count
           OR COALESCE((
                  SELECT SUM(CAST(role.value AS INTEGER))
                  FROM json_each(
                      e.details_json, '$.source_summary.use_roles'
                  ) role
              ), 0) <> e.source_logical_use_count
           OR COALESCE((
                  SELECT SUM(CAST(status.value AS INTEGER))
                  FROM json_each(
                      e.details_json, '$.source_summary.scan_statuses'
                  ) status
              ), 0) <> e.procedure_scan_count
        """,
    ),
    (
        "control_flow_metadata_row_count_mismatch",
        """
        WITH site_counts AS (
            SELECT extraction_id, COUNT(*) AS row_count
            FROM control_flow_site_assertions
            GROUP BY extraction_id
        ), use_counts AS (
            SELECT extraction_id, COUNT(*) AS row_count
            FROM control_flow_use_assertions
            GROUP BY extraction_id
        ), scan_counts AS (
            SELECT extraction_id, COUNT(*) AS row_count
            FROM control_flow_scans
            GROUP BY extraction_id
        )
        SELECT COUNT(*)
        FROM control_flow_extractions e
        LEFT JOIN site_counts site USING (extraction_id)
        LEFT JOIN use_counts use_count USING (extraction_id)
        LEFT JOIN scan_counts scan USING (extraction_id)
        WHERE COALESCE(site.row_count, 0) <>
                  e.persisted_physical_site_count
           OR COALESCE(use_count.row_count, 0) <>
                  e.persisted_logical_use_count
           OR COALESCE(scan.row_count, 0) <> e.procedure_scan_count
        """,
    ),
    (
        "control_flow_policy_trigger_count_mismatch",
        f"""
        WITH role_counts AS (
            SELECT extraction_id,
                   COUNT(*) AS use_count,
                   SUM(CASE WHEN role IN ({_CALL_RELEVANT_SQL})
                            THEN 1 ELSE 0 END) AS trigger_count
            FROM control_flow_use_assertions
            GROUP BY extraction_id
        )
        SELECT COUNT(*)
        FROM control_flow_extractions e
        LEFT JOIN role_counts role USING (extraction_id)
        WHERE (e.persistence_policy = 'call_relevant_v1' AND (
                  COALESCE(role.trigger_count, 0) <>
                      e.triggering_logical_use_count
                  OR ({_CALL_RELEVANT_SOURCE_COUNT_SQL}) <>
                      e.triggering_logical_use_count
              ))
           OR (e.persistence_policy = 'all_branches_v1' AND (
                  COALESCE(role.use_count, 0) <>
                      e.triggering_logical_use_count
                  OR e.triggering_logical_use_count <>
                      e.source_logical_use_count
              ))
        """,
    ),
    (
        "control_flow_sites_without_policy_trigger_use",
        f"""
        WITH triggering_sites AS (
            SELECT assertion.extraction_id, use.site_id
            FROM control_flow_use_assertions assertion
            JOIN control_flow_uses use USING (use_id, program_id)
            WHERE assertion.role IN ({_CALL_RELEVANT_SQL})
            GROUP BY assertion.extraction_id, use.site_id
        )
        SELECT COUNT(*)
        FROM control_flow_site_assertions site
        JOIN control_flow_extractions extraction USING (extraction_id)
        LEFT JOIN triggering_sites trigger
          ON trigger.extraction_id = site.extraction_id
         AND trigger.site_id = site.site_id
        WHERE extraction.persistence_policy = 'call_relevant_v1'
          AND trigger.site_id IS NULL
        """,
    ),
    (
        "control_flow_sites_without_any_use",
        """
        WITH used_sites AS (
            SELECT assertion.extraction_id, use.site_id
            FROM control_flow_use_assertions assertion
            JOIN control_flow_uses use USING (use_id, program_id)
            GROUP BY assertion.extraction_id, use.site_id
        )
        SELECT COUNT(*)
        FROM control_flow_site_assertions site
        LEFT JOIN used_sites used
          ON used.extraction_id = site.extraction_id
         AND used.site_id = site.site_id
        WHERE used.site_id IS NULL
        """,
    ),
    (
        "control_flow_uses_without_site_assertion",
        """
        SELECT COUNT(*)
        FROM control_flow_use_assertions assertion
        JOIN control_flow_uses use USING (use_id, program_id)
        LEFT JOIN control_flow_site_assertions site
          ON site.extraction_id = assertion.extraction_id
         AND site.program_id = assertion.program_id
         AND site.site_id = use.site_id
        WHERE site.assertion_id IS NULL
        """,
    ),
    (
        "control_flow_uses_without_matching_scan",
        """
        SELECT COUNT(*)
        FROM control_flow_use_assertions assertion
        JOIN control_flow_uses use USING (use_id, program_id)
        LEFT JOIN control_flow_scans scan
          ON scan.extraction_id = assertion.extraction_id
         AND scan.program_id = assertion.program_id
         AND scan.procedure_record_id = use.procedure_record_id
        WHERE scan.scan_id IS NULL OR scan.function_id IS NOT use.function_id
        """,
    ),
    (
        "control_flow_canonical_sites_without_assertions",
        """
        WITH asserted_sites AS (
            SELECT program_id, site_id
            FROM control_flow_site_assertions
            GROUP BY program_id, site_id
        )
        SELECT COUNT(*)
        FROM control_flow_sites site
        LEFT JOIN asserted_sites assertion USING (program_id, site_id)
        WHERE assertion.site_id IS NULL
        """,
    ),
    (
        "control_flow_canonical_uses_without_assertions",
        """
        WITH asserted_uses AS (
            SELECT program_id, use_id
            FROM control_flow_use_assertions
            GROUP BY program_id, use_id
        )
        SELECT COUNT(*)
        FROM control_flow_uses use
        LEFT JOIN asserted_uses assertion USING (program_id, use_id)
        WHERE assertion.use_id IS NULL
        """,
    ),
    (
        "control_flow_scan_use_count_mismatch",
        """
        WITH actual_uses AS (
            SELECT assertion.extraction_id, assertion.program_id,
                   use.procedure_record_id, COUNT(*) AS use_count
            FROM control_flow_use_assertions assertion
            JOIN control_flow_uses use USING (use_id, program_id)
            GROUP BY assertion.extraction_id, assertion.program_id,
                     use.procedure_record_id
        )
        SELECT COUNT(*)
        FROM control_flow_scans scan
        LEFT JOIN actual_uses actual
          ON actual.extraction_id = scan.extraction_id
         AND actual.program_id = scan.program_id
         AND actual.procedure_record_id = scan.procedure_record_id
        WHERE scan.persisted_branch_use_count <>
              COALESCE(actual.use_count, 0)
        """,
    ),
    (
        "control_flow_use_outside_scan_extent",
        """
        SELECT COUNT(*)
        FROM control_flow_use_assertions assertion
        JOIN control_flow_uses use USING (use_id, program_id)
        JOIN control_flow_sites site USING (site_id, program_id)
        JOIN address_groups site_address
          ON site_address.address_group_id = site.address_group_id
         AND site_address.program_id = site.program_id
        JOIN control_flow_scans scan
          ON scan.extraction_id = assertion.extraction_id
         AND scan.program_id = assertion.program_id
         AND scan.procedure_record_id = use.procedure_record_id
        LEFT JOIN address_groups scan_address
          ON scan_address.address_group_id = scan.scan_address_group_id
         AND scan_address.program_id = scan.program_id
        WHERE scan_address.address_group_id IS NULL
           OR site_address.address_space <> scan_address.address_space
           OR site_address.address < scan_address.address
           OR site_address.address >= scan_address.address + scan.scanned_size
        """,
    ),
    (
        "control_flow_scan_endpoint_mismatch",
        """
        SELECT COUNT(*)
        FROM control_flow_scans scan
        LEFT JOIN functions function
          ON function.function_id = scan.function_id
         AND function.program_id = scan.program_id
        LEFT JOIN unresolved_targets target
          ON target.target_id = scan.unresolved_target_id
         AND target.program_id = scan.program_id
        WHERE (scan.function_id IS NOT NULL AND (
                  function.function_id IS NULL OR
                  function.address_group_id IS NOT scan.scan_address_group_id
              ))
           OR (scan.unresolved_target_id IS NOT NULL AND (
                  target.target_id IS NULL OR
                  target.address_group_id IS NOT scan.scan_address_group_id
              ))
           OR ((scan.status = 'unresolved_va') <>
               (scan.scan_address_group_id IS NULL))
        """,
    ),
    (
        "control_flow_raw_endpoint_mismatch",
        """
        SELECT COUNT(*)
        FROM control_flow_site_assertions assertion
        JOIN control_flow_sites site USING (site_id, program_id)
        JOIN address_groups site_address
          ON site_address.address_group_id = site.address_group_id
         AND site_address.program_id = site.program_id
        LEFT JOIN address_groups target_address
          ON target_address.address_group_id = assertion.target_address_group_id
         AND target_address.program_id = assertion.program_id
        WHERE assertion.raw_site_va <> site_address.address
           OR (assertion.target_kind = 'indirect' AND (
                  assertion.raw_target_va IS NOT NULL OR
                  assertion.target_address_group_id IS NOT NULL OR
                  assertion.target_function_id IS NOT NULL OR
                  assertion.target_fold_group_id IS NOT NULL OR
                  assertion.target_record_count <> 0
              ))
           OR (assertion.target_kind <> 'indirect' AND (
                  target_address.address_group_id IS NULL OR
                  assertion.raw_target_va IS NOT target_address.address OR
                  site_address.address_space <> target_address.address_space
              ))
        """,
    ),
    (
        "control_flow_unique_endpoint_cardinality_mismatch",
        """
        WITH function_counts AS (
            SELECT program_id, address_group_id, COUNT(*) AS function_count
            FROM functions
            GROUP BY program_id, address_group_id
        )
        SELECT COUNT(*)
        FROM control_flow_site_assertions assertion
        LEFT JOIN functions function
          ON function.function_id = assertion.target_function_id
         AND function.program_id = assertion.program_id
        LEFT JOIN function_counts count
          ON count.program_id = assertion.program_id
         AND count.address_group_id = assertion.target_address_group_id
        WHERE assertion.target_kind = 'unique_procedure'
          AND (function.function_id IS NULL
               OR function.address_group_id IS NOT
                    assertion.target_address_group_id
               OR COALESCE(count.function_count, 0) <> 1
               OR assertion.target_record_count <> 1)
        """,
    ),
    (
        "control_flow_fold_endpoint_cardinality_mismatch",
        """
        WITH function_counts AS (
            SELECT program_id, address_group_id, COUNT(*) AS function_count
            FROM functions
            GROUP BY program_id, address_group_id
        ), fold_stats AS (
            SELECT group_row.fold_group_id, group_row.program_id,
                   COUNT(member.function_id) AS member_count,
                   MIN(function.address_group_id) AS first_address_group_id,
                   MAX(function.address_group_id) AS last_address_group_id
            FROM fold_groups group_row
            LEFT JOIN fold_group_members member
              ON member.fold_group_id = group_row.fold_group_id
             AND member.program_id = group_row.program_id
            LEFT JOIN functions function
              ON function.function_id = member.function_id
             AND function.program_id = member.program_id
            GROUP BY group_row.fold_group_id, group_row.program_id
        )
        SELECT COUNT(*)
        FROM control_flow_site_assertions assertion
        LEFT JOIN function_counts count
          ON count.program_id = assertion.program_id
         AND count.address_group_id = assertion.target_address_group_id
        LEFT JOIN fold_stats fold
          ON fold.fold_group_id = assertion.target_fold_group_id
         AND fold.program_id = assertion.program_id
        WHERE assertion.target_kind = 'fold_group'
          AND (COALESCE(count.function_count, 0) <= 1
               OR count.function_count IS NOT assertion.target_record_count
               OR fold.member_count IS NOT assertion.target_record_count
               OR fold.first_address_group_id IS NOT
                    assertion.target_address_group_id
               OR fold.last_address_group_id IS NOT
                    assertion.target_address_group_id)
        """,
    ),
    (
        "control_flow_non_entry_endpoint_cardinality_mismatch",
        """
        WITH function_counts AS (
            SELECT program_id, address_group_id, COUNT(*) AS function_count
            FROM functions
            GROUP BY program_id, address_group_id
        )
        SELECT COUNT(*)
        FROM control_flow_site_assertions assertion
        LEFT JOIN function_counts count
          ON count.program_id = assertion.program_id
         AND count.address_group_id = assertion.target_address_group_id
        WHERE assertion.target_kind IN (
                  'executable_non_entry', 'outside_executable'
              )
          AND (COALESCE(count.function_count, 0) <> 0
               OR assertion.target_function_id IS NOT NULL
               OR assertion.target_fold_group_id IS NOT NULL
               OR assertion.target_record_count <> 0)
        """,
    ),
    (
        "control_flow_non_xbox_addressing",
        """
        SELECT COUNT(*) FROM (
            SELECT 'extraction' AS row_kind, extraction.extraction_id AS row_id
            FROM control_flow_extractions extraction
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
            UNION ALL
            SELECT 'site', site.site_id
            FROM control_flow_sites site
            LEFT JOIN programs program USING (program_id)
            LEFT JOIN address_groups address
              ON address.address_group_id = site.address_group_id
             AND address.program_id = site.program_id
            WHERE program.platform IS NOT 'xbox360'
               OR address.address_space IS NOT 'xbox-va'
            UNION ALL
            SELECT 'use-function', use.use_id
            FROM control_flow_uses use
            LEFT JOIN functions function
              ON function.function_id = use.function_id
             AND function.program_id = use.program_id
            LEFT JOIN address_groups address
              ON address.address_group_id = function.address_group_id
             AND address.program_id = function.program_id
            LEFT JOIN programs program ON program.program_id = use.program_id
            WHERE program.platform IS NOT 'xbox360'
               OR address.address_space IS NOT 'xbox-va'
            UNION ALL
            SELECT 'direct-target', assertion.assertion_id
            FROM control_flow_site_assertions assertion
            LEFT JOIN address_groups address
              ON address.address_group_id = assertion.target_address_group_id
             AND address.program_id = assertion.program_id
            WHERE assertion.target_address_group_id IS NOT NULL
              AND address.address_space IS NOT 'xbox-va'
            UNION ALL
            SELECT 'scan', scan.scan_id
            FROM control_flow_scans scan
            LEFT JOIN address_groups address
              ON address.address_group_id = scan.scan_address_group_id
             AND address.program_id = scan.program_id
            WHERE scan.scan_address_group_id IS NOT NULL
              AND address.address_space IS NOT 'xbox-va'
        ) violation
        """,
    ),
    (
        "control_flow_scan_total_mismatch",
        """
        WITH scan_totals AS (
            SELECT extraction_id,
                   SUM(source_branch_use_count) AS source_use_count,
                   SUM(persisted_branch_use_count) AS persisted_use_count
            FROM control_flow_scans
            GROUP BY extraction_id
        )
        SELECT COUNT(*)
        FROM control_flow_extractions extraction
        LEFT JOIN scan_totals total USING (extraction_id)
        WHERE COALESCE(total.source_use_count, 0) <>
                  extraction.source_logical_use_count
           OR COALESCE(total.persisted_use_count, 0) <>
                  extraction.persisted_logical_use_count
        """,
    ),
    (
        "control_flow_provenance_created_function_or_name",
        """
        WITH control_flow_provenance AS (
            SELECT provenance_id
            FROM control_flow_extractions
            GROUP BY provenance_id
        )
        SELECT
            (SELECT COUNT(*)
             FROM function_assertions assertion
             JOIN control_flow_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM function_names name
             JOIN control_flow_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM function_name_assertions assertion
             JOIN control_flow_provenance producer USING (provenance_id))
        """,
    ),
    (
        "control_flow_provenance_created_match_state",
        """
        WITH control_flow_provenance AS (
            SELECT provenance_id
            FROM control_flow_extractions
            GROUP BY provenance_id
        )
        SELECT
            (SELECT COUNT(*)
             FROM match_claims claim
             JOIN control_flow_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM match_hypothesis_sets hypothesis
             JOIN control_flow_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM claim_evidence evidence
             JOIN control_flow_provenance producer USING (provenance_id))
          + (SELECT COUNT(*)
             FROM match_hypothesis_evidence evidence
             JOIN control_flow_provenance producer USING (provenance_id))
        """,
    ),
    (
        "control_flow_matching_provenance_leakage",
        """
        WITH producer AS (
            SELECT provenance_id FROM provenance
            WHERE producer = 'fnv_atlas.control_flow_matching'
        )
        SELECT
            (SELECT COUNT(*) FROM function_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM function_names row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM function_name_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM function_source_ranges row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM function_source_range_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM function_signatures row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM fold_groups row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM class_names row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM class_name_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM vtables row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM vtable_slots row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM vtable_slot_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM review_releases row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM review_decisions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM control_flow_extractions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM vtable_alignment_candidates row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM vtable_slot_alignments row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM vtable_alignment_issues row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM claim_evidence row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM match_hypothesis_evidence row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM observations row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM call_edges row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM codeview_type_extractions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM data_symbol_extractions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM xbox_vftable_extractions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM sdk_extractions row
             JOIN producer USING (provenance_id))
        """,
    ),
    (
        "control_flow_matching_candidate_state_mismatch",
        """
        WITH producer AS (
            SELECT provenance_id FROM provenance
            WHERE producer = 'fnv_atlas.control_flow_matching'
        )
        SELECT COUNT(*) FROM (
            SELECT hypothesis.hypothesis_set_id AS row_id
            FROM match_hypothesis_sets hypothesis
            JOIN producer USING (provenance_id)
            WHERE hypothesis.status <> 'candidate'
               OR json_extract(hypothesis.details_json, '$.candidate_only') IS NOT 1
               OR json_type(hypothesis.details_json, '$.confidence') IS NOT 'null'
               OR json_extract(hypothesis.details_json, '$.policy') IS NOT
                    'closed_square_unique_residual_v1'
            UNION ALL
            SELECT claim.claim_id
            FROM match_claims claim
            JOIN producer USING (provenance_id)
            WHERE claim.status <> 'candidate'
               OR claim.confidence_label IS NOT NULL
               OR claim.confidence_value IS NOT NULL
               OR json_extract(claim.details_json, '$.candidate_only') IS NOT 1
               OR json_type(claim.details_json, '$.confidence') IS NOT 'null'
               OR json_extract(claim.details_json, '$.name_transfer') IS NOT 'forbidden'
            UNION ALL
            SELECT target.target_id
            FROM unresolved_targets target
            JOIN producer USING (provenance_id)
            LEFT JOIN address_groups address
              ON address.address_group_id = target.address_group_id
             AND address.program_id = target.program_id
            LEFT JOIN programs program USING (program_id)
            WHERE target.target_kind <> 'control_flow_address_only'
               OR target.status <> 'open'
               OR target.resolved_function_id IS NOT NULL
               OR target.name_hint IS NOT NULL
               OR address.address_group_id IS NULL
               OR address.address_space <> 'xbox-va'
               OR program.platform <> 'xbox360'
               OR json_extract(target.details_json, '$.candidate_only') IS NOT 1
               OR json_extract(target.details_json, '$.function_creation')
                    IS NOT 'forbidden'
               OR NOT EXISTS (
                    SELECT 1
                    FROM match_claims claim
                    JOIN match_hypothesis_alternatives alternative
                      USING (claim_id)
                    JOIN match_hypothesis_sets hypothesis
                      USING (hypothesis_set_id)
                    WHERE claim.xbox_target_id = target.target_id
                      AND claim.provenance_id IN (
                          SELECT provenance_id FROM producer
                      )
                      AND hypothesis.provenance_id IN (
                          SELECT provenance_id FROM producer
                      )
                  )
        ) violation
        """,
    ),
    (
        "control_flow_matching_evidence_scope_mismatch",
        """
        WITH producer AS (
            SELECT provenance_id FROM provenance
            WHERE producer = 'fnv_atlas.control_flow_matching'
        ), matcher_sets AS (
            SELECT hypothesis_set_id
            FROM match_hypothesis_sets hypothesis
            JOIN producer USING (provenance_id)
        )
        SELECT COUNT(*) FROM (
            SELECT evidence.evidence_id AS row_id
            FROM claim_evidence evidence
            JOIN producer USING (provenance_id)
            UNION ALL
            SELECT evidence.evidence_id
            FROM match_hypothesis_evidence evidence
            JOIN producer USING (provenance_id)
            UNION ALL
            SELECT evidence.evidence_id
            FROM match_hypothesis_alternative_evidence evidence
            JOIN producer USING (provenance_id)
            LEFT JOIN match_hypothesis_alternatives alternative
              USING (alternative_id)
            LEFT JOIN matcher_sets matcher
              USING (hypothesis_set_id)
            WHERE matcher.hypothesis_set_id IS NULL
               OR evidence.effect <> 'supports'
               OR json_extract(
                      evidence.details_json, '$.conditional_evidence'
                  ) IS NOT 1
               OR json_extract(
                      evidence.details_json, '$.independent_confirmation'
                  ) IS NOT 0
               OR json_extract(
                      evidence.details_json, '$.acceptance_effect'
                  ) IS NOT 'none'
        ) violation
        """,
    ),
    (
        "control_flow_matching_incomplete_alternatives",
        """
        WITH producer AS (
            SELECT provenance_id FROM provenance
            WHERE producer = 'fnv_atlas.control_flow_matching'
        ), matcher_sets AS (
            SELECT hypothesis_set_id
            FROM match_hypothesis_sets hypothesis
            JOIN producer USING (provenance_id)
        ), matcher_claims AS (
            SELECT claim_id FROM match_claims claim
            JOIN producer USING (provenance_id)
        )
        SELECT COUNT(*) FROM (
            SELECT matcher.hypothesis_set_id AS row_id
            FROM matcher_sets matcher
            WHERE NOT EXISTS (
                SELECT 1 FROM match_hypothesis_alternatives alternative
                WHERE alternative.hypothesis_set_id = matcher.hypothesis_set_id
            )
            UNION ALL
            SELECT alternative.alternative_id
            FROM match_hypothesis_alternatives alternative
            JOIN matcher_sets matcher USING (hypothesis_set_id)
            WHERE NOT EXISTS (
                SELECT 1
                FROM match_hypothesis_alternative_evidence evidence
                JOIN producer USING (provenance_id)
                WHERE evidence.alternative_id = alternative.alternative_id
            )
               OR (alternative.claim_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM matcher_claims claim
                    WHERE claim.claim_id = alternative.claim_id
                  ))
            UNION ALL
            SELECT claim.claim_id
            FROM matcher_claims claim
            LEFT JOIN match_hypothesis_alternatives alternative
              ON alternative.claim_id = claim.claim_id
            LEFT JOIN matcher_sets matcher USING (hypothesis_set_id)
            GROUP BY claim.claim_id
            HAVING COUNT(alternative.alternative_id) <> 1
                OR COUNT(matcher.hypothesis_set_id) <> 1
        ) violation
        """,
    ),
    (
        "control_flow_matching_disjunction_mismatch",
        """
        WITH producer AS (
            SELECT provenance_id FROM provenance
            WHERE producer = 'fnv_atlas.control_flow_matching'
        ), matcher_sets AS (
            SELECT hypothesis.*,
                   json_extract(hypothesis.details_json, '$.kind') AS set_kind
            FROM match_hypothesis_sets hypothesis
            JOIN producer USING (provenance_id)
        ), alternative_counts AS (
            SELECT hypothesis_set_id, COUNT(*) AS alternative_count
            FROM match_hypothesis_alternatives GROUP BY hypothesis_set_id
        )
        SELECT COUNT(*)
        FROM matcher_sets hypothesis
        LEFT JOIN alternative_counts alternative USING (hypothesis_set_id)
        WHERE hypothesis.set_kind IS NULL
           OR hypothesis.set_kind NOT IN (
                  'closed_call_square_relation',
                  'unique_residual_call_proposal'
              )
           OR (hypothesis.set_kind = 'closed_call_square_relation' AND
               COALESCE(alternative.alternative_count, 0) <> 1)
           OR (hypothesis.set_kind = 'unique_residual_call_proposal' AND (
                  hypothesis.identity_key IS NOT hypothesis.hypothesis_set_id
                  OR json_extract(
                         hypothesis.details_json,
                         '$.proposal_set.proposal_set_id'
                     ) IS NOT hypothesis.hypothesis_set_id
                  OR json_type(
                         hypothesis.details_json,
                         '$.proposal_set.alternative_ids'
                     ) IS NOT 'array'
                  OR COALESCE(alternative.alternative_count, 0) <>
                     json_array_length(
                         hypothesis.details_json,
                         '$.proposal_set.alternative_ids'
                     )
                  OR json_array_length(
                         hypothesis.details_json,
                         '$.proposal_set.alternative_ids'
                     ) <> (
                         SELECT COUNT(DISTINCT expected.value)
                         FROM json_each(
                             hypothesis.details_json,
                             '$.proposal_set.alternative_ids'
                         ) expected
                     )
                  OR EXISTS (
                         SELECT 1
                         FROM json_each(
                             hypothesis.details_json,
                             '$.proposal_set.alternative_ids'
                         ) expected
                         WHERE NOT EXISTS (
                             SELECT 1
                             FROM match_hypothesis_alternatives stored
                             WHERE stored.hypothesis_set_id =
                                    hypothesis.hypothesis_set_id
                               AND stored.alternative_id = expected.value
                         )
                     )
                  OR EXISTS (
                         SELECT 1
                         FROM match_hypothesis_alternatives stored
                         WHERE stored.hypothesis_set_id =
                                hypothesis.hypothesis_set_id
                           AND NOT EXISTS (
                               SELECT 1
                               FROM json_each(
                                   hypothesis.details_json,
                                   '$.proposal_set.alternative_ids'
                               ) expected
                               WHERE expected.value = stored.alternative_id
                           )
                     )
              ))
        """,
    ),
    (
        "xbox_vftable_extraction_summary_mismatch",
        """
        WITH assertion_stats AS (
            SELECT extraction_id, COUNT(*) AS physical_records,
                   SUM(address_group_id IS NOT NULL) AS resolved_records,
                   SUM(address_group_id IS NULL) AS unresolved_records,
                   COUNT(DISTINCT canonical_name_id) AS canonical_names
            FROM xbox_vftable_symbol_assertions GROUP BY extraction_id
        ), observation_stats AS (
            SELECT extraction_id, COUNT(*) AS address_observations
            FROM xbox_vftable_address_observations GROUP BY extraction_id
        ), run_stats AS (
            SELECT extraction_id, COUNT(*) AS pointer_runs
            FROM xbox_vftable_pointer_runs GROUP BY extraction_id
        ), slot_stats AS (
            SELECT extraction_id, COUNT(*) AS pointer_slots
            FROM xbox_vftable_pointer_slots GROUP BY extraction_id
        ), diagnostic_stats AS (
            SELECT extraction_id,
                   SUM(diagnostic_scope = 'symbol_extraction') AS symbol_diagnostics,
                   SUM(diagnostic_scope = 'pointer_run') AS run_diagnostics,
                   SUM(diagnostic_scope = 'pointer_scan') AS scan_diagnostics
            FROM xbox_vftable_diagnostics GROUP BY extraction_id
        )
        SELECT COUNT(*)
        FROM xbox_vftable_extractions extraction
        LEFT JOIN assertion_stats assertion USING (extraction_id)
        LEFT JOIN observation_stats observation USING (extraction_id)
        LEFT JOIN run_stats run USING (extraction_id)
        LEFT JOIN slot_stats slot USING (extraction_id)
        LEFT JOIN diagnostic_stats diagnostic USING (extraction_id)
        WHERE extraction.physical_record_count <>
                  COALESCE(assertion.physical_records, 0)
           OR extraction.resolved_record_count <>
                  COALESCE(assertion.resolved_records, 0)
           OR extraction.unresolved_record_count <>
                  COALESCE(assertion.unresolved_records, 0)
           OR extraction.canonical_name_count <>
                  COALESCE(assertion.canonical_names, 0)
           OR extraction.source_address_group_count <>
                  COALESCE(observation.address_observations, 0)
           OR extraction.pointer_run_count <> COALESCE(run.pointer_runs, 0)
           OR extraction.pointer_slot_count <> COALESCE(slot.pointer_slots, 0)
           OR extraction.symbol_diagnostic_count <>
                  COALESCE(diagnostic.symbol_diagnostics, 0)
           OR extraction.run_diagnostic_count <>
                  COALESCE(diagnostic.run_diagnostics, 0)
           OR extraction.scan_diagnostic_count <>
                  COALESCE(diagnostic.scan_diagnostics, 0)
        """,
    ),
    (
        "xbox_vftable_name_identity_mismatch",
        """
        SELECT COUNT(*)
        FROM xbox_vftable_name_identities name
        WHERE sha256_hex(name.decorated_name_bytes)
                  IS NOT name.decorated_name_sha256
           OR name.canonical_name_id IS NOT
                  'x360-msvc-vftable-name:sha256:' ||
                  name.decorated_name_sha256
           OR latin1_bytes(name.decorated_name)
                  IS NOT name.decorated_name_bytes
        """,
    ),
    (
        "xbox_vftable_record_integrity_mismatch",
        """
        SELECT COUNT(*) FROM (
            SELECT record.vftable_record_id AS row_id
            FROM xbox_vftable_symbol_records record
            WHERE length(record.raw_record) <> record.record_length + 2
               OR sha256_hex(record.raw_record) IS NOT record.raw_record_sha256
            UNION ALL
            SELECT assertion.assertion_id
            FROM xbox_vftable_symbol_assertions assertion
            LEFT JOIN xbox_vftable_symbol_records record
              ON record.vftable_record_id = assertion.vftable_record_id
             AND record.program_id = assertion.program_id
            LEFT JOIN xbox_vftable_name_identities name
              ON name.canonical_name_id = assertion.canonical_name_id
            WHERE record.vftable_record_id IS NULL
               OR name.canonical_name_id IS NULL
               OR vftable_record_matches(
                      record.raw_record, record.record_length,
                      assertion.record_kind_code, assertion.public_flags,
                      assertion.section_offset, assertion.section,
                      name.decorated_name_bytes
                  ) <> 1
        ) violation
        """,
    ),
    (
        "xbox_vftable_records_without_assertions",
        """
        SELECT COUNT(*)
        FROM xbox_vftable_symbol_records record
        WHERE NOT EXISTS (
            SELECT 1 FROM xbox_vftable_symbol_assertions assertion
            WHERE assertion.vftable_record_id = record.vftable_record_id
              AND assertion.program_id = record.program_id
        )
        """,
    ),
    (
        "xbox_vftable_symbol_assertion_identity_mismatch",
        """
        SELECT COUNT(*)
        FROM xbox_vftable_symbol_assertions assertion
        LEFT JOIN xbox_vftable_extractions extraction
          ON extraction.extraction_id = assertion.extraction_id
         AND extraction.program_id = assertion.program_id
        LEFT JOIN xbox_vftable_symbol_records record
          ON record.vftable_record_id = assertion.vftable_record_id
         AND record.program_id = assertion.program_id
        LEFT JOIN address_groups address
          ON address.address_group_id = assertion.address_group_id
         AND address.program_id = assertion.program_id
        WHERE extraction.extraction_id IS NULL
           OR record.vftable_record_id IS NULL
           OR record.symbol_record_stream <> extraction.symbol_record_stream
           OR assertion.record_kind <> 'S_PUB32'
           OR assertion.record_kind_code <> 4366
           OR ((assertion.resolved_va IS NULL) <>
               (assertion.address_group_id IS NULL))
           OR (assertion.resolved_va IS NOT NULL AND (
                  address.address_group_id IS NULL OR
                  address.address_space <> 'xbox-va' OR
                  address.address IS NOT assertion.resolved_va
              ))
        """,
    ),
    (
        "xbox_vftable_address_membership_mismatch",
        """
        WITH member_stats AS (
            SELECT address_observation_id, COUNT(*) AS member_count,
                   MIN(source_ordinal) AS first_ordinal,
                   MAX(source_ordinal) AS last_ordinal,
                   SUM(is_ranked) AS ranked_count
            FROM xbox_vftable_address_members GROUP BY address_observation_id
        ), assertion_members AS (
            SELECT assertion.assertion_id, assertion.address_group_id,
                   COUNT(member.membership_id) AS member_count
            FROM xbox_vftable_symbol_assertions assertion
            LEFT JOIN xbox_vftable_address_members member
              ON member.extraction_id = assertion.extraction_id
             AND member.vftable_record_id = assertion.vftable_record_id
            GROUP BY assertion.assertion_id, assertion.address_group_id
        )
        SELECT COUNT(*) FROM (
            SELECT observation.address_observation_id AS row_id
            FROM xbox_vftable_address_observations observation
            LEFT JOIN member_stats member USING (address_observation_id)
            WHERE observation.member_count <> COALESCE(member.member_count, 0)
               OR COALESCE(member.ranked_count, 0) <> 0
               OR COALESCE(member.first_ordinal, 0) <> 0
               OR COALESCE(member.last_ordinal, -1) <>
                    observation.member_count - 1
            UNION ALL
            SELECT member.membership_id
            FROM xbox_vftable_address_members member
            LEFT JOIN xbox_vftable_address_observations observation
              USING (address_observation_id, extraction_id, program_id)
            LEFT JOIN xbox_vftable_symbol_assertions assertion
              ON assertion.extraction_id = member.extraction_id
             AND assertion.vftable_record_id = member.vftable_record_id
            WHERE observation.address_observation_id IS NULL
               OR assertion.assertion_id IS NULL
               OR assertion.canonical_name_id <> member.canonical_name_id
               OR assertion.address_group_id IS NULL
               OR assertion.address_group_id <> observation.address_group_id
            UNION ALL
            SELECT assertion_id FROM assertion_members
            WHERE (address_group_id IS NULL AND member_count <> 0)
               OR (address_group_id IS NOT NULL AND member_count <> 1)
        ) violation
        """,
    ),
    (
        "xbox_vftable_pointer_run_membership_mismatch",
        """
        WITH observation_runs AS (
            SELECT observation.address_observation_id,
                   COUNT(run.pointer_run_id) AS run_count
            FROM xbox_vftable_address_observations observation
            LEFT JOIN xbox_vftable_pointer_runs run
              USING (address_observation_id, extraction_id, program_id)
            GROUP BY observation.address_observation_id
        )
        SELECT COUNT(*) FROM (
            SELECT address_observation_id AS row_id FROM observation_runs
            WHERE run_count <> 1
            UNION ALL
            SELECT run.pointer_run_id
            FROM xbox_vftable_pointer_runs run
            LEFT JOIN xbox_vftable_address_observations observation
              USING (address_observation_id, extraction_id, program_id)
            WHERE observation.address_observation_id IS NULL
               OR run.table_address_group_id <> observation.address_group_id
               OR run.table_va <> observation.table_va
            UNION ALL
            SELECT run.pointer_run_id || ':table:' || member.source_ordinal
            FROM xbox_vftable_pointer_runs run
            JOIN xbox_vftable_address_members member
              ON member.address_observation_id = run.address_observation_id
            LEFT JOIN xbox_vftable_pointer_run_symbols symbol
              ON symbol.pointer_run_id = run.pointer_run_id
             AND symbol.membership_role = 'table'
             AND symbol.source_ordinal = member.source_ordinal
             AND symbol.vftable_record_id = member.vftable_record_id
            WHERE symbol.run_symbol_id IS NULL
            UNION ALL
            SELECT symbol.run_symbol_id
            FROM xbox_vftable_pointer_run_symbols symbol
            JOIN xbox_vftable_pointer_runs run USING (pointer_run_id)
            LEFT JOIN xbox_vftable_address_members member
              ON member.address_observation_id = run.address_observation_id
             AND member.source_ordinal = symbol.source_ordinal
             AND member.vftable_record_id = symbol.vftable_record_id
            WHERE symbol.membership_role = 'table'
              AND member.membership_id IS NULL
            UNION ALL
            SELECT run.pointer_run_id || ':next:' || member.source_ordinal
            FROM xbox_vftable_pointer_runs run
            JOIN xbox_vftable_address_observations observation
              ON observation.extraction_id = run.extraction_id
             AND observation.address_group_id =
                    run.next_vftable_address_group_id
             AND observation.table_va = run.next_vftable_va
            JOIN xbox_vftable_address_members member
              ON member.address_observation_id = observation.address_observation_id
            LEFT JOIN xbox_vftable_pointer_run_symbols symbol
              ON symbol.pointer_run_id = run.pointer_run_id
             AND symbol.membership_role = 'next'
             AND symbol.source_ordinal = member.source_ordinal
             AND symbol.vftable_record_id = member.vftable_record_id
            WHERE symbol.run_symbol_id IS NULL
            UNION ALL
            SELECT symbol.run_symbol_id
            FROM xbox_vftable_pointer_run_symbols symbol
            JOIN xbox_vftable_pointer_runs run USING (pointer_run_id)
            LEFT JOIN xbox_vftable_address_observations observation
              ON observation.extraction_id = run.extraction_id
             AND observation.address_group_id =
                    run.next_vftable_address_group_id
             AND observation.table_va = run.next_vftable_va
            LEFT JOIN xbox_vftable_address_members member
              ON member.address_observation_id = observation.address_observation_id
             AND member.source_ordinal = symbol.source_ordinal
             AND member.vftable_record_id = symbol.vftable_record_id
            WHERE symbol.membership_role = 'next'
              AND member.membership_id IS NULL
            UNION ALL
            SELECT run.pointer_run_id
            FROM xbox_vftable_pointer_runs run
            WHERE run.next_vftable_va IS NULL AND EXISTS (
                SELECT 1 FROM xbox_vftable_pointer_run_symbols symbol
                WHERE symbol.pointer_run_id = run.pointer_run_id
                  AND symbol.membership_role = 'next'
            )
        ) violation
        """,
    ),
    (
        "xbox_vftable_pointer_run_observation_mismatch",
        """
        WITH slot_stats AS (
            SELECT pointer_run_id, COUNT(*) AS slot_count,
                   MIN(slot_index) AS first_slot,
                   MAX(slot_index) AS last_slot
            FROM xbox_vftable_pointer_slots GROUP BY pointer_run_id
        )
        SELECT COUNT(*) FROM (
            SELECT run.pointer_run_id AS row_id
            FROM xbox_vftable_pointer_runs run
            JOIN xbox_vftable_extractions extraction USING (extraction_id)
            LEFT JOIN slot_stats slot USING (pointer_run_id)
            WHERE run.extent_semantics <>
                    'observed_pointer_prefix_not_declared_extent'
               OR run.observed_pointer_count <> COALESCE(slot.slot_count, 0)
               OR COALESCE(slot.first_slot, 0) <> 0
               OR COALESCE(slot.last_slot, -1) <>
                    run.observed_pointer_count - 1
               OR run.observed_pointer_count > extraction.scan_max_slots
               OR run.termination_va IS NOT
                    run.table_va + run.observed_pointer_count * 4
               OR run.termination_kind NOT IN (
                    'unmapped_table_address', 'ambiguous_table_mapping',
                    'mapped_section_end', 'max_slots_reached',
                    'first_non_text_pointer'
                  )
               OR ((run.termination_kind = 'first_non_text_pointer') <>
                   (run.termination_word IS NOT NULL))
               OR (run.termination_kind = 'max_slots_reached' AND
                   run.observed_pointer_count <> extraction.scan_max_slots)
               OR (run.termination_kind IN (
                       'unmapped_table_address', 'ambiguous_table_mapping'
                   ) AND run.observed_pointer_count <> 0)
               OR (run.next_vftable_va IS NULL AND (
                      run.next_vftable_address_group_id IS NOT NULL OR
                      run.known_boundary_slot_index IS NOT NULL OR
                      run.boundary_relation <> 'no_later_vftable_symbol'
                  ))
               OR (run.next_vftable_va IS NOT NULL AND (
                      run.next_vftable_va <= run.table_va OR
                      CASE
                        WHEN (run.next_vftable_va - run.table_va) % 4 <> 0
                        THEN run.known_boundary_slot_index IS NOT NULL OR
                             run.boundary_relation <>
                                'next_vftable_symbol_unaligned'
                        ELSE run.known_boundary_slot_index IS NOT
                                (run.next_vftable_va - run.table_va) / 4 OR
                             run.boundary_relation <> CASE
                               WHEN (run.next_vftable_va - run.table_va) / 4 <
                                      run.observed_pointer_count
                               THEN 'next_vftable_inside_pointer_run'
                               WHEN (run.next_vftable_va - run.table_va) / 4 =
                                      run.observed_pointer_count
                               THEN 'next_vftable_at_pointer_run_end'
                               ELSE 'next_vftable_after_pointer_run'
                             END
                      END
                  ))
            UNION ALL
            SELECT slot.pointer_slot_id
            FROM xbox_vftable_pointer_slots slot
            JOIN xbox_vftable_pointer_runs run USING (pointer_run_id)
            WHERE slot.slot_va <> run.table_va + slot.slot_index * 4
               OR big_endian_u32_matches(slot.raw_word, slot.target_va) <> 1
        ) violation
        """,
    ),
    (
        "xbox_vftable_non_xbox_addressing",
        """
        SELECT COUNT(*) FROM (
            SELECT extraction.extraction_id AS row_id
            FROM xbox_vftable_extractions extraction
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
               OR extraction.address_space <> 'xbox-va'
            UNION ALL
            SELECT record.vftable_record_id
            FROM xbox_vftable_symbol_records record
            LEFT JOIN programs program USING (program_id)
            WHERE program.platform IS NOT 'xbox360'
            UNION ALL
            SELECT observation.address_observation_id
            FROM xbox_vftable_address_observations observation
            LEFT JOIN address_groups address
              ON address.address_group_id = observation.address_group_id
             AND address.program_id = observation.program_id
            WHERE address.address_space IS NOT 'xbox-va'
               OR address.address IS NOT observation.table_va
            UNION ALL
            SELECT run.pointer_run_id
            FROM xbox_vftable_pointer_runs run
            LEFT JOIN address_groups table_address
              ON table_address.address_group_id = run.table_address_group_id
             AND table_address.program_id = run.program_id
            LEFT JOIN address_groups next_address
              ON next_address.address_group_id =
                    run.next_vftable_address_group_id
             AND next_address.program_id = run.program_id
            WHERE table_address.address_space IS NOT 'xbox-va'
               OR table_address.address IS NOT run.table_va
               OR (run.next_vftable_va IS NOT NULL AND (
                      next_address.address_space IS NOT 'xbox-va' OR
                      next_address.address IS NOT run.next_vftable_va
                  ))
            UNION ALL
            SELECT slot.pointer_slot_id
            FROM xbox_vftable_pointer_slots slot
            LEFT JOIN address_groups slot_address
              ON slot_address.address_group_id = slot.slot_address_group_id
             AND slot_address.program_id = slot.program_id
            LEFT JOIN address_groups target_address
              ON target_address.address_group_id = slot.target_address_group_id
             AND target_address.program_id = slot.program_id
            WHERE slot_address.address_space IS NOT 'xbox-va'
               OR slot_address.address IS NOT slot.slot_va
               OR target_address.address_space IS NOT 'xbox-va'
               OR target_address.address IS NOT slot.target_va
        ) violation
        """,
    ),
    (
        "xbox_vftable_diagnostic_identity_mismatch",
        """
        WITH ordered AS (
            SELECT diagnostic.*,
                   ROW_NUMBER() OVER (
                       PARTITION BY extraction_id, diagnostic_scope,
                                    COALESCE(pointer_run_id, '')
                       ORDER BY source_ordinal
                   ) - 1 AS expected_ordinal
            FROM xbox_vftable_diagnostics diagnostic
        )
        SELECT COUNT(*)
        FROM ordered diagnostic
        LEFT JOIN xbox_vftable_extractions extraction
          ON extraction.extraction_id = diagnostic.extraction_id
         AND extraction.program_id = diagnostic.program_id
        LEFT JOIN xbox_vftable_pointer_runs run
          ON run.pointer_run_id = diagnostic.pointer_run_id
         AND run.extraction_id = diagnostic.extraction_id
         AND run.program_id = diagnostic.program_id
        WHERE extraction.extraction_id IS NULL
           OR diagnostic.source_ordinal <> diagnostic.expected_ordinal
           OR ((diagnostic.diagnostic_scope = 'pointer_run') <>
               (diagnostic.pointer_run_id IS NOT NULL))
           OR (diagnostic.pointer_run_id IS NOT NULL AND
               run.pointer_run_id IS NULL)
        """,
    ),
    (
        "xbox_vftable_provenance_leakage",
        """
        WITH producer AS (
            SELECT provenance_id FROM xbox_vftable_extractions GROUP BY provenance_id
        )
        SELECT
            (SELECT COUNT(*) FROM function_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM function_names row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM function_name_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM class_names row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM class_name_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM match_claims row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM match_hypothesis_sets row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM claim_evidence row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM match_hypothesis_evidence row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM match_hypothesis_alternative_evidence row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM review_releases row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM review_decisions row
             JOIN producer USING (provenance_id))
        """,
    ),
    (
        "sdk_extraction_summary_mismatch",
        """
        WITH prototype_stats AS (
            SELECT membership.extraction_id, COUNT(*) AS observation_count,
                   COUNT(DISTINCT observation.address) AS unique_addresses,
                   COUNT(DISTINCT CASE WHEN observation.program_variant = 'game'
                                       THEN observation.address END)
                       AS game_addresses,
                   COUNT(DISTINCT CASE WHEN observation.program_variant = 'geck'
                                       THEN observation.address END)
                       AS geck_addresses
            FROM sdk_prototype_extraction_assertions membership
            JOIN sdk_prototype_observations observation
              USING (prototype_observation_id, source_tree_sha256)
            GROUP BY membership.extraction_id
        ), call_stats AS (
            SELECT extraction_id, COUNT(*) AS observation_count
            FROM sdk_call_target_extraction_assertions GROUP BY extraction_id
        ), data_stats AS (
            SELECT extraction_id, COUNT(*) AS observation_count
            FROM sdk_data_extraction_assertions GROUP BY extraction_id
        ), diagnostic_stats AS (
            SELECT extraction_id, COUNT(*) AS diagnostic_count
            FROM sdk_diagnostics GROUP BY extraction_id
        ), code_join_stats AS (
            SELECT extraction_id,
                   SUM(observation_kind = 'prototype') AS prototype_joins,
                   SUM(observation_kind = 'call_target') AS call_joins
            FROM sdk_code_inventory_joins GROUP BY extraction_id
        ), data_join_stats AS (
            SELECT extraction_id, COUNT(*) AS data_joins
            FROM sdk_data_inventory_joins GROUP BY extraction_id
        ), definitive_stats AS (
            SELECT joined.extraction_id, COUNT(*) AS link_count
            FROM sdk_game_exact_entry_links link
            JOIN sdk_code_inventory_joins joined USING (code_join_id)
            GROUP BY joined.extraction_id
        ), candidate_stats AS (
            SELECT joined.extraction_id, COUNT(*) AS link_count
            FROM sdk_unspecified_exact_entry_candidates link
            JOIN sdk_code_inventory_joins joined USING (code_join_id)
            GROUP BY joined.extraction_id
        ), boundary_stats AS (
            SELECT extraction_id, COUNT(*) AS candidate_count,
                   COALESCE(SUM(containing_entry_count), 0) AS container_count
            FROM sdk_boundary_candidates GROUP BY extraction_id
        )
        SELECT COUNT(*)
        FROM sdk_extractions extraction
        LEFT JOIN sdk_source_trees tree USING (source_tree_sha256)
        LEFT JOIN prototype_stats prototype USING (extraction_id)
        LEFT JOIN call_stats call USING (extraction_id)
        LEFT JOIN data_stats data USING (extraction_id)
        LEFT JOIN diagnostic_stats diagnostic USING (extraction_id)
        LEFT JOIN code_join_stats code_join USING (extraction_id)
        LEFT JOIN data_join_stats data_join USING (extraction_id)
        LEFT JOIN definitive_stats definitive USING (extraction_id)
        LEFT JOIN candidate_stats candidate USING (extraction_id)
        LEFT JOIN boundary_stats boundary USING (extraction_id)
        WHERE tree.source_tree_sha256 IS NULL
           OR extraction.files_scanned <> tree.file_count
           OR extraction.prototype_count <>
                  COALESCE(prototype.observation_count, 0)
           OR extraction.unique_prototype_address_count <>
                  COALESCE(prototype.unique_addresses, 0)
           OR extraction.game_prototype_address_count <>
                  COALESCE(prototype.game_addresses, 0)
           OR extraction.geck_prototype_address_count <>
                  COALESCE(prototype.geck_addresses, 0)
           OR extraction.call_target_count <>
                  COALESCE(call.observation_count, 0)
           OR extraction.data_address_count <>
                  COALESCE(data.observation_count, 0)
           OR extraction.diagnostic_count <>
                  COALESCE(diagnostic.diagnostic_count, 0)
           OR extraction.prototype_join_count <>
                  COALESCE(code_join.prototype_joins, 0)
           OR extraction.call_target_join_count <>
                  COALESCE(code_join.call_joins, 0)
           OR extraction.data_join_count <> COALESCE(data_join.data_joins, 0)
           OR extraction.definitive_game_link_count <>
                  COALESCE(definitive.link_count, 0)
           OR extraction.unspecified_entry_candidate_count <>
                  COALESCE(candidate.link_count, 0)
           OR extraction.boundary_candidate_count <>
                  COALESCE(boundary.candidate_count, 0)
           OR extraction.boundary_container_count <>
                  COALESCE(boundary.container_count, 0)
        """,
    ),
    (
        "sdk_source_tree_integrity_mismatch",
        """
        WITH actual AS (
            SELECT tree.source_tree_sha256, COUNT(file.source_file_id) AS file_count,
                   COALESCE(SUM(file.byte_length), 0) AS total_byte_count,
                   sdk_source_tree_sha256(
                       file.relative_path, file.byte_length,
                       file.source_file_sha256
                   ) AS computed_tree_sha256
            FROM sdk_source_trees tree
            LEFT JOIN sdk_source_tree_files file USING (source_tree_sha256)
            GROUP BY tree.source_tree_sha256
        )
        SELECT COUNT(*) FROM (
            SELECT tree.source_tree_sha256 AS row_id
            FROM sdk_source_trees tree
            JOIN actual USING (source_tree_sha256)
            WHERE tree.file_count <> actual.file_count
               OR tree.total_byte_count <> actual.total_byte_count
               OR tree.source_tree_sha256 IS NOT actual.computed_tree_sha256
            UNION ALL
            SELECT file.source_file_id
            FROM sdk_source_tree_files file
            WHERE unicode_casefold(file.relative_path)
                    IS NOT file.relative_path_casefold
               OR sdk_relative_path_valid(file.relative_path) <> 1
               OR length(file.source_file_sha256) <> 64
               OR lower(file.source_file_sha256) <> file.source_file_sha256
               OR file.source_file_sha256 GLOB '*[^0-9a-f]*'
        ) violation
        """,
    ),
    (
        "sdk_source_observation_file_mismatch",
        """
        SELECT COUNT(*) FROM (
            SELECT observation.prototype_observation_id AS row_id
            FROM sdk_prototype_observations observation
            LEFT JOIN sdk_source_tree_files file
              ON file.source_file_id = observation.source_file_id
             AND file.source_tree_sha256 = observation.source_tree_sha256
            WHERE file.source_file_id IS NULL
               OR file.relative_path <> observation.source_path
               OR file.source_file_sha256 <> observation.source_file_sha256
            UNION ALL
            SELECT observation.call_target_observation_id
            FROM sdk_call_target_observations observation
            LEFT JOIN sdk_source_tree_files file
              ON file.source_file_id = observation.source_file_id
             AND file.source_tree_sha256 = observation.source_tree_sha256
            WHERE file.source_file_id IS NULL
               OR file.relative_path <> observation.source_path
               OR file.source_file_sha256 <> observation.source_file_sha256
            UNION ALL
            SELECT observation.data_observation_id
            FROM sdk_data_observations observation
            LEFT JOIN sdk_source_tree_files file
              ON file.source_file_id = observation.source_file_id
             AND file.source_tree_sha256 = observation.source_tree_sha256
            WHERE file.source_file_id IS NULL
               OR file.relative_path <> observation.source_path
               OR file.source_file_sha256 <> observation.source_file_sha256
            UNION ALL
            SELECT diagnostic.diagnostic_id
            FROM sdk_diagnostics diagnostic
            LEFT JOIN sdk_source_tree_files file
              ON file.source_file_id = diagnostic.source_file_id
             AND file.source_tree_sha256 = diagnostic.source_tree_sha256
            WHERE file.source_file_id IS NULL
               OR file.relative_path <> diagnostic.source_path
               OR file.source_file_sha256 <> diagnostic.source_file_sha256
        ) violation
        """,
    ),
    (
        "sdk_observations_without_memberships",
        """
        SELECT COUNT(*) FROM (
            SELECT observation.prototype_observation_id AS row_id
            FROM sdk_prototype_observations observation
            WHERE NOT EXISTS (
                SELECT 1 FROM sdk_prototype_extraction_assertions membership
                WHERE membership.prototype_observation_id =
                        observation.prototype_observation_id
                  AND membership.source_tree_sha256 =
                        observation.source_tree_sha256
            )
            UNION ALL
            SELECT observation.call_target_observation_id
            FROM sdk_call_target_observations observation
            WHERE NOT EXISTS (
                SELECT 1 FROM sdk_call_target_extraction_assertions membership
                WHERE membership.call_target_observation_id =
                        observation.call_target_observation_id
                  AND membership.source_tree_sha256 =
                        observation.source_tree_sha256
            )
            UNION ALL
            SELECT observation.data_observation_id
            FROM sdk_data_observations observation
            WHERE NOT EXISTS (
                SELECT 1 FROM sdk_data_extraction_assertions membership
                WHERE membership.data_observation_id =
                        observation.data_observation_id
                  AND membership.source_tree_sha256 =
                        observation.source_tree_sha256
            )
        ) violation
        """,
    ),
    (
        "sdk_call_sequence_mismatch",
        """
        WITH parameter_stats AS (
            SELECT call_target_observation_id, COUNT(*) AS item_count,
                   MIN(ordinal) AS first_ordinal, MAX(ordinal) AS last_ordinal
            FROM sdk_call_parameter_types GROUP BY call_target_observation_id
        ), argument_stats AS (
            SELECT call_target_observation_id, COUNT(*) AS item_count,
                   MIN(ordinal) AS first_ordinal, MAX(ordinal) AS last_ordinal
            FROM sdk_call_argument_expressions GROUP BY call_target_observation_id
        )
        SELECT COUNT(*)
        FROM sdk_call_target_observations observation
        LEFT JOIN parameter_stats parameter USING (call_target_observation_id)
        LEFT JOIN argument_stats argument USING (call_target_observation_id)
        WHERE (observation.parameter_types_known = 0 AND
               COALESCE(parameter.item_count, 0) <> 0)
           OR (COALESCE(parameter.item_count, 0) > 0 AND (
                  parameter.first_ordinal <> 0 OR
                  parameter.last_ordinal <> parameter.item_count - 1
              ))
           OR (COALESCE(argument.item_count, 0) > 0 AND (
                  argument.first_ordinal <> 0 OR
                  argument.last_ordinal <> argument.item_count - 1
              ))
        """,
    ),
    (
        "sdk_observation_join_mismatch",
        """
        SELECT COUNT(*) FROM (
            SELECT membership.assertion_id AS row_id
            FROM sdk_prototype_extraction_assertions membership
            JOIN sdk_prototype_observations observation
              USING (prototype_observation_id, source_tree_sha256)
            LEFT JOIN sdk_code_inventory_joins joined
              ON joined.extraction_id = membership.extraction_id
             AND joined.source_tree_sha256 = membership.source_tree_sha256
             AND joined.observation_kind = 'prototype'
             AND joined.prototype_observation_id =
                    membership.prototype_observation_id
             AND joined.source_ordinal = membership.source_ordinal
            WHERE joined.code_join_id IS NULL
               OR joined.program_variant <> observation.program_variant
               OR joined.address <> observation.address
            UNION ALL
            SELECT membership.assertion_id
            FROM sdk_call_target_extraction_assertions membership
            JOIN sdk_call_target_observations observation
              USING (call_target_observation_id, source_tree_sha256)
            LEFT JOIN sdk_code_inventory_joins joined
              ON joined.extraction_id = membership.extraction_id
             AND joined.source_tree_sha256 = membership.source_tree_sha256
             AND joined.observation_kind = 'call_target'
             AND joined.call_target_observation_id =
                    membership.call_target_observation_id
             AND joined.source_ordinal = membership.source_ordinal
            WHERE joined.code_join_id IS NULL
               OR joined.program_variant <> observation.program_variant
               OR joined.address <> observation.address
            UNION ALL
            SELECT joined.code_join_id
            FROM sdk_code_inventory_joins joined
            LEFT JOIN sdk_prototype_extraction_assertions prototype
              ON joined.observation_kind = 'prototype'
             AND prototype.extraction_id = joined.extraction_id
             AND prototype.source_tree_sha256 = joined.source_tree_sha256
             AND prototype.prototype_observation_id =
                    joined.prototype_observation_id
             AND prototype.source_ordinal = joined.source_ordinal
            LEFT JOIN sdk_call_target_extraction_assertions call
              ON joined.observation_kind = 'call_target'
             AND call.extraction_id = joined.extraction_id
             AND call.source_tree_sha256 = joined.source_tree_sha256
             AND call.call_target_observation_id =
                    joined.call_target_observation_id
             AND call.source_ordinal = joined.source_ordinal
            WHERE (joined.observation_kind = 'prototype' AND
                   prototype.assertion_id IS NULL)
               OR (joined.observation_kind = 'call_target' AND
                   call.assertion_id IS NULL)
            UNION ALL
            SELECT membership.assertion_id
            FROM sdk_data_extraction_assertions membership
            JOIN sdk_data_observations observation
              USING (data_observation_id, source_tree_sha256)
            LEFT JOIN sdk_data_inventory_joins joined
              ON joined.extraction_id = membership.extraction_id
             AND joined.source_tree_sha256 = membership.source_tree_sha256
             AND joined.data_observation_id = membership.data_observation_id
             AND joined.source_ordinal = membership.source_ordinal
            WHERE joined.data_join_id IS NULL
               OR joined.program_variant <> observation.program_variant
               OR joined.address <> observation.address
               OR joined.data_kind <> observation.data_kind
            UNION ALL
            SELECT joined.data_join_id
            FROM sdk_data_inventory_joins joined
            LEFT JOIN sdk_data_extraction_assertions membership
              ON membership.extraction_id = joined.extraction_id
             AND membership.source_tree_sha256 = joined.source_tree_sha256
             AND membership.data_observation_id = joined.data_observation_id
             AND membership.source_ordinal = joined.source_ordinal
            WHERE membership.assertion_id IS NULL
        ) violation
        """,
    ),
    (
        "sdk_code_variant_link_mismatch",
        """
        SELECT COUNT(*)
        FROM sdk_code_inventory_joins joined
        JOIN sdk_extractions extraction USING (extraction_id)
        LEFT JOIN sdk_game_exact_entry_links definitive USING (code_join_id)
        LEFT JOIN sdk_unspecified_exact_entry_candidates candidate
          USING (code_join_id)
        LEFT JOIN functions function
          ON function.function_id = COALESCE(
                 definitive.function_id, candidate.candidate_function_id
             )
        LEFT JOIN address_groups address
          ON address.address_group_id = function.address_group_id
         AND address.program_id = function.program_id
        LEFT JOIN programs program ON program.program_id = function.program_id
        WHERE (joined.program_variant = 'geck' AND (
                  joined.classification <> 'non_game_variant' OR
                  definitive.code_join_id IS NOT NULL OR
                  candidate.code_join_id IS NOT NULL
              ))
           OR (joined.program_variant = 'game' AND (
                  joined.classification NOT IN (
                    'pc_function_entry', 'pc_executable_non_entry',
                    'pc_non_executable_section', 'outside_pc_image_sections'
                  ) OR
                  ((joined.classification = 'pc_function_entry') <>
                   (definitive.code_join_id IS NOT NULL)) OR
                  candidate.code_join_id IS NOT NULL
              ))
           OR (joined.program_variant = 'unspecified_pc' AND (
                  joined.classification NOT IN (
                    'pc_function_entry_variant_unspecified',
                    'pc_executable_non_entry_variant_unspecified',
                    'pc_non_executable_section_variant_unspecified',
                    'outside_pc_image_sections_variant_unspecified'
                  ) OR
                  ((joined.classification =
                    'pc_function_entry_variant_unspecified') <>
                   (candidate.code_join_id IS NOT NULL)) OR
                  definitive.code_join_id IS NOT NULL
              ))
           OR ((definitive.code_join_id IS NOT NULL OR
                candidate.code_join_id IS NOT NULL) AND (
                  function.function_id IS NULL OR
                  function.program_id <> extraction.pc_program_id OR
                  address.address_space <> extraction.pc_address_space OR
                  address.address <> joined.address OR
                  program.platform <> 'pc'
              ))
        """,
    ),
    (
        "sdk_data_variant_classification_mismatch",
        """
        SELECT COUNT(*)
        FROM sdk_data_inventory_joins joined
        WHERE (joined.program_variant = 'geck' AND
               joined.classification <> 'non_game_variant')
           OR (joined.program_variant = 'game' AND
               joined.classification NOT IN (
                   'pc_executable_section', 'pc_data_section',
                   'outside_pc_image_sections'
               ))
           OR (joined.program_variant = 'unspecified_pc' AND
               joined.classification NOT IN (
                   'pc_executable_section_variant_unspecified',
                   'pc_data_section_variant_unspecified',
                   'outside_pc_image_sections_variant_unspecified'
               ))
           OR (joined.classification LIKE 'pc_executable_%' AND
               joined.section_executable IS NOT 1)
           OR (joined.classification LIKE 'pc_data_%' AND
               joined.section_executable IS NOT 0)
           OR (joined.classification LIKE 'outside_pc_image_sections%' AND
               (joined.section_name IS NOT NULL OR
                joined.section_executable IS NOT NULL))
        """,
    ),
    (
        "sdk_boundary_candidate_mismatch",
        """
        WITH container_stats AS (
            SELECT boundary_candidate_id, COUNT(*) AS container_count,
                   MIN(source_ordinal) AS first_ordinal,
                   MAX(source_ordinal) AS last_ordinal
            FROM sdk_boundary_candidate_containers
            GROUP BY boundary_candidate_id
        ), candidate_order AS (
            SELECT candidate.*,
                   ROW_NUMBER() OVER (
                       PARTITION BY extraction_id ORDER BY source_ordinal
                   ) - 1 AS expected_ordinal
            FROM sdk_boundary_candidates candidate
        )
        SELECT COUNT(*) FROM (
            SELECT joined.code_join_id AS row_id
            FROM sdk_code_inventory_joins joined
            JOIN sdk_prototype_observations observation
              ON observation.prototype_observation_id =
                    joined.prototype_observation_id
             AND observation.source_tree_sha256 = joined.source_tree_sha256
            WHERE joined.observation_kind = 'prototype'
              AND joined.program_variant IN ('game', 'unspecified_pc')
              AND joined.classification IN (
                  'pc_executable_non_entry',
                  'pc_executable_non_entry_variant_unspecified'
              )
              AND observation.evidence_kind = 'create_object_macro'
              AND NOT EXISTS (
                  SELECT 1 FROM sdk_boundary_candidates candidate
                  WHERE candidate.extraction_id = joined.extraction_id
                    AND candidate.code_join_id = joined.code_join_id
                    AND candidate.prototype_observation_id =
                          joined.prototype_observation_id
              )
            UNION ALL
            SELECT candidate.boundary_candidate_id
            FROM candidate_order candidate
            LEFT JOIN sdk_code_inventory_joins joined
              ON joined.code_join_id = candidate.code_join_id
             AND joined.extraction_id = candidate.extraction_id
             AND joined.source_tree_sha256 = candidate.source_tree_sha256
            LEFT JOIN sdk_prototype_observations observation
              ON observation.prototype_observation_id =
                    candidate.prototype_observation_id
             AND observation.source_tree_sha256 = candidate.source_tree_sha256
            LEFT JOIN container_stats container USING (boundary_candidate_id)
            WHERE joined.code_join_id IS NULL
               OR joined.observation_kind <> 'prototype'
               OR joined.prototype_observation_id <>
                    candidate.prototype_observation_id
               OR joined.program_variant NOT IN ('game', 'unspecified_pc')
               OR joined.classification NOT IN (
                    'pc_executable_non_entry',
                    'pc_executable_non_entry_variant_unspecified'
                  )
               OR observation.evidence_kind <> 'create_object_macro'
               OR candidate.address <> joined.address
               OR candidate.inventory_classification <> joined.classification
               OR candidate.candidate_reason <>
                    'sdk_create_object_target_is_executable_non_entry'
               OR candidate.source_ordinal <> candidate.expected_ordinal
               OR candidate.containing_entry_count <>
                    COALESCE(container.container_count, 0)
               OR (COALESCE(container.container_count, 0) > 0 AND (
                    container.first_ordinal <> 0 OR
                    container.last_ordinal <> container.container_count - 1
                  ))
            UNION ALL
            SELECT container.container_id
            FROM sdk_boundary_candidate_containers container
            LEFT JOIN sdk_boundary_candidates candidate
              USING (boundary_candidate_id)
            LEFT JOIN sdk_extractions extraction USING (extraction_id)
            LEFT JOIN address_groups address
              ON address.address_group_id = container.address_group_id
            LEFT JOIN programs program ON program.program_id = address.program_id
            WHERE candidate.boundary_candidate_id IS NULL
               OR address.program_id <> extraction.pc_program_id
               OR address.address_space <> extraction.pc_address_space
               OR address.address <> container.entry_address
               OR program.platform <> 'pc'
               OR NOT EXISTS (
                    SELECT 1 FROM functions function
                    WHERE function.program_id = extraction.pc_program_id
                      AND function.address_group_id = container.address_group_id
                  )
        ) violation
        """,
    ),
    (
        "sdk_non_pc_addressing",
        """
        SELECT COUNT(*)
        FROM sdk_extractions extraction
        LEFT JOIN programs program ON program.program_id = extraction.pc_program_id
        WHERE program.platform IS NOT 'pc'
           OR length(extraction.pc_address_space) = 0
        """,
    ),
    (
        "sdk_provenance_leakage",
        """
        WITH producer AS (
            SELECT provenance_id FROM sdk_extractions GROUP BY provenance_id
        )
        SELECT
            (SELECT COUNT(*) FROM function_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM function_names row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM function_name_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM class_names row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM class_name_assertions row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM match_claims row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM match_hypothesis_sets row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM claim_evidence row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM match_hypothesis_evidence row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM match_hypothesis_alternative_evidence row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM review_releases row
             JOIN producer USING (provenance_id))
          + (SELECT COUNT(*) FROM review_decisions row
             JOIN producer USING (provenance_id))
        """,
    ),
)


def semantic_validation_counts(
    connection: sqlite3.Connection,
) -> dict[str, int]:
    """Return deterministic violation counts; a valid completed build is all zero."""

    connection.create_function(
        "sha256_hex", 1, _sha256_hex, deterministic=True
    )
    connection.create_function(
        "codeview_record_sha256",
        2,
        _codeview_record_sha256,
        deterministic=True,
    )
    connection.create_function(
        "latin1_bytes", 1, _latin1_bytes, deterministic=True
    )
    connection.create_function(
        "vftable_record_matches",
        7,
        _vftable_record_matches,
        deterministic=True,
    )
    connection.create_function(
        "big_endian_u32_matches",
        2,
        _big_endian_u32_matches,
        deterministic=True,
    )
    connection.create_function(
        "unicode_casefold", 1, _unicode_casefold, deterministic=True
    )
    connection.create_function(
        "sdk_relative_path_valid",
        1,
        _sdk_relative_path_valid,
        deterministic=True,
    )
    connection.create_aggregate(
        "sdk_source_tree_sha256", 3, _SdkSourceTreeSha256
    )
    return {
        name: int(connection.execute(sql).fetchone()[0])
        for name, sql in SEMANTIC_CHECKS
    }


def semantic_validation_ok(counts: dict[str, int]) -> bool:
    return all(count == 0 for count in counts.values())


__all__ = [
    "SEMANTIC_CHECKS",
    "semantic_validation_counts",
    "semantic_validation_ok",
]
