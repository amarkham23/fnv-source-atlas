from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import sqlite3
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.database import (  # noqa: E402
    AtlasDatabase,
    AtlasError,
    IdentityConflictError,
)
from fnv_atlas.pdb_globals import (  # noqa: E402
    DataSymbolExtraction,
    DataSymbolRecord,
    build_data_address_groups,
    make_data_record_id,
)
from fnv_atlas.tpi_layouts import (  # noqa: E402
    LF_CLASS,
    LF_FIELDLIST,
    LF_MEMBER,
    LF_METHOD,
    LF_METHODLIST,
    LayoutDiagnostic,
    LayoutExtraction,
    LayoutMember,
    MethodOverload,
    RawTypeRecord,
    TagLayout,
    TpiLayoutCorpus,
    TypeRecordExtraction,
)


def _raw(type_index: int, leaf_kind: int, body: bytes) -> RawTypeRecord:
    return RawTypeRecord(
        type_index=type_index,
        leaf_kind=leaf_kind,
        leaf_name=f"LF_0x{leaf_kind:04X}",
        record_length=len(body) + 2,
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        rendered_type=f"type_0x{type_index:X}",
    )


def _tag_hash(raw: RawTypeRecord) -> str:
    return hashlib.sha256(
        raw.leaf_kind.to_bytes(2, "little") + raw.body
    ).hexdigest()


def _tpi_fixture() -> TpiLayoutCorpus:
    raw_records = (
        _raw(0x1100, LF_FIELDLIST, b"field-list"),
        _raw(0x1200, LF_METHODLIST, b"method-list"),
        _raw(0x1300, LF_CLASS, b"first-tag"),
        _raw(0x1301, LF_CLASS, b"second-tag"),
        _raw(0x1302, LF_CLASS, b"forward-tag"),
    )
    raw_by_index = {record.type_index: record for record in raw_records}
    overloads = (
        MethodOverload(
            ordinal=0,
            attributes=3,
            access="public",
            method_kind="vanilla",
            method_options=0,
            type_index=0x2000,
            rendered_type="void ()",
            vtable_offset=None,
        ),
        MethodOverload(
            ordinal=1,
            attributes=19,
            access="public",
            method_kind="introducing_virtual",
            method_options=0,
            type_index=0x2001,
            rendered_type="void (int)",
            vtable_offset=8,
        ),
    )
    data_member = LayoutMember(
        ordinal=0,
        source_field_list_type_index=0x1100,
        source_record_offset=0,
        leaf_kind=LF_MEMBER,
        member_kind="data_member",
        attributes=3,
        access="public",
        name="value",
        type_index=0x74,  # primitive: deliberately absent from raw records
        rendered_type="int",
        offset=2**63 + 7,
    )
    method_member = LayoutMember(
        ordinal=1,
        source_field_list_type_index=0x1100,
        source_record_offset=16,
        leaf_kind=LF_METHOD,
        member_kind="overloaded_method",
        name="Tick",
        method_list_type_index=0x1200,
        declared_overload_count=2,
        overloads=overloads,
    )
    shared_members = (data_member, method_member)
    first = TagLayout(
        type_index=0x1300,
        leaf_kind=LF_CLASS,
        tag_kind="class",
        member_count=3,
        properties=0x200,
        field_list_type_index=0x1100,
        derived_type_index=0,
        vtable_shape_type_index=0,
        underlying_type_index=None,
        size=2**63 + 11,
        name="Duplicate",
        unique_name=".?AVDuplicate@One@@",
        is_forward_reference=False,
        record_sha256=_tag_hash(raw_by_index[0x1300]),
        members=shared_members,
        diagnostics=(
            LayoutDiagnostic(
                code="missing_referenced_type",
                type_index=0xDEADBEEF,
                offset=4,
                message="unavailable type remains explicit",
                remaining_hex="aabb",
            ),
        ),
    )
    second = replace(
        first,
        type_index=0x1301,
        unique_name=".?AVDuplicate@Two@@",
        record_sha256=_tag_hash(raw_by_index[0x1301]),
        diagnostics=(),
    )
    forward = TagLayout(
        type_index=0x1302,
        leaf_kind=LF_CLASS,
        tag_kind="class",
        member_count=0,
        properties=0x80,
        field_list_type_index=0,
        derived_type_index=0,
        vtable_shape_type_index=0,
        underlying_type_index=None,
        size=0,
        name="Duplicate",
        unique_name=".?AVDuplicate@One@@",
        is_forward_reference=True,
        record_sha256=_tag_hash(raw_by_index[0x1302]),
        members=(),
        diagnostics=(),
    )
    return TpiLayoutCorpus(
        TypeRecordExtraction(raw_records),
        LayoutExtraction((first, second, forward)),
    )


def _data_record(
    module_index: int,
    record_offset: int,
    *,
    va: int | None,
    name: str,
    type_index: int,
    symbol_stream: int = 12,
) -> DataSymbolRecord:
    return DataSymbolRecord(
        record_id=make_data_record_id(
            module_index, symbol_stream, record_offset
        ),
        module_index=module_index,
        module_name=f"module-{module_index}",
        symbol_stream=symbol_stream,
        record_offset=record_offset,
        record_length=24,
        record_kind="S_GDATA32",
        record_kind_code=0x110D,
        va=va,
        section=1 if va is not None else 99,
        section_offset=record_offset,
        type_index=type_index,
        raw_name=name,
    )


class TypeAndDataPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create()
        self.db.upsert_program("pc", platform="pc", name="PC")
        self.db.upsert_program("x360", platform="xbox360", name="Xbox")
        self.first_provenance = self.db.upsert_provenance(
            kind="pdb", producer="type-data-tests", producer_version="1"
        )
        self.second_provenance = self.db.upsert_provenance(
            kind="pdb", producer="type-data-tests", producer_version="2"
        )

    def tearDown(self) -> None:
        self.db.close()

    def test_tpi_persistence_is_lossless_shared_and_replay_safe(self) -> None:
        corpus = _tpi_fixture()
        result = self.db.persist_tpi_layout_corpus(
            corpus,
            program_id="x360",
            provenance_id=self.first_provenance,
            details={"source": "synthetic"},
        )
        self.assertEqual(result.raw_type_records, 5)
        self.assertEqual(result.tag_records, 3)
        self.assertEqual(result.definitions, 2)
        self.assertEqual(result.forward_references, 1)
        self.assertEqual(result.tag_member_occurrences, 4)
        self.assertEqual(result.physical_field_members, 2)
        self.assertEqual(result.physical_method_overloads, 2)
        self.assertEqual(result.diagnostics, 1)
        self.assertTrue(self.db.validate_tpi_layout_extraction(result.extraction_id))

        raw_rows = list(
            self.db.iter_codeview_type_records(
                extraction_id=result.extraction_id
            )
        )
        self.assertEqual(len(raw_rows), 5)
        self.assertEqual(raw_rows[0]["raw_body"], b"field-list")
        tags = list(self.db.iter_codeview_tag_layouts(result.extraction_id))
        self.assertEqual([tag["display_name"] for tag in tags], ["Duplicate"] * 3)
        self.assertEqual(tags[0]["size"], 2**63 + 11)
        first_members = list(
            self.db.iter_codeview_tag_members(tags[0]["tag_layout_id"])
        )
        self.assertEqual(first_members[0]["type_index"], 0x74)
        self.assertEqual(first_members[0]["offset"], 2**63 + 7)
        self.assertEqual(
            [item["method_type_index"] for item in first_members[1]["overloads"]],
            [0x2000, 0x2001],
        )
        diagnostics = list(
            self.db.iter_codeview_layout_diagnostics(result.extraction_id)
        )
        self.assertEqual(diagnostics[0]["source_type_index"], 0xDEADBEEF)
        self.assertEqual(diagnostics[0]["remaining_hex"], "aabb")

        replay = self.db.persist_tpi_layout_corpus(
            corpus,
            program_id="x360",
            provenance_id=self.first_provenance,
            details={"source": "synthetic"},
        )
        self.assertEqual(replay, result)
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM codeview_type_record_assertions"
            ).fetchone()[0],
            5,
        )

        second = self.db.persist_tpi_layout_corpus(
            corpus,
            program_id="x360",
            provenance_id=self.second_provenance,
            details={"source": "synthetic"},
        )
        self.assertNotEqual(second.extraction_id, result.extraction_id)
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM codeview_type_records"
            ).fetchone()[0],
            5,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM codeview_type_record_assertions"
            ).fetchone()[0],
            10,
        )

    def test_tpi_rejects_inconsistent_reused_physical_decodes_atomically(self) -> None:
        corpus = _tpi_fixture()
        first, second, forward = corpus.layouts.records
        changed_member = replace(second.members[0], name="different")
        inconsistent = replace(
            corpus,
            layouts=LayoutExtraction(
                (first, replace(second, members=(changed_member, second.members[1])), forward)
            ),
        )
        with self.assertRaisesRegex(ValueError, "decoded inconsistently"):
            self.db.persist_tpi_layout_corpus(
                inconsistent,
                program_id="x360",
                provenance_id=self.first_provenance,
            )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM codeview_type_extractions"
            ).fetchone()[0],
            0,
        )

        changed_overloads = (
            replace(second.members[1].overloads[0], type_index=0x9999),
            second.members[1].overloads[1],
        )
        inconsistent_method = replace(
            corpus,
            layouts=LayoutExtraction(
                (
                    first,
                    replace(
                        second,
                        members=(
                            second.members[0],
                            replace(second.members[1], overloads=changed_overloads),
                        ),
                    ),
                    forward,
                )
            ),
        )
        with self.assertRaisesRegex(ValueError, "decoded inconsistently"):
            self.db.persist_tpi_layout_corpus(
                inconsistent_method,
                program_id="x360",
                provenance_id=self.first_provenance,
            )

    def test_tpi_platform_and_immutability_guards_survive_direct_sql(self) -> None:
        with self.assertRaises(AtlasError):
            self.db.persist_tpi_layout_corpus(
                _tpi_fixture(),
                program_id="pc",
                provenance_id=self.first_provenance,
            )
        result = self.db.persist_tpi_layout_corpus(
            _tpi_fixture(),
            program_id="x360",
            provenance_id=self.first_provenance,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE codeview_type_extractions SET diagnostic_count = 0 "
                "WHERE extraction_id = ?",
                (result.extraction_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "DELETE FROM codeview_type_record_assertions "
                "WHERE extraction_id = ?",
                (result.extraction_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE programs SET platform = 'pc' WHERE program_id = 'x360'"
            )

    def test_data_symbols_preserve_aliases_unresolved_and_lineage(self) -> None:
        records = (
            _data_record(1, 4, va=0x82001000, name="first", type_index=0x74),
            _data_record(1, 32, va=0x82001000, name="alias", type_index=0xBEEF),
            _data_record(2, 4, va=None, name="unresolved", type_index=0xDEAD),
        )
        extraction = DataSymbolExtraction(
            records,
            build_data_address_groups(records),
        )
        existing_address = self.db.upsert_address_group(
            program_id="x360",
            address_space="xbox-va",
            address=0x82001000,
            kind="code",
            details={"keep": True},
        )
        result = self.db.persist_data_symbol_extraction(
            extraction,
            program_id="x360",
            provenance_id=self.first_provenance,
        )
        self.assertEqual(
            (result.records, result.resolved_records, result.unresolved_records),
            (3, 2, 1),
        )
        self.assertEqual(result.unique_addresses, 1)
        self.assertTrue(
            self.db.validate_data_symbol_extraction(result.extraction_id)
        )
        at_address = self.db.data_symbols_at(
            "x360", 0x82001000, extraction_id=result.extraction_id
        )
        self.assertEqual({row["raw_name"] for row in at_address}, {"first", "alias"})
        unresolved = list(
            self.db.iter_data_symbols(
                extraction_id=result.extraction_id, resolved=False
            )
        )
        self.assertEqual(unresolved[0]["raw_name"], "unresolved")
        self.assertIsNone(unresolved[0]["address_group_id"])
        address = self.db.connection.execute(
            "SELECT kind, details_json FROM address_groups WHERE address_group_id = ?",
            (existing_address,),
        ).fetchone()
        self.assertEqual((address["kind"], address["details_json"]), ("code", '{"keep":true}'))
        for table in ("functions", "function_names", "match_claims"):
            self.assertEqual(
                self.db.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                0,
            )

        replay = self.db.persist_data_symbol_extraction(
            extraction,
            program_id="x360",
            provenance_id=self.first_provenance,
        )
        self.assertEqual(replay, result)
        second = self.db.persist_data_symbol_extraction(
            extraction,
            program_id="x360",
            provenance_id=self.second_provenance,
        )
        self.assertNotEqual(second.extraction_id, result.extraction_id)
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM data_symbol_records"
            ).fetchone()[0],
            3,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM data_symbol_record_assertions"
            ).fetchone()[0],
            6,
        )

    def test_data_symbol_guards_and_atomic_conflicts(self) -> None:
        record = _data_record(
            1, 4, va=0x82001000, name="first", type_index=0x1234
        )
        extraction = DataSymbolExtraction(
            (record,), build_data_address_groups((record,))
        )
        with self.assertRaises(AtlasError):
            self.db.persist_data_symbol_extraction(
                extraction,
                program_id="pc",
                provenance_id=self.first_provenance,
            )
        result = self.db.persist_data_symbol_extraction(
            extraction,
            program_id="x360",
            provenance_id=self.first_provenance,
        )

        # Same canonical physical ID with conflicting coordinates cannot move.
        db_record_id = self.db.connection.execute(
            "SELECT data_record_id FROM data_symbol_records"
        ).fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE data_symbol_records SET record_offset = 8 "
                "WHERE data_record_id = ?",
                (db_record_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "DELETE FROM data_symbol_record_assertions WHERE extraction_id = ?",
                (result.extraction_id,),
            )
        resolved_group = self.db.connection.execute(
            """
            SELECT address_group_id FROM data_symbol_record_assertions
            WHERE extraction_id = ? AND address_group_id IS NOT NULL
            """,
            (result.extraction_id,),
        ).fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE address_groups SET address_space = 'ram' "
                "WHERE address_group_id = ?",
                (resolved_group,),
            )

        ram_address = self.db.upsert_address_group(
            program_id="x360",
            address_space="ram",
            address=0x82002000,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                INSERT INTO data_symbol_record_assertions(
                    assertion_id, extraction_id, program_id, data_record_id,
                    module_name, record_length, record_kind, record_kind_code,
                    resolved_va, address_group_id, section, section_offset,
                    type_index, raw_name
                ) VALUES (?, ?, ?, ?, '', 24, 'S_GDATA32', 4365,
                          ?, ?, 1, 0, 116, 'bad-domain')
                """,
                (
                    "bad-address-assertion",
                    result.extraction_id,
                    "x360",
                    db_record_id,
                    0x82002000,
                    ram_address,
                ),
            )

        bad = replace(record, record_kind="S_LDATA32")
        with self.assertRaises(ValueError):
            self.db.persist_data_symbol_extraction(
                DataSymbolExtraction((bad,), build_data_address_groups((bad,))),
                program_id="x360",
                provenance_id=self.second_provenance,
            )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM data_symbol_extractions"
            ).fetchone()[0],
            1,
        )

    def test_raw_type_identity_conflict_rolls_back_new_extraction(self) -> None:
        corpus = _tpi_fixture()
        first = self.db.persist_tpi_layout_corpus(
            corpus,
            program_id="x360",
            provenance_id=self.first_provenance,
        )
        original = corpus.type_records.records[0]
        changed_body = b"different-raw-field-list"
        changed = replace(
            original,
            body=changed_body,
            record_length=len(changed_body) + 2,
            body_sha256=hashlib.sha256(changed_body).hexdigest(),
        )
        conflict = replace(
            corpus,
            type_records=TypeRecordExtraction(
                (changed,) + corpus.type_records.records[1:]
            ),
        )
        before = self.db.connection.execute(
            "SELECT COUNT(*) FROM codeview_type_extractions"
        ).fetchone()[0]
        with self.assertRaises(IdentityConflictError):
            self.db.persist_tpi_layout_corpus(
                conflict,
                program_id="x360",
                provenance_id=self.second_provenance,
            )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM codeview_type_extractions"
            ).fetchone()[0],
            before,
        )
        self.assertTrue(self.db.validate_tpi_layout_extraction(first.extraction_id))


if __name__ == "__main__":
    unittest.main()
