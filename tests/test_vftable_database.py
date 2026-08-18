from __future__ import annotations

import sqlite3
import struct
import unittest

from fnv_atlas.database import AtlasDatabase, IdentityConflictError
from fnv_atlas.pdb_vftables import (
    PeImage,
    PeSection,
    S_PUB32,
    VftableCorpus,
    parse_vftable_symbol_records,
    scan_vftable_pointer_runs,
)


def _record(kind: int, body: bytes) -> bytes:
    record = struct.pack("<HH", 2 + len(body), kind) + body
    return record + b"\0" * ((-len(record)) % 4)


def _public(
    name: str, *, offset: int, section: int = 1, flags: int = 0
) -> bytes:
    body = struct.pack("<IIH", flags, offset, section)
    body += name.encode("latin-1") + b"\0"
    return _record(S_PUB32, body)


def _corpus(*, second_table_offset: int = 8) -> VftableCorpus:
    data = bytearray(0x200)
    struct.pack_into(">4I", data, 0, 0x82002000, 0x82002004, 0x82002008, 0)
    image = PeImage(
        image_base=0x82000000,
        sections=(
            PeSection(1, ".rdata", 0x82001000, 0x100, 0, 0x100, 0),
            PeSection(
                2,
                ".text",
                0x82002000,
                0x100,
                0x100,
                0x100,
                0x20000000,
            ),
        ),
        data=bytes(data),
    )
    symbols = parse_vftable_symbol_records(
        _public("??_7First@@6B@", offset=0, flags=8)
        + _public("??_7FirstAlias@@6B@", offset=0)
        + _public("??_7Second@@6B@", offset=second_table_offset)
        + _public("??_7Unresolved@@6B@", offset=4, section=3),
        symbol_record_stream=7,
        section_bases=image.section_bases,
    )
    return VftableCorpus(
        symbols=symbols,
        pointer_runs=scan_vftable_pointer_runs(image, symbols.address_groups),
    )


class VftableDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AtlasDatabase.create(":memory:")
        self.db.upsert_program(
            "xbox", platform="xbox360", name="Fallout New Vegas Xbox"
        )
        self.db.upsert_program("pc", platform="pc", name="Fallout New Vegas PC")
        self.provenance = self.db.upsert_provenance(
            kind="test", producer="tests.test_vftable_database"
        )

    def tearDown(self) -> None:
        self.db.close()

    def test_lossless_groups_runs_replay_and_multi_producer_lineage(self):
        corpus = _corpus()
        canonical_before = {
            table: self.db.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in ("functions", "function_names", "vtables", "match_claims")
        }

        result = self.db.persist_vftable_corpus(
            "vftable-one",
            corpus,
            program_id="xbox",
            provenance_id=self.provenance,
            scan_max_slots=4096,
        )

        self.assertEqual(result.physical_records, 4)
        self.assertEqual(result.resolved_records, 3)
        self.assertEqual(result.unresolved_records, 1)
        self.assertEqual(result.address_groups, 2)
        self.assertTrue(self.db.validate_vftable_extraction("vftable-one"))
        stored = list(
            self.db.iter_vftable_symbol_records(extraction_id="vftable-one")
        )
        self.assertEqual(
            [row["raw_record"] for row in stored],
            [record.raw_record for record in corpus.symbols.records],
        )
        self.assertEqual(
            [row["decorated_name"] for row in stored],
            [record.decorated_name for record in corpus.symbols.records],
        )
        self.assertIsNone(stored[-1]["address_group_id"])

        groups = list(self.db.iter_vftable_address_observations("vftable-one"))
        self.assertEqual([len(group["members"]) for group in groups], [2, 1])
        self.assertTrue(
            all(
                member["is_ranked"] == 0
                for group in groups
                for member in group["members"]
            )
        )
        runs = list(self.db.iter_vftable_pointer_runs("vftable-one"))
        self.assertEqual(
            {run["extent_semantics"] for run in runs},
            {"observed_pointer_prefix_not_declared_extent"},
        )
        self.assertEqual(runs[0]["boundary_relation"], "next_vftable_inside_pointer_run")
        slots = list(
            self.db.iter_vftable_pointer_slots(extraction_id="vftable-one")
        )
        self.assertEqual(
            [slot["raw_word_hex"] for slot in slots[:3]],
            ["82002000", "82002004", "82002008"],
        )
        self.assertIn(
            "unresolved_pe_section",
            [row["code"] for row in self.db.iter_vftable_diagnostics("vftable-one")],
        )
        canonical_after = {
            table: self.db.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in canonical_before
        }
        self.assertEqual(canonical_after, canonical_before)

        self.db.persist_vftable_corpus(
            "vftable-one",
            corpus,
            program_id="xbox",
            provenance_id=self.provenance,
        )
        second_provenance = self.db.upsert_provenance(
            kind="test", producer="second-vftable-producer"
        )
        self.db.persist_vftable_corpus(
            "vftable-two",
            corpus,
            program_id="xbox",
            provenance_id=second_provenance,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM xbox_vftable_symbol_records"
            ).fetchone()[0],
            4,
        )
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM xbox_vftable_symbol_assertions"
            ).fetchone()[0],
            8,
        )
        with self.assertRaises(IdentityConflictError):
            self.db.persist_vftable_corpus(
                "vftable-one",
                corpus,
                program_id="xbox",
                provenance_id=self.provenance,
                scan_max_slots=4097,
            )

    def test_boundary_after_observed_prefix_is_persisted_as_a_coordinate(self):
        corpus = _corpus(second_table_offset=16)
        first_run = corpus.pointer_runs.runs[0]
        self.assertEqual(first_run.observed_pointer_count, 3)
        self.assertEqual(first_run.known_boundary_slot_index, 4)
        self.assertEqual(
            first_run.boundary_relation, "next_vftable_after_pointer_run"
        )

        self.db.persist_vftable_corpus(
            "vftable-boundary-after-prefix",
            corpus,
            program_id="xbox",
            provenance_id=self.provenance,
        )

        stored_run = next(
            run
            for run in self.db.iter_vftable_pointer_runs(
                "vftable-boundary-after-prefix"
            )
            if run["table_va"] == first_run.table_va
        )
        self.assertEqual(stored_run["observed_pointer_count"], 3)
        self.assertEqual(stored_run["known_boundary_slot_index"], 4)
        self.assertEqual(
            stored_run["boundary_relation"],
            "next_vftable_after_pointer_run",
        )
        self.assertTrue(
            self.db.validate_vftable_extraction(
                "vftable-boundary-after-prefix"
            )
        )

    def test_platform_address_and_immutability_triggers_are_directly_enforced(self):
        corpus = _corpus()
        self.db.persist_vftable_corpus(
            "vftable-guards",
            corpus,
            program_id="xbox",
            provenance_id=self.provenance,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                """
                INSERT INTO xbox_vftable_extractions(
                    extraction_id, program_id, dbi_stream,
                    symbol_record_stream, scan_max_slots,
                    physical_record_count, resolved_record_count,
                    unresolved_record_count, canonical_name_count,
                    source_address_group_count, pointer_run_count,
                    pointer_slot_count, symbol_diagnostic_count,
                    run_diagnostic_count, scan_diagnostic_count, provenance_id
                ) VALUES ('wrong-platform', 'pc', 3, 7, 1, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, ?)
                """,
                (self.provenance,),
            )
        slot = self.db.connection.execute(
            "SELECT pointer_slot_id FROM xbox_vftable_pointer_slots LIMIT 1"
        ).fetchone()[0]
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.db.connection.execute(
                "UPDATE xbox_vftable_pointer_slots SET raw_word = x'00000000' "
                "WHERE pointer_slot_id = ?",
                (slot,),
            )
        address_group = self.db.connection.execute(
            "SELECT slot_address_group_id FROM xbox_vftable_pointer_slots LIMIT 1"
        ).fetchone()[0]
        with self.assertRaisesRegex(sqlite3.IntegrityError, "address identity"):
            self.db.connection.execute(
                "UPDATE address_groups SET address = address + 4 "
                "WHERE address_group_id = ?",
                (address_group,),
            )

    def test_late_identity_conflict_rolls_back_extraction_and_address_rows(self):
        corpus = _corpus()
        first = corpus.symbols.records[0]
        digest = first.canonical_name_id.rsplit(":", 1)[-1]
        self.db.connection.execute(
            """
            INSERT INTO xbox_vftable_name_identities(
                canonical_name_id, decorated_name, decorated_name_bytes,
                decorated_name_sha256
            ) VALUES (?, 'conflicting', x'00', ?)
            """,
            (first.canonical_name_id, digest),
        )
        address_count = self.db.connection.execute(
            "SELECT COUNT(*) FROM address_groups WHERE program_id = 'xbox'"
        ).fetchone()[0]

        with self.assertRaises(IdentityConflictError):
            self.db.persist_vftable_corpus(
                "rollback-vftable",
                corpus,
                program_id="xbox",
                provenance_id=self.provenance,
            )

        self.assertIsNone(self.db.get_vftable_extraction("rollback-vftable"))
        self.assertEqual(
            self.db.connection.execute(
                "SELECT COUNT(*) FROM address_groups WHERE program_id = 'xbox'"
            ).fetchone()[0],
            address_count,
        )


if __name__ == "__main__":
    unittest.main()
