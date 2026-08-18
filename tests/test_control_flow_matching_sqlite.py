from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))


from fnv_atlas.control_flow_matching_sqlite import (
    analyze_control_flow_candidates_from_sqlite,
    load_control_flow_matching_inputs,
)
from fnv_atlas.database import AtlasDatabase


PC = "program:pc:adapter-fixture"
XBOX = "program:xbox:adapter-fixture"


def _create_function(
    db: AtlasDatabase,
    *,
    program_id: str,
    function_id: str,
    address_space: str,
    address: int,
    provenance_id: str,
) -> tuple[str, str]:
    address_group = db.upsert_address_group(
        program_id=program_id,
        address_space=address_space,
        address=address,
        kind="code",
    )
    function = db.upsert_function(
        function_id=function_id,
        address_group_id=address_group,
        identity_key=function_id,
        provenance_id=provenance_id,
    )
    return function, address_group


def _add_scalar_mapping(
    db: AtlasDatabase,
    *,
    ordinal: str,
    pc_function_id: str,
    xbox_function_id: str,
    provenance_id: str,
    claim_status: str = "candidate",
) -> None:
    claim = db.upsert_match_claim(
        claim_id=f"claim:{ordinal}",
        pc_function_id=pc_function_id,
        xbox_function_id=xbox_function_id,
        status=claim_status,
        provenance_id=provenance_id,
    )
    hypothesis = db.upsert_match_hypothesis_set(
        hypothesis_set_id=f"set:{ordinal}",
        identity_key=ordinal,
        pc_function_id=pc_function_id,
        provenance_id=provenance_id,
    )
    db.add_match_hypothesis_alternative(
        hypothesis,
        alternative_id=f"alternative:{ordinal}",
        claim_id=claim,
    )


def _create_fixture() -> AtlasDatabase:
    db = AtlasDatabase.create()
    db.upsert_program(PC, platform="pc", name="Adapter PC")
    db.upsert_program(XBOX, platform="xbox360", name="Adapter Xbox")
    provenance = db.upsert_provenance(
        kind="test",
        producer="tests.test_control_flow_matching_sqlite",
    )

    pc_functions: dict[str, str] = {}
    for ordinal, name in enumerate(("A", "B", "C", "F", "Z"), 1):
        function, _ = _create_function(
            db,
            program_id=PC,
            function_id=f"pc:{name}",
            address_space="ram",
            address=0x400000 + ordinal * 0x100,
            provenance_id=provenance,
        )
        pc_functions[name] = function

    xbox_functions: dict[str, str] = {}
    xbox_groups: dict[str, str] = {}
    for ordinal, name in enumerate(("A", "B", "C", "M1", "M2"), 1):
        address = 0x82000000 + ordinal * 0x100
        if name in {"M1", "M2"}:
            address = 0x8200F000
        function, group = _create_function(
            db,
            program_id=XBOX,
            function_id=f"x:{name}",
            address_space="xbox-va",
            address=address,
            provenance_id=provenance,
        )
        xbox_functions[name] = function
        xbox_groups[name] = group

    _add_scalar_mapping(
        db,
        ordinal="caller",
        pc_function_id=pc_functions["A"],
        xbox_function_id=xbox_functions["A"],
        provenance_id=provenance,
    )
    _add_scalar_mapping(
        db,
        ordinal="closed",
        pc_function_id=pc_functions["B"],
        xbox_function_id=xbox_functions["B"],
        provenance_id=provenance,
    )
    _add_scalar_mapping(
        db,
        ordinal="rejected",
        pc_function_id=pc_functions["Z"],
        xbox_function_id=xbox_functions["M1"],
        provenance_id=provenance,
        claim_status="rejected",
    )

    fold = db.upsert_fold_group(
        "fold:fixture",
        program_id=XBOX,
        provenance_id=provenance,
    )
    db.add_fold_member(fold, xbox_functions["M1"])
    db.add_fold_member(fold, xbox_functions["M2"])
    fold_set = db.upsert_match_hypothesis_set(
        hypothesis_set_id="set:fold",
        identity_key="fold",
        pc_function_id=pc_functions["F"],
        provenance_id=provenance,
    )
    db.add_match_hypothesis_alternative(
        fold_set,
        alternative_id="alternative:fold",
        xbox_fold_group_id=fold,
    )

    db.upsert_call_edge(
        edge_id="edge:A:B",
        caller_function_id=pc_functions["A"],
        callee_function_id=pc_functions["B"],
        provenance_id=provenance,
    )
    db.upsert_call_edge(
        edge_id="edge:A:C",
        caller_function_id=pc_functions["A"],
        callee_function_id=pc_functions["C"],
        provenance_id=provenance,
    )
    unresolved_group = db.upsert_address_group(
        program_id=PC,
        address_space="ghidra-offset-unknown",
        address=0x1234,
        kind="unresolved-reference",
    )
    unresolved = db.upsert_unresolved_target(
        target_id="pc:unresolved:external",
        program_id=PC,
        address_group_id=unresolved_group,
        target_kind="external_offset",
        reason="fixture unresolved edge",
        provenance_id=provenance,
    )
    db.upsert_call_edge(
        edge_id="edge:Z:unresolved",
        caller_function_id=pc_functions["Z"],
        unresolved_target_id=unresolved,
        provenance_id=provenance,
    )

    first_extraction = db.upsert_control_flow_extraction(
        extraction_id="extraction:first",
        program_id=XBOX,
        persistence_policy="call_relevant_v1",
        source_physical_site_count=2,
        source_logical_use_count=2,
        persisted_physical_site_count=2,
        persisted_logical_use_count=2,
        triggering_logical_use_count=2,
        procedure_scan_count=0,
        provenance_id=provenance,
    )
    second_extraction = db.upsert_control_flow_extraction(
        extraction_id="extraction:second",
        program_id=XBOX,
        persistence_policy="call_relevant_v1",
        source_physical_site_count=1,
        source_logical_use_count=1,
        persisted_physical_site_count=1,
        persisted_logical_use_count=1,
        triggering_logical_use_count=1,
        procedure_scan_count=0,
        provenance_id=provenance,
    )
    address_only_group = db.upsert_address_group(
        program_id=XBOX,
        address_space="xbox-va",
        address=0x8200E000,
        kind="unresolved-reference",
    )
    for ordinal, (site_id, site_address, target_function, target_group) in enumerate(
        (
            ("site:one", 0x82000104, xbox_functions["B"], xbox_groups["B"]),
            ("site:two", 0x82000108, xbox_functions["C"], xbox_groups["C"]),
        ),
        1,
    ):
        site_group = db.upsert_address_group(
            program_id=XBOX,
            address_space="xbox-va",
            address=site_address,
            kind="code",
        )
        db.upsert_control_flow_site(site_id, address_group_id=site_group)
        db.add_control_flow_site_assertion(
            first_extraction,
            site_id,
            assertion_id=f"site-assertion:first:{ordinal}",
            raw_site_va=site_address,
            instruction_word=0x48000001,
            branch_kind="branch_immediate",
            raw_target_va=0x82000000 + (ordinal + 1) * 0x100,
            target_kind="unique_procedure",
            target_record_count=1,
            link=True,
            absolute=False,
            conditional=False,
            indirect=False,
            target_address_group_id=target_group,
            target_function_id=target_function,
        )
        use_id = f"use:{ordinal}"
        db.upsert_control_flow_use(
            use_id,
            procedure_record_id=xbox_functions["A"],
            function_id=xbox_functions["A"],
            site_id=site_id,
        )
        db.add_control_flow_use_assertion(
            first_extraction,
            use_id,
            assertion_id=f"use-assertion:first:{ordinal}",
            role="direct_call",
        )

    db.add_control_flow_site_assertion(
        second_extraction,
        "site:one",
        assertion_id="site-assertion:second:1",
        raw_site_va=0x82000104,
        instruction_word=0x48000000,
        branch_kind="branch_immediate",
        raw_target_va=0x8200E000,
        target_kind="executable_non_entry",
        target_record_count=0,
        link=False,
        absolute=False,
        conditional=False,
        indirect=False,
        target_address_group_id=address_only_group,
    )
    db.add_control_flow_use_assertion(
        second_extraction,
        "use:1",
        assertion_id="use-assertion:second:1",
        role="tail_transfer",
    )
    return db


class ControlFlowMatchingSqliteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = _create_fixture()

    def tearDown(self) -> None:
        self.db.close()

    def test_loader_preserves_endpoints_folds_and_same_extraction_pairing(self) -> None:
        inputs = load_control_flow_matching_inputs(self.db.connection)

        self.assertEqual(len(inputs.mapping_alternatives), 4)
        rejected = next(
            item for item in inputs.mapping_alternatives if item.alternative_id == "alternative:rejected"
        )

        self.assertEqual(
            rejected.status,
            "hypothesis:candidate|claim:rejected",
        )
        fold = next(
            item for item in inputs.mapping_alternatives if item.alternative_id == "alternative:fold"
        )
        self.assertEqual(fold.xbox_endpoint.kind, "fold_group")
        self.assertEqual(fold.xbox_endpoint.identity, "fold:fixture")
        self.assertEqual(
            {(item.fold_group_id, item.function_id) for item in inputs.fold_memberships},
            {("fold:fixture", "x:M1"), ("fold:fixture", "x:M2")},
        )

        self.assertEqual(len(inputs.pc_call_edges), 3)
        unresolved = next(
            item for item in inputs.pc_call_edges if item.edge_id == "edge:Z:unresolved"
        )
        self.assertEqual(unresolved.callee_endpoint.kind, "unresolved_target")
        self.assertEqual(
            unresolved.callee_endpoint.identity, "pc:unresolved:external"
        )

        self.assertEqual(len(inputs.xbox_flow_occurrences), 3)
        paired = {
            (
                item.extraction_id,
                item.use_assertion_id,
                item.site_assertion_id,
                item.role,
                item.target_endpoint.kind,
                item.target_endpoint.identity,
            )
            for item in inputs.xbox_flow_occurrences
        }
        self.assertEqual(
            paired,
            {
                (
                    "extraction:first",
                    "use-assertion:first:1",
                    "site-assertion:first:1",
                    "direct_call",
                    "function",
                    "x:B",
                ),
                (
                    "extraction:first",
                    "use-assertion:first:2",
                    "site-assertion:first:2",
                    "direct_call",
                    "function",
                    "x:C",
                ),
                (
                    "extraction:second",
                    "use-assertion:second:1",
                    "site-assertion:second:1",
                    "tail_transfer",
                    "address_only",
                    next(
                        item.target_endpoint.identity
                        for item in inputs.xbox_flow_occurrences
                        if item.extraction_id == "extraction:second"
                    ),
                ),
            },
        )

    def test_matcher_derived_candidates_are_never_recursive_seeds(self) -> None:
        provenance = self.db.upsert_provenance(
            kind="analysis",
            producer="fnv_atlas.control_flow_matching",
        )
        _add_scalar_mapping(
            self.db,
            ordinal="derived",
            pc_function_id="pc:A",
            xbox_function_id="x:A",
            provenance_id=provenance,
        )

        inputs = load_control_flow_matching_inputs(self.db.connection)
        derived = next(
            item
            for item in inputs.mapping_alternatives
            if item.alternative_id == "alternative:derived"
        )
        self.assertEqual(derived.status, "derived_non_seed")
        result = analyze_control_flow_candidates_from_sqlite(self.db.connection)
        self.assertIn(
            ("derived_non_seed", 1),
            result.summary.excluded_mapping_status_counts,
        )
        self.assertEqual(result.summary.proposal_sets, 1)

    def test_loader_and_analysis_are_select_only_and_do_not_read_names(self) -> None:
        connection = self.db.connection
        before_changes = connection.total_changes
        before_counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "match_hypothesis_alternatives",
                "call_edges",
                "control_flow_use_assertions",
                "control_flow_site_assertions",
                "fold_group_members",
            )
        }
        read_tables: set[str] = set()
        denied_actions = {
            getattr(sqlite3, name)
            for name in (
                "SQLITE_INSERT",
                "SQLITE_UPDATE",
                "SQLITE_DELETE",
                "SQLITE_CREATE_TABLE",
                "SQLITE_DROP_TABLE",
                "SQLITE_ALTER_TABLE",
                "SQLITE_CREATE_INDEX",
                "SQLITE_DROP_INDEX",
                "SQLITE_PRAGMA",
                "SQLITE_ATTACH",
                "SQLITE_DETACH",
            )
        }

        def authorize(
            action: int,
            first: str | None,
            second: str | None,
            database: str | None,
            trigger: str | None,
        ) -> int:
            del second, database, trigger
            if action == sqlite3.SQLITE_READ and first is not None:
                read_tables.add(first)
            if action in denied_actions:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(authorize)
        try:
            first = load_control_flow_matching_inputs(connection)
            result = analyze_control_flow_candidates_from_sqlite(connection)
            second = load_control_flow_matching_inputs(connection)
        finally:
            connection.set_authorizer(None)

        self.assertEqual(first, second)
        self.assertEqual(connection.total_changes, before_changes)
        self.assertEqual(
            before_counts,
            {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in before_counts
            },
        )
        self.assertNotIn("function_names", read_tables)
        self.assertNotIn("function_name_assertions", read_tables)
        self.assertIn("fold_group_members", read_tables)
        self.assertIn("control_flow_use_assertions", read_tables)
        self.assertIn("control_flow_site_assertions", read_tables)

        self.assertEqual(result.summary.excluded_mapping_status_counts, (
            ("hypothesis:candidate|claim:rejected", 1),
        ))
        self.assertEqual(result.summary.proposal_sets, 1)
        self.assertEqual(result.summary.proposal_alternatives, 1)
        self.assertEqual(result.summary.proposal_evidence_occurrences, 1)
        proposal = result.proposals[0]
        self.assertEqual(proposal.pc_endpoint.identity, "pc:C")
        self.assertEqual(proposal.xbox_endpoint.identity, "x:C")
        self.assertEqual(
            result.summary.excluded_xbox_role_counts,
            (("tail_transfer", 1),),
        )


if __name__ == "__main__":
    unittest.main()
