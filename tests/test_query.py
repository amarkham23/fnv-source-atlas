from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))


from fnv_atlas.cli import database_summary, main
from fnv_atlas.database import AtlasDatabase
from fnv_atlas.query import AtlasQuery, QueryError, parse_query_address, render_human
from fnv_atlas.tpi_signatures import FunctionSignature, LF_PROCEDURE, SignatureResult


PC = "program:pc:fixture"
XBOX = "program:xbox360:fixture"


def _create_fixture(path: Path) -> None:
    with AtlasDatabase.create(path) as db:
        db.upsert_program(PC, platform="pc", name="Fixture PC")
        db.upsert_program(XBOX, platform="xbox360", name="Fixture Xbox")
        provenance = db.upsert_provenance(kind="test", producer="tests.test_query")

        pc_group = db.upsert_address_group(
            program_id=PC, address_space="ram", address=0x401000
        )
        pc_function = db.upsert_function(
            function_id="pc:function:tick",
            address_group_id=pc_group,
            identity_key="ghidra-entry",
            provenance_id=provenance,
            details={"size": 32},
        )
        db.add_function_name(
            pc_function,
            "Actor::Tick",
            name_kind="ghidra",
            is_primary=True,
            provenance_id=provenance,
        )
        source = db.upsert_source_file(
            "pc:source:actor",
            program_id=PC,
            normalized_path="game/Actor.cpp",
            language="c++",
        )
        db.add_function_source_range(
            pc_function,
            source,
            line_start=42,
            line_end=44,
            is_primary=True,
            provenance_id=provenance,
        )

        module = db.upsert_module(
            "xbox:module:actor", program_id=XBOX, name="Actor.obj", compiland_index=1
        )
        shared_group = db.upsert_address_group(
            program_id=XBOX, address_space="xbox-va", address=0x82001000
        )
        xbox_functions = []
        for ordinal in (1, 2):
            function_id = db.upsert_function(
                function_id=f"x360-proc:fixture:{ordinal}",
                address_group_id=shared_group,
                identity_key=f"record:{ordinal}",
                type_index=0x2000 if ordinal == 1 else 0x2001,
                module_id=module,
                symbol_record_kind="S_GPROC32",
                provenance_id=provenance,
                details={"record_offset": ordinal * 48, "size": 16},
            )
            db.add_function_name(
                function_id,
                "?Tick@Actor@@UEAAXXZ",
                name_kind="pdb_procedure_name",
                is_primary=True,
                provenance_id=provenance,
            )
            xbox_functions.append(function_id)
        fold = db.upsert_fold_group(
            "x360-fold:82001000",
            program_id=XBOX,
            provenance_id=provenance,
            details={"address": 0x82001000, "record_count": 2},
        )
        for function_id in xbox_functions:
            db.add_fold_member(fold, function_id)

        unique_group = db.upsert_address_group(
            program_id=XBOX, address_space="xbox-va", address=0x82002000
        )
        unique_xbox = db.upsert_function(
            function_id="x360-proc:fixture:3",
            address_group_id=unique_group,
            identity_key="record:3",
            type_index=0x2002,
            module_id=module,
            symbol_record_kind="S_LPROC32",
            provenance_id=provenance,
            details={"record_offset": 144, "size": 24},
        )
        db.add_function_name(
            unique_xbox,
            "?Other@Actor@@QEAAXXZ",
            name_kind="pdb_procedure_name",
            is_primary=True,
            provenance_id=provenance,
        )
        signature = FunctionSignature(
            type_index=0x2000,
            leaf_kind=LF_PROCEDURE,
            leaf_name="LF_PROCEDURE",
            return_type_index=3,
            class_type_index=None,
            this_type_index=None,
            calling_convention=0,
            calling_convention_name="near_c",
            attributes=0,
            this_adjustment=None,
            parameter_count=1,
            argument_list_type_index=0x2100,
            argument_list_count=1,
            argument_type_indices=(0x74,),
            is_variadic=False,
            rendered_return_type="void",
            rendered_class_type=None,
            rendered_this_type=None,
            rendered_argument_types=("int",),
            rendered_signature="void __cdecl (int)",
        )
        db.upsert_signature_result(
            xbox_functions[0],
            SignatureResult(0x2000, signature),
            provenance_id=provenance,
        )

        pc_class = db.upsert_class(
            "pc:class:Actor", program_id=PC, identity_key="Actor"
        )
        xbox_class = db.upsert_class(
            "xbox:class:Actor", program_id=XBOX, identity_key="Actor"
        )
        db.add_class_name(
            pc_class,
            "Actor",
            name_kind="pc_rtti_class_key",
            is_primary=True,
            provenance_id=provenance,
        )
        db.add_class_name(
            xbox_class,
            "Actor",
            name_kind="xbox_vftable_class_key",
            is_primary=True,
            provenance_id=provenance,
        )
        pc_table = db.upsert_vtable(
            "pc:vtable:Actor",
            program_id=PC,
            class_id=pc_class,
            address_space="ram",
            address=0x500000,
            vfptr_role="primary",
            subobject_offset=0,
            provenance_id=provenance,
            details={"observed_slot_count": 1},
        )
        xbox_table = db.upsert_vtable(
            "xbox:vtable:Actor",
            program_id=XBOX,
            class_id=xbox_class,
            address_space="xbox-va",
            address=0x82010000,
            vfptr_role="primary",
            subobject_offset=0,
            provenance_id=provenance,
            details={"observed_slot_count": 1},
        )
        db.upsert_vtable_slot(
            pc_table,
            0,
            target_address_group_id=pc_group,
            provenance_id=provenance,
            details={"slot_id": "pc-slot:0"},
        )
        db.upsert_vtable_slot(
            xbox_table,
            0,
            target_address_group_id=shared_group,
            provenance_id=provenance,
            details={
                "slot_id": "xbox-slot:0",
                "name_observations": [
                    {"raw_name": "address_derived_only", "ambiguity": "folded"}
                ],
            },
        )

        fold_set = db.upsert_match_hypothesis_set(
            hypothesis_set_id="set:vtable:fold",
            identity_key="slot:0",
            pc_function_id=pc_function,
            provenance_id=provenance,
            details={"class_name": "Actor", "slot_index": 0},
        )
        db.add_match_hypothesis_alternative(
            fold_set,
            alternative_id="alternative:vtable:fold",
            xbox_fold_group_id=fold,
            details={"endpoint_kind": "fold_group"},
        )
        db.add_match_hypothesis_evidence(
            fold_set,
            evidence_id="evidence:vtable:fold",
            effect="supports",
            evidence_kind="equal_vtable_slot_index",
            independence_group="class_slot_alignment",
            provenance_id=provenance,
            details={"slot_index": 0},
        )
        alignment = db.upsert_vtable_alignment_candidate(
            "alignment:Actor:primary",
            pc_vtable_id=pc_table,
            xbox_vtable_id=xbox_table,
            class_name="Actor",
            vfptr_role="primary",
            subobject_offset=0,
            provenance_id=provenance,
            details={"shared_prefix_slot_count": 1},
        )
        db.upsert_vtable_slot_alignment(
            slot_alignment_id="slot-alignment:Actor:0",
            alignment_id=alignment,
            pc_slot_index=0,
            xbox_slot_index=0,
            hypothesis_set_id=fold_set,
            provenance_id=provenance,
        )
        db.upsert_vtable_alignment_issue(
            "issue:Actor:fixture",
            issue_kind="fixture_diagnostic",
            class_name="Actor",
            message="fixture issue retained for audit",
            provenance_id=provenance,
            details={"pc_vtable_ids": [pc_table]},
        )

        scalar_claims = []
        for ordinal, xbox_function in enumerate((xbox_functions[0], unique_xbox), 1):
            scalar_claims.append(
                db.upsert_match_claim(
                    claim_id=f"claim:legacy:{ordinal}",
                    pc_function_id=pc_function,
                    xbox_function_id=xbox_function,
                    provenance_id=provenance,
                    details={"fixture": True},
                )
            )
        ambiguous_set = db.upsert_match_hypothesis_set(
            hypothesis_set_id="set:legacy:ambiguous",
            identity_key="legacy:ambiguous",
            pc_function_id=pc_function,
            provenance_id=provenance,
        )
        for ordinal, claim_id in enumerate(scalar_claims, 1):
            db.add_match_hypothesis_alternative(
                ambiguous_set,
                alternative_id=f"alternative:legacy:{ordinal}",
                claim_id=claim_id,
            )
        db.add_match_hypothesis_evidence(
            ambiguous_set,
            evidence_id="evidence:legacy:ambiguous",
            effect="context",
            evidence_kind="legacy_master",
            independence_group="legacy_accumulator",
            provenance_id=provenance,
        )

        missing_target = db.upsert_unresolved_target(
            target_id="xbox:target:missing",
            program_id=XBOX,
            target_kind="unresolved_symbol_name",
            name_hint="?Missing@Actor@@",
            reason="no exact PDB record",
            provenance_id=provenance,
        )
        missing_claim = db.upsert_match_claim(
            claim_id="claim:missing",
            pc_function_id=pc_function,
            xbox_target_id=missing_target,
            provenance_id=provenance,
        )
        conflicted_set = db.upsert_match_hypothesis_set(
            hypothesis_set_id="set:conflicted",
            identity_key="conflicted",
            pc_function_id=pc_function,
            status="conflicted",
            provenance_id=provenance,
        )
        db.add_match_hypothesis_alternative(
            conflicted_set,
            alternative_id="alternative:missing",
            claim_id=missing_claim,
        )
        db.add_match_hypothesis_evidence(
            conflicted_set,
            evidence_id="evidence:conflicted",
            effect="contradicts",
            evidence_kind="manual_conflict",
            independence_group="manual_review",
            provenance_id=provenance,
        )

        reviewer = db.upsert_reviewer(
            reviewer_id="reviewer:fixture",
            identity_kind="test",
            identity_key="fixture-reviewer",
            display_name="Fixture Reviewer",
        )
        release = db.upsert_review_release(
            review_release_id="review-release:fixture",
            release_key="fixture-v6",
            label="Fixture v6",
            version="6",
            provenance_id=provenance,
        )
        db.add_review_decision(
            decision_id="review-decision:fixture",
            reviewer_id=reviewer,
            action="defer",
            decided_at="2026-08-17T12:00:00.000000Z",
            rationale="Retain the folded endpoint for later disambiguation.",
            provenance_id=provenance,
            review_release_id=release,
            alternative_id="alternative:vtable:fold",
        )

        extraction = db.upsert_control_flow_extraction(
            extraction_id="control-flow:fixture",
            program_id=XBOX,
            persistence_policy="call_relevant_v1",
            source_physical_site_count=3,
            source_logical_use_count=3,
            persisted_physical_site_count=3,
            persisted_logical_use_count=3,
            triggering_logical_use_count=3,
            procedure_scan_count=3,
            provenance_id=provenance,
            details={"fixture": True},
        )
        address_only_group = db.upsert_address_group(
            program_id=XBOX, address_space="xbox-va", address=0x82003000
        )
        flow_rows = (
            (
                "flow-site:unique",
                0x82001004,
                "flow-use:unique",
                xbox_functions[0],
                "direct_call",
                "unique_procedure",
                0x82002000,
                unique_group,
                unique_xbox,
                None,
                1,
            ),
            (
                "flow-site:fold",
                0x82002004,
                "flow-use:fold",
                unique_xbox,
                "tail_transfer",
                "fold_group",
                0x82001000,
                shared_group,
                None,
                fold,
                2,
            ),
            (
                "flow-site:address-only",
                0x82002008,
                "flow-use:address-only",
                unique_xbox,
                "direct_call",
                "executable_non_entry",
                0x82003000,
                address_only_group,
                None,
                None,
                0,
            ),
        )
        for (
            site_id,
            site_address,
            use_id,
            caller_id,
            role,
            target_kind,
            target_address,
            target_group,
            target_function,
            target_fold,
            target_count,
        ) in flow_rows:
            site_group = db.upsert_address_group(
                program_id=XBOX,
                address_space="xbox-va",
                address=site_address,
            )
            db.upsert_control_flow_site(site_id, address_group_id=site_group)
            db.add_control_flow_site_assertion(
                extraction,
                site_id,
                raw_site_va=site_address,
                instruction_word=0x48000001,
                branch_kind="branch_immediate",
                raw_target_va=target_address,
                target_kind=target_kind,
                target_record_count=target_count,
                link=role == "direct_call",
                absolute=False,
                conditional=False,
                indirect=False,
                target_address_group_id=target_group,
                target_function_id=target_function,
                target_fold_group_id=target_fold,
            )
            db.upsert_control_flow_use(
                use_id,
                procedure_record_id=caller_id,
                function_id=caller_id,
                site_id=site_id,
            )
            db.add_control_flow_use_assertion(
                extraction, use_id, role=role
            )
        for function_id, address_group, declared_size, scanned_size, status, uses in (
            (xbox_functions[0], shared_group, 16, 16, "ok", 1),
            (xbox_functions[1], shared_group, 16, 16, "ok", 0),
            (unique_xbox, unique_group, 24, 12, "truncated_raw_extent", 2),
        ):
            db.add_control_flow_scan(
                extraction,
                procedure_record_id=function_id,
                function_id=function_id,
                scan_address_group_id=address_group,
                declared_size=declared_size,
                scanned_size=scanned_size,
                unscanned_byte_count=declared_size - scanned_size,
                status=status,
                source_branch_use_count=uses,
                persisted_branch_use_count=uses,
            )
        db.validate_control_flow_extraction(extraction)

        second_extraction = db.upsert_control_flow_extraction(
            extraction_id="control-flow:fixture:second",
            program_id=XBOX,
            persistence_policy="call_relevant_v1",
            source_physical_site_count=1,
            source_logical_use_count=1,
            persisted_physical_site_count=1,
            persisted_logical_use_count=1,
            triggering_logical_use_count=1,
            procedure_scan_count=1,
            provenance_id=provenance,
            details={"fixture": "second-producer"},
        )
        db.add_control_flow_site_assertion(
            second_extraction,
            "flow-site:unique",
            raw_site_va=0x82001004,
            instruction_word=0x48000000,
            branch_kind="branch_immediate",
            raw_target_va=0x82003000,
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
            "flow-use:unique",
            role="tail_transfer",
        )
        db.add_control_flow_scan(
            second_extraction,
            procedure_record_id=xbox_functions[0],
            function_id=xbox_functions[0],
            scan_address_group_id=shared_group,
            declared_size=16,
            scanned_size=16,
            unscanned_byte_count=0,
            status="ok",
            source_branch_use_count=1,
            persisted_branch_use_count=1,
        )
        db.validate_control_flow_extraction(second_extraction)


class QueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "atlas.sqlite"
        _create_fixture(self.database)
        self.db = AtlasDatabase.open(self.database, read_only=True)
        self.query = AtlasQuery(self.db.connection)

    def tearDown(self) -> None:
        self.db.close()
        self.temporary.cleanup()

    def test_address_parser_accepts_decimal_and_prefixed_hex(self) -> None:
        self.assertEqual(parse_query_address("0x401000"), 0x401000)
        self.assertEqual(parse_query_address(str(0x401000)), 0x401000)
        self.assertEqual(parse_query_address(0x401000), 0x401000)
        with self.assertRaises(QueryError):
            parse_query_address("4010zz")
        with self.assertRaises(QueryError):
            parse_query_address(-1)

    def test_pc_address_composes_function_source_vtable_and_evidence(self) -> None:
        before = self.db.connection.total_changes
        result = self.query.pc_address("0x401000")

        self.assertTrue(result["found"])
        self.assertEqual(result["functions_page"]["total"], 1)
        function = result["functions"][0]
        self.assertEqual(function["names"][0]["name"], "Actor::Tick")
        self.assertEqual(function["sources"][0]["normalized_path"], "game/Actor.cpp")
        self.assertEqual(function["sources"][0]["line_start"], 42)
        self.assertEqual(len(result["vtable_slots_targeting_address"]), 1)
        self.assertEqual(result["mapping_hypotheses"]["page"]["total"], 3)
        evidence_kinds = {
            evidence["evidence_kind"]
            for item in result["mapping_hypotheses"]["items"]
            for evidence in item["evidence"]
        }
        self.assertIn("equal_vtable_slot_index", evidence_kinds)
        self.assertEqual(self.db.connection.total_changes, before)
        self.assertIn("Mapping hypotheses: 3", render_human(result))

    def test_xbox_address_and_name_keep_physical_fold_ambiguity(self) -> None:
        result = self.query.xbox("0x82001000")

        self.assertEqual(result["physical_records_page"]["total"], 2)
        self.assertEqual(len(result["fold_groups"]), 1)
        self.assertEqual(result["fold_groups"][0]["member_count"], 2)
        self.assertTrue(result["ambiguity"]["is_ambiguous"])
        self.assertIn(
            "multiple_physical_pdb_records_match",
            result["ambiguity"]["reasons"],
        )
        self.assertGreaterEqual(result["pc_mapping_hypotheses"]["page"]["total"], 2)
        signature = next(
            item["signature"]
            for item in result["physical_records"]
            if item["signature"] is not None
        )
        self.assertEqual(signature["rendered_signature"], "void __cdecl (int)")

        exact = self.query.xbox("?Tick@Actor@@UEAAXXZ", name_mode="exact")
        contains = self.query.xbox("actor", name_mode="contains")
        self.assertEqual(exact["physical_records_page"]["total"], 2)
        self.assertEqual(contains["physical_records_page"]["total"], 3)

        first = self.query.xbox("actor", name_mode="contains", limit=1, offset=0)
        second = self.query.xbox("actor", name_mode="contains", limit=1, offset=1)
        self.assertTrue(first["physical_records_page"]["has_more"])
        self.assertNotEqual(
            first["physical_records"][0]["function_id"],
            second["physical_records"][0]["function_id"],
        )

        unresolved = self.query.xbox("?Missing@Actor@@", name_mode="exact")
        self.assertTrue(unresolved["found"])
        self.assertEqual(unresolved["physical_records_page"]["total"], 0)
        self.assertEqual(unresolved["unresolved_targets_page"]["total"], 1)
        self.assertEqual(unresolved["pc_mapping_hypotheses"]["page"]["total"], 1)

    def test_class_lookup_returns_both_platforms_slots_alignments_and_issues(self) -> None:
        result = self.query.class_lookup("Actor", slot_limit=1)

        self.assertEqual(result["classes_page"]["total"], 2)
        self.assertEqual(result["cross_platform_presence"], ["pc", "xbox360"])
        self.assertEqual(len(result["alignment_issues"]), 1)
        for class_record in result["classes"]:
            self.assertEqual(len(class_record["vtables"]), 1)
            table = class_record["vtables"][0]
            self.assertEqual(table["vfptr_role"], "primary")
            self.assertEqual(table["slots_page"]["total"], 1)
            self.assertEqual(len(table["alignment_candidates"]), 1)
        xbox = next(item for item in result["classes"] if item["platform"] == "xbox360")
        xbox_slot = xbox["vtables"][0]["slots"][0]
        self.assertEqual(xbox_slot["target_function_count"], 2)
        self.assertTrue(xbox_slot["ambiguity"]["is_ambiguous"])

    def test_candidate_listings_distinguish_unresolved_conflicted_and_ambiguous(self) -> None:
        unresolved = self.query.candidates("unresolved")
        conflicted = self.query.candidates("conflicted")
        ambiguous = self.query.candidates("ambiguous")
        all_candidates = self.query.candidates("all", limit=2)

        self.assertEqual(unresolved["page"]["total"], 1)
        self.assertEqual(
            unresolved["items"][0]["target"]["name_hint"],
            "?Missing@Actor@@",
        )
        self.assertEqual(conflicted["page"]["total"], 1)
        self.assertEqual(
            conflicted["items"][0]["record"]["hypothesis_set_id"],
            "set:conflicted",
        )
        self.assertEqual(ambiguous["page"]["total"], 2)
        self.assertEqual(all_candidates["page"]["total"], 3)
        self.assertTrue(all_candidates["page"]["has_more"])

    def test_flow_by_procedure_preserves_fold_and_address_only_targets(self) -> None:
        before = self.db.connection.total_changes
        result = self.query.flow("x360-proc:fixture:3")

        self.assertEqual(result["procedure_records_page"]["total"], 1)
        self.assertEqual(result["logical_memberships_page"]["total"], 2)
        self.assertEqual(result["physical_sites_page"]["total"], 2)
        self.assertEqual(result["scan_coverage_page"]["total"], 1)
        self.assertEqual(result["scan_coverage"][0]["status"], "truncated_raw_extent")
        self.assertFalse(result["scan_coverage"][0]["coverage"]["bytes_complete"])
        self.assertEqual(
            result["role_counts"], {"direct_call": 1, "tail_transfer": 1}
        )
        self.assertEqual(
            result["target_kind_counts"],
            {"executable_non_entry": 1, "fold_group": 1},
        )
        endpoints = {
            assertion["target_endpoint"]["endpoint_kind"]
            for site in result["physical_sites"]
            for assertion in site["assertions"]
        }
        self.assertEqual(endpoints, {"address_only", "fold_group"})
        fold_endpoint = next(
            assertion["target_endpoint"]
            for site in result["physical_sites"]
            for assertion in site["assertions"]
            if assertion["target_endpoint"]["endpoint_kind"] == "fold_group"
        )
        self.assertEqual(fold_endpoint["fold_group"]["member_count"], 2)
        self.assertNotIn("function", fold_endpoint)
        self.assertEqual(self.db.connection.total_changes, before)

    def test_flow_site_pairs_roles_and_targets_with_the_same_extraction(self) -> None:
        result = self.query.flow(site_address="0x82001004")

        self.assertEqual(result["procedure_records_page"]["total"], 1)
        self.assertEqual(result["physical_sites_page"]["total"], 1)
        self.assertEqual(result["logical_memberships_page"]["total"], 1)
        membership = result["logical_memberships"][0]
        self.assertEqual(membership["roles"], ["direct_call", "tail_transfer"])
        observations = {
            assertion["extraction_id"]: (
                assertion["role"],
                assertion["site_observation"]["target_endpoint"]["endpoint_kind"],
            )
            for assertion in membership["role_assertions"]
        }
        self.assertEqual(
            observations,
            {
                "control-flow:fixture": ("direct_call", "unique_procedure"),
                "control-flow:fixture:second": ("tail_transfer", "address_only"),
            },
        )
        self.assertEqual(result["scan_coverage_page"]["total"], 2)
        self.assertIn("multiple_extraction_assertions_for_site", result["physical_sites"][0]["ambiguity"]["reasons"])

    def test_flow_name_address_intersection_and_paging_are_explicit(self) -> None:
        folded_name = self.query.flow("?Tick@Actor@@UEAAXXZ", name_mode="exact")
        self.assertEqual(folded_name["procedure_records_page"]["total"], 2)
        self.assertEqual(folded_name["logical_memberships_page"]["total"], 1)
        self.assertEqual(folded_name["scan_coverage_page"]["total"], 3)
        self.assertIn(
            "multiple_physical_procedure_records_match",
            folded_name["ambiguity"]["reasons"],
        )

        intersection = self.query.flow(
            "0x82002000", site_address="0x82002004"
        )
        self.assertEqual(
            intersection["query"]["membership_scope"],
            "intersection_of_procedure_and_site",
        )
        self.assertEqual(intersection["logical_memberships_page"]["total"], 1)

        first = self.query.flow("x360-proc:fixture:3", limit=1)
        second = self.query.flow("x360-proc:fixture:3", limit=1, offset=1)
        self.assertTrue(first["logical_memberships_page"]["has_more"])
        self.assertNotEqual(
            first["logical_memberships"][0]["use_id"],
            second["logical_memberships"][0]["use_id"],
        )
        with self.assertRaises(QueryError):
            self.query.flow()

    def test_summary_counts_control_flow_and_independent_reviews(self) -> None:
        summary = database_summary(self.database)

        self.assertEqual(
            summary["control_flow"],
            {
                "extractions": 2,
                "physical_sites": 3,
                "site_assertions": 4,
                "logical_uses": 3,
                "use_assertions": 4,
                "procedure_scans": 4,
                "target_kinds": {
                    "executable_non_entry": 2,
                    "fold_group": 1,
                    "unique_procedure": 1,
                },
                "roles": {"direct_call": 2, "tail_transfer": 2},
                "scan_statuses": {"ok": 3, "truncated_raw_extent": 1},
            },
        )
        self.assertEqual(summary["reviews"]["reviewers"], 1)
        self.assertEqual(summary["reviews"]["releases"], 1)
        self.assertEqual(summary["reviews"]["decisions"], 1)
        self.assertEqual(summary["reviews"]["current_decisions"], 1)
        self.assertEqual(summary["reviews"]["current_statuses"], {"deferred": 1})
        self.assertEqual(
            summary["codeview_types"],
            {
                "extractions": 0,
                "raw_records": 0,
                "record_assertions": 0,
                "raw_body_bytes": 0,
                "tags": 0,
                "definitions": 0,
                "forward_references": 0,
                "tag_member_occurrences": 0,
                "physical_field_members": 0,
                "physical_method_overloads": 0,
                "diagnostics": 0,
            },
        )
        self.assertEqual(
            summary["data_symbols"],
            {
                "extractions": 0,
                "records": 0,
                "record_assertions": 0,
                "resolved_records": 0,
                "unresolved_records": 0,
                "unique_addresses": 0,
            },
        )
        self.assertEqual(
            summary["match_hypotheses"]["alternative_evidence"], 0
        )
        self.assertEqual(
            summary["xbox_raw_vftables"],
            {
                "extractions": 0,
                "physical_records": 0,
                "record_assertions": 0,
                "canonical_names": 0,
                "address_observations": 0,
                "address_members": 0,
                "pointer_runs": 0,
                "pointer_slots": 0,
                "diagnostics": 0,
            },
        )
        self.assertEqual(
            summary["sdk"],
            {
                "source_trees": 0,
                "source_files": 0,
                "extractions": 0,
                "prototype_observations": 0,
                "call_target_observations": 0,
                "data_observations": 0,
                "diagnostics": 0,
                "code_inventory_joins": 0,
                "data_inventory_joins": 0,
                "definitive_game_links": 0,
                "unspecified_entry_candidates": 0,
                "boundary_candidates": 0,
                "boundary_containers": 0,
            },
        )
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["summary", str(self.database)]), 0)
        self.assertIn("set evidence / 0 alternative evidence", output.getvalue())

    def test_cli_defaults_to_human_and_json_is_stable(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(["pc", str(self.database), "0x401000"])
        self.assertEqual(result, 0)
        self.assertIn("PC ram:0x00401000", output.getvalue())
        self.assertIn("Actor::Tick", output.getvalue())

        first = io.StringIO()
        second = io.StringIO()
        arguments = [
            "xbox",
            str(self.database),
            "?Tick@Actor@@UEAAXXZ",
            "--exact",
            "--json",
        ]
        with redirect_stdout(first):
            self.assertEqual(main(arguments), 0)
        with redirect_stdout(second):
            self.assertEqual(main(arguments), 0)
        self.assertEqual(first.getvalue(), second.getvalue())
        document = json.loads(first.getvalue())
        self.assertEqual(document["physical_records_page"]["total"], 2)

        flow_human = io.StringIO()
        with redirect_stdout(flow_human):
            self.assertEqual(
                main(
                    [
                        "flow",
                        str(self.database),
                        "x360-proc:fixture:3",
                    ]
                ),
                0,
            )
        self.assertIn("Xbox control flow", flow_human.getvalue())
        self.assertIn("fold x360-fold:82001000 (2 members)", flow_human.getvalue())

        flow_json = io.StringIO()
        with redirect_stdout(flow_json):
            self.assertEqual(
                main(
                    [
                        "flow",
                        str(self.database),
                        "--site",
                        "0x82001004",
                        "--json",
                    ]
                ),
                0,
            )
        flow_document = json.loads(flow_json.getvalue())
        self.assertEqual(flow_document["physical_sites_page"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
