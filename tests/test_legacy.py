import json
from pathlib import Path
import tempfile
import unittest

from fnv_atlas.legacy import load_legacy_claims


class LegacyImportTests(unittest.TestCase):
    def test_preserves_conflicts_and_context_without_promoting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final = root / "names_final.json"
            tiered = root / "names_tiered.json"
            namemap = root / "namemap.json"
            final.write_text(json.dumps({"0x401000": "Actor::Process", "0x28": "DebugBreak"}), encoding="utf-8")
            tiered.write_text(
                json.dumps(
                    {
                        "0x401000": {
                            "name": "Actor::Process",
                            "tier": "corroborated",
                            "channels": ["vtable", "vtable_recon"],
                        },
                        "0x28": {
                            "name": "DebugBreak",
                            "tier": "derived",
                            "channels": ["graph"],
                            "depth": 1,
                        },
                    }
                ),
                encoding="utf-8",
            )
            namemap.write_text(
                json.dumps(
                    {
                        "0x401000": {
                            "vtable": "Actor::Process",
                            "vtable_recon": "Actor::Update",
                            "public": "SomePatch::Install",
                            "source": "Actor.cpp",
                            "_notes": {"modules": 2},
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = load_legacy_claims(
                names_tiered_path=tiered,
                names_final_path=final,
                namemap_path=namemap,
                known_pc_entries={0x401000},
            )

        by_name = {claim.proposed_name: claim for claim in result.claims}
        self.assertIn("Actor::Process", by_name)
        self.assertIn("Actor::Update", by_name)
        self.assertIn("DebugBreak", by_name)
        self.assertNotIn("SomePatch::Install", by_name)
        self.assertNotIn("Actor.cpp", by_name)
        self.assertEqual(by_name["Actor::Process"].resolution, "function_entry")
        self.assertEqual(by_name["DebugBreak"].resolution, "unresolved_address")
        self.assertEqual(len(result.context), 2)
        groups = {
            evidence.independence_group
            for evidence in by_name["Actor::Process"].evidence
            if evidence.channel in {"vtable", "vtable_recon"}
        }
        self.assertEqual(groups, {"class_slot_alignment"})

    def test_imports_raw_candidates_and_agent_rejections_losslessly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tiered = root / "names_tiered.json"
            final = root / "names_final.json"
            namemap = root / "namemap.json"
            strmatch = root / "strmatch.json"
            pgm = root / "pgm.json"
            graph = root / "matched_ghidra.json"
            seeds = root / "all_seeds.json"
            agents = root / "agent_verdicts.json"
            tiered.write_text(
                json.dumps(
                    {
                        "0x401000": {
                            "name": "A::f",
                            "tier": "agent",
                            "channels": [],
                            "agent": "CONFIRM",
                        }
                    }
                ),
                encoding="utf-8",
            )
            final.write_text(json.dumps({"0x401000": "A::f"}), encoding="utf-8")
            namemap.write_text("{}", encoding="utf-8")
            strmatch.write_text(
                json.dumps({"0x401010": {"name": "A::g", "shared": 2}}),
                encoding="utf-8",
            )
            pgm.write_text(
                json.dumps({"0x401020": {"name": "A::h", "votes": 5}}),
                encoding="utf-8",
            )
            graph.write_text(
                json.dumps(
                    {
                        "0x401030": {"name": "A::i", "depth": 4},
                        "0x401070": {"name": "A::seed", "depth": 0},
                    }
                ),
                encoding="utf-8",
            )
            seeds.write_text(
                json.dumps({"0x401040": {"name": "A::j"}}),
                encoding="utf-8",
            )
            agents.write_text(
                json.dumps(
                    [
                        {
                            "address": "0x401050",
                            "claim": "A::bad",
                            "verdict": "REJECT",
                            "reason": "wrong callees",
                        },
                        {
                            "address": "0x401060",
                            "claim": "A::good",
                            "verdict": "CONFIRM",
                        },
                    ]
                ),
                encoding="utf-8",
            )

            result = load_legacy_claims(
                names_tiered_path=tiered,
                names_final_path=final,
                namemap_path=namemap,
                strmatch_path=strmatch,
                pgm_path=pgm,
                matched_ghidra_path=graph,
                all_seeds_path=seeds,
                agent_verdicts_path=agents,
                known_pc_entries={
                    0x401000,
                    0x401010,
                    0x401020,
                    0x401030,
                    0x401040,
                    0x401050,
                    0x401060,
                    0x401070,
                },
            )

        by_name = {claim.proposed_name: claim for claim in result.claims}
        self.assertEqual(
            set(by_name),
            {
                "A::f",
                "A::g",
                "A::h",
                "A::i",
                "A::j",
                "A::bad",
                "A::good",
                "A::seed",
            },
        )
        self.assertIn(
            "contradicts",
            {evidence.effect for evidence in by_name["A::bad"].evidence},
        )
        self.assertIn(
            "supports",
            {evidence.effect for evidence in by_name["A::good"].evidence},
        )
        master = next(
            evidence
            for evidence in by_name["A::f"].evidence
            if evidence.channel == "legacy_master"
        )
        self.assertEqual(master.effect, "context")
        pgm_evidence = next(
            evidence
            for evidence in by_name["A::h"].evidence
            if evidence.channel == "pgm"
        )
        graph_evidence = next(
            evidence
            for evidence in by_name["A::i"].evidence
            if evidence.channel == "graph"
        )
        self.assertEqual(pgm_evidence.independence_group, "call_graph")
        self.assertEqual(graph_evidence.independence_group, "call_graph")
        graph_seed = next(
            evidence
            for evidence in by_name["A::seed"].evidence
            if evidence.artifact == "matched_ghidra.json"
        )
        self.assertEqual(graph_seed.channel, "seed")
        self.assertEqual(graph_seed.effect, "context")
        seed_evidence = next(
            evidence
            for evidence in by_name["A::j"].evidence
            if evidence.channel == "seed"
        )
        self.assertEqual(seed_evidence.effect, "context")

    def test_retains_experimental_candidates_with_dependency_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "fingerprint": root / "fp3.json",
                "callee": root / "calleealign.json",
                "callee_new": root / "calleealign_new.json",
                "wrappers": root / "wrappers.json",
                "pgm2": root / "pgm2.json",
                "pgm_new": root / "pgm_new.json",
                "const": root / "constmatch.json",
            }
            paths["fingerprint"].write_text(
                json.dumps({"0x401100": {"name": "A::f", "score": 2.8}}),
                encoding="utf-8",
            )
            paths["callee"].write_text(
                json.dumps({"0x401100": {"name": "A::f", "via": "A::root"}}),
                encoding="utf-8",
            )
            paths["callee_new"].write_text(
                json.dumps({"0x401100": {"name": "A::f", "regret": 1.2}}),
                encoding="utf-8",
            )
            paths["wrappers"].write_text(
                json.dumps({"0x401110": {"name": "B::g", "authors": 3}}),
                encoding="utf-8",
            )
            paths["pgm2"].write_text(
                json.dumps({"0x401120": {"name": "C::h", "votes": 5}}),
                encoding="utf-8",
            )
            paths["pgm_new"].write_text(
                json.dumps({"0x401120": {"name": "C::h", "votes": 7}}),
                encoding="utf-8",
            )
            paths["const"].write_text(
                json.dumps({"0x401130": {"name": "D::i", "shared": 9}}),
                encoding="utf-8",
            )

            result = load_legacy_claims(
                fingerprint_path=paths["fingerprint"],
                calleealign_path=paths["callee"],
                calleealign_new_path=paths["callee_new"],
                wrappers_path=paths["wrappers"],
                pgm2_path=paths["pgm2"],
                pgm_new_path=paths["pgm_new"],
                constmatch_path=paths["const"],
                known_pc_entries={0x401100, 0x401110, 0x401120, 0x401130},
            )

        by_name = {claim.proposed_name: claim for claim in result.claims}
        self.assertEqual(set(by_name), {"A::f", "B::g", "C::h", "D::i"})
        self.assertEqual(result.experimental_claim_count, 4)
        self.assertEqual(result.experimental_evidence_count, 7)

        composite = by_name["A::f"].evidence
        self.assertEqual(len(composite), 3)
        self.assertEqual(
            {evidence.independence_group for evidence in composite},
            {"legacy_composite_structural"},
        )
        self.assertEqual({evidence.effect for evidence in composite}, {"context"})
        self.assertTrue(all(evidence.details["lineage"] for evidence in composite))

        wrapper = by_name["B::g"].evidence[0]
        self.assertEqual(wrapper.effect, "supports")
        self.assertEqual(wrapper.independence_group, "public_wrapper_consensus")
        pgm = by_name["C::h"].evidence
        self.assertEqual(len(pgm), 2)
        self.assertEqual({e.independence_group for e in pgm}, {"call_graph"})
        constant = by_name["D::i"].evidence[0]
        self.assertEqual(constant.effect, "context")
        self.assertEqual(constant.independence_group, "constant_reference")


if __name__ == "__main__":
    unittest.main()
