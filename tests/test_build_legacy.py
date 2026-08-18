from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.build import (  # noqa: E402
    PC_PROGRAM_ID,
    XBOX_PROGRAM_ID,
    _insert_legacy_claims,
)
from fnv_atlas.database import AtlasDatabase  # noqa: E402
from fnv_atlas.legacy import LegacyClaim, LegacyEvidence  # noqa: E402
from fnv_atlas.pc_inventory import stable_pc_function_id  # noqa: E402


class BuildLegacyEvidenceTests(unittest.TestCase):
    def test_explicit_effects_survive_database_import(self):
        pc_address = 0x401000
        pc_function = stable_pc_function_id(pc_address)
        xbox_function = "xbox:fixture"
        claim = LegacyClaim(
            claim_id="legacy:fixture",
            pc_address=pc_address,
            pc_function_id=pc_function,
            proposed_name="Actor::Fixture",
            resolution="function_entry",
            legacy_tier="agent",
            evidence=(
                LegacyEvidence(
                    channel="legacy_master",
                    kind="selected_claim_record",
                    effect="context",
                    independence_group="legacy_accumulator",
                    artifact="names_final.json",
                ),
                LegacyEvidence(
                    channel="agent",
                    kind="raw_agent_verdict",
                    effect="contradicts",
                    independence_group="decompiler_agent_review",
                    artifact="agent_verdicts.json",
                    details={"verdict": "REJECT"},
                ),
            ),
        )

        with AtlasDatabase.create() as db:
            db.upsert_program(PC_PROGRAM_ID, platform="pc", name="PC")
            db.upsert_program(
                XBOX_PROGRAM_ID, platform="xbox360", name="Xbox"
            )
            pc_group = db.upsert_address_group(
                program_id=PC_PROGRAM_ID,
                address_space="ram",
                address=pc_address,
            )
            db.upsert_function(
                function_id=pc_function,
                address_group_id=pc_group,
                identity_key="fixture",
            )
            xbox_group = db.upsert_address_group(
                program_id=XBOX_PROGRAM_ID,
                address_space="xbox-va",
                address=0x82001000,
            )
            db.upsert_function(
                function_id=xbox_function,
                address_group_id=xbox_group,
                identity_key="fixture",
            )
            provenance = db.upsert_provenance(
                kind="test", producer="test_build_legacy"
            )
            _insert_legacy_claims(
                db,
                (claim,),
                {"Actor::Fixture": (xbox_function,)},
                ((0x400000, 0x500000),),
                provenance_id=provenance,
            )
            effects = {
                row["evidence_kind"]: row["effect"]
                for row in db.connection.execute(
                    "SELECT evidence_kind, effect FROM match_hypothesis_evidence"
                )
            }
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_sets"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_alternatives"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM claim_evidence"
                ).fetchone()[0],
                0,
            )

        self.assertEqual(effects["legacy_master"], "context")
        self.assertEqual(effects["agent"], "contradicts")

    def test_ambiguous_alternatives_do_not_fan_out_occurrence_evidence(self):
        pc_address = 0x401000
        pc_function = stable_pc_function_id(pc_address)
        claim = LegacyClaim(
            claim_id="legacy:ambiguous",
            pc_address=pc_address,
            pc_function_id=pc_function,
            proposed_name="SharedName",
            resolution="function_entry",
            legacy_tier="vtable",
            evidence=(
                LegacyEvidence(
                    channel="vtable",
                    kind="slot_observation",
                    effect="supports",
                    independence_group="class_slot_alignment",
                    artifact="names_tiered.json",
                ),
            ),
        )

        with AtlasDatabase.create() as db:
            db.upsert_program(PC_PROGRAM_ID, platform="pc", name="PC")
            db.upsert_program(XBOX_PROGRAM_ID, platform="xbox360", name="Xbox")
            pc_group = db.upsert_address_group(
                program_id=PC_PROGRAM_ID,
                address_space="ram",
                address=pc_address,
            )
            db.upsert_function(
                function_id=pc_function,
                address_group_id=pc_group,
                identity_key="fixture",
            )
            xbox_ids = []
            for ordinal, address in enumerate((0x82001000, 0x82002000)):
                group = db.upsert_address_group(
                    program_id=XBOX_PROGRAM_ID,
                    address_space="xbox-va",
                    address=address,
                )
                xbox_ids.append(
                    db.upsert_function(
                        function_id=f"xbox:fixture:{ordinal}",
                        address_group_id=group,
                        identity_key=f"fixture:{ordinal}",
                    )
                )
            provenance = db.upsert_provenance(
                kind="test", producer="test_build_legacy"
            )

            _insert_legacy_claims(
                db,
                (claim,),
                {"SharedName": tuple(xbox_ids)},
                ((0x400000, 0x500000),),
                provenance_id=provenance,
            )

            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_sets"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_alternatives"
                ).fetchone()[0],
                2,
            )
            self.assertEqual(
                db.connection.execute(
                    "SELECT COUNT(*) FROM match_hypothesis_evidence"
                ).fetchone()[0],
                1,
            )


if __name__ == "__main__":
    unittest.main()
