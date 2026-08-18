from __future__ import annotations

from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.build import (  # noqa: E402
    XBOX_PROGRAM_ID,
    _insert_xbox_procedures,
    _insert_xbox_signatures,
)
from fnv_atlas.database import AtlasDatabase  # noqa: E402
from fnv_atlas.pdb_symbols import ProcedureExtraction, ProcedureRecord  # noqa: E402
from fnv_atlas.tpi_signatures import (  # noqa: E402
    FunctionSignature,
    LF_PROCEDURE,
    SignatureResolution,
    SignatureResult,
)


def _record(record_id: str, type_index: int, va: int | None) -> ProcedureRecord:
    return ProcedureRecord(
        record_id=record_id,
        module_index=1,
        module_name="fixture.obj",
        symbol_stream=9,
        record_offset=int(record_id.rsplit(":", 1)[-1]),
        record_length=40,
        record_kind="S_GPROC32",
        record_kind_code=0x1110,
        va=va,
        section=1,
        section_offset=0x100,
        size=16,
        type_index=type_index,
        flags=0,
        raw_name=f"fixture_{type_index:x}",
        parent_offset=0,
        end_offset=0,
        next_offset=0,
        debug_start=0,
        debug_end=16,
    )


def _signature(type_index: int) -> FunctionSignature:
    return FunctionSignature(
        type_index=type_index,
        leaf_kind=LF_PROCEDURE,
        leaf_name="LF_PROCEDURE",
        return_type_index=3,
        class_type_index=None,
        this_type_index=None,
        calling_convention=0x0F,
        calling_convention_name="ppc_call",
        attributes=0,
        this_adjustment=None,
        parameter_count=1,
        argument_list_type_index=0x3000,
        argument_list_count=1,
        argument_type_indices=(0x74,),
        is_variadic=False,
        rendered_return_type="void",
        rendered_class_type=None,
        rendered_this_type=None,
        rendered_argument_types=("int",),
        rendered_signature="void __ppccall (int)",
    )


class BuildSignatureTests(unittest.TestCase):
    def test_signature_join_uses_record_identity_and_retains_unresolved(self):
        extraction = ProcedureExtraction(
            records=(
                _record("fixture:1", 0x2000, 0x82001000),
                _record("fixture:2", 0x2001, 0x82001010),
                _record("fixture:3", 0x2002, None),
            ),
            alias_groups=(),
        )
        resolution = SignatureResolution(
            (
                SignatureResult(0x2000, _signature(0x2000)),
                SignatureResult(
                    0x2001,
                    None,
                    error_code="not_function_type",
                    error_message="fixture unresolved type",
                    actual_leaf_kind=0x1002,
                    actual_leaf_name="LF_POINTER",
                ),
                SignatureResult(
                    0x2002,
                    None,
                    error_code="missing_type",
                    error_message="fixture missing type",
                ),
            )
        )

        with AtlasDatabase.create() as db:
            db.upsert_program(
                XBOX_PROGRAM_ID,
                platform="xbox360",
                name="Xbox fixture",
            )
            pdb_provenance = db.upsert_provenance(
                kind="test", producer="test_build_signatures.pdb"
            )
            signature_provenance = db.upsert_provenance(
                kind="test", producer="test_build_signatures.tpi"
            )
            _insert_xbox_procedures(
                db, extraction, provenance_id=pdb_provenance
            )
            counts = _insert_xbox_signatures(
                db,
                extraction,
                resolution,
                provenance_id=signature_provenance,
            )

            self.assertEqual(counts.rows, 2)
            self.assertEqual(counts.resolved, 1)
            self.assertEqual(counts.unresolved, 1)
            self.assertEqual(counts.arguments, 1)
            self.assertEqual(counts.rows_without_function, 1)
            self.assertEqual(
                db.get_function_signature("fixture:1")["resolution_status"],
                "resolved",
            )
            self.assertEqual(
                db.get_function_signature("fixture:2")["error_code"],
                "not_function_type",
            )
            self.assertIsNone(db.get_function_signature("fixture:3"))

    def test_occurrence_count_mismatch_is_rejected(self):
        extraction = ProcedureExtraction(
            records=(_record("fixture:1", 0x2000, 0x82001000),),
            alias_groups=(),
        )
        with AtlasDatabase.create() as db:
            with self.assertRaisesRegex(ValueError, "occurrence counts disagree"):
                _insert_xbox_signatures(
                    db,
                    extraction,
                    SignatureResolution(()),
                    provenance_id="unused",
                )


if __name__ == "__main__":
    unittest.main()
