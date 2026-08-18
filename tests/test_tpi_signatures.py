from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.tpi_signatures import (  # noqa: E402
    LF_ARGLIST,
    LF_MFUNCTION,
    LF_POINTER,
    LF_PROCEDURE,
    T_NOTYPE,
    TpiFormatError,
    TpiTypeResolver,
    TypeResolutionError,
)


def _type_record(leaf: int, body: bytes) -> bytes:
    payload = struct.pack("<H", leaf) + body
    padding = (-(2 + len(payload))) % 4
    if padding:
        # CodeView padding bytes count down to LF_PAD0.  The signature parser
        # ignores them after consuming each record's fixed/count-delimited body.
        payload += bytes(0xF0 + value for value in range(padding, 0, -1))
    return struct.pack("<H", len(payload)) + payload


def _tpi_stream(*records: bytes, begin: int = 0x1000) -> bytes:
    record_data = b"".join(records)
    header = struct.pack(
        "<IIIIIHHIIIIIIII",
        20040203,
        56,
        begin,
        begin + len(records),
        len(record_data),
        0xFFFF,
        0xFFFF,
        4,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    assert len(header) == 56
    return header + record_data


def _arglist(*indices: int, declared_count: int | None = None) -> bytes:
    count = len(indices) if declared_count is None else declared_count
    return _type_record(
        LF_ARGLIST,
        struct.pack("<I", count)
        + (struct.pack(f"<{len(indices)}I", *indices) if indices else b""),
    )


class TpiSignatureTests(unittest.TestCase):
    def test_procedure_preserves_raw_fields_and_terminal_vararg(self) -> None:
        # 0x1000 = arglist; 0x1001 = procedure.
        stream = _tpi_stream(
            _arglist(0x0074, 0x0040, T_NOTYPE),
            _type_record(
                LF_PROCEDURE,
                struct.pack(
                    "<IBBHI",
                    0x0075,  # unsigned int return
                    0x0F,  # PPC calling convention
                    0xA5,  # raw CV_funcattr bits
                    2,  # fixed parameter count
                    0x1000,
                ),
            ),
        )
        resolver = TpiTypeResolver(stream)
        signature = resolver.resolve(0x1001)

        self.assertEqual(signature.type_index, 0x1001)
        self.assertEqual(signature.leaf_kind, LF_PROCEDURE)
        self.assertEqual(signature.return_type_index, 0x0075)
        self.assertIsNone(signature.class_type_index)
        self.assertIsNone(signature.this_type_index)
        self.assertEqual(signature.calling_convention, 0x0F)
        self.assertEqual(signature.calling_convention_name, "ppc_call")
        self.assertEqual(signature.attributes, 0xA5)
        self.assertIsNone(signature.this_adjustment)
        self.assertEqual(signature.parameter_count, 2)
        self.assertEqual(signature.argument_list_type_index, 0x1000)
        self.assertEqual(signature.argument_list_count, 3)
        self.assertEqual(signature.argument_type_indices, (0x0074, 0x0040, 0))
        self.assertTrue(signature.is_variadic)
        self.assertEqual(signature.rendered_argument_types, ("int", "float", "..."))
        self.assertIn("__ppccall", signature.rendered_signature)
        self.assertEqual(
            signature.to_dict()["argument_type_indices"], [0x0074, 0x0040, 0]
        )

    def test_member_function_preserves_class_this_and_signed_adjustment(self) -> None:
        # The class/this records need not be renderable for their exact indices
        # to remain authoritative.
        stream = _tpi_stream(
            _arglist(0x0470),
            _type_record(
                LF_MFUNCTION,
                struct.pack(
                    "<IIIBBHIi",
                    0x0003,
                    0x2345,
                    0x3456,
                    0x0B,
                    0x02,
                    1,
                    0x1000,
                    -12,
                ),
            ),
        )
        signature = TpiTypeResolver(stream).resolve(0x1001)

        self.assertTrue(signature.is_member_function)
        self.assertEqual(signature.return_type_index, 0x0003)
        self.assertEqual(signature.class_type_index, 0x2345)
        self.assertEqual(signature.this_type_index, 0x3456)
        self.assertEqual(signature.calling_convention, 0x0B)
        self.assertEqual(signature.calling_convention_name, "thiscall")
        self.assertEqual(signature.attributes, 0x02)
        self.assertEqual(signature.this_adjustment, -12)
        self.assertEqual(signature.argument_type_indices, (0x0470,))

    def test_many_preserves_order_duplicates_and_nonfunction_records(self) -> None:
        stream = _tpi_stream(
            _arglist(),
            _type_record(
                LF_PROCEDURE, struct.pack("<IBBHI", 0x0003, 0, 0, 0, 0x1000)
            ),
            _type_record(LF_POINTER, struct.pack("<II", 0x0074, 0)),
        )
        resolver = TpiTypeResolver(stream)
        resolution = resolver.resolve_many([0x1001, 0x1002, 0x1001, 0])

        self.assertEqual(resolution.requested_count, 4)
        self.assertEqual(resolution.unique_requested_count, 3)
        self.assertEqual(resolution.resolved_count, 2)
        self.assertEqual(resolution.unique_resolved_count, 1)
        self.assertEqual(
            [result.type_index for result in resolution.results],
            [0x1001, 0x1002, 0x1001, 0],
        )
        self.assertEqual(
            resolution.results[1].error_code, "not_function_type"
        )
        self.assertEqual(resolution.results[1].actual_leaf_kind, LF_POINTER)
        self.assertEqual(
            resolution.results[3].error_code, "primitive_or_zero_type"
        )
        self.assertEqual(
            resolution.error_counts,
            {"not_function_type": 1, "primitive_or_zero_type": 1},
        )
        self.assertEqual(set(resolution.signatures_by_index()), {0x1001})

    def test_strict_mode_rejects_nonfunction_index(self) -> None:
        resolver = TpiTypeResolver(
            _tpi_stream(_type_record(LF_POINTER, struct.pack("<II", 0x74, 0)))
        )
        with self.assertRaises(TypeResolutionError) as raised:
            resolver.resolve_many([0x1000], strict=True)
        self.assertEqual(raised.exception.type_index, 0x1000)
        self.assertEqual(raised.exception.code, "not_function_type")

    def test_argument_list_reference_and_length_are_validated(self) -> None:
        wrong_leaf = TpiTypeResolver(
            _tpi_stream(
                _type_record(LF_POINTER, struct.pack("<II", 0x74, 0)),
                _type_record(
                    LF_PROCEDURE,
                    struct.pack("<IBBHI", 3, 0, 0, 0, 0x1000),
                ),
            )
        ).resolve_many([0x1001])
        self.assertEqual(
            wrong_leaf.results[0].error_code, "wrong_argument_list_leaf"
        )

        malformed = TpiTypeResolver(
            _tpi_stream(
                _arglist(0x74, declared_count=3),
                _type_record(
                    LF_PROCEDURE,
                    struct.pack("<IBBHI", 3, 0, 0, 3, 0x1000),
                ),
            )
        ).resolve_many([0x1001])
        self.assertEqual(
            malformed.results[0].error_code, "malformed_argument_list"
        )

    def test_tpi_record_region_must_match_declared_index_range(self) -> None:
        stream = bytearray(_tpi_stream(_arglist()))
        # Claim a second type index without supplying a second record.
        struct.pack_into("<I", stream, 12, 0x1002)
        with self.assertRaises(TpiFormatError):
            TpiTypeResolver(bytes(stream))


if __name__ == "__main__":
    unittest.main()

