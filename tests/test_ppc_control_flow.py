from __future__ import annotations

import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from fnv_atlas.ppc_control_flow import (  # noqa: E402
    ExecutableFormatError,
    ExecutableImage,
    ExecutableSection,
    IMAGE_FILE_MACHINE_POWERPCBE,
    ProcedureExtent,
    decode_ppc_branch,
    extract_ppc_control_flow,
    read_xbox_pe_image,
    select_control_flow,
    write_control_flow_jsonl,
)


def _immediate_branch(address: int, target: int, *, link: bool = False) -> int:
    displacement = (target - address) & 0x03FFFFFC
    return 0x48000000 | displacement | int(link)


def _conditional_branch(address: int, target: int, *, link: bool = False) -> int:
    displacement = (target - address) & 0xFFFC
    return 0x40000000 | (20 << 21) | displacement | int(link)


def _image(words: dict[int, int], *, start: int = 0x1000, size: int = 0x400):
    data = bytearray(size)
    for address, word in words.items():
        struct.pack_into(">I", data, address - start, word)
    return ExecutableImage(
        data=bytes(data),
        machine=IMAGE_FILE_MACHINE_POWERPCBE,
        image_base=0,
        sections=(
            ExecutableSection(
                name=".text",
                start=start,
                virtual_size=size,
                raw_offset=0,
                raw_size=size,
                characteristics=0x60000020,
            ),
        ),
    )


def _minimal_pe(*, machine: int = IMAGE_FILE_MACHINE_POWERPCBE) -> bytes:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xE0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, 0x82000000)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x100, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    struct.pack_into(">I", data, 0x200, 0x4E800020)
    return bytes(data)


class PpcDecoderTests(unittest.TestCase):
    def test_decodes_relative_absolute_conditional_and_indirect_forms(self):
        call = decode_ppc_branch(0x48000035, 0x1000)
        self.assertEqual(call.branch_kind, "branch_immediate")
        self.assertEqual(call.target_va, 0x1034)
        self.assertTrue(call.link)
        self.assertFalse(call.absolute)

        backward = decode_ppc_branch(0x4BFFFFFC, 0x1000)
        self.assertEqual(backward.target_va, 0x0FFC)
        self.assertFalse(backward.link)

        absolute = decode_ppc_branch(0x48001003, 0x90000000)
        self.assertEqual(absolute.target_va, 0x1000)
        self.assertTrue(absolute.absolute)
        self.assertTrue(absolute.link)

        conditional_word = _conditional_branch(0x2000, 0x1FF0, link=True)
        conditional = decode_ppc_branch(conditional_word, 0x2000)
        self.assertEqual(conditional.branch_kind, "branch_conditional")
        self.assertEqual(conditional.target_va, 0x1FF0)
        self.assertEqual(conditional.bo, 20)
        self.assertTrue(conditional.link)

        bctrl = decode_ppc_branch(0x4E800421, 0x3000)
        self.assertEqual(bctrl.branch_kind, "branch_to_count_register")
        self.assertTrue(bctrl.indirect)
        self.assertTrue(bctrl.link)

        blr = decode_ppc_branch(0x4E800020, 0x3004)
        self.assertEqual(blr.branch_kind, "branch_to_link_register")
        self.assertTrue(blr.indirect)
        self.assertFalse(blr.link)
        self.assertIsNone(decode_ppc_branch(0x60000000, 0x3008))

    def test_rejects_values_outside_32_bit_instruction_space(self):
        with self.assertRaises(ValueError):
            decode_ppc_branch(-1, 0)
        with self.assertRaises(ValueError):
            decode_ppc_branch(0, 1 << 32)


class PpcControlFlowExtractionTests(unittest.TestCase):
    def setUp(self):
        self.image = _image(
            {
                0x1000: _immediate_branch(0x1000, 0x1100, link=True),
                0x1004: _conditional_branch(0x1004, 0x100C),
                0x1008: 0x4E800421,  # bctrl
                0x100C: _immediate_branch(0x100C, 0x1200),
                0x1010: _immediate_branch(0x1010, 0x1014, link=True),
                0x1100: 0x4E800020,  # blr
                0x1200: 0x4E800020,
            }
        )
        self.procedures = (
            ProcedureExtent("caller", 0x1000, 0x14),
            ProcedureExtent("unique", 0x1100, 4),
            ProcedureExtent("fold-a", 0x1200, 4),
            ProcedureExtent("fold-b", 0x1200, 4),
        )

    def test_preserves_physical_sites_logical_records_and_fold_bundle(self):
        result = extract_ppc_control_flow(self.image, self.procedures)
        self.assertEqual(result.physical_site_count, 7)
        self.assertEqual(result.logical_use_count, 8)

        sites = {site.site_va: site for site in result.sites}
        self.assertEqual(sites[0x1000].target_kind, "unique_procedure")
        self.assertEqual(sites[0x1000].target_record_id, "unique")
        self.assertEqual(sites[0x1000].target_record_count, 1)

        folded = sites[0x100C]
        self.assertEqual(folded.target_kind, "fold_group")
        self.assertEqual(folded.target_fold_group_id, "x360-fold:00001200")
        self.assertEqual(folded.target_record_count, 2)
        self.assertIsNone(folded.target_record_id)

        roles = {
            use.site_va: use.role
            for use in result.uses
            if use.record_id == "caller"
        }
        self.assertEqual(
            roles,
            {
                0x1000: "direct_call",
                0x1004: "local_conditional_branch",
                0x1008: "indirect_call",
                0x100C: "tail_transfer",
                0x1010: "link_register_setup",
            },
        )
        fold_uses = [use for use in result.uses if use.site_va == 0x1200]
        self.assertEqual({use.record_id for use in fold_uses}, {"fold-a", "fold-b"})
        self.assertTrue(all(use.role == "return_or_indirect_branch" for use in fold_uses))

    def test_input_order_does_not_change_output_or_jsonl(self):
        left = extract_ppc_control_flow(self.image, self.procedures)
        right = extract_ppc_control_flow(self.image, reversed(self.procedures))
        self.assertEqual(left, right)
        left_json = io.StringIO()
        right_json = io.StringIO()
        write_control_flow_jsonl(left, left_json)
        write_control_flow_jsonl(right, right_json)
        self.assertEqual(left_json.getvalue(), right_json.getvalue())
        self.assertTrue(left_json.getvalue().startswith('{"direct_target_sites":'))

    def test_call_relevant_policy_keeps_physical_sites_and_complete_scans(self):
        full = extract_ppc_control_flow(self.image, self.procedures)
        selected = select_control_flow(full, policy="call_relevant_v1")
        self.assertEqual(
            {site.site_va for site in selected.sites},
            {0x1000, 0x1008, 0x100C},
        )
        self.assertEqual(
            {(use.record_id, use.site_va) for use in selected.uses},
            {("caller", 0x1000), ("caller", 0x1008), ("caller", 0x100C)},
        )
        self.assertEqual(selected.scans, full.scans)
        self.assertIs(select_control_flow(full, policy="all_branches_v1"), full)
        with self.assertRaisesRegex(ValueError, "unsupported control-flow"):
            select_control_flow(full, policy="calls_v0")

    def test_scan_diagnostics_never_silently_drop_invalid_extents(self):
        image = ExecutableImage(
            data=b"\0" * 8,
            machine=IMAGE_FILE_MACHINE_POWERPCBE,
            image_base=0,
            sections=(
                ExecutableSection(".text", 0x1000, 16, 0, 8, 0x60000020),
                ExecutableSection(".data", 0x2000, 8, 0, 8, 0x40000040),
            ),
        )
        records = (
            ProcedureExtent("empty", 0x1000, 0),
            ProcedureExtent("truncated", 0x1004, 8),
            ProcedureExtent("unaligned", 0x1000, 7),
            ProcedureExtent("data", 0x2000, 4),
            ProcedureExtent("missing", 0x3000, 4),
            ProcedureExtent("no-va", None, 9),
        )
        result = extract_ppc_control_flow(image, records)
        statuses = {scan.record_id: scan.status for scan in result.scans}
        self.assertEqual(
            statuses,
            {
                "data": "non_executable_section",
                "empty": "empty",
                "missing": "unmapped_va",
                "no-va": "unresolved_va",
                "truncated": "truncated_raw_extent",
                "unaligned": "unaligned_size",
            },
        )
        scans = {scan.record_id: scan for scan in result.scans}
        self.assertEqual(scans["truncated"].scanned_size, 4)
        self.assertEqual(scans["truncated"].unscanned_byte_count, 4)
        self.assertEqual(scans["unaligned"].scanned_size, 4)
        self.assertEqual(scans["unaligned"].unscanned_byte_count, 3)

    def test_duplicate_logical_record_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate procedure record"):
            extract_ppc_control_flow(
                self.image,
                (
                    ProcedureExtent("same", 0x1000, 4),
                    ProcedureExtent("same", 0x1100, 4),
                ),
            )

        with self.assertRaisesRegex(ValueError, "wraps 32-bit"):
            extract_ppc_control_flow(
                self.image,
                (ProcedureExtent("wrapped", 0xFFFFFFFC, 8),),
            )


class XboxPeImageTests(unittest.TestCase):
    def test_reads_raw_and_virtual_coordinates_from_powerpc_pe(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "fixture.exe"
            path.write_bytes(_minimal_pe())
            image = read_xbox_pe_image(path)
        self.assertEqual(image.machine, IMAGE_FILE_MACHINE_POWERPCBE)
        self.assertEqual(image.image_base, 0x82000000)
        self.assertEqual(image.read(0x82001000, 4), b"\x4E\x80\x00\x20")
        self.assertEqual(image.executable_ranges, ((0x82001000, 0x82001100),))

    def test_rejects_wrong_machine_and_out_of_file_section(self):
        with tempfile.TemporaryDirectory() as root:
            wrong = Path(root) / "wrong.exe"
            wrong.write_bytes(_minimal_pe(machine=0x14C))
            with self.assertRaisesRegex(ExecutableFormatError, "PowerPC-BE"):
                read_xbox_pe_image(wrong)

            malformed = bytearray(_minimal_pe())
            section = 0x98 + 0xE0
            struct.pack_into("<I", malformed, section + 20, 0x380)
            bad = Path(root) / "bad.exe"
            bad.write_bytes(malformed)
            with self.assertRaisesRegex(ExecutableFormatError, "outside the file"):
                read_xbox_pe_image(bad)


if __name__ == "__main__":
    unittest.main()
