import json
from pathlib import Path
import tempfile
import unittest

from fnv_atlas.pc_inventory import (
    executable_ranges_from_pe,
    load_ghidra_inventory,
    stable_pc_function_id,
)


class PCInventoryTests(unittest.TestCase):
    def test_only_function_keys_become_identities(self):
        document = {
            "image_base": "0x400000",
            "functions": {
                "0x401000": {
                    "name": "first",
                    "size": 12,
                    "thunk": False,
                    "callees": ["0x401020", "0x28", "0x401005", "0x401020"],
                },
                "0x401020": {
                    "name": "second",
                    "size": 4,
                    "thunk": True,
                    "callees": [],
                },
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "functions.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            inventory = load_ghidra_inventory(
                path,
                executable_ranges=[(0x401000, 0x402000)],
            )

        self.assertEqual(inventory.image_base, 0x400000)
        self.assertEqual(inventory.entries, {0x401000, 0x401020})
        self.assertEqual(inventory.functions[0].function_id, stable_pc_function_id(0x401000))
        self.assertEqual(
            [(c.address, c.classification) for c in inventory.functions[0].callees],
            [
                (0x28, "outside_executable_ranges"),
                (0x401005, "executable_non_entry"),
                (0x401020, "function_entry"),
            ],
        )

    def test_reads_executable_ranges_from_pe32(self):
        data = bytearray(0x200)
        data[:2] = b"MZ"
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        data[0x80:0x84] = b"PE\0\0"
        data[0x86:0x88] = (1).to_bytes(2, "little")
        data[0x94:0x96] = (0xE0).to_bytes(2, "little")
        optional = 0x98
        data[optional:optional + 2] = (0x10B).to_bytes(2, "little")
        data[optional + 28:optional + 32] = (0x400000).to_bytes(4, "little")
        section = optional + 0xE0
        data[section:section + 8] = b".text\0\0\0"
        data[section + 8:section + 12] = (0x1234).to_bytes(4, "little")
        data[section + 12:section + 16] = (0x1000).to_bytes(4, "little")
        data[section + 16:section + 20] = (0x1400).to_bytes(4, "little")
        data[section + 36:section + 40] = (0x60000020).to_bytes(4, "little")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.exe"
            path.write_bytes(data)
            ranges = executable_ranges_from_pe(path)

        self.assertEqual(ranges, ((0x401000, 0x402400),))


if __name__ == "__main__":
    unittest.main()
