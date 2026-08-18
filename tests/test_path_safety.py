from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.build import (  # noqa: E402
    paths_alias,
    reject_destination_aliases,
    write_sha256_sidecar,
)
from fnv_atlas.cli import _write_atomic_via, main  # noqa: E402


class PathSafetyTests(unittest.TestCase):
    def test_path_writer_rejects_a_late_destination_alias_without_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "input.pdb"
            destination = root / "output.jsonl"
            protected.write_bytes(b"protected input")

            def writer(temporary: Path) -> None:
                temporary.write_text('{"safe": true}\n', encoding="utf-8")
                os.link(protected, destination)

            with self.assertRaisesRegex(ValueError, "aliases protected PDB input"):
                _write_atomic_via(
                    destination,
                    writer,
                    protected_paths=(("PDB input", protected),),
                    destination_label="JSONL output",
                )
            self.assertEqual(protected.read_bytes(), b"protected input")
            self.assertEqual(destination.read_bytes(), b"protected input")
            self.assertEqual(list(root.glob("*.building")), [])

    def test_lexical_and_hardlink_aliases_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.pdb"
            source.write_bytes(b"symbols")
            self.assertTrue(paths_alias(source, root / "." / "input.pdb"))

            hardlink = root / "output.sqlite"
            os.link(source, hardlink)
            self.assertTrue(paths_alias(source, hardlink))
            with self.assertRaisesRegex(ValueError, "aliases protected PDB input"):
                reject_destination_aliases(
                    hardlink,
                    (("PDB input", source),),
                    destination_label="database output",
                )

    def test_distinct_destination_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.json"
            source.write_text("{}", encoding="ascii")
            reject_destination_aliases(
                root / "output.jsonl",
                (("JSON input", source),),
                destination_label="JSONL output",
            )

    def test_destination_inside_protected_source_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_tree = root / "sdk"
            source_tree.mkdir()
            with self.assertRaisesRegex(
                ValueError, "aliases protected SDK source tree"
            ):
                reject_destination_aliases(
                    source_tree / "generated.sqlite",
                    (("SDK source tree", source_tree),),
                    destination_label="database output",
                )

    def test_checksum_sidecar_is_exact_atomic_and_cannot_replace_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "atlas.sqlite"
            source.write_bytes(b"atlas fixture")
            sidecar = write_sha256_sidecar(source)
            self.assertEqual(sidecar, root / "atlas.sqlite.sha256.txt")
            self.assertEqual(
                sidecar.read_text(encoding="ascii"),
                "76E4EE29B0B670A7A7917729DA5D529C464201CB569221C478F272BFA896A24F "
                "*atlas.sqlite\n",
            )
            with self.assertRaisesRegex(
                ValueError, "aliases protected checksum source"
            ):
                write_sha256_sidecar(source, source)

    def test_build_rejects_report_checksum_collision_before_reading_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "atlas.sqlite"
            checksum = root / "atlas.sqlite.sha256.txt"
            with self.assertRaisesRegex(
                ValueError, "aliases protected database checksum output"
            ):
                main(
                    [
                        "build",
                        "--repo",
                        str(root),
                        "--xbox-pdb",
                        str(root / "missing.pdb"),
                        "--xbox-exe",
                        str(root / "missing.exe"),
                        "--output",
                        str(output),
                        "--report",
                        str(checksum),
                    ]
                )

    def test_build_rejects_checksum_hardlinked_to_an_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pc_functions = root / "binport" / "ghidra_functions.json"
            pc_functions.parent.mkdir(parents=True)
            pc_functions.write_text("{}", encoding="ascii")
            output = root / "atlas.sqlite"
            os.link(pc_functions, Path(str(output) + ".sha256.txt"))
            with self.assertRaisesRegex(
                ValueError, "aliases protected pc_function_export"
            ):
                main(
                    [
                        "build",
                        "--repo",
                        str(root),
                        "--xbox-pdb",
                        str(root / "missing.pdb"),
                        "--xbox-exe",
                        str(root / "missing.exe"),
                        "--output",
                        str(output),
                    ]
                )

    def test_control_flow_cli_rejects_output_alias_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pdb = root / "input.pdb"
            executable = root / "input.exe"
            modules = root / "modules.json"
            pdb.write_bytes(b"not parsed because alias guard runs first")
            executable.write_bytes(b"not a PE")
            modules.write_text("[]", encoding="ascii")

            with self.assertRaisesRegex(
                ValueError, "aliases protected PDB input"
            ):
                main(
                    [
                        "extract-xbox-control-flow",
                        "--pdb",
                        str(pdb),
                        "--exe",
                        str(executable),
                        "--modules",
                        str(modules),
                        "--output",
                        str(pdb),
                    ]
                )

    def test_data_symbol_cli_rejects_output_alias_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pdb = root / "input.pdb"
            executable = root / "input.exe"
            modules = root / "modules.json"
            pdb.write_bytes(b"not parsed because alias guard runs first")
            executable.write_bytes(b"not a PE")
            modules.write_text("[]", encoding="ascii")

            with self.assertRaisesRegex(
                ValueError, "aliases protected PDB input"
            ):
                main(
                    [
                        "extract-xbox-data-symbols",
                        "--pdb",
                        str(pdb),
                        "--exe",
                        str(executable),
                        "--modules",
                        str(modules),
                        "--output",
                        str(pdb),
                    ]
                )

    def test_vftable_cli_rejects_input_and_cross_output_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pdb = root / "input.pdb"
            executable = root / "input.exe"
            symbols = root / "symbols.jsonl"
            pdb.write_bytes(b"not parsed because alias guard runs first")
            executable.write_bytes(b"not a PE")

            with self.assertRaisesRegex(
                ValueError, "aliases protected PDB input"
            ):
                main(
                    [
                        "extract-xbox-vftables",
                        "--pdb",
                        str(pdb),
                        "--exe",
                        str(executable),
                        "--symbols-output",
                        str(pdb),
                        "--runs-output",
                        str(root / "runs.jsonl"),
                    ]
                )

            with self.assertRaisesRegex(
                ValueError, "aliases protected pointer-run JSONL output"
            ):
                main(
                    [
                        "extract-xbox-vftables",
                        "--pdb",
                        str(pdb),
                        "--exe",
                        str(executable),
                        "--symbols-output",
                        str(symbols),
                        "--runs-output",
                        str(symbols),
                    ]
                )

    def test_sdk_cli_rejects_output_inside_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / "sdk"
            sdk.mkdir()
            (sdk / "sample.hpp").write_text(
                "// GAME - 0x401000\nvoid Sample();\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError, "aliases protected SDK source tree"
            ):
                main(
                    [
                        "extract-sdk-observations",
                        "--sdk-root",
                        str(sdk),
                        "--output",
                        str(sdk / "observations.json"),
                    ]
                )

if __name__ == "__main__":
    unittest.main()
