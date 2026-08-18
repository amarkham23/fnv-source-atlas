from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from fnv_atlas.sdk_prototypes import (  # noqa: E402
    SdkSourceFile,
    classify_sdk_prototypes,
    extract_sdk_prototypes,
    sdk_source_manifest_bytes,
)
import fnv_atlas.sdk_prototypes as sdk_prototypes_module  # noqa: E402


class SdkPrototypeTests(unittest.TestCase):
    def test_variant_comments_preserve_overloads_templates_and_multiple_addresses(self):
        source = """
// GAME - 0x401000, 0x401020
// GECK - 0x501000
template<typename T>
inline T Widget<T>::operator[](unsigned index) const {
    return values[index];
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.inl").write_text(source, encoding="utf-8")
            result = extract_sdk_prototypes(root)

        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(len(result.observations), 3)
        self.assertEqual(
            [(item.program_variant, item.address) for item in result.observations],
            [("game", 0x401000), ("game", 0x401020), ("geck", 0x501000)],
        )
        self.assertTrue(
            all(
                item.declared_name == "Widget<T>::operator[]"
                for item in result.observations
            )
        )
        self.assertIn("template<typename T>", result.observations[0].signature)
        self.assertEqual(result.game_addresses, {0x401000, 0x401020})
        self.assertEqual(result.geck_addresses, {0x501000})
        self.assertFalse(result.diagnostics)

    def test_create_object_invocation_is_an_unspecified_observation_not_a_mapping(self):
        source = """
#define CREATE_OBJECT(CLASS, ADDRESS) static CLASS* CreateObject();
class NiThing {
    CREATE_OBJECT(NiThing, 0xA12340);
};
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "NiThing.hpp"
            source_path.write_text(source, encoding="utf-8")
            expected_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
            result = extract_sdk_prototypes(root)

        self.assertEqual(len(result.observations), 1)
        item = result.observations[0]
        self.assertEqual(item.program_variant, "unspecified_pc")
        self.assertEqual(item.address, 0xA12340)
        self.assertEqual(item.declared_name, "NiThing::CreateObject")
        self.assertEqual(item.evidence_kind, "create_object_macro")
        self.assertEqual(item.source_file_sha256, expected_hash)
        self.assertTrue(item.observation_id.startswith("sdk-prototype:sha256:"))

    def test_spaced_allocation_operator_is_recognized(self):
        source = """
// GAME - 0xAA1420
void* NiMemObject::operator new[](size_t size) {
    return nullptr;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "NiMemObject.cpp").write_text(source, encoding="utf-8")
            result = extract_sdk_prototypes(root)

        self.assertFalse(result.diagnostics)
        self.assertEqual(
            result.observations[0].declared_name,
            "NiMemObject::operator new[]",
        )

    def test_orphan_and_malformed_comments_are_diagnostics_not_guessed_bindings(self):
        source = """
// GAME - pending
int value = 3;
// GAME - 0x401000
int another_value = 4;
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "broken.cpp").write_text(source, encoding="utf-8")
            result = extract_sdk_prototypes(root)

        self.assertFalse(result.observations)
        self.assertEqual(
            [item.code for item in result.diagnostics],
            ["address_comment_without_address", "address_comment_without_declaration"],
        )

    def test_output_order_ids_and_relative_paths_are_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "z.cpp").write_text(
                "// GAME - 0x402000\nvoid Last() {}\n", encoding="utf-8"
            )
            nested = root / "a"
            nested.mkdir()
            (nested / "first.hpp").write_text(
                "// GAME - 0x401000\nvoid First();\n", encoding="utf-8"
            )
            unused = root / "unused.c"
            unused.write_text("int unreferenced;\n", encoding="utf-8")
            first = extract_sdk_prototypes(root)
            second = extract_sdk_prototypes(root)
            unused.write_text("int changed_but_still_unreferenced;\n", encoding="utf-8")
            changed = extract_sdk_prototypes(root)
            manifest = sdk_source_manifest_bytes(root)

        self.assertEqual(first, second)
        self.assertEqual(
            [item.source_path for item in first.observations],
            ["a/first.hpp", "z.cpp"],
        )
        payload = first.observations[0].to_dict()
        self.assertEqual(payload["address_hex"], "0x00401000")
        self.assertEqual(payload["observation_id"], first.observations[0].observation_id)
        extraction_payload = first.to_dict()
        self.assertNotIn("root", extraction_payload)
        self.assertEqual(
            [item.relative_path for item in first.source_files],
            ["a/first.hpp", "unused.c", "z.cpp"],
        )
        self.assertEqual(
            extraction_payload["source_tree_sha256"], first.source_tree_sha256
        )
        self.assertEqual(len(extraction_payload["source_files"]), 3)
        self.assertNotEqual(first.source_tree_sha256, changed.source_tree_sha256)
        self.assertEqual(first.observations, changed.observations)

        self.assertIn(changed.source_tree_sha256.encode("ascii"), manifest)
        self.assertNotIn(str(root).encode("utf-8"), manifest)

    def test_source_tree_identity_is_portable_across_ordinary_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            roots = (base / "first-sdk", base / "second-sdk")
            for root in roots:
                nested = root / "include" / "engine"
                nested.mkdir(parents=True)
                (nested / "Sample.hpp").write_text(
                    "// GAME - 0x401000\nvoid Sample();\n",
                    encoding="utf-8",
                )

            first = extract_sdk_prototypes(roots[0])
            second = extract_sdk_prototypes(roots[1])
            first_manifest = sdk_source_manifest_bytes(roots[0])
            second_manifest = sdk_source_manifest_bytes(roots[1])

        self.assertEqual(first.source_tree_sha256, second.source_tree_sha256)
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(
            [item.relative_path for item in first.source_files],
            ["include/engine/Sample.hpp"],
        )
        self.assertNotIn(str(roots[0]).encode("utf-8"), first_manifest)

    def test_source_discovery_rejects_a_simulated_junction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            junction = root / "linked-tree"
            junction.mkdir()
            (junction / "escaped.hpp").write_text("void Escaped();\n", encoding="utf-8")
            original = sdk_prototypes_module._is_link_or_reparse_point

            def is_link_like(path: Path) -> bool:
                return path == junction or original(path)

            with mock.patch.object(
                sdk_prototypes_module,
                "_is_link_or_reparse_point",
                side_effect=is_link_like,
            ), self.assertRaisesRegex(ValueError, "symlink, junction, or reparse"):
                extract_sdk_prototypes(root)

    def test_source_discovery_rejects_a_resolved_descendant_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "sdk"
            root.mkdir()
            candidate = root / "redirected.hpp"
            candidate.write_text("void Redirected();\n", encoding="utf-8")
            outside = base / "outside.hpp"
            outside.write_text("void Outside();\n", encoding="utf-8")
            original = sdk_prototypes_module._resolve_source_path

            def resolve(path: Path) -> Path:
                if path == candidate:
                    return outside.resolve(strict=True)
                return original(path)

            with mock.patch.object(
                sdk_prototypes_module,
                "_resolve_source_path",
                side_effect=resolve,
            ), self.assertRaisesRegex(ValueError, "resolves outside the SDK root"):
                sdk_source_manifest_bytes(root)

    def test_source_manifest_rejects_nonportable_paths(self):
        for path in ("/absolute.cpp", "../escape.cpp", "a/./b.cpp", "C:/drive.cpp"):
            with self.subTest(path=path), self.assertRaisesRegex(
                ValueError, "normalized relative POSIX"
            ):
                SdkSourceFile(path, "0" * 64, 0)

    def test_non_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with self.assertRaisesRegex(ValueError, "not a directory"):
                extract_sdk_prototypes(missing)

    def test_inventory_classification_preserves_observation_order_and_multiplicity(self):
        source = """
// GAME - 0x401000, 0x401004, 0x900000
void Function();
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.hpp").write_text(source, encoding="utf-8")
            extraction = extract_sdk_prototypes(root)

        joined = classify_sdk_prototypes(
            iter(extraction.observations),
            pc_function_entries={0x401000},
            executable_ranges=((0x401000, 0x402000),),
        )
        self.assertEqual(
            [item.classification for item in joined],
            ["pc_function_entry", "executable_non_entry", "outside_executable_ranges"],
        )
        self.assertEqual(
            [item.observation.address for item in joined],
            [0x401000, 0x401004, 0x900000],
        )
        self.assertEqual(
            joined[0].to_dict()["pc_inventory_classification"],
            "pc_function_entry",
        )

    def test_inventory_classification_validates_ranges_and_marks_unknown_non_entries(self):
        source = "// GAME - 0x401004\nvoid Function();\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.hpp").write_text(source, encoding="utf-8")
            observation = extract_sdk_prototypes(root).observations[0]

        joined = classify_sdk_prototypes(
            (observation,), pc_function_entries=frozenset()
        )
        self.assertEqual(joined[0].classification, "unresolved_non_entry")
        with self.assertRaisesRegex(ValueError, "increasing"):
            classify_sdk_prototypes(
                (observation,),
                pc_function_entries=set(),
                executable_ranges=((0x402000, 0x401000),),
            )


if __name__ == "__main__":
    unittest.main()
