from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from fnv_atlas.sdk_prototypes import (
    classify_sdk_prototypes,
    extract_sdk_prototypes,
    select_sdk_boundary_candidates,
)


class SdkPrototypeExtendedTests(unittest.TestCase):
    def test_helper_calls_retain_variants_context_and_argument_expressions(self):
        source = """
class Bridge {
public:
    int Run(int value) {
#if GAME
        return ThisCall<int>(0x401000, this, value);
#else
        return CdeclCall<int>(0x501000, value);
#endif
    }
};
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "Bridge.hpp"
            path.write_text(source, encoding="utf-8")
            expected_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            extraction = extract_sdk_prototypes(root)

        self.assertEqual(len(extraction.call_targets), 2)
        game, geck = extraction.call_targets
        self.assertEqual(
            (game.program_variant, game.address, game.calling_convention),
            ("game", 0x401000, "__thiscall"),
        )
        self.assertEqual(game.helper_name, "ThisCall")
        self.assertEqual(game.rendered_return_type, "int")
        self.assertIsNone(game.parameter_types)
        self.assertEqual(game.argument_expressions, ("this", "value"))
        self.assertEqual(game.enclosing_declared_name, "Run")
        self.assertEqual(game.enclosing_owner_hint, "Bridge")
        self.assertEqual(game.enclosing_signature, "int Run(int value)")
        self.assertIn("int Run(int value)", game.declaration_text or "")
        self.assertEqual(game.source_file_sha256, expected_hash)
        self.assertEqual(
            (geck.program_variant, geck.address, geck.calling_convention),
            ("geck", 0x501000, "__cdecl"),
        )
        self.assertFalse(extraction.diagnostics)

    def test_typed_call_preserves_exact_target_type_without_naming_target(self):
        source = """
bool Test(void* object, int value) {
    return ((bool(__thiscall*)(void*, int))0x402000)(object, value);
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "typed.cpp").write_text(source, encoding="utf-8")
            extraction = extract_sdk_prototypes(root)

        self.assertEqual(len(extraction.call_targets), 1)
        item = extraction.call_targets[0]
        self.assertEqual(item.invocation_kind, "typed_function_pointer_call")
        self.assertEqual(item.program_variant, "unspecified_pc")
        self.assertEqual(item.address, 0x402000)
        self.assertEqual(item.calling_convention, "__thiscall")
        self.assertEqual(item.rendered_return_type, "bool")
        self.assertEqual(item.parameter_types, ("void*", "int"))
        self.assertEqual(item.rendered_target_type, "bool (__thiscall*)(void*, int)")
        self.assertEqual(item.argument_expressions, ("object", "value"))
        self.assertEqual(item.enclosing_declared_name, "Test")
        self.assertFalse(hasattr(item, "declared_name"))
        self.assertTrue(item.observation_id.startswith("sdk-call-target:sha256:"))

    def test_global_data_observations_are_typed_owned_and_separate_from_code(self):
        source = """
class NiThing {
public:
    NIRTTI_ADDRESS(0x11F4000);
#if GAME
    static constexpr AddressPtr<NiThing*, 0x11F5000> singleton;
#else
    static constexpr AddressPtr<NiThing*, 0x0F15000> singleton;
#endif
};
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "NiThing.hpp").write_text(source, encoding="utf-8")
            extraction = extract_sdk_prototypes(root)

        self.assertFalse(extraction.observations)
        self.assertFalse(extraction.call_targets)
        self.assertEqual(len(extraction.data_addresses), 3)
        rtti, game, geck = extraction.data_addresses
        self.assertEqual(
            (rtti.data_kind, rtti.declared_name, rtti.declared_type),
            ("ni_rtti", "NiThing::ms_RTTI", "NiRTTI"),
        )
        self.assertEqual(rtti.program_variant, "unspecified_pc")
        self.assertEqual(rtti.owner_basis, "lexical_class_scope")
        self.assertEqual(
            (game.data_kind, game.program_variant, game.address),
            ("address_ptr", "game", 0x11F5000),
        )
        self.assertEqual(game.declared_name, "NiThing::singleton")
        self.assertEqual(game.declared_type, "NiThing*")
        self.assertEqual(geck.program_variant, "geck")
        self.assertEqual(geck.address, 0x0F15000)
        self.assertFalse(extraction.diagnostics)

    def test_unowned_data_is_retained_with_an_explicit_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "orphan.hpp").write_text(
                "NIRTTI_ADDRESS(0x11F4000);\n", encoding="utf-8"
            )
            extraction = extract_sdk_prototypes(root)

        self.assertEqual(len(extraction.data_addresses), 1)
        self.assertIsNone(extraction.data_addresses[0].owner_name)
        self.assertEqual(extraction.data_addresses[0].declared_name, "ms_RTTI")
        self.assertEqual(
            [diagnostic.code for diagnostic in extraction.diagnostics],
            ["data_address_without_class_owner"],
        )

    def test_concrete_comment_and_call_variant_disagreement_is_diagnostic(self):
        source = """
// GAME - 0xE7ECD0
// GAME - 0xC15520
void Stage::ReturnToPool() {
#if GAME
    ThisCall(0xE7ECD0, this);
#else
    ThisCall(0xC15520, this);
#endif
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Stage.cpp").write_text(source, encoding="utf-8")
            extraction = extract_sdk_prototypes(root)

        self.assertEqual(len(extraction.observations), 2)
        self.assertEqual(len(extraction.call_targets), 2)
        self.assertEqual(
            [diagnostic.code for diagnostic in extraction.diagnostics],
            ["variant_label_disagreement"],
        )
        self.assertEqual(extraction.diagnostics[0].line, 8)
        self.assertIn("0x00C15520", extraction.diagnostics[0].message)

    def test_boundary_selector_only_returns_create_object_non_entries(self):
        source = """
class First {
    CREATE_OBJECT(First, 0x401010);
};
class Existing {
    CREATE_OBJECT(Existing, 0x401100);
};
// GAME - 0x401020
void MerelyAnnotated();
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "objects.hpp").write_text(source, encoding="utf-8")
            extraction = extract_sdk_prototypes(root)

        classified = classify_sdk_prototypes(
            extraction.observations,
            pc_function_entries={0x401100},
            executable_ranges=((0x401000, 0x402000),),
        )
        candidates = select_sdk_boundary_candidates(
            classified,
            function_extents=((0x401000, 0x401080),),
        )
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(
            candidate.source_observation.declaration_text,
            "CREATE_OBJECT(First, 0x401010);",
        )
        self.assertEqual(candidate.source_observation.address, 0x401010)
        self.assertEqual(
            candidate.candidate_reason,
            "sdk_create_object_target_is_executable_non_entry",
        )
        self.assertEqual(candidate.containing_function_entries, (0x401000,))
        self.assertTrue(candidate.candidate_id.startswith("sdk-boundary-candidate:"))
        self.assertEqual(
            candidate.to_dict()["source_observation_id"],
            candidate.source_observation.observation_id,
        )
        self.assertEqual(
            candidate.to_dict()["source_observation"]["source_file_sha256"],
            candidate.source_observation.source_file_sha256,
        )

    def test_boundary_selector_rejects_invalid_extents(self):
        with self.assertRaisesRegex(ValueError, "increasing"):
            select_sdk_boundary_candidates((), function_extents=((5, 4),))

    def test_serialization_is_portable_and_category_preserving(self):
        source = """
class State {
    static constexpr AddressPtr<int, 0x11F0000> value;
public:
    void Apply() { ThisCall(0x401000, this); }
};
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "State.hpp").write_text(source, encoding="utf-8")
            extraction = extract_sdk_prototypes(root)

        payload = extraction.to_dict()
        self.assertNotIn("root", payload)
        self.assertEqual(payload["observation_count"], 0)
        self.assertEqual(payload["call_target_count"], 1)
        self.assertEqual(payload["data_address_count"], 1)
        self.assertEqual(
            payload["call_targets"][0]["argument_expressions"], ["this"]
        )
        self.assertIsNone(payload["call_targets"][0]["parameter_types"])
        self.assertEqual(payload["data_addresses"][0]["data_kind"], "address_ptr")


if __name__ == "__main__":
    unittest.main()

