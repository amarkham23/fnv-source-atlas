from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from fnv_atlas.pc_inventory import PCFunction, PCInventory, PESection
from fnv_atlas.sdk_inventory import join_sdk_to_pc_inventory
from fnv_atlas.sdk_prototypes import extract_sdk_prototypes


def _inventory() -> PCInventory:
    return PCInventory(
        image_base=0x400000,
        functions=(
            PCFunction(
                function_id="pc:ram:00401000",
                address=0x401000,
                address_space="ram",
                name="Existing",
                size=0x40,
                thunk=False,
                in_executable_range=True,
                callees=(),
            ),
        ),
    )


SECTIONS = (
    PESection(".text", 0x401000, 0x402000, 0x20000000),
    PESection(".data", 0x500000, 0x501000, 0xC0000040),
)


class SdkInventoryJoinTests(unittest.TestCase):
    def _extract(self, source: str):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        (root / "sample.hpp").write_text(source, encoding="utf-8")
        return directory, extract_sdk_prototypes(root)

    def test_game_joins_exactly_but_geck_numeric_collision_never_does(self):
        directory, extraction = self._extract(
            """
// GAME - 0x401000
void GameExact();
// GECK - 0x401000
void EditorCollision();
"""
        )
        with directory:
            joined = join_sdk_to_pc_inventory(extraction, _inventory(), SECTIONS)

        game, geck = joined.prototype_joins
        self.assertEqual(game.classification, "pc_function_entry")
        self.assertEqual(game.pc_function_id, "pc:ram:00401000")
        self.assertIsNone(game.candidate_pc_function_id)
        self.assertEqual(geck.classification, "non_game_variant")
        self.assertIsNone(geck.pc_function_id)
        self.assertIsNone(geck.candidate_pc_function_id)

    def test_unspecified_exact_entry_is_candidate_not_definitive(self):
        directory, extraction = self._extract(
            """
class Existing {
    CREATE_OBJECT(Existing, 0x401000);
};
"""
        )
        with directory:
            joined = join_sdk_to_pc_inventory(extraction, _inventory(), SECTIONS)

        item = joined.prototype_joins[0]
        self.assertEqual(
            item.classification, "pc_function_entry_variant_unspecified"
        )
        self.assertIsNone(item.pc_function_id)
        self.assertEqual(
            item.candidate_pc_function_id, "pc:ram:00401000"
        )
        self.assertFalse(joined.boundary_candidates)

    def test_call_targets_keep_wrapper_context_out_of_name_join(self):
        directory, extraction = self._extract(
            """
void Wrapper() {
#if GAME
    ThisCall<void>(0x401000, this);
#else
    ThisCall<void>(0x401000, this);
#endif
}
"""
        )
        with directory:
            joined = join_sdk_to_pc_inventory(extraction, _inventory(), SECTIONS)

        game, geck = joined.call_target_joins
        self.assertEqual(game.observation_kind, "call_target")
        self.assertEqual(game.classification, "pc_function_entry")
        self.assertEqual(geck.classification, "non_game_variant")
        self.assertNotIn("Wrapper", str(game.to_dict()))

    def test_data_requires_a_non_executable_pc_section(self):
        directory, extraction = self._extract(
            """
class Data {
#if GAME
    static constexpr AddressPtr<int, 0x500010> value;
#else
    static constexpr AddressPtr<int, 0x401010> editorValue;
#endif
    NIRTTI_ADDRESS(0x500020);
};
"""
        )
        with directory:
            joined = join_sdk_to_pc_inventory(extraction, _inventory(), SECTIONS)

        game, geck, unspecified = joined.data_joins
        self.assertEqual(game.classification, "pc_data_section")
        self.assertEqual(game.section_name, ".data")
        self.assertEqual(geck.classification, "non_game_variant")
        self.assertEqual(
            unspecified.classification,
            "pc_data_section_variant_unspecified",
        )

    def test_create_object_nonentry_is_review_candidate_not_a_function(self):
        directory, extraction = self._extract(
            """
class NewType {
    CREATE_OBJECT(NewType, 0x401080);
};
"""
        )
        with directory:
            joined = join_sdk_to_pc_inventory(extraction, _inventory(), SECTIONS)

        item = joined.prototype_joins[0]
        self.assertEqual(
            item.classification,
            "pc_executable_non_entry_variant_unspecified",
        )
        self.assertIsNone(item.pc_function_id)
        self.assertIsNone(item.candidate_pc_function_id)
        self.assertEqual(len(joined.boundary_candidates), 1)
        self.assertEqual(
            joined.boundary_candidates[0].source_observation.address,
            0x401080,
        )

    def test_overlapping_or_invalid_sections_are_rejected(self):
        directory, extraction = self._extract(
            """
class NewType {
    CREATE_OBJECT(NewType, 0x401080);
};
"""
        )
        with directory:
            with self.assertRaisesRegex(ValueError, "must not overlap"):
                join_sdk_to_pc_inventory(
                    extraction,
                    _inventory(),
                    (
                        PESection("one", 0x401000, 0x402000, 0x20000000),
                        PESection("two", 0x401800, 0x403000, 0x20000000),
                    ),
                )


if __name__ == "__main__":
    unittest.main()
