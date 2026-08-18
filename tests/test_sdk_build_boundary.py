from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from fnv_atlas.build import BuildConfig  # noqa: E402
from fnv_atlas.cli import main  # noqa: E402


class _ConfigCaptured(Exception):
    pass


class SdkBuildBoundaryTests(unittest.TestCase):
    def test_repo_config_does_not_discover_colocated_sdk_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("sdk", "local-sdk", "private-sdk-fixture"):
                sdk = root / name
                sdk.mkdir()
                (sdk / "sample.hpp").write_text(
                    "// GAME - 0x401000\nvoid Sample();\n",
                    encoding="utf-8",
                )

            config = BuildConfig.from_repo(
                root,
                xbox_pdb=root / "xbox.pdb",
                xbox_executable=root / "xbox.exe",
            )

            self.assertIsNone(config.pc_sdk_root)
            self.assertEqual(config.input_directories(), ())

    def test_repo_config_includes_only_an_explicit_sdk_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / "private-inputs" / "local-sdk"
            sdk.mkdir(parents=True)

            config = BuildConfig.from_repo(
                root,
                xbox_pdb=root / "xbox.pdb",
                xbox_executable=root / "xbox.exe",
                sdk_root=sdk,
            )

            self.assertEqual(config.pc_sdk_root, sdk.resolve())
            self.assertEqual(
                config.input_directories(),
                (
                    (
                        "pc_sdk_source_tree",
                        sdk.resolve(),
                        "application/vnd.fnv.sdk-source-manifest+json",
                    ),
                ),
            )

    def test_build_cli_forwards_sdk_root_only_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_arguments = [
                "build",
                "--repo",
                str(root),
                "--xbox-pdb",
                str(root / "xbox.pdb"),
                "--xbox-exe",
                str(root / "xbox.exe"),
            ]

            with patch(
                "fnv_atlas.cli.BuildConfig.from_repo",
                side_effect=_ConfigCaptured,
            ) as from_repo:
                with self.assertRaises(_ConfigCaptured):
                    main(base_arguments)
            self.assertIsNone(from_repo.call_args.kwargs["sdk_root"])

            sdk = root / "private-inputs" / "local-sdk"
            with patch(
                "fnv_atlas.cli.BuildConfig.from_repo",
                side_effect=_ConfigCaptured,
            ) as from_repo:
                with self.assertRaises(_ConfigCaptured):
                    main([*base_arguments, "--sdk-root", str(sdk)])
            self.assertEqual(from_repo.call_args.kwargs["sdk_root"], sdk)


if __name__ == "__main__":
    unittest.main()
