#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "cfs-rfid-tool-v2.py"
BUILDER = ROOT / "tools" / "build_patch_153_v2.py"
VALIDATOR = ROOT / "tools" / "validate_patch_153.py"
SOURCE = ROOT / "cfs0_050_G32-cfs0_000_153.bin"
MANIFEST = ROOT / "patches" / "patch_manifest_153_v2.json"

spec = importlib.util.spec_from_file_location("cfs_rfid_tool_v2", TOOL)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ProtocolV2Tests(unittest.TestCase):
    def test_full_byte_unauthenticated_index(self):
        self.assertEqual(m.payload_for("read-block", 0, 0, 0)[-1], 0)
        self.assertEqual(m.payload_for("read-block", 0, 0, 255)[-1], 255)
        with self.assertRaises(ValueError):
            m.payload_for("read-block", 0, 0, 256)

    def test_authenticated_path_remains_conservative(self):
        self.assertEqual(
            len(m.payload_for("read-block-auth", 0, 0, 63, "ffffffffffff")),
            10,
        )
        with self.assertRaises(ValueError):
            m.payload_for("read-block-auth", 0, 0, 64, "ffffffffffff")

    def test_info_fixture_v2(self):
        info = m.decode_info(bytes([2, 2, 2, 0x1F, 0xFF, 16]))
        self.assertEqual(info["api_version"], 2)
        self.assertEqual(info["max_block_or_page"], 255)
        self.assertFalse(info["capabilities"]["write"])
        self.assertFalse(info["capabilities"]["raw_transceive"])


class PatchV2Tests(unittest.TestCase):
    def test_manifest_safety_boundary(self):
        man = json.loads(MANIFEST.read_text())
        self.assertEqual(man["schema"], 2)
        self.assertEqual(man["diagnostic_api_version"], 2)
        self.assertEqual(man["limits"]["unauthenticated_read_index"], "0..255")
        self.assertEqual(man["limits"]["authenticated_block"], "0..63")
        self.assertFalse(man["forbidden_calls_present"])
        self.assertEqual(
            set(man["external_calls"]),
            {
                "0x0801914c",
                "0x0801959e",
                "0x080195d8",
                "0x08019824",
                "0x0801baf2",
            },
        )
        self.assertNotIn("write", set(man["subcommands"].values()))

    @unittest.skipUnless(SOURCE.exists(), "exact vendor source image not present")
    def test_rebuild_and_non_interference(self):
        source = SOURCE.read_bytes()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            out = td / "patched.bin"
            man = td / "manifest.json"
            dis = td / "handler.txt"
            report = td / "report.json"
            subprocess.check_call(
                [
                    sys.executable,
                    str(BUILDER),
                    "--input",
                    str(SOURCE),
                    "--output",
                    str(out),
                    "--manifest",
                    str(man),
                    "--disasm",
                    str(dis),
                ],
                stdout=subprocess.DEVNULL,
            )
            subprocess.check_call(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--source",
                    str(SOURCE),
                    "--patched",
                    str(out),
                    "--manifest",
                    str(man),
                    "--report",
                    str(report),
                ],
                stdout=subprocess.DEVNULL,
            )

            patched = out.read_bytes()
            hook = 0xC3A0
            self.assertEqual(source[:hook], patched[:hook])
            self.assertEqual(source[hook + 4 :], patched[hook + 4 : len(source)])

            rep = json.loads(report.read_text())
            self.assertTrue(rep["ok"])
            self.assertEqual(
                rep["changed_original_offsets"],
                ["0xc3a0", "0xc3a1", "0xc3a2", "0xc3a3"],
            )
            self.assertEqual(rep["forbidden_targets"], [])
            self.assertEqual(
                rep["stock_jumps"],
                ["0x801c704", "0x801c7f8", "0x801c808"],
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)