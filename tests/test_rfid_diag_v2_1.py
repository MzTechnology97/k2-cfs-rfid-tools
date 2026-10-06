#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "cfs-rfid-tool-v2_1.py"
BUILDER = ROOT / "tools" / "build_patch_153_v2_1.py"
VALIDATOR = ROOT / "tools" / "validate_patch_153_v2_1.py"
SOURCE = ROOT / "cfs0_050_G32-cfs0_000_153.bin"
MANIFEST = ROOT / "patches" / "patch_manifest_153_v2_1.json"

spec = importlib.util.spec_from_file_location("cfs_rfid_tool_v21", TOOL)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ProtocolV21Tests(unittest.TestCase):
    def test_info_v3_capabilities(self):
        info = m.decode_info(bytes([3, 2, 2, 0x7F, 0xFF, 16]))
        self.assertEqual(info["api_version"], 3)
        self.assertTrue(info["capabilities"]["stock_state"])
        self.assertTrue(info["capabilities"]["stock_busy_guard"])
        self.assertFalse(info["capabilities"]["write"])
        self.assertFalse(info["capabilities"]["raw_transceive"])

    def test_stock_state_payload(self):
        self.assertEqual(m.payload_for("stock-state"), b"\x05")

    def test_stock_state_idle(self):
        state = m.decode_stock_state(bytes([0x40, 0, 4, 0]))
        self.assertFalse(state["stock_rfid_busy"])
        self.assertIsNone(state["active_slot"])

    def test_stock_state_busy_slot(self):
        state = m.decode_stock_state(bytes([0x40, 0, 2, 0]))
        self.assertTrue(state["stock_rfid_busy"])
        self.assertEqual(state["active_slot"], 2)

    def test_read_bounds_preserved(self):
        self.assertEqual(m.payload_for("read-block", 0, 0, 255)[-1], 255)
        with self.assertRaises(ValueError):
            m.payload_for("read-block", 0, 0, 256)
        self.assertEqual(
            len(m.payload_for("read-block-auth", 0, 0, 63, "ffffffffffff")),
            10,
        )
        with self.assertRaises(ValueError):
            m.payload_for("read-block-auth", 0, 0, 64, "ffffffffffff")


class PatchV21Tests(unittest.TestCase):
    def test_manifest_guard(self):
        man = json.loads(MANIFEST.read_text())
        self.assertEqual(man["schema"], 3)
        self.assertEqual(man["diagnostic_api_version"], 3)
        self.assertEqual(man["candidate_revision"], "2.1")
        self.assertEqual(man["subcommands"]["5"], "stock-state")
        self.assertEqual(man["status"]["7"], "stock RFID busy")
        self.assertEqual(man["stock_state"]["address"], "0x200001f0")
        self.assertEqual(man["stock_state"]["active_slot_offset"], 2)
        self.assertFalse(man["forbidden_calls_present"])
        self.assertNotIn("write", set(man["subcommands"].values()))

    @unittest.skipUnless(SOURCE.exists(), "exact vendor source image not present")
    def test_rebuild_validator_and_stock_non_interference(self):
        source = SOURCE.read_bytes()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            out = td / "patched.bin"
            man = td / "manifest.json"
            dis = td / "handler.txt"
            report = td / "report.json"

            subprocess.check_call([
                sys.executable, str(BUILDER),
                "--input", str(SOURCE),
                "--output", str(out),
                "--manifest", str(man),
                "--disasm", str(dis),
            ], stdout=subprocess.DEVNULL)

            subprocess.check_call([
                sys.executable, str(VALIDATOR),
                "--source", str(SOURCE),
                "--patched", str(out),
                "--manifest", str(man),
                "--report", str(report),
            ], stdout=subprocess.DEVNULL)

            patched = out.read_bytes()
            hook = 0xC3A0
            self.assertEqual(source[:hook], patched[:hook])
            self.assertEqual(source[hook + 4:], patched[hook + 4:len(source)])

            rep = json.loads(report.read_text())
            self.assertTrue(rep["ok"])
            self.assertEqual(rep["errors"], [])
            self.assertEqual(
                rep["changed_original_offsets"],
                ["0xc3a0", "0xc3a1", "0xc3a2", "0xc3a3"],
            )
            self.assertEqual(rep["forbidden_targets"], [])
            self.assertTrue(rep["stock_state_guard"]["signature_found"])
            self.assertTrue(rep["stock_state_guard"]["passive_export_found"])
            self.assertEqual(rep["stock_state_guard"]["address_materialization_count"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)