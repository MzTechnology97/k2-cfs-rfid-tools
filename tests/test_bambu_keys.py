#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "bambu_keys.py"
spec = importlib.util.spec_from_file_location("bambu_keys", TOOL)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class BambuKeyTests(unittest.TestCase):
    def test_public_eafe5cfc_fixture(self):
        keys = m.derive(bytes.fromhex("EAFE5CFC"))
        self.assertEqual(keys["A"][0].hex().upper(), "2FC5F17A68A4")
        self.assertEqual(keys["B"][0].hex().upper(), "759F4DF068B6")
        self.assertEqual(keys["A"][1].hex().upper(), "5E670EC6C2A6")
        self.assertEqual(keys["B"][1].hex().upper(), "19D28609FC31")

    def test_requires_four_byte_uid(self):
        with self.assertRaises(ValueError):
            m.derive(bytes.fromhex("01020304050607"))


if __name__ == "__main__":
    unittest.main(verbosity=2)