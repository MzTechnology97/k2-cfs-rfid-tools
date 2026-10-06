#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import cfs_image


class CFSImageTests(unittest.TestCase):
    def fixture(self):
        data = bytearray(0x300)
        data[0:4] = (0x20001000).to_bytes(4, "little")
        data[4:8] = (0x08010101).to_bytes(4, "little")
        data[0x200:0x20C] = b"cfs0_000_153"
        return data

    def test_reference_crc(self):
        self.assertEqual(cfs_image.creality_crc16(b"123456789"), 0xFEE8)

    def test_repack_and_validate(self):
        raw = self.fixture()
        packed = cfs_image.repack_image(raw)
        info = cfs_image.validate_image(packed, "cfs0_000_153")
        self.assertTrue(info["crc16_valid"])
        self.assertTrue(info["size_valid"])
        self.assertEqual(info["declared_size"], len(packed))

    def test_content_change_requires_repack(self):
        packed = bytearray(cfs_image.repack_image(self.fixture()))
        packed[-1] ^= 1
        with self.assertRaises(cfs_image.CFSImageError):
            cfs_image.validate_image(packed, "cfs0_000_153")

    def test_declared_size_is_checked(self):
        packed = bytearray(cfs_image.repack_image(self.fixture()))
        packed[0x20E:0x212] = (len(packed) - 1).to_bytes(4, "little")
        with self.assertRaises(cfs_image.CFSImageError):
            cfs_image.validate_image(packed, "cfs0_000_153")


if __name__ == "__main__":
    unittest.main(verbosity=2)
