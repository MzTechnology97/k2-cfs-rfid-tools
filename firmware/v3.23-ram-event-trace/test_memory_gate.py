"""Offline CI regression for conservative CFS v3.23 memory analysis only."""
import importlib.util
import struct
import tempfile
from pathlib import Path

SOURCE = Path(__file__).with_name("memory_gate.py")
SPEC = importlib.util.spec_from_file_location("cfs_v323_memory_gate", SOURCE)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

def mock_app(size):
    data = bytearray(size)
    struct.pack_into("<I", data, 0, 0x20006EE8)
    struct.pack_into("<I", data, 4, 0x08010221)
    struct.pack_into("<I", data, MOD.FW_LENGTH_OFF, size)
    return bytes(data)

def test_empirical_size_gate():
    available = MOD.EMPIRICAL_END - MOD.APP_BASE
    assert available == 178176
    for length in (0x212, 177700, 177684, 178140, available):
        result = MOD.inspect_app(mock_app(length))
        assert result["passes_conservative_empirical_size_limit"]
        assert result["header_length_consistent"]
        assert result["initial_sp_within_64kb_sram"]
        assert result["reset_is_thumb_and_within_image"]
        assert not result["safe_to_flash"]  # Never a proof of bootloader bounds
    assert MOD.inspect_app(mock_app(available))["remaining_bytes_to_empirical_limit"] == 0
    for length in (available + 1, available + 16, 179128):
        assert not MOD.inspect_app(mock_app(length))["passes_conservative_empirical_size_limit"]
        assert not MOD.inspect_app(mock_app(length))["safe_to_flash"]

def test_header_validation():
    data = bytearray(mock_app(178140))
    struct.pack_into("<I", data, MOD.FW_LENGTH_OFF, 178139)
    assert not MOD.inspect_app(bytes(data))["header_length_consistent"]
    data = bytearray(mock_app(178140))
    struct.pack_into("<I", data, 4, 0x08010220)  # non-Thumb
    assert not MOD.inspect_app(bytes(data))["reset_is_thumb_and_within_image"]
    data = bytearray(mock_app(178140))
    struct.pack_into("<I", data, 0, 0x20020000)  # invalid SP
    assert not MOD.inspect_app(bytes(data))["initial_sp_within_64kb_sram"]

def test_readonly_dump_inventory():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "offline.bin"
        data = bytearray(0x2000)
        struct.pack_into("<I", data, 0x80, MOD.EMPIRICAL_END)
        struct.pack_into("<I", data, 0x100, MOD.APP_BASE)
        path.write_bytes(data)
        before = path.read_bytes()
        result = MOD.inspect_dump(path, 0x08000000)
        assert result["read_only_offline_analysis"]
        assert not result["bootloader_partition_verified"]
        matches = result["literal_matches_HYPOTHESES_NOT_LIMIT_PROOF"]
        assert "0x800080" in matches["empirical_end"]["aligned_literal_addresses"]
        assert path.read_bytes() == before

if __name__ == "__main__":
    test_empirical_size_gate()
    test_header_validation()
    test_readonly_dump_inventory()
    print("PASS: v3.23 conservative memory gate, header checks, read-only SWD inventory")
