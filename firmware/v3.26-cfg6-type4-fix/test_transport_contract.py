#!/usr/bin/env python3
"""Offline transport-contract audit: released CFG6 versus type4 experimental BIN.

Creality's T113 /usr/bin/mcu_util_485 (ARM ELF, read-only analysis, 2026-10-24)
reads up to 255 bytes per firmware data request and retries with a 500ms
response timeout. The script does not interact with the connected printer.
It cannot establish which packet failed without byte-level transfer logs.
"""
from pathlib import Path
import hashlib
import struct
import json

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT.parent / "v3.25-cfg6-lab" / "CFG6-ALL-ADVANCED-LAB-NOT-FOR-FLASH.bin"
CANDIDATE = ROOT / "CFG6-TYPE4-RESCAN-FIX-NOT-FOR-FLASH.bin"
OLD_SHA = "6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6"
NEW_SHA = "7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb"
APP_BASE = 0x08010000
BOOT_PARAM_PAGE = 0x0807F800
CHUNK_BYTES = 255
CRC_OFF, LEN_OFF, META_END = 0x20C, 0x20E, 0x212

def crc16_bypass(payload):
    crc = 0
    for byte in payload:
        crc ^= byte << 8
        for _ in range(8):
            crc = (((crc << 1) ^ 0x8005) & 0xFFFF) if (crc & 0x8000) else ((crc << 1) & 0xFFFF)
    return crc

def inspect(path, expected_sha):
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected_sha
    ident = data[0x200:0x20C].decode("ascii")
    assert ident == "cfs0_000_153"
    crc, size = struct.unpack_from("<HI", data, CRC_OFF)
    assert size == len(data)
    check = bytearray(data)
    check[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
    assert crc16_bypass(check) == crc
    msp, reset = struct.unpack_from("<II", data)
    assert 0x20000000 <= msp < 0x20080000 and (msp & 7) == 0
    assert reset & 1 and APP_BASE <= (reset & ~1) < APP_BASE+len(data)
    assert APP_BASE+len(data) < BOOT_PARAM_PAGE
    packets = [data[i:i+CHUNK_BYTES] for i in range(0, len(data), CHUNK_BYTES)]
    return {"size":len(data), "crc16":hex(crc), "declared_len":size,
            "app_id":ident, "sha256":expected_sha, "packet_count":len(packets),
            "last_packet_bytes":len(packets[-1]), "image_end":hex(APP_BASE+len(data)-1),
            "packets":packets, "data":data}
def main():
    a = inspect(ORIGINAL, OLD_SHA)
    b = inspect(CANDIDATE, NEW_SHA)
    changed = [i+1 for i,(pa,pb) in enumerate(zip(a["packets"],b["packets"])) if pa!=pb]
    assert len(a["packets"]) == len(b["packets"]) == 702
    assert a["packets"][:2] == b["packets"][:2]
    assert changed[0] == 3
    first_diff = next(i for i,(x,y) in enumerate(zip(a["data"],b["data"])) if x!=y)
    assert first_diff == CRC_OFF
    print(json.dumps({
        "passed":True,"hardware_flash_attempted":False,"packet_payload_bytes":CHUNK_BYTES,
        "baseline":{k:v for k,v in a.items() if k not in ("packets","data")},
        "candidate":{k:v for k,v in b.items() if k not in ("packets","data")},
        "first_changed_byte":hex(first_diff),
        "first_changed_packet_1based":changed[0],
        "equal_leading_packets":2,
        "changed_packet_count":len(changed),
        "scope":"Static contract only; physical failing packet index is unknown."
    },indent=2))
if __name__=="__main__":
    main()
