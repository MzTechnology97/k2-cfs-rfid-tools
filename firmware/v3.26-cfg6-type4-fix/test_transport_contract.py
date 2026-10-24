#!/usr/bin/env python3
"""Offline CFG6 container and variable-length RS-485 transport audit.

In Creality's T113 mcu_util_485 ARM ELF, the file read at 0x1522c is
__read_chk(fd, buffer, r5, 255). 255 is the *buffer capacity*, NOT the
requested length. The device reply byte copied at 0x12278..0x1227c feeds
a signed quantity at 0x15208; for -1..-63, the updater requests 4..252
bytes. Actual reply byte sequences are absent from the historical log,
so no fixed packet count or failing packet index can be established.
No printer commands or flash writes are performed.
"""
from pathlib import Path
import hashlib
import struct
import json

ROOT = Path(__file__).resolve().parent
OLD = ROOT.parent / "v3.25-cfg6-lab" / "CFG6-ALL-ADVANCED-LAB-NOT-FOR-FLASH.bin"
NEW = ROOT / "CFG6-TYPE4-RESCAN-FIX-NOT-FOR-FLASH.bin"
OLD_SHA = "6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6"
NEW_SHA = "7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb"
# Physical load address verified by historical original-loader ARM audit and
# the active T113 updater's custom CFS validator. Firmware builder uses a
# *nominal* 0x08010000 PC origin for source offsets: do NOT change the builder.
PHYSICAL_APP_BASE = 0x08003000
NOMINAL_BUILDER_ORIGIN = 0x08010000
PARAM_PAGE = 0x0807F800
CRC_OFF, LEN_OFF, META_END = 0x20C, 0x20E, 0x212

def crc16(data):
    c = 0
    for x in data:
        c ^= x << 8
        for _ in range(8):
            c = (((c << 1) ^ 0x8005) & 0xFFFF) if (c & 0x8000) else (c << 1) & 0xFFFF
    return c

def inspect(p, sha):
    b = p.read_bytes()
    assert hashlib.sha256(b).hexdigest() == sha
    assert b[0x200:0x20C] == b"cfs0_000_153"
    crc,declared = struct.unpack_from("<HI", b, CRC_OFF)
    assert declared == len(b)
    check=bytearray(b);check[CRC_OFF:META_END] = bytes(META_END-CRC_OFF)
    assert crc16(check) == crc
    sp,rv=struct.unpack_from("<II",b)
    assert 0x20000000 <= sp < 0x20080000 and sp % 8 == 0
    assert (rv & 1) and PHYSICAL_APP_BASE <= (rv & ~1) < PHYSICAL_APP_BASE+len(b)
    assert PHYSICAL_APP_BASE+len(b) < PARAM_PAGE
    assert len(b)%4 == 0
    return b, {"size":len(b), "sha256":sha,"crc16":hex(crc),
               "length":declared,"physical_image_end":hex(PHYSICAL_APP_BASE+len(b)-1),"builder_nominal_end":hex(NOMINAL_BUILDER_ORIGIN+len(b)-1),"word_aligned":True}

def requested_bytes(reply_byte):
    # Decompiled from the updater's ARM assembly, not a verified bus capture.
    signed=reply_byte if reply_byte<128 else reply_byte-256
    return (((signed*63)<<2)&0xff) if signed<0 else 0

def main():
    a,aa=inspect(OLD,OLD_SHA)
    b,bb=inspect(NEW,NEW_SHA)
    assert requested_bytes(0xFF)==4
    assert requested_bytes(0xC1)==252
    assert requested_bytes(0xFE)==8
    first=next(i for i,(x,y) in enumerate(zip(a,b)) if x!=y)
    assert first==CRC_OFF
    # Packet lengths below are what-if examples ONLY, not observed wire data.
    sizes=(4,16,32,64,128,252)
    hypothetical=[{"data_bytes":n,"old_chunk_count":(len(a)+n-1)//n,
                   "new_chunk_count":(len(b)+n-1)//n} for n in sizes]
    print(json.dumps({
      "pass":True,"hardware_interaction":False,
      "original":aa,"candidate":bb,"first_difference_offset":hex(first),
      "identical_initial_bytes":first,
      "updater_read_buffer_capacity":255,
      "phys_app_base":hex(PHYSICAL_APP_BASE),
      "builder_nominal_origin":hex(NOMINAL_BUILDER_ORIGIN),
      "device_requested_data_bytes":{"min":4,"max":252,"multiple_of":4},
      "actual_number_of_chunks":"unknown: device requests variable-length data",
      "actual_failed_chunk_index":"unknown: log does not include it",
      "hypothetical_chunk_counts_not_observed":hypothetical
    },indent=2))

if __name__=="__main__":
    main()
