#!/usr/bin/env python3
"""CFS v3.23 OFFLINE memory/address gate. No serial I/O or firmware flashing.

This tool does NOT establish the vendor updater's partition boundaries.
It enforces a conservative empirically motivated limit while bootloader
proof remains missing. An optional pre-obtained SWD readback dump is parsed
read-only; raw dump data is never emitted to console or to the report.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

APP_BASE = 0x08010000
EMPIRICAL_END = 0x0803B800  # Not a bootloader-certified app maximum.
SIDECAR_BASE = 0x20006EE8
SIDECAR_END = 0x20006F28
PROPOSED_RING_BASE = 0x20006F28
PROPOSED_RING_BYTES = 512
FW_LENGTH_OFF = 0x20E
EXPECTED_BASELINE_END = 0x0803B7DC

def inspect_app(data: bytes, app_max=EMPIRICAL_END):
    if len(data) < 0x212:
        raise ValueError("Not enough bytes for CFS app header")
    vector_sp = struct.unpack_from("<I", data, 0)[0]
    reset = struct.unpack_from("<I", data, 4)[0]
    stored_length = struct.unpack_from("<I", data, FW_LENGTH_OFF)[0]
    end = APP_BASE + len(data)
    safety = {
        "passes_conservative_empirical_size_limit": end <= app_max,
        "size_bytes": len(data),
        "app_base": hex(APP_BASE),
        "app_end": hex(end),
        "empirical_limit_UNVERIFIED": hex(app_max),
        "remaining_bytes_to_empirical_limit": app_max - end,
        "initial_sp": hex(vector_sp),
        "reset_vector": hex(reset),
        "header_length": stored_length,
        "header_length_consistent": stored_length == len(data),
        "initial_sp_within_64kb_sram": 0x20000000 < vector_sp <= 0x20010000,
        "reset_is_thumb_and_within_image": bool(reset & 1) and APP_BASE <= (reset & ~1) < end,
        "sha256": hashlib.sha256(data).hexdigest(),
        "flash_boundary_authoritatively_verified": False,
        "safe_to_flash": False,
    }
    return safety

def inspect_dump(path: Path, dump_base: int):
    # Pre-acquired SWD dump only. No OpenOCD, serial, reset, or reading devices.
    data = path.read_bytes()
    if len(data) < 0x1000:
        raise ValueError("Too little data for a meaningful offline dump")
    # Literal counts only, never a claim the executable uses these constants
    # as a bootloader limit; context disassembly is still necessary.
    candidates = [
        ("app_base", APP_BASE),
        ("empirical_end", EMPIRICAL_END),
        ("physical_512k_end", 0x08080000),
        ("empirical_image_bytes", EMPIRICAL_END - APP_BASE),
        ("physical_512k_bytes", 0x80000),
    ]
    counts = {}
    for name, value in candidates:
        pattern = struct.pack("<I", value)
        matches = []
        pos = 0
        while True:
            index = data.find(pattern, pos)
            if index == -1:
                break
            if index % 4 == 0:
                matches.append(hex(dump_base + index))
            pos = index + 1
        counts[name] = {"value": hex(value), "aligned_literal_addresses": matches[:80],
                        "total_aligned_occurrences": len(matches)}
    return {
        "dump_size_bytes": len(data),
        "dump_base": hex(dump_base),
        "dump_sha256": hashlib.sha256(data).hexdigest(),
        "literal_matches_HYPOTHESES_NOT_LIMIT_PROOF": counts,
        "bootloader_partition_verified": False,
        "read_only_offline_analysis": True,
    }

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--app", type=Path, help="Existing CFS .bin (read-only)")
    ap.add_argument("--swd-dump", type=Path,
                    help="Previously acquired flash dump (never captured by this script)")
    ap.add_argument("--dump-base", type=lambda x: int(x, 0), default=0x08000000)
    ap.add_argument("--json-out", type=Path,
                    help="Report path; stores only lengths/hashes/constants, never dump bytes")
    args = ap.parse_args(argv)
    if not args.app and not args.swd_dump:
        ap.error("--app and/or --swd-dump required")
    report = {
        "tool": "CFS offline memory audit",
        "mutates_cfs_or_binary": False,
        "empirical_limit_not_bootloader_proof": hex(EMPIRICAL_END),
        "currently_tested_v322_end": hex(EXPECTED_BASELINE_END),
        "sidecar_span": [hex(SIDECAR_BASE), hex(SIDECAR_END)],
        "ring_proposed_UNVERIFIED_span": [
            hex(PROPOSED_RING_BASE),
            hex(PROPOSED_RING_BASE + PROPOSED_RING_BYTES)
        ],
        "ring_reservation_proven_safe": False,
        "bootloader_map_proven_safe": False,
        "release_approval": False,
    }
    if args.app:
        report["app"] = inspect_app(args.app.read_bytes())
        if not (report["app"]["passes_conservative_empirical_size_limit"]
                and report["app"]["header_length_consistent"]
                and report["app"]["initial_sp_within_64kb_sram"]
                and report["app"]["reset_is_thumb_and_within_image"]):
            report["validation_failure"] = "One or more conservative app checks failed."
    if args.swd_dump:
        report["swd_dump"] = inspect_dump(args.swd_dump, args.dump_base)
    result = json.dumps(report, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(result)
    print(result, end="")
    return 1 if report.get("validation_failure") else 0

if __name__ == "__main__":
    raise SystemExit(main())
