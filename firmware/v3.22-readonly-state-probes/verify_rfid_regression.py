#!/usr/bin/env python3
"""Fail-closed source-level RFID regression check, v3.12 vs v3.22.

This checks the normalized bodies of verified API7/stock-RFID/remaining
routines, not merely labels or textual README statements. It cannot replace
physical third-party and Creality-spool regression tests.
"""
import argparse
import hashlib
import re
from pathlib import Path

ROUTINES = [
    'op_info',
    'internal_ptr',
    'neighbor_ptr',
    'internal_tag_valid',
    'op_arm3',
    'op_clear',
    'clear_full',
    'find_override_by_uid',
    'key_ptr_for_index',
    'disarm_preserve_result',
    'disarm_preserve_capture',
    'capture_result',
    'capture_block4',
    'update_result',
    'uid_compare_wrapper',
    'msg_validate_wrapper',
    'capture_complete_record',
    'capture_complete_slot',
    'thirdparty_ready_slot',
    'clear_remaining_latch',
    'remaining_gate_wrapper',
    'remaining_init_wrapper',
    'remaining_valid_wrapper',
    'legacy_read0_wrapper',
    'legacy_read1_wrapper',
    'legacy_read2_wrapper',
    'legacy_common',
    'alt_read_wrapper'
]
EXPECTED_COUNT = 28
MARKERS = ("K2O2", "K2N2", "K2C3", "K2D3", "K2RL")


def sections(source):
    matches = list(re.finditer(r"^([A-Za-z_.$][\\w.$]*):[^\\n]*\\n", source, re.M))
    result = {}
    for i, item in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(source)
        raw = source[item.end():end]
        body = "\n".join(line.split("@", 1)[0].strip()
                         for line in raw.splitlines())
        result[item.group(1)] = "\n".join(line for line in body.splitlines() if line)
    return result


def check(v312, v322):
    if len(ROUTINES) != EXPECTED_COUNT or len(set(ROUTINES)) != EXPECTED_COUNT:
        raise ValueError("expected exact unique 28 RFID routines")
    old = sections(v312)
    new = sections(v322)
    for name in ROUTINES:
        if name not in old or name not in new:
            raise ValueError("missing validated RFID section: " + name)
        if old[name] != new[name]:
            raise ValueError("RFID/remaining regression detected at: " + name)
    for marker in MARKERS:
        if marker not in v312 or marker not in v322:
            raise ValueError("missing required API7 scratch/latch marker " + marker)
    if "config_v2_get_value" not in new or "cfg7_r0_wrapper" not in new:
        raise ValueError("expected v3.22 advanced bench and timing markers missing")
    if len(re.findall(r"^\\s*bl\\s+config_v2_get_value\\b", v322, re.M)) != 3:
        # one normal GET + two stock timing wrappers
        raise ValueError("unexpected runtime hook graph; inspect new caller(s)")
    return {
        "checked_routines": len(ROUTINES),
        "api7_stock_read_and_remaining_routines_match_v312": True,
        "reviewed_markers": MARKERS,
        "full_firmware_safety_proven": False,
    }


def main():
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v312", type=Path,
                   default=root / "v3.12-remaining/handler-v3_12.S")
    p.add_argument("--v322", type=Path,
                   default=root / "v3.22-readonly-state-probes/handler-v3_22.S")
    args = p.parse_args()
    x = check(args.v312.read_text(), args.v322.read_text())
    print("PASS: %d preserved RFID/remaining routines (NOT a motion safety proof)" %
          x["checked_routines"])


if __name__ == "__main__":
    main()
