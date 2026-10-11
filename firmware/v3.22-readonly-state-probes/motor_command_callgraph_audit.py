#!/usr/bin/env python3
"""Offline stock Creality CFS motor-command wrapper callgraph audit.

Saved, SHA-pinned original CFS 1.5.3 and v3.22 application binaries only.
No serial, bootloader, MCU or flash access. Does NOT create a firmware BIN.
This identifies host-independent *motor commands*, NOT physical movement,
true stop/idle state, IRQ/task ownership, or complete motor-hook coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM

from flash_ram_phase2_audit import (
    APP_BASE, CRC_OFF, META_END, crc16_bypass, pinned, report_image,
)

DUTY_ENTRY = 0x0801E0CC
FORWARD_ENTRY = 0x0801E164
REVERSE_ENTRY = 0x0801E17E
ZERO_COMMAND_ENTRY = 0x0801E198

# Exact Thumb BL sites from the original Creality 1.5.3 APP, independently
# enumerated on 2026-10-11. These sites and targets are unchanged in v3.22.
# "forward", "reverse" and "zero" are static API names, not verified
# electrical movement/stop signals from real motor hardware.
_CALLSITE_WORDS = {
    FORWARD_ENTRY: """
    08010E84 08010F2C 08010F8A 0801110C 08011158 0801173E
    08011BD0 08011E58 08012A9E 08012AC0 08012E8A 08014DB8
    0801538E 08015534 080156E6 08016178 080161EA 080161F0
    08016340 080163C2 08016428 0801BC56 0801C07A 0801CB3E
    0801E38E 0801E41A 0801E6E0 0801E7B0 0801F510 0801FF9E
    08032C60 08032DA8 08032E02
    """,
    REVERSE_ENTRY: """
    08010F7C 08011178 08011CB2 08014DC2 0801539A 08015546
    0801573E 08016172 080161A6 080161C8 08016308 08016362
    080163E0 08016640 0801BC5E 0801E37A 0801E414
    """,
    ZERO_COMMAND_ENTRY: """
    080105F0 08010640 08010694 08010EBE 08010EF2 08010FCC
    080117BA 08011BDA 08011CC2 08011E2A 08011E6A 08011E78
    08012AA8 08012E50 08012EAC 08012F94 08014C9E 08014D92
    08014DAE 08015514 08015702 08015784 08015E74 0801618C
    080161DA 08016330 08016392 080163D6 08016400 08016432
    0801664A 0801BC64 0801BED6 0801C084 0801C0A6 0801CAC0
    0801CB48 0801E424 0801E84E 0801E876 0801E87E 0801F638
    0801FFDE 08032CD0 08032D04 08032D2E 08032D52 08032DB8
    08032E9E 08032EAA
    """,
    DUTY_ENTRY: "0801E366 0801E536",
}

CALLS = {
    target: tuple(int(address, 16) for address in words.split())
    for target, words in _CALLSITE_WORDS.items()
}

# The wrappers use tail branches to the COMMON duty setter.
TAILS = {
    0x0801E17C: DUTY_ENTRY,
    0x0801E196: DUTY_ENTRY,
    0x0801E1A8: DUTY_ENTRY,
}

# Constants / load sites match original memory driver use.
ROM_WORDS = {
    0x0801E244: 0x20004960,
    0x0801E258: 0x20003778,
}

# The stop-like wrapper calls hardware setup, then issues zero duty.
# This proves a zero command, not actual zero encoder speed or idle.
VERIFIED_INSTRUCTIONS = {
    0x0801E0CC: ("push.w", "{r4, r5, r6, r7, r8, lr}"),
    0x0801E0D0: ("mov", "r5, r0"),
    0x0801E0D2: ("cmp", "r0, #0xff"),
    0x0801E164: ("push", "{r4, lr}"),
    0x0801E170: ("movs", "r0, #0"),
    0x0801E17E: ("push", "{r4, lr}"),
    0x0801E18A: ("movs", "r0, #1"),
    0x0801E198: ("push", "{r4, lr}"),
    0x0801E1A6: ("movs", "r0, #0"),
    0x0801E0DC: ("movw", "r0, #0xc350"),
}
EXPECTED_COUNTS = {
    FORWARD_ENTRY: 33,
    REVERSE_ENTRY: 17,
    ZERO_COMMAND_ENTRY: 50,
    DUTY_ENTRY: 2,
}


def dword(image: bytes, address: int) -> int:
    off = address - APP_BASE
    if off < 0 or off + 4 > len(image):
        raise ValueError(f"ROM word out of range: {address:#x}")
    return struct.unpack_from("<I", image, off)[0]


def one_ins(image: bytes, address: int):
    off = address - APP_BASE
    if off < 0 or off + 4 > len(image):
        raise ValueError(f"ARM instruction out of range: {address:#x}")
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    i = next(cs.disasm(image[off:off + 4], address, count=1), None)
    if i is None:
        raise ValueError(f"Thumb decode failed: {address:#x}")
    return i


def verify(image: bytes, kind: str, all_sites_scan: bool = False) -> dict:
    report = report_image(image, kind)
    all_locations = [site for sites in CALLS.values() for site in sites]
    if len(all_locations) != len(set(all_locations)):
        raise ValueError("duplicated wrapper callsite in evidence inventory")
    if {t: len(c) for t, c in CALLS.items()} != EXPECTED_COUNTS:
        raise ValueError("known static callsite inventory unexpectedly altered")
    calls = []
    for target, addresses in CALLS.items():
        for address in addresses:
            i = one_ins(image, address)
            if (i.mnemonic != "bl" or i.size != 4 or
                    i.op_str != f"#0x{target:x}"):
                raise ValueError(
                    f"original Thumb BL changed at {address:#x}: "
                    f"{i.mnemonic} {i.op_str}")
            calls.append({
                "callsite": hex(address),
                "target": hex(target),
                "bytes": i.bytes.hex(),
            })
    tails = []
    for address, target in TAILS.items():
        i = one_ins(image, address)
        if not i.mnemonic.startswith("b") or i.op_str != f"#0x{target:x}":
            raise ValueError(f"motor command tail branch changed at {address:#x}")
        tails.append({
            "at": hex(address), "target": hex(target),
            "thumb_encoding": i.bytes.hex(),
        })
    checked = []
    for address, (mnemonic, operands) in VERIFIED_INSTRUCTIONS.items():
        i = one_ins(image, address)
        if (i.mnemonic, i.op_str) != (mnemonic, operands):
            raise ValueError(f"candidate motor command changed at {address:#x}")
        checked.append({
            "at": hex(address), "mnemonic": mnemonic,
            "operands": operands, "thumb_encoding": i.bytes.hex(),
        })
    for address, value in ROM_WORDS.items():
        if dword(image, address) != value:
            raise ValueError(f"original motor RAM pointer changed at {address:#x}")
    if all_sites_scan:
        # Check that the inventoried direct BL destinations are exhaustive
        # for ALL halfword-aligned Thumb BL encodings. This is an
        # over-approximation when instructions overlap data; never promote
        # static direct-call counts to runtime motor coverage claims.
        discovered = {target: [] for target in CALLS}
        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        for offset in range(0, len(image) - 4, 2):
            address = APP_BASE + offset
            i = next(cs.disasm(image[offset:offset + 4],
                               address, count=1), None)
            if i is None or i.mnemonic != "bl":
                continue
            if len(i.operands) != 1 or i.operands[0].type != ARM_OP_IMM:
                continue
            target = i.operands[0].imm
            if target in CALLS:
                discovered[target].append(address)
        for target, expected in CALLS.items():
            if tuple(discovered[target]) != expected:
                raise ValueError(
                    f"static BL scan differs from pinned inventory @ {target:#x}")
    fingerprint_material = "\n".join(
        f"{item['callsite']}:{item['target']}:{item['bytes']}"
        for item in sorted(calls, key=lambda x: int(x["callsite"], 16)))
    report.update({
        "callsite_total": len(calls),
        "forward_wrapper_static_BL": len(CALLS[FORWARD_ENTRY]),
        "reverse_wrapper_static_BL": len(CALLS[REVERSE_ENTRY]),
        "zero_command_wrapper_static_BL": len(CALLS[ZERO_COMMAND_ENTRY]),
        "direct_duty_setter_static_BL": len(CALLS[DUTY_ENTRY]),
        "callsite_inventory_sha256": hashlib.sha256(
            fingerprint_material.encode()).hexdigest(),
        "callsite_records": calls,
        "wrapper_tails": tails,
        "pinned_Thumb_prologue_and_command_instructions": checked,
        "ROM_pointer_words": [
            {"address": hex(a), "value": hex(v)} for a, v in ROM_WORDS.items()],
        "full_scan_completed": all_sites_scan,
        "all_physical_motor_start_stop_events_proven": False,
        "zero_duty_command_proves_motor_idle": False,
        "safe_to_write_motor_registers": False,
        "safe_to_install_trace_hook": False,
        "safe_to_flash_expanded_app": False,
    })
    return report


def fail_closed_tests(image: bytes) -> dict:
    # Re-sign each altered in-memory APP so the failure cannot be explained
    # away as an invalid header CRC. No file/flash modification is performed.
    sites = {
        "shared_duty_prologue": 0x0801E0CC,
        "forward_direction": 0x0801E170,
        "reverse_direction": 0x0801E18A,
        "zero_duty_instruction": 0x0801E1A6,
        "zero_to_setter_tail": 0x0801E1A8,
        "stock_stop_callsite": 0x080105F0,
        "stock_forward_callsite": 0x08010E84,
        "stock_reverse_callsite": 0x08010F7C,
        "pinned_motor_RAM_pointer": 0x0801E244,
    }
    rejected = []
    for label, address in sites.items():
        altered = bytearray(image)
        altered[address - APP_BASE] ^= 1
        for_crc = bytearray(altered)
        for_crc[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
        struct.pack_into("<H", altered, CRC_OFF, crc16_bypass(for_crc))
        try:
            verify(bytes(altered), "running_v322", all_sites_scan=False)
        except ValueError:
            rejected.append(label)
        else:
            raise AssertionError("dangerous altered motor command accepted: " + label)
    return {"crc_valid_changes_rejected": rejected, "count": len(rejected)}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v322", required=True, type=Path)
    p.add_argument("--stock", type=Path)
    p.add_argument("--scan-all", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--json-out", type=Path)
    opts = p.parse_args()
    current = pinned(opts.v322, "running_v322")
    original = pinned(opts.stock, "creality_stock_153") if opts.stock else None
    output = {
        "scope": "strictly offline Thumb static command xrefs; NOT real motor status",
        "stock_compared": original is not None,
        "v322": verify(current, "running_v322", opts.scan_all),
        "stock_153": verify(original, "creality_stock_153", opts.scan_all)
        if original is not None else None,
        "physical_motor_motion_observed": False,
        "firmware_or_serial_operations": False,
        "release_allowed": False,
    }
    if original is not None:
        for key in ("callsite_inventory_sha256", "wrapper_tails",
                    "pinned_Thumb_prologue_and_command_instructions",
                    "ROM_pointer_words"):
            if output["v322"][key] != output["stock_153"][key]:
                raise ValueError("Creality original vs v3.22 motor command changed")
    if opts.self_test:
        output["fail_closed"] = fail_closed_tests(current)
    result = json.dumps(output, indent=2) + "\n"
    if opts.json_out:
        opts.json_out.write_text(result)
    print(result, end="")


if __name__ == "__main__":
    main()
