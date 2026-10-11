#!/usr/bin/env python3
"""Differential, isolated Thumb emulator for Creality CFS zero/nonzero duty.

The original CFS 1.5.3 and byte-exact v3.22 APP are SHA-pinned.
No hardware interface, serial transport, firmware update, motor movement,
or flashable output. External hardware functions are replaced by mocks.
DOES NOT verify physical rotor speed, MCU motor idle or hook safety.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned, report_image, APP_BASE

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC,
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_SP,
)

DUTY_ENTRY = 0x0801E0CC
MOTOR_ROOT = 0x20004960
MOTOR_STATE = MOTOR_ROOT + 0xB4
HOST_CACHE = 0x20003778
RAM_BEGIN = 0x20000000
FLASH_BEGIN = 0x08000000
FLASH_MAP_BYTES = 0x80000
RAM_MAP_BYTES = 0x10000
RETURN_SENTINEL = 0x0803B700

# Stub ONLY the external hardware-dependent procedures. The original
# duty-controller assembly executes unchanged up until its branch targets.
STUBS = {
    0x08026516: "hardware_set_value",
    0x08026488: "hardware_set_pwm",
    0x0802F270: "zero_state_auxiliary",
    0x08013CD6: "zero_state_clear",
}
ZERO_BRANCH_STATIC_STOP = 0x0801E14A
NONZERO_BRANCH_STATIC_STOP = 0x0802F190

# Crucial exact instructions and control-flow boundaries observed in the
# original manufacturer app; unchanged in v3.22. No inferred semantics
# about actual motor-current or encoder state are asserted.
PINNED_INS = {
    0x0801E0CC: ("push.w", "{r4, r5, r6, r7, r8, lr}"),
    0x0801E0D2: ("cmp", "r0, #0xff"),
    0x0801E0F4: ("cbz", "r5, #0x801e10e"),
    0x0801E10A: ("str", "r6, [r7, #0x30]"),
    0x0801E10C: ("str", "r6, [r7, #0x34]"),
    0x0801E116: ("bl", "#0x8026516"),
    0x0801E11E: ("bl", "#0x8026488"),
    0x0801E122: ("movs", "r0, r5"),
    0x0801E126: ("strh", "r0, [r4, #6]"),
    0x0801E128: ("beq", "#0x801e13c"),
    0x0801E12A: ("strb", "r6, [r5]"),
    0x0801E12E: ("strb.w", "r0, [r5, #0x29]"),
    0x0801E136: ("ldr", "r0, [pc, #0x10c]"),
    0x0801E138: ("b.w", "#0x802f190"),
    0x0801E13E: ("bl", "#0x802f270"),
    0x0801E146: ("bl", "#0x8013cd6"),
    0x0801E14A: ("movs", "r0, #0x14"),
    0x0801E14C: ("strb.w", "r0, [r7, #0x3c]"),
    0x0801E154: ("vstr", "s0, [r5, #0x20]"),
    0x0801E158: ("vstr", "s0, [r5, #0x24]"),
    0x0801E15C: ("strb.w", "r6, [r5, #0x28]"),
}
# The default nonzero/zero route model stops BEFORE low-level branches or
# VFP initialization. It does not execute the entire motor function.
SPEED_CASES = (0, 1, 127, 255, 300)

def _read(image, at, size):
    start = at - APP_BASE
    if start < 0 or start + size > len(image):
        raise ValueError("requested ROM bytes outside pinned app")
    return image[start:start + size]


def verify_instructions(image):
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    result = []
    for at, expected in PINNED_INS.items():
        ins = next(decoder.disasm(_read(image, at, 4), at, count=1), None)
        if ins is None or (ins.mnemonic, ins.op_str) != expected:
            raise ValueError(f"stock zero/nonzero branch changed @ {at:#x}")
        result.append({
            "at": hex(at), "instruction": ins.mnemonic + " " + ins.op_str,
            "bytes": ins.bytes.hex(),
        })
    return result


def snapshot(uc):
    def d16(at):
        return struct.unpack("<H", uc.mem_read(at, 2))[0]
    def d32(at):
        return struct.unpack("<I", uc.mem_read(at, 4))[0]
    return {
        "previous_requested_duty": d16(MOTOR_STATE + 8),
        "current_requested_duty": d16(MOTOR_STATE + 6),
        "motor_state_subfields_0x30_0x34": [
            d32(MOTOR_ROOT + 0x30), d32(MOTOR_ROOT + 0x34)
        ],
        "host_cache_first_byte": uc.mem_read(HOST_CACHE, 1).hex(),
        "host_cache_direction": uc.mem_read(HOST_CACHE + 0x29, 1).hex(),
        "status_0x3c": uc.mem_read(MOTOR_ROOT + 0x3C, 1).hex(),
    }


def run_case(image, value):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(FLASH_BEGIN, FLASH_MAP_BYTES)
    u.mem_map(RAM_BEGIN, RAM_MAP_BYTES)
    u.mem_write(APP_BASE, image)
    u.mem_write(MOTOR_ROOT, bytes([0xA5]) * 0x150)
    u.mem_write(HOST_CACHE, bytes([0x5A]) * 0x50)
    u.mem_write(MOTOR_STATE, struct.pack("<I", 0x20002000))
    u.mem_write(MOTOR_STATE + 4, bytes([0x01]))
    u.mem_write(MOTOR_STATE + 6, struct.pack("<H", 72))
    u.mem_write(MOTOR_STATE + 8, struct.pack("<H", 17))
    u.mem_write(MOTOR_STATE + 10, struct.pack("<h", 3))
    u.reg_write(UC_ARM_REG_SP, 0x2000E000)
    u.reg_write(UC_ARM_REG_LR, RETURN_SENTINEL | 1)
    u.reg_write(UC_ARM_REG_R0, value)
    u.reg_write(UC_ARM_REG_PC, DUTY_ENTRY | 1)
    events = []
    writes = []
    reached = []

    def _code(uc, at, size, _):
        if at in STUBS:
            events.append({
                "target": hex(at), "stub": STUBS[at],
                "r0": hex(uc.reg_read(UC_ARM_REG_R0)),
                "r1": hex(uc.reg_read(UC_ARM_REG_R1)),
                "r2": hex(uc.reg_read(UC_ARM_REG_R2)),
                "r3": hex(uc.reg_read(UC_ARM_REG_R3)),
            })
            # Simulated AAPCS-style immediate return. The hardware-side
            # effects are deliberately NOT asserted.
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif at in (ZERO_BRANCH_STATIC_STOP, NONZERO_BRANCH_STATIC_STOP):
            reached.append(at)
            uc.emu_stop()

    def _mem_write(uc, access, at, size, value, _):
        if RAM_BEGIN <= at < RAM_BEGIN + RAM_MAP_BYTES:
            writes.append({
                "address": hex(at), "size": size,
                "value": hex(value & ((1 << (size * 8)) - 1)),
            })

    u.hook_add(UC_HOOK_CODE, _code)
    u.hook_add(UC_HOOK_MEM_WRITE, _mem_write)
    u.emu_start(DUTY_ENTRY | 1, 0, count=500)
    expected = ZERO_BRANCH_STATIC_STOP if value == 0 else NONZERO_BRANCH_STATIC_STOP
    if reached != [expected]:
        raise ValueError(
            f"wrong control branch value {value}: {list(map(hex, reached))}")
    if len(events) != (4 if value == 0 else 2):
        raise ValueError("unexpected stub calls during DUTY branch")
    if events[0]["target"] != hex(0x08026516) or events[1]["target"] != hex(0x08026488):
        raise ValueError("two low-level setup calls not reached")
    observed = snapshot(u)
    if observed["current_requested_duty"] != min(value, 255):
        raise ValueError("stored requested duty did not match input")
    if observed["previous_requested_duty"] != 72:
        raise ValueError("previous requested value not copied to prior field")
    root_subfields = observed["motor_state_subfields_0x30_0x34"]
    if value != 0:
        if root_subfields != [0, 0]:
            raise ValueError("nonzero-duty branch unexpectedly retains root flags")
        if observed["host_cache_first_byte"] != "00":
            raise ValueError("nonzero branch did not clear host cache first byte")
    else:
        if root_subfields != [0xA5A5A5A5] * 2:
            raise ValueError("zero branch unexpectedly wrote nonzero-only flags")
        if [e["target"] for e in events[2:]] != [
                hex(0x0802F270), hex(0x08013CD6)]:
            raise ValueError("zero branch missing original auxiliary calls")
    return {
        "duty_requested": value,
        "control_branch": "zero" if value == 0 else "nonzero",
        "simulator_paused_at": hex(expected),
        "low_level_hardware_calls_replaced_by_mocks": len(events),
        "stubbed_original_call_targets": [e["target"] for e in events],
        "known_RAM_writes_before_branch_stop": [
            w for w in writes if w["address"] in {
                hex(MOTOR_STATE + 6), hex(MOTOR_STATE + 8),
                hex(MOTOR_ROOT + 0x30), hex(MOTOR_ROOT + 0x34),
                hex(HOST_CACHE), hex(HOST_CACHE + 0x29)}
        ],
        "RAM_snapshot_before_external_state_update": observed,
        "hardware_motor_status_observed": False,
    }


def audit(image, kind):
    header = report_image(image, kind)
    pin = verify_instructions(image)
    cases = [run_case(image, value) for value in SPEED_CASES]
    return {
        "input": header,
        "pinned_thumb_instructions": pin,
        "simulation_cases": cases,
        "safety": {
            "all_external_hardware_functions_stubbed": True,
            "controller_emulation_stops_before_VFP_and_external_finalizers": True,
            "can_determine_real_motor_idle": False,
            "can_reconstruct_all_physical_motor_events": False,
            "safe_to_flash": False,
        },
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--v322", required=True, type=Path)
    cli.add_argument("--stock", type=Path)
    cli.add_argument("--json-out", type=Path)
    x = cli.parse_args()
    current = audit(pinned(x.v322, "running_v322"), "running_v322")
    stock = audit(pinned(x.stock, "creality_stock_153"),
                  "creality_stock_153") if x.stock else None
    if stock:
        if stock["pinned_thumb_instructions"] != current["pinned_thumb_instructions"]:
            raise ValueError("stock original MCU branch differs from v3.22")
        if stock["simulation_cases"] != current["simulation_cases"]:
            raise ValueError("stock original / v3.22 case-by-case execution differs")
    report = {
        "scope": "offline Thumb constrained differential, not real movement",
        "stock_compared": stock is not None,
        "v322": current,
        "stock_153": stock,
        "actual_mcu_device_access": False,
        "motor_idle_proven": False,
        "flash_release_authorized": False,
    }
    text = json.dumps(report, indent=2) + "\n"
    if x.json_out:
        x.json_out.write_text(text)
    print(text, end="")


if __name__ == "__main__":
    main()
