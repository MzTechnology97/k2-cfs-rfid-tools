#!/usr/bin/env python3
"""Original Creality CFS PWM HAL/RT-Thread dispatch: SAFE offline audit.

Runs exact, SHA-pinned original Thumb *generic PWM dispatcher* and a
timer-base selector in Unicorn. The dispatcher is STOPPED at its target:
no timer HW setter, GPIO driver, IRQ, UART or MCU peripheral executes.

IMPORTANT: NO evidence yet that live registry object named "pwm1" points
to this generic dispatcher. In fact original high-level code issues
0x1e04/0x1e05, which this candidate generic dispatcher rejects.
Do not equate a PWM command, ACK or timer register with motor idle.

No firmware generated, flashed, patched, or CFS serial accessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from flash_ram_phase2_audit import (
    APP_BASE, CRC_OFF, META_END, crc16_bypass, pinned, report_image,
)
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_SP,
)

FLASH_BASE = 0x08000000
FLASH_BYTES = 0x80000
RAM_BASE = 0x20000000
RAM_BYTES = 0x10000
SELECT_TIMER = 0x08028128
GENERIC_PWM_DISPATCH = 0x08028394
RETURN_SENTINEL = 0x0803B700
MOCK_DEVICE = 0x20001000
MOCK_DEVICE_PRIVATE = 0x20001100
MOCK_PWM_PARAMS = 0x20002000

TARGETS = {
    0x1E00: 0x0802820C,
    0x1E01: 0x0802820C,
    0x1E02: 0x0802828E,
    0x1E03: 0x080285E0,
}
UNSUPPORTED = (0x1E04, 0x1E05)
TIMER_VALUES = (
    0x40012C00,
    0x40000000,
    0x40000400,
    0x40000800,
    0x40000C00,
    0x40001000,
    0x40001400,
    0x40013400,
    0x40014C00,
    0x40015000,
    0x40015400,
    0x40001800,
    0x40001C00,
    0x40002000,
)
# Exact original machine instructions; keep code bytes unchanged.
PINS = {
    0x08028128: ("push", "{r4, lr}"),
    0x0802812C: ("ldr", "r4, [pc, #0x394]"),
    0x0802812E: ("cmp", "r1, #0xe"),
    0x08028132: ("tbb", "[pc, r1]"),
    0x08028144: ("mov", "r0, r4"),
    0x08028146: ("pop", "{r4, pc}"),
    0x08028394: ("mov", "r3, r1"),
    0x08028396: ("ldr", "r0, [r0, #0x3c]"),
    0x08028398: ("mov", "r1, r2"),
    0x0802839A: ("cmp.w", "r3, #0x1e00"),
    0x0802839E: ("beq", "#0x80283b4"),
    0x080283A0: ("mvn", "r2, #0x1e00"),
    0x080283A4: ("adds", "r2, r3, r2"),
    0x080283A6: ("beq", "#0x80283b6"),
    0x080283A8: ("cmp", "r2, #1"),
    0x080283AA: ("beq", "#0x80283b8"),
    0x080283AC: ("cmp", "r2, #2"),
    0x080283AE: ("beq", "#0x80283ba"),
    0x080283B0: ("movs", "r0, #5"),
    0x080283B2: ("bx", "lr"),
    0x080283B4: ("movs", "r2, #1"),
    0x080283B6: ("b", "#0x802820c"),
    0x080283B8: ("b", "#0x802828e"),
    0x080283BA: ("b.w", "#0x80285e0"),
    0x0802820C: ("push", "{r4, r5, r6, lr}"),
    0x0802828E: ("push.w", "{r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}"),
    0x080285E0: ("push.w", "{r4, r5, r6, r7, r8, sb, sl, lr}"),
    # Direct high-level CFS calls with additional command IDs, whose
    # path through the *runtime* object is NOT proved to be this dispatcher.
    0x08026538: ("movw", "r1, #0x1e02"),
    0x080264AA: ("movw", "r1, #0x1e05"),
    0x080264B8: ("movw", "r1, #0x1e04"),
    0x080264C4: ("mov.w", "r1, #0x1e00"),
}
LITERAL_WORDS = {
    addr: val for addr, val in zip(
        range(0x080284C4, 0x080284F8, 4), (
            TIMER_VALUES[0],
            *TIMER_VALUES[2:7],
            *TIMER_VALUES[7:11],
            *TIMER_VALUES[11:],
        ))
}
# The selector's 0x40000000 case is an immediate, not a ROM pointer.
LITERAL_WORDS[0x080284C8] = TIMER_VALUES[2]
LITERAL_WORDS[0x080284C4] = TIMER_VALUES[0]


def _u32(image: bytes, address: int) -> int:
    off = address - APP_BASE
    if not 0 <= off <= len(image) - 4:
        raise ValueError("literal address outside original image")
    return struct.unpack_from("<I", image, off)[0]


def verify_static(image: bytes, kind: str) -> dict:
    result = report_image(image, kind)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    checks = []
    for at, want in PINS.items():
        off = at - APP_BASE
        ins = next(cs.disasm(image[off:off + 4], at, count=1), None)
        if ins is None or (ins.mnemonic, ins.op_str) != want:
            raise ValueError(f"original CFS PWM Thumb mismatch at {at:#x}")
        checks.append({
            "at": hex(at), "mnemonic": ins.mnemonic,
            "operands": ins.op_str, "bytes": ins.bytes.hex(),
        })
    for at, word in LITERAL_WORDS.items():
        if _u32(image, at) != word:
            raise ValueError(f"original GD32 timer literal changed at {at:#x}")
    result.update({
        "pinned_Thumb_instructions": checks,
        "pinned_timer_base_ROM_words": [
            {"at": hex(at), "word": hex(word)}
            for at, word in sorted(LITERAL_WORDS.items())],
        "dispatcher_proven_used_by_runtime_pwm1_object": False,
        "physical_motor_idle_confirmed": False,
        "direct_hardware_peripheral_calls_enabled": False,
    })
    return result


def _new_machine(image):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(FLASH_BASE, FLASH_BYTES)
    u.mem_map(RAM_BASE, RAM_BYTES)
    u.mem_write(APP_BASE, image)
    u.reg_write(UC_ARM_REG_SP, 0x2000E000)
    u.reg_write(UC_ARM_REG_LR, RETURN_SENTINEL | 1)
    return u


def timer_selector_cases(image):
    cases = []
    for index, expected in enumerate(TIMER_VALUES):
        u = _new_machine(image)
        u.reg_write(UC_ARM_REG_R0, index)
        reached = []
        def _code(uc, pc, size, _):
            if pc == RETURN_SENTINEL:
                reached.append(pc)
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE, _code)
        u.emu_start(SELECT_TIMER | 1, 0, count=40)
        if reached != [RETURN_SENTINEL]:
            raise ValueError("timer selector did not return correctly")
        got = u.reg_read(UC_ARM_REG_R0)
        if got != expected:
            raise ValueError(
                f"GD32 timer mapping changed index={index} "
                f"got={got:#x} wanted={expected:#x}")
        cases.append({"selector_index": index, "timer_register_base": hex(got)})
    return cases


def pwm_dispatch_cases(image):
    cases = []
    for opcode in (*TARGETS, *UNSUPPORTED):
        u = _new_machine(image)
        u.mem_write(MOCK_DEVICE + 0x3C,
                    struct.pack("<I", MOCK_DEVICE_PRIVATE))
        u.mem_write(MOCK_PWM_PARAMS, bytes([0x5A]) * 16)
        u.reg_write(UC_ARM_REG_R0, MOCK_DEVICE)
        u.reg_write(UC_ARM_REG_R1, opcode)
        u.reg_write(UC_ARM_REG_R2, MOCK_PWM_PARAMS)
        stops = []
        def _code(uc, pc, size, _):
            if pc in TARGETS.values():
                stops.append({
                    "target": hex(pc),
                    "private_ptr": hex(uc.reg_read(UC_ARM_REG_R0)),
                    "args_ptr": hex(uc.reg_read(UC_ARM_REG_R1)),
                    "enable_or_disable_value": uc.reg_read(UC_ARM_REG_R2),
                })
                uc.emu_stop()
            elif pc == RETURN_SENTINEL:
                stops.append({"target": "unsupported-return",
                              "result": uc.reg_read(UC_ARM_REG_R0)})
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE, _code)
        u.emu_start(GENERIC_PWM_DISPATCH | 1, 0, count=60)
        if len(stops) != 1:
            raise ValueError("PWM dispatcher did not stop at one safe boundary")
        status = stops[0]
        if opcode in TARGETS:
            if (status["target"] != hex(TARGETS[opcode]) or
                    status["private_ptr"] != hex(MOCK_DEVICE_PRIVATE) or
                    status["args_ptr"] != hex(MOCK_PWM_PARAMS)):
                raise ValueError(f"PWM dispatcher wrong target for {opcode:#x}")
            if opcode in (0x1E00, 0x1E01) and status[
                    "enable_or_disable_value"] != (
                        1 if opcode == 0x1E00 else 0):
                raise ValueError("PWM enable/disable selector mismatch")
        elif status != {"target": "unsupported-return", "result": 5}:
            raise ValueError("unknown PWM op did not return fixed 5")
        cases.append({"request_code": hex(opcode), **status})
    return cases


def tamper(image: bytes):
    samples = {
        "timer_select_index_cmp": 0x0802812E,
        "timer_index_base_literal": 0x080284C4,
        "timer_last_base_literal": 0x080284F4,
        "PWM_dispatch_command_cmp": 0x0802839A,
        "PWM_get_request_branch": 0x080283AC,
        "PWM_unknown_return": 0x080283B0,
        "PWM_set_request_branch": 0x080283B8,
        "PWM_control_header_1E02": 0x08026538,
        "PWM_control_header_1E05": 0x080264AA,
        "PWM_control_header_1E04": 0x080264B8,
    }
    rejected = []
    for label, at in samples.items():
        mutant = bytearray(image)
        mutant[at - APP_BASE] ^= 1
        crc_copy = bytearray(mutant)
        crc_copy[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
        struct.pack_into("<H", mutant, CRC_OFF, crc16_bypass(crc_copy))
        if not report_image(bytes(mutant), "running_v322")["header_crc_valid"]:
            raise AssertionError("test mutant CRC not valid")
        try:
            verify_static(bytes(mutant), "running_v322")
        except ValueError:
            rejected.append(label)
        else:
            raise AssertionError("unsafe modification undetected: " + label)
    return {"CRC_valid_corruptions_rejected": rejected, "count": len(rejected)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v322", required=True, type=Path)
    p.add_argument("--stock", type=Path)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--json-out", type=Path)
    opt = p.parse_args()
    cur_bin = pinned(opt.v322, "running_v322")
    stock_bin = pinned(opt.stock, "creality_stock_153") if opt.stock else None

    def audit(image, kind):
        return {
            "static": verify_static(image, kind),
            "timer_base_selector_cases": timer_selector_cases(image),
            "generic_pwm_dispatch_cases": pwm_dispatch_cases(image),
            "actual_pwm1_registry_driver_identity_proven": False,
            "PWM_output_zero_proves_motor_stopped": False,
            "firmware_release_approved": False,
        }
    cur = audit(cur_bin, "running_v322")
    stock = audit(stock_bin, "creality_stock_153") if stock_bin else None
    if stock:
        for key in ("timer_base_selector_cases", "generic_pwm_dispatch_cases"):
            if stock[key] != cur[key]:
                raise ValueError("stock/v3.22 original PWM execution differs: " + key)
        for key in ("pinned_Thumb_instructions", "pinned_timer_base_ROM_words"):
            if stock["static"][key] != cur["static"][key]:
                raise ValueError("stock/v3.22 original PWM instructions differ: " + key)

    output = {
        "scope": "offline, exact original ARM Thumb; hardware calls never executed",
        "stock_compared": stock is not None,
        "v322": cur, "original": stock,
        "physical_CFS_access": False,
        "device_name_pwm1_registry_object_resolved": False,
        "independent_motor_rotor_stopped_confirmed": False,
        "firmware_release_approved": False,
    }
    if opt.self_test:
        output["mutations"] = tamper(cur_bin)
    serialized = json.dumps(output, indent=2) + "\n"
    if opt.json_out:
        opt.json_out.write_text(serialized)
    print(serialized, end="")


if __name__ == "__main__":
    main()
