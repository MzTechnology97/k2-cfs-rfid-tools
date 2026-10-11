#!/usr/bin/env python3
"""Offline stock CFS motor "pwm1" device lookup and RAM pointer assignment.

Actual original ARM Thumb code is executed for pointer clearing, "pwm1"
lookup, and storing the returned device pointer in 0x20004A14.
ONLY the underlying device-registry search is replaced by a synthetic
callback. This does NOT identify the actual object registered as "pwm1",
any physical motor driver, or any reliable motor idle/feedback signal.

No MCU, UART, serial transport, real motor or flash write. No firmware
image generated. Original stock 1.5.3 and exact validated v3.22 supported.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from flash_ram_phase2_audit import (
    APP_BASE, CRC_OFF, META_END, crc16_bypass, pinned, report_image,
)
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R4, UC_ARM_REG_SP,
)

FLASH_BASE = 0x08000000
FLASH_BYTES = 0x80000
RAM_BASE = 0x20000000
RAM_BYTES = 0x10000
ROOT = 0x20004960
DEVICE_PTR_FIELD = ROOT + 0xB4    # = 0x20004A14
LOOKUP_NAME_AT = 0x0801E28C
LOOKUP_NAME = b"pwm1\x00"
LOOKUP_WRAPPER = 0x08023774
LOOKUP_REGISTRY = 0x0802E1B4
LOOKUP_TYPE = 9
LOOKUP_BEGIN = 0x0801E080
LOOKUP_POST_STORE = 0x0801E088
INIT_CLEAR_START = 0x0801DFE8
INIT_CLEAR_END = 0x0801DFF0
FIVE_OTHER_OBJECTS = (
    0x2000075C, 0x200007BC, 0x2000081C,
    0x2000087C, 0x200008DC,
)
# Test both a candidate belonging to the five-object array and a
# wholly unrelated object, as well as lookup-not-found. Passing all
# demonstrates that identity is unknown, not that one belongs to a motor.
FAKE_LOOKUP_RESULTS = (FIVE_OTHER_OBJECTS[0], 0x20003000, 0)
PINS = {
    0x0801DFE8: ("ldr", "r4, [pc, #0x258]"),
    0x0801DFEA: ("movs", "r0, #0"),
    0x0801DFEC: ("adds", "r4, #0xb4"),
    0x0801DFEE: ("str", "r0, [r4]"),
    0x0801E080: ("adr", "r0, #0x208"),
    0x0801E082: ("bl", "#0x8023774"),
    0x0801E086: ("str", "r0, [r4]"),
    0x0801E088: ("cbz", "r0, #0x801e0a2"),
    0x08023774: ("movs", "r1, #9"),
    0x08023776: ("b.w", "#0x802e1b4"),
}
LITERAL_AT = 0x0801E244


def dword(image: bytes, at: int) -> int:
    off = at - APP_BASE
    if not 0 <= off <= len(image) - 4:
        raise ValueError(f"invalid ROM word {at:#x}")
    return struct.unpack_from("<I", image, off)[0]


def audit_static(image: bytes, kind: str):
    record = report_image(image, kind)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    instructions = []
    for at, (mnemonic, operands) in PINS.items():
        off = at - APP_BASE
        ins = next(cs.disasm(image[off:off + 4], at, count=1), None)
        if ins is None or (ins.mnemonic, ins.op_str) != (mnemonic, operands):
            raise ValueError(f"original motor lookup Thumb changed at {at:#x}")
        instructions.append({
            "address": hex(at), "encoding": ins.bytes.hex(),
            "instruction": f"{ins.mnemonic} {ins.op_str}",
        })
    if dword(image, LITERAL_AT) != ROOT:
        raise ValueError("motor root literal modified")
    if image[LOOKUP_NAME_AT - APP_BASE:
             LOOKUP_NAME_AT - APP_BASE + len(LOOKUP_NAME)] != LOOKUP_NAME:
        raise ValueError("pwm1 device lookup string modified")
    record.update({
        "instructions": instructions,
        "motor_root_literal": {"at": hex(LITERAL_AT), "value": hex(ROOT)},
        "name_literal": {"at": hex(LOOKUP_NAME_AT), "value": "pwm1"},
        "lookup_device_type": LOOKUP_TYPE,
    })
    return record


def _new_uc(image):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(FLASH_BASE, FLASH_BYTES)
    u.mem_map(RAM_BASE, RAM_BYTES)
    u.mem_write(APP_BASE, image)
    u.mem_write(DEVICE_PTR_FIELD, struct.pack("<I", 0xDEADBEEF))
    u.reg_write(UC_ARM_REG_SP, 0x2000E000)
    return u


def model_original_pointer_clear(image):
    u = _new_uc(image)
    visited = []
    writes = []
    def _code(uc, at, size, _):
        if at == INIT_CLEAR_END:
            visited.append(at)
            uc.emu_stop()
    def _write(uc, access, at, size, value, _):
        if at == DEVICE_PTR_FIELD:
            writes.append((size, value))
    u.hook_add(UC_HOOK_CODE, _code)
    u.hook_add(UC_HOOK_MEM_WRITE, _write)
    u.emu_start(INIT_CLEAR_START | 1, 0, count=20)
    if visited != [INIT_CLEAR_END] or writes != [(4, 0)]:
        raise ValueError("original motor device pointer clear changed")
    actual = struct.unpack("<I", u.mem_read(DEVICE_PTR_FIELD, 4))[0]
    if actual != 0 or u.reg_read(UC_ARM_REG_R4) != DEVICE_PTR_FIELD:
        raise ValueError("motor RAM pointer clear did not reach root + 0xB4")
    return {"entry": hex(INIT_CLEAR_START),
            "cleared_RAM_field": hex(DEVICE_PTR_FIELD),
            "original_store_observed": True}


def model_named_lookup(image, result):
    u = _new_uc(image)
    u.reg_write(UC_ARM_REG_R4, DEVICE_PTR_FIELD)
    observations = []
    writes = []
    reached = []
    def _code(uc, at, size, _):
        if at == LOOKUP_REGISTRY:
            name_addr = uc.reg_read(UC_ARM_REG_R0)
            name = bytes(uc.mem_read(name_addr, len(LOOKUP_NAME)))
            type_id = uc.reg_read(UC_ARM_REG_R1)
            if (name_addr, name, type_id) != (
                    LOOKUP_NAME_AT, LOOKUP_NAME, LOOKUP_TYPE):
                raise ValueError("motor lookup name/type changed")
            observations.append({
                "original_ROM_name_pointer": hex(name_addr),
                "literal": name[:-1].decode("ascii"),
                "lookup_type": type_id,
            })
            # Simulate the registry's answer ONLY. The ADR, BL, wrapper
            # MOV, tail branch and STR are original Thumb instructions.
            uc.reg_write(UC_ARM_REG_R0, result)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif at == LOOKUP_POST_STORE:
            reached.append(at)
            uc.emu_stop()
    def _write(uc, access, at, size, value, _):
        if at == DEVICE_PTR_FIELD:
            writes.append((size, value))
    u.hook_add(UC_HOOK_CODE, _code)
    u.hook_add(UC_HOOK_MEM_WRITE, _write)
    u.emu_start(LOOKUP_BEGIN | 1, 0, count=30)
    if len(observations) != 1 or reached != [LOOKUP_POST_STORE]:
        raise ValueError("original lookup sequence did not return")
    if writes != [(4, result)]:
        raise ValueError("original device pointer store changed")
    got = struct.unpack("<I", u.mem_read(DEVICE_PTR_FIELD, 4))[0]
    if got != result:
        raise ValueError("RAM device pointer does not equal lookup return")
    return {
        "lookup": observations[0],
        "synthetic_registry_result": hex(result),
        "stored_at": hex(DEVICE_PTR_FIELD),
        "stored_value": hex(got),
        "matches_one_of_five_separately_constructed_objects":
            got in FIVE_OTHER_OBJECTS,
        "actual_runtime_registry_identity_proven": False,
        "motor_feedback_or_actual_idle_proven": False,
    }


def tamper_tests(image):
    positions = {
        "root_pointer_literal": LITERAL_AT,
        "clear_pointer_store": 0x0801DFEE,
        "name_address_generation": 0x0801E080,
        "generic_lookup_call": 0x0801E082,
        "store_device_lookup_result": 0x0801E086,
        "lookup_type_code": 0x08023774,
        "lookup_wrapper_branch": 0x08023776,
        "original_name": LOOKUP_NAME_AT,
    }
    rejected = []
    for label, at in positions.items():
        altered = bytearray(image)
        altered[at - APP_BASE] ^= 1
        unsigned = bytearray(altered)
        unsigned[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
        struct.pack_into("<H", altered, CRC_OFF, crc16_bypass(unsigned))
        if not report_image(bytes(altered), "running_v322")["header_crc_valid"]:
            raise AssertionError("CRC-corrected mutant should be valid")
        try:
            audit_static(bytes(altered), "running_v322")
        except ValueError:
            rejected.append(label)
        else:
            raise AssertionError("mutated device lookup silently accepted: " + label)
    return {"CRC_corrected_cases_rejected": rejected, "count": len(rejected)}


def audit(image, kind):
    return {
        "static": audit_static(image, kind),
        "clearing": model_original_pointer_clear(image),
        "named_lookup_cases": [
            model_named_lookup(image, result) for result in FAKE_LOOKUP_RESULTS
        ],
        "real_named_device_identity_observed": False,
        "real_motor_completion_feedback_observed": False,
        "firmware_flash_safe": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v322", required=True, type=Path)
    p.add_argument("--stock", type=Path)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--json-out", type=Path)
    x = p.parse_args()
    v = pinned(x.v322, "running_v322")
    stock = pinned(x.stock, "creality_stock_153") if x.stock else None
    current = audit(v, "running_v322")
    original = audit(stock, "creality_stock_153") if stock else None
    if original:
        if original["static"]["instructions"] != current["static"]["instructions"]:
            raise ValueError("stock/v3.22 motor lookup instructions differ")
        for k in ("clearing", "named_lookup_cases"):
            if original[k] != current[k]:
                raise ValueError("stock/v3.22 actual motor lookup Thumb behavior differs")
    result = {
        "scope": "offline original ARM motor pwm1 lookup and RAM assignment",
        "stock_compared": stock is not None,
        "v322": current,
        "stock": original,
        "real_device_registry_accessed": False,
        "real_CFS_motor_instance_identity_proven": False,
        "all_CFS_motors_idle_proven": False,
        "firmware_release_authorized": False,
    }
    if x.self_test:
        result["mutations"] = tamper_tests(v)
    body = json.dumps(result, indent=2) + "\n"
    if x.json_out:
        x.json_out.write_text(body)
    print(body, end="")


if __name__ == "__main__":
    main()
