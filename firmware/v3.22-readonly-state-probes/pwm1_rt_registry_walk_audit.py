#!/usr/bin/env python3
"""Offline original CFS RT-Thread name registry walk, type=9 PWM devices.

Executes saved, SHA-pinned original ARM Thumb:
  startup pwm1 ADR -> RT type-9 lookup wrapper ->
  RT-Thread registry linked-list walk and 8-byte name compare ->
  original store of the found device pointer at 0x20004A14.

The registry LIST and RTOS primitives are entirely SYNTHETIC. Actual
lookup, list iteration, branch, and resulting store use manufacturer ROM.
Neither the actual name registration nor its callback is discovered.
No CM5/CFS operation, UART, flash, RAM/MCU read/write or motor movement.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from flash_ram_phase2_audit import APP_BASE, CRC_OFF, META_END, crc16_bypass, pinned, report_image
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R4,
    UC_ARM_REG_SP,
)

FLASH_BASE = 0x08000000
FLASH_SIZE = 0x80000
RAM_BASE = 0x20000000
RAM_SIZE = 0x10000

APP_LOOKUP = 0x0801E080
APP_STORE = 0x0801E086
APP_AFTER_STORE = 0x0801E088
LOOKUP_NAME = 0x0801E28C
TYPE9_WRAPPER = 0x08023774
REGISTRY_LOOKUP = 0x0802E1B4
MOTOR_PTR = 0x20004A14
REG_CLASS = 0x20001100
HEAD = REG_CLASS + 4

OBJ_ONE = 0x20002000
OBJ_TWO = 0x20002100
OBJ_THREE = 0x20002200
LIST_OFFSET = 0xC

# Stub ONLY RTOS management/locking and string-comparison primitives.
RT_TYPE_CLASS = 0x0802DF42
RT_IRQ_SAVE = 0x080230DC
RT_IN_INTERRUPT = 0x0802CBFC
RT_IRQ_RESTORE = 0x080230E4
RT_LIST_LOCK = 0x0802E526
RT_LIST_UNLOCK = 0x0802E53C
RT_STRNCMP = 0x0802D360
RT_RETURN_HELPER = 0x0802DFA0

PINS = {
    0x0801E080: ("adr", "r0, #0x208"),
    0x0801E082: ("bl", "#0x8023774"),
    0x0801E086: ("str", "r0, [r4]"),
    0x08023774: ("movs", "r1, #9"),
    0x08023776: ("b.w", "#0x802e1b4"),
    0x0802E1B4: ("push.w", "{r4, r5, r6, r7, r8, lr}"),
    0x0802E1B8: ("mov", "r6, r0"),
    0x0802E1BA: ("mov", "r0, r1"),
    0x0802E1BC: ("bl", "#0x802df42"),
    0x0802E1C2: ("cbz", "r6, #0x802e1fa"),
    0x0802E1C4: ("cbz", "r5, #0x802e1fa"),
    0x0802E1EA: ("mov", "r0, r4"),
    0x0802E1F4: ("ldr", "r4, [r5, #4]!"),
    0x0802E200: ("sub.w", "r0, r4, #0xc"),
    0x0802E204: ("mov", "r7, r0"),
    0x0802E206: ("movs", "r2, #8"),
    0x0802E208: ("mov", "r1, r6"),
    0x0802E20A: ("bl", "#0x802d360"),
    0x0802E20E: ("cbz", "r0, #0x802e21c"),
    0x0802E210: ("ldr", "r4, [r4]"),
    0x0802E212: ("cmp", "r4, r5"),
    0x0802E214: ("bne", "#0x802e200"),
    0x0802E220: ("mov", "r0, r7"),
    0x0802E222: ("b", "#0x802dfa0"),
}
LITERAL_ROM_PW1 = b"pwm1\x00"
EXPECTED_UPPER_BOUND = 300

CASES = (
    # Names in synthetic registry; lookup always comes from actual ROM "pwm1".
    ("first_name_match", ("pwm1", "pwm3"), OBJ_ONE),
    ("second_name_match", ("pwm3", "pwm1"), OBJ_TWO),
    ("third_name_match", ("pwm3", "pwm4", "pwm1"), OBJ_THREE),
    ("no_match", ("pwm3", "pwm4"), 0),
    ("empty_registry", (), 0),
    ("name_prefix_not_match", ("pwm12", "pwm1"), OBJ_TWO),
    ("case_sensitive", ("PWM1", "pwm1"), OBJ_TWO),
)


def static_pins(image: bytes, kind: str) -> dict:
    report = report_image(image, kind)
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    instructions = []
    for addr, want in PINS.items():
        offset = addr - APP_BASE
        ins = next(decoder.disasm(image[offset:offset+4], addr, count=1), None)
        if ins is None or (ins.mnemonic, ins.op_str) != want:
            raise ValueError(f"original named PWM registry opcode changed @ {addr:#x}")
        instructions.append({
            "address": hex(addr),
            "code": ins.bytes.hex(),
            "assembly": ins.mnemonic + " " + ins.op_str,
        })
    start = LOOKUP_NAME - APP_BASE
    if image[start:start+len(LITERAL_ROM_PW1)] != LITERAL_ROM_PW1:
        raise ValueError("stock original pwm1 name changed")
    report.update({
        "pinned_registry_thumb_instructions": instructions,
        "original_name": "pwm1",
        "original_lookup_type": 9,
        "synthetic_registry_not_real_devices": True,
    })
    return report


def emulate_case(image: bytes, label: str, names: tuple[str,...],
                 expected_object: int) -> dict:
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(FLASH_BASE, FLASH_SIZE)
    u.mem_map(RAM_BASE, RAM_SIZE)
    u.mem_write(APP_BASE, image)
    u.mem_write(MOTOR_PTR, struct.pack("<I", 0xDEADBEEF))
    u.reg_write(UC_ARM_REG_SP, 0x2000E000)
    u.reg_write(UC_ARM_REG_R4, MOTOR_PTR)
    u.reg_write(UC_ARM_REG_PC, APP_LOOKUP | 1)

    fake_addresses = (OBJ_ONE, OBJ_TWO, OBJ_THREE)
    head_link = fake_addresses[0] + LIST_OFFSET if names else HEAD
    u.mem_write(HEAD, struct.pack("<I", head_link))
    for idx, name in enumerate(names):
        if len(name.encode("ascii")) > 7:
            raise ValueError("test names must fit in RT_NAME_MAX=8")
        address = fake_addresses[idx]
        u.mem_write(address, name.encode("ascii").ljust(8,b"\x00"))
        next_entry = (fake_addresses[idx+1] + LIST_OFFSET
                      if idx+1 < len(names) else HEAD)
        u.mem_write(address+LIST_OFFSET, struct.pack("<I", next_entry))

    trace = {
        "types": [], "strcmp": [], "device_store": [],
        "registry_exit": [], "irq_saves": 0, "lock_calls": 0,
        "callback_invocations": 0, "external_MMIO_reads": 0,
    }

    def return_stub(uc, val=None):
        if val is not None:
            uc.reg_write(UC_ARM_REG_R0, val & 0xFFFFFFFF)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def code(uc, address, size, _):
        if address == RT_TYPE_CLASS:
            typ = uc.reg_read(UC_ARM_REG_R0)
            trace["types"].append(typ)
            return_stub(uc, REG_CLASS if typ == 9 else 0)
        elif address == RT_IRQ_SAVE:
            trace["irq_saves"] += 1
            return_stub(uc, 0)
        elif address == RT_IN_INTERRUPT:
            return_stub(uc, 0)
        elif address in (RT_IRQ_RESTORE, RT_LIST_UNLOCK):
            return_stub(uc)
        elif address == RT_LIST_LOCK:
            trace["lock_calls"] += 1
            return_stub(uc)
        elif address == RT_STRNCMP:
            n = uc.reg_read(UC_ARM_REG_R2)
            a = uc.reg_read(UC_ARM_REG_R0)
            b = uc.reg_read(UC_ARM_REG_R1)
            if n != 8:
                raise ValueError("RT-Thread original name compare length changed")
            left = bytes(uc.mem_read(a, n))
            right = bytes(uc.mem_read(b, n))
            # RT strncmp semantics: bytewise until mismatch or NUL.
            result = 0
            for xa, xb in zip(left, right):
                if xa != xb:
                    result = 1 if xa > xb else -1
                    break
                if xa == 0:
                    break
            trace["strcmp"].append({
                "registry": left.split(b"\x00")[0].decode("ascii"),
                "requested": right.split(b"\x00")[0].decode("ascii"),
                "max_bytes": n, "match": result == 0,
            })
            return_stub(uc, result)
        elif address == APP_AFTER_STORE:
            # Do not stub the shared 0x0802DFA0 return epilogue:
            # execute the original Thumb pop/return machinery so
            # APP_STORE is reached only through genuine saved LR.

            uc.emu_stop()

    def mem_write(uc, access, addr, size, value, _):
        if addr == MOTOR_PTR:
            trace["device_store"].append({
                "address": hex(addr), "value": hex(value), "size": size,
            })

    u.hook_add(UC_HOOK_CODE, code)
    u.hook_add(UC_HOOK_MEM_WRITE, mem_write)
    u.emu_start(APP_LOOKUP | 1, 0, count=EXPECTED_UPPER_BOUND)
    actual = struct.unpack("<I", u.mem_read(MOTOR_PTR, 4))[0]
    if actual != expected_object:
        raise ValueError(
            f"named pwm1 registry traversal wrong {label}: "
            f"{actual:#x} vs {expected_object:#x}")
    if trace["types"] != [9] or trace["irq_saves"] != 1:
        raise ValueError("original typed registry name lookup not run")
    if len(trace["device_store"]) != 1 or trace["device_store"][0] != {
            "address": hex(MOTOR_PTR), "value": hex(expected_object), "size": 4}:
        raise ValueError("original motor pointer not stored by original ROM")
    expected_cmps = (names.index("pwm1")+1
                     if "pwm1" in names else len(names))
    if len(trace["strcmp"]) != expected_cmps:
        raise ValueError("unexpected RT registry list walk count")
    if trace["callback_invocations"] or trace["external_MMIO_reads"]:
        raise ValueError("test is no longer passive or synthetic")
    return {
        "scenario": label,
        "synthetic_device_names": list(names),
        "actual_original_ROM_name": "pwm1",
        "original_name_type": 9,
        "original_device_pointer_stored": hex(actual),
        "synthetic_list_comparisons": trace["strcmp"],
        "original_pointer_writes": trace["device_store"],
        "real_runtime_object_identity_proven": False,
        "real_callback_or_motor_hardware_executed": False,
    }


def mutate_and_reject(image: bytes):
    addresses = {
        "lookup_name_literal": LOOKUP_NAME,
        "typed_wrapper": 0x08023774,
        "rt_registry_entry": 0x0802E1B4,
        "lookup_name_argument_copy": 0x0802E1B8,
        "list_entry_offset_minus12": 0x0802E200,
        "compare_exact_eight_bytes": 0x0802E206,
        "registry_strncmp_call": 0x0802E20A,
        "link_next_pointer": 0x0802E210,
        "motor_pointer_store": APP_STORE,
    }
    rejected = []
    for label, at in addresses.items():
        mutant = bytearray(image)
        mutant[at-APP_BASE] ^= 1
        copy = bytearray(mutant)
        copy[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
        struct.pack_into("<H", mutant, CRC_OFF, crc16_bypass(copy))
        if not report_image(bytes(mutant), "running_v322")["header_crc_valid"]:
            raise AssertionError("invalid APP CRC mutant")
        try:
            static_pins(bytes(mutant), "running_v322")
        except ValueError:
            rejected.append(label)
        else:
            raise AssertionError("registry alteration went undetected: " + label)
    return {"crc_valid_mutants_rejected": rejected, "count": len(rejected)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v322", required=True, type=Path)
    parser.add_argument("--stock", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json-out", type=Path)
    opts = parser.parse_args()
    current = pinned(opts.v322, "running_v322")
    original = pinned(opts.stock, "creality_stock_153") if opts.stock else None

    def audit(image, source):
        return {
            "static": static_pins(image, source),
            "named_registry_walk_cases": [
                emulate_case(image, *scenario) for scenario in CASES
            ],
            "RTOS_registry_and_object_data_synthetic": True,
            "actual_pwm1_registration_callback_unknown": True,
            "MCU_motor_idle_derived": False,
            "flashable_firmware_generated": False,
        }
    v = audit(current, "running_v322")
    stock = audit(original, "creality_stock_153") if original else None
    if stock:
        if v["static"]["pinned_registry_thumb_instructions"] != (
                stock["static"]["pinned_registry_thumb_instructions"]):
            raise ValueError("stock-v322 registry ROM instruction changed")
        if v["named_registry_walk_cases"] != stock["named_registry_walk_cases"]:
            raise ValueError("stock-v322 registry execution changed")
    report = {
        "scope": "OFFLINE original RT-Thread list walker with mock RTOS and names",
        "stock_compared": stock is not None,
        "v322": v, "stock_original": stock,
        "real_device_registry_contents_not_observed": True,
        "physical_CFS_or_serial_accessed": False,
        "runtime_motor_object_identity_proven": False,
        "independent_motor_stop_feedback_proven": False,
        "firmware_release_authorized": False,
    }
    if opts.self_test:
        report["tamper_tests"] = mutate_and_reject(current)
    result = json.dumps(report, indent=2) + "\n"
    if opts.json_out:
        opts.json_out.write_text(result)
    print(result, end="")


if __name__ == "__main__":
    main()
