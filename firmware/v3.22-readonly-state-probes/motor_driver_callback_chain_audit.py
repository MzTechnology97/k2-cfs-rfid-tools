#!/usr/bin/env python3
"""OFFLINE CFS ARM callback dispatch audit (original 1.5.3 vs v3.22).

Proof scope:
  - The generic device-request path at 0x08023A92 calls the callback
    stored at object offset 0x38 (no callback = error return).
  - A separate output-signal path at 0x08025EEC routes to the second
    callback pointer stored behind RAM global 0x20004C44 + 0x40.
  - Original high-level motor code uses both of these abstractions.

No real peripheral or MCU is accessed. A synthetic callback at 0x08050000
returns an arbitrary chosen status and NEVER attempts hardware work.
Mock success is *not* motor completion or a safety signal.

No app binaries, firmware patching, bootloader calls or device I/O.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import APP_BASE, CRC_OFF, META_END, crc16_bypass, pinned, report_image

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP
)

FLASH_BASE = 0x08000000
FLASH_MAP_LENGTH = 0x80000
RAM_BASE = 0x20000000
RAM_MAP_LENGTH = 0x10000

DEVICE_DISPATCH = 0x08023A92
DEVICE_CALLBACK_OFFSET = 0x38
DEVICE_OBJECT = 0x20001000
DEVICE_BUFFER = 0x20002000
DEVICE_TYPE_BYTE = 9
DEVICE_NO_CALLBACK_ERROR = 0xFFFFFFD3

GLOBAL_GPIO_DISPATCH = 0x08025EEC
GLOBAL_GPIO_ROOT = 0x20004C44
GLOBAL_GPIO_CALLBACK_TABLE = 0x20001200

MOCK_CALLBACK = 0x08050000
RETURN_SENTINEL = 0x0803B700

# Pin Thumb addresses and code at exact original ROM locations, including
# both core interfaces, motor-request wrappers and root pointer literals.
PINS = {
    0x08023A92: ("push", "{r4, r5, r6, lr}"),
    0x08023AAC: ("bl", "#0x802e198"),
    0x08023AB0: ("cmp", "r0, #9"),
    0x08023AC2: ("ldr", "r3, [r4, #0x38]"),
    0x08023AC4: ("cbz", "r3, #0x8023ad2"),
    0x08023ACC: ("pop.w", "{r4, r5, r6, lr}"),
    0x08023AD0: ("bx", "r3"),
    0x08023AD2: ("mvn", "r0, #0x2c"),
    0x08026516: ("push", "{r4, r5, r6, r7, lr}"),
    0x08026538: ("movw", "r1, #0x1e02"),
    0x08026540: ("bl", "#0x8023a92"),
    0x08026488: ("push", "{r4, r5, lr}"),
    0x080264AA: ("movw", "r1, #0x1e05"),
    0x080264B8: ("movw", "r1, #0x1e04"),
    0x080264BE: ("bl", "#0x8023a92"),
    0x080264C4: ("mov.w", "r1, #0x1e00"),
    0x080264CA: ("bl", "#0x8023a92"),
    0x08025EEC: ("push", "{r4, r5, r6, lr}"),
    0x08025EEE: ("ldr", "r4, [pc, #0x27c]"),
    0x08025EF4: ("ldr", "r0, [r4, #0x40]"),
    0x08025F04: ("ldr", "r0, [r4, #0x40]"),
    0x08025F0A: ("ldr", "r3, [r0, #4]"),
    0x08025F0C: ("pop.w", "{r4, r5, r6, lr}"),
    0x08025F10: ("ldr", "r0, [pc, #0x258]"),
    0x08025F12: ("bx", "r3"),
    0x08025E1A: ("str", "r4, [r1, #0x40]"),
    0x08025E16: ("str", "r3, [r1, #0x34]"),
}
# Some instructions act on distinct abstract device objects. These address
# words do NOT prove a live callback vtable or identify its hardware owner.
LITERAL_WORDS = {
    0x0802616C: GLOBAL_GPIO_ROOT,
}

HARDWARE_REQUEST_IDS = (0x1E00, 0x1E02, 0x1E04, 0x1E05)


def decode_one(image: bytes, address: int):
    offset = address - APP_BASE
    if offset < 0 or offset + 4 > len(image):
        raise ValueError("Thumb address outside pinned image: " + hex(address))
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    ins = next(cs.disasm(image[offset:offset + 4], address, count=1), None)
    if ins is None:
        raise ValueError("Thumb decode failed: " + hex(address))
    return ins


def verify_static(image: bytes, kind: str) -> dict:
    src = report_image(image, kind)
    statements = []
    for at, expected in PINS.items():
        ins = decode_one(image, at)
        if (ins.mnemonic, ins.op_str) != expected:
            raise ValueError(
                "changed MCU callback chain @ %s: %s %s" %
                (hex(at), ins.mnemonic, ins.op_str))
        statements.append({
            "at": hex(at), "mnemonic": ins.mnemonic,
            "operand": ins.op_str, "original_encoding": ins.bytes.hex()
        })
    for at, want in LITERAL_WORDS.items():
        if struct.unpack_from("<I", image, at - APP_BASE)[0] != want:
            raise ValueError("changed global GPIO callback root pointer")
    src.update({
        "verified_Thumb_instructions": statements,
        "original_GPIO_callback_root_literal": hex(GLOBAL_GPIO_ROOT),
        "device_generic_callback_offset": hex(DEVICE_CALLBACK_OFFSET),
        "device_pretends_motor_is_idle": False,
        "device_dispatch_is_indirect": True,
        "gpio_dispatch_is_indirect": True,
    })
    return src


def model_dispatch(image: bytes, kind: str, which: str, mock_return: int,
                   callback_installed: bool = True) -> dict:
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(FLASH_BASE, FLASH_MAP_LENGTH)
    u.mem_map(RAM_BASE, RAM_MAP_LENGTH)
    u.mem_write(APP_BASE, image)
    u.reg_write(UC_ARM_REG_SP, 0x2000E000)
    u.reg_write(UC_ARM_REG_LR, RETURN_SENTINEL | 1)

    if which == "device":
        entry = DEVICE_DISPATCH
        u.mem_write(DEVICE_OBJECT + 8, bytes([DEVICE_TYPE_BYTE]))
        cb = MOCK_CALLBACK | 1 if callback_installed else 0
        u.mem_write(DEVICE_OBJECT + DEVICE_CALLBACK_OFFSET,
                    struct.pack("<I", cb))
        u.reg_write(UC_ARM_REG_R0, DEVICE_OBJECT)
        u.reg_write(UC_ARM_REG_R1, 0x1E02)
        u.reg_write(UC_ARM_REG_R2, DEVICE_BUFFER)
        callback_args = (DEVICE_OBJECT, 0x1E02, DEVICE_BUFFER)
    elif which == "gpio":
        if not callback_installed:
            raise ValueError("global GPIO missing callback not supported")
        entry = GLOBAL_GPIO_DISPATCH
        u.mem_write(GLOBAL_GPIO_ROOT + 0x40,
                    struct.pack("<I", GLOBAL_GPIO_CALLBACK_TABLE))
        u.mem_write(GLOBAL_GPIO_CALLBACK_TABLE + 4,
                    struct.pack("<I", MOCK_CALLBACK | 1))
        u.reg_write(UC_ARM_REG_R0, 0x44)
        u.reg_write(UC_ARM_REG_R1, 1)
        u.reg_write(UC_ARM_REG_R2, 0x1234)
        callback_args = (GLOBAL_GPIO_ROOT, 0x44, 1)
    else:
        raise ValueError("unknown callback model")

    state = {"seen_callback": [], "seen_return": [], "reads": []}

    def _code(uc, pc, size, user):
        if pc == MOCK_CALLBACK:
            args = tuple(uc.reg_read(r) for r in (
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
            state["seen_callback"].append(args)
            uc.reg_write(UC_ARM_REG_R0, mock_return)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif pc == RETURN_SENTINEL:
            state["seen_return"].append(uc.reg_read(UC_ARM_REG_R0))
            uc.emu_stop()

    def _read(uc, access, at, size, value, user):
        state["reads"].append((at, size))

    u.hook_add(UC_HOOK_CODE, _code)
    u.hook_add(UC_HOOK_MEM_READ, _read)
    u.emu_start(entry | 1, 0, count=200)

    expected_ret = (
        DEVICE_NO_CALLBACK_ERROR if which == "device" and
        not callback_installed else mock_return
    )
    if state["seen_return"] != [expected_ret]:
        raise ValueError("unexpected callback return flow")
    if callback_installed:
        if state["seen_callback"] != [callback_args]:
            raise ValueError("callback arguments differ from expected ABI")
    elif state["seen_callback"]:
        raise ValueError("callback invoked despite empty vtable entry")

    if which == "device":
        expected_reads = (DEVICE_OBJECT + 8, DEVICE_OBJECT + DEVICE_CALLBACK_OFFSET)
    else:
        expected_reads = (
            0x0802616C, GLOBAL_GPIO_ROOT + 0x40,
            GLOBAL_GPIO_CALLBACK_TABLE + 4
        )
    reads = [at for at, size in state["reads"]]
    if not all(any(at == x for at in reads) for x in expected_reads):
        raise ValueError("dispatcher did not read expected table fields")

    return {
        "firmware": kind,
        "interface": which,
        "synthetic_callback_enabled": callback_installed,
        "synthetic_callback_returned": hex(mock_return),
        "actual_mock_callback_invocations": len(state["seen_callback"]),
        "callback_arguments": [
            [hex(x) for x in args] for args in state["seen_callback"]],
        "dispatcher_returned": hex(expected_ret),
        "memory_read_addresses": [hex(at) for at, size in state["reads"]],
        "motor_feedback_or_encoder_read_observed": False,
        "physical_motor_completion_not_proven": True,
    }


def mutation_tests(image: bytes) -> dict:
    markers = {
        "device_vtable_load": 0x08023AC2,
        "device_indirect_branch": 0x08023AD0,
        "GPIO_global_table_load": 0x08025EF4,
        "GPIO_indirect_branch": 0x08025F12,
        "motor_request_1E02": 0x08026538,
        "motor_request_1E05": 0x080264AA,
        "motor_request_1E04": 0x080264B8,
        "motor_request_1E00": 0x080264C4,
        "GPIO_root_literal": 0x0802616C,
    }
    failed_closed = []
    for name, at in markers.items():
        mutant = bytearray(image)
        # BX r3 encodes the low bit as an unused bit in Thumb. Flip bit
        # 2 instead: it changes BX to BXNS and must fail the exact pin.
        mask = 4 if name in (
            "device_indirect_branch", "GPIO_indirect_branch") else 1
        mutant[at - APP_BASE] ^= mask
        normalized = bytearray(mutant)
        normalized[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
        struct.pack_into("<H", mutant, CRC_OFF, crc16_bypass(normalized))
        check_header = report_image(bytes(mutant), "running_v322")
        if not check_header["header_crc_valid"]:
            raise AssertionError("bad mutant CRC invalidates fail-closed claim")
        try:
            verify_static(bytes(mutant), "running_v322")
        except ValueError:
            failed_closed.append(name)
        else:
            raise AssertionError("altered dispatcher accepted: " + name)
    return {"CRC_valid_mutations_rejected": failed_closed,
            "count": len(failed_closed)}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v322", type=Path, required=True)
    p.add_argument("--stock", type=Path)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--json-out", type=Path)
    opts = p.parse_args()
    current_image = pinned(opts.v322, "running_v322")
    stock_image = pinned(opts.stock, "creality_stock_153") if opts.stock else None

    def run(image, label):
        static = verify_static(image, label)
        trials = [
            model_dispatch(image, label, "device", 0),
            model_dispatch(image, label, "device", 0x5A),
            model_dispatch(image, label, "device", 0, False),
            model_dispatch(image, label, "gpio", 0),
            model_dispatch(image, label, "gpio", 0x5A),
        ]
        return {
            "static": static,
            "mock_callback_trials": trials,
            "independent_physical_motor_completion_observed": False,
            "validated_hardware_callback_implementation": False,
            "safe_to_flash": False,
        }

    v322 = run(current_image, "running_v322")
    stock = run(stock_image, "creality_stock_153") if stock_image else None
    if stock:
        a, b = v322["static"], stock["static"]
        if a["verified_Thumb_instructions"] != b["verified_Thumb_instructions"]:
            raise ValueError("original vs v3.22 callback path changed")
        for va, vb in zip(v322["mock_callback_trials"],
                          stock["mock_callback_trials"]):
            aa, bb = dict(va), dict(vb)
            aa.pop("firmware")
            bb.pop("firmware")
            if aa != bb:
                raise ValueError("original vs v3.22 callback model differs")
    result = {
        "scope": "strictly offline, synthetic callbacks; no real motor status",
        "original_stock_compared": stock is not None,
        "v322": v322, "original_stock": stock,
        "hardware_or_serial_interface_opened": False,
        "app_binary_modified": False,
        "MCU_motor_idle_confirmed": False,
        "release_approved": False,
    }
    if opts.self_test:
        result["fail_closed_tests"] = mutation_tests(current_image)
    text = json.dumps(result, indent=2) + "\n"
    if opts.json_out:
        opts.json_out.write_text(text)
    print(text, end="")


if __name__ == "__main__":
    main()
