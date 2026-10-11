#!/usr/bin/env python3
"""OFFLINE original CFS extended-PWM control shim differential ARM audit.

Examines genuine stock 1.5.3 original code at 0x0802639C:
  * 0x1E04: store 1 at [request+0x14], return 0.
  * 0x1E05: store 0 at [request+0x14], return 0.
  * Other commands: delegate to [device+0x40][0] if non-NULL.
This function is a *candidate* extended command handler. It has NOT
been established as the registered "pwm1" object's callback; its
direct BL/ROM pointer inventory is empty, so runtime reachability
is unproven. Setting a request flag is not mechanical motor feedback.

All input images SHA-pinned. Unicorn callbacks are synthetic only.
No original hardware routines, ROM writes, UART, motors or flashing.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM
from flash_ram_phase2_audit import (
    APP_BASE, CRC_OFF, META_END, crc16_bypass, pinned, report_image,
)
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP
)

ENTRY = 0x0802639C
SHIM_REQUEST_1E04 = 0x1E04
SHIM_REQUEST_1E05 = 0x1E05
REQUEST_FALLBACKS = (0x1E00, 0x1E02, 0x1E03, 0x1E06)
FLASH_BEGIN = 0x08000000
FLASH_BYTES = 0x80000
RAM_BEGIN = 0x20000000
RAM_BYTES = 0x10000
DEVICE = 0x20001000
BACKEND_INTERFACE = 0x20001400
REQUEST = 0x20002000
STATUS_FIELD = REQUEST + 0x14
MOCK_CALLBACK = 0x08050000
RETURN_SENTINEL = 0x0803B700

PINS = {
    0x0802639C: ("push", "{r4, lr}"),
    0x0802639E: ("movs", "r3, #0"),
    0x080263A0: ("sub.w", "r4, r1, #0x1e00"),
    0x080263A4: ("subs", "r4, #4"),
    0x080263A6: ("beq", "#0x80263ba"),
    0x080263A8: ("cmp", "r4, #1"),
    0x080263AA: ("beq", "#0x80263be"),
    0x080263AC: ("ldr", "r4, [r0, #0x40]"),
    0x080263AE: ("ldr", "r4, [r4]"),
    0x080263B0: ("cbz", "r4, #0x80263b6"),
    0x080263B2: ("blx", "r4"),
    0x080263B4: ("mov", "r3, r0"),
    0x080263B6: ("mov", "r0, r3"),
    0x080263B8: ("pop", "{r4, pc}"),
    0x080263BA: ("movs", "r0, #1"),
    0x080263BC: ("b", "#0x80263c0"),
    0x080263BE: ("movs", "r0, #0"),
    0x080263C0: ("str", "r0, [r2, #0x14]"),
    0x080263C2: ("b", "#0x80263b6"),
    0x080264AA: ("movw", "r1, #0x1e05"),
    0x080264B8: ("movw", "r1, #0x1e04"),
    0x080264F2: ("movw", "r1, #0x1e05"),
    0x080264FE: ("movw", "r1, #0x1e04"),
}
CASE_IDS = (
    (0x1E04, False, 0),
    (0x1E04, True, 0x5A),
    (0x1E05, False, 0),
    (0x1E05, True, 0x5A),
    (0x1E00, False, 0),
    (0x1E00, True, 0x5A),
    (0x1E02, True, 0x5A),
    (0x1E03, True, 0),
    (0x1E06, True, 0x5A),
)


def verify_static(image: bytes, kind: str) -> dict:
    result = report_image(image, kind)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    pins = []
    for address, expected in PINS.items():
        off = address - APP_BASE
        ins = next(cs.disasm(image[off:off + 4], address, count=1), None)
        if ins is None or (ins.mnemonic, ins.op_str) != expected:
            raise ValueError(f"original extended PWM opcode changed @ {address:#x}")
        pins.append({"address": hex(address),
                     "text": ins.mnemonic + " " + ins.op_str,
                     "encoding": ins.bytes.hex()})
    result.update({
        "exact_Thumb_pins": pins,
        "candidate_extended_pwm_entry": hex(ENTRY),
        "runtime_pwm1_object_callback_proven": False,
        "physical_motor_enable_or_stop_proven": False,
    })
    return result


def emulate(image: bytes, code: int, installed: bool, fake_return: int):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(FLASH_BEGIN, FLASH_BYTES)
    u.mem_map(RAM_BEGIN, RAM_BYTES)
    u.mem_write(APP_BASE, image)
    u.mem_write(DEVICE + 0x40, struct.pack("<I", BACKEND_INTERFACE))
    u.mem_write(BACKEND_INTERFACE, struct.pack(
        "<I", MOCK_CALLBACK | 1 if installed else 0))
    u.mem_write(STATUS_FIELD, struct.pack("<I", 0xA5A5A5A5))
    u.reg_write(UC_ARM_REG_SP, 0x2000E000)
    u.reg_write(UC_ARM_REG_LR, RETURN_SENTINEL | 1)
    u.reg_write(UC_ARM_REG_R0, DEVICE)
    u.reg_write(UC_ARM_REG_R1, code)
    u.reg_write(UC_ARM_REG_R2, REQUEST)
    calls = []
    returns = []
    writes = []

    def on_code(uc, pc, size, _):
        if pc == MOCK_CALLBACK:
            args = [uc.reg_read(r) for r in (
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
            calls.append([hex(a) for a in args])
            uc.reg_write(UC_ARM_REG_R0, fake_return)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif pc == RETURN_SENTINEL:
            returns.append(uc.reg_read(UC_ARM_REG_R0))
            uc.emu_stop()

    def on_write(uc, access, address, size, value, _):
        # Ignore AAPCS stack saves/pops. Track persistent request/device
        # data writes only; stack is mapped at 0x2000E000.
        if address < 0x2000C000:
            writes.append((address, size, value))

    u.hook_add(UC_HOOK_CODE, on_code)
    u.hook_add(UC_HOOK_MEM_WRITE, on_write)
    u.emu_start(ENTRY | 1, 0, count=70)
    if len(returns) != 1:
        raise ValueError("extended PWM shim never returned")
    status = struct.unpack("<I", u.mem_read(STATUS_FIELD, 4))[0]
    special = code in (SHIM_REQUEST_1E04, SHIM_REQUEST_1E05)
    want_status = (
        1 if code == SHIM_REQUEST_1E04 else
        0 if code == SHIM_REQUEST_1E05 else 0xA5A5A5A5
    )
    if status != want_status:
        raise ValueError("original request flag store not observed")
    if special:
        if calls or writes != [(STATUS_FIELD, 4, want_status)]:
            raise ValueError("extended command unexpectedly called hardware")
        want_result = 0
    else:
        want_calls = 1 if installed else 0
        if len(calls) != want_calls or writes:
            raise ValueError("delegated command did not follow callback path")
        if installed and calls != [[hex(DEVICE), hex(code), hex(REQUEST)]]:
            raise ValueError("fallback callback ABI differs")
        want_result = fake_return if installed else 0
    if returns != [want_result]:
        raise ValueError("original extended command returned unexpected status")
    return {
        "request": hex(code),
        "synthetic_backend_installed": installed,
        "synthetic_backend_return": hex(fake_return),
        "status_word_after": hex(status),
        "status_word_updated": special,
        "backend_callback_invocations": len(calls),
        "returned": hex(want_result),
        "original_writes": [
            {"address": hex(a), "size": size, "value": hex(val)}
            for a, size, val in writes],
        "real_motor_rotation_or_idle_proven": False,
    }


def original_static_reference_inventory(image: bytes) -> dict:
    # Exhaustively check halfword-aligned direct BL targets, plus any
    # unaligned literal address words. This is NOT a full recursive
    # control-flow proof: indirect BLX, synthesized addresses, bootloader
    # and firmware loader registrations are outside this analysis.
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    calls = []
    for offset in range(0, len(image) - 4, 2):
        ins = next(decoder.disasm(image[offset:offset + 4],
                                  APP_BASE + offset, count=1), None)
        if ins is not None and ins.mnemonic == "bl" and len(ins.operands) == 1:
            op = ins.operands[0]
            if op.type == ARM_OP_IMM and op.imm == ENTRY:
                calls.append(hex(APP_BASE + offset))
    words = {}
    for t in (ENTRY, ENTRY | 1):
        encoded = struct.pack("<I", t)
        positions = []
        start = 0
        while True:
            idx = image.find(encoded, start)
            if idx == -1:
                break
            positions.append(hex(APP_BASE + idx))
            start = idx + 1
        words[hex(t)] = positions
    return {
        "direct_Thumb_BL_sites_in_saved_APP": calls,
        "raw_address_word_sites_in_saved_APP": words,
        "function_runtime_unreachable_proven": False,
        "actual_pwm1_device_callback_binding_proven": False,
    }


def tamper(image: bytes):
    locations = {
        "extended_request_decode": 0x080263A0,
        "request_1E04_select": 0x080263A6,
        "request_1E05_select": 0x080263AA,
        "backend_vtable_root": 0x080263AC,
        "backend_call": 0x080263B2,
        "backend_return_value": 0x080263B4,
        "special_bool_true": 0x080263BA,
        "special_bool_false": 0x080263BE,
        "special_payload_write": 0x080263C0,
        "caller_request_1E04": 0x080264B8,
        "caller_request_1E05": 0x080264AA,
    }
    rejected = []
    for name, addr in locations.items():
        altered = bytearray(image)
        altered[addr - APP_BASE] ^= 1
        unsigned = bytearray(altered)
        unsigned[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
        struct.pack_into("<H", altered, CRC_OFF, crc16_bypass(unsigned))
        if not report_image(bytes(altered), "running_v322")["header_crc_valid"]:
            raise AssertionError("mutation must maintain valid CFS APP CRC")
        try:
            verify_static(bytes(altered), "running_v322")
        except ValueError:
            rejected.append(name)
        else:
            raise AssertionError("unsafe extended PWM opcode accepted: " + name)
    return {"CRC_corrected_mutations_rejected": rejected, "count": len(rejected)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v322", type=Path, required=True)
    p.add_argument("--stock", type=Path)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--json-out", type=Path)
    args = p.parse_args()
    running = pinned(args.v322, "running_v322")
    stock = pinned(args.stock, "creality_stock_153") if args.stock else None
    def run(image, kind):
        return {
            "static": verify_static(image, kind),
            "cases": [emulate(image, *item) for item in CASE_IDS],
            "static_reference_inventory": original_static_reference_inventory(image),
            "runtime_pwm1_uses_this_callback": False,
            "safe_to_install_MCU_trampoline": False,
        }
    cur = run(running, "running_v322")
    original = run(stock, "creality_stock_153") if stock else None
    if original:
        if cur["static"]["exact_Thumb_pins"] != original["static"]["exact_Thumb_pins"]:
            raise ValueError("stock/v3.22 Thumb bytes not identical")
        if cur["cases"] != original["cases"]:
            raise ValueError("stock/v3.22 original extended PWM semantics differ")
        if cur["static_reference_inventory"] != original["static_reference_inventory"]:
            raise ValueError("stock/v3.22 extended PWM static reference differs")
    outcome = {
        "scope": "strictly offline, exact Thumb synthetic callback tests",
        "stock_compared": stock is not None,
        "v322": cur, "stock": original,
        "physical_hardware_accessed": False,
        "motor_idle_proven": False,
        "runtime_pwm1_callback_identity_proven": False,
        "firmware_release_authorized": False,
    }
    if args.self_test:
        outcome["fail_closed"] = tamper(running)
    serialized = json.dumps(outcome, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(serialized)
    print(serialized, end="")


if __name__ == "__main__":
    main()
