#!/usr/bin/env python3
"""Offline Creality CFS device-object callback initialization, ARM Thumb.

Compares SHA-pinned stock 1.5.3/v3.22. Uses an isolated Unicorn 64-KiB
SRAM and dummy RTOS registration/memset routines. This does NOT prove
the device objects are the motor control object's runtime instances.
No physical UART, GPIO, MCU, firmware writing, app BIN, motor motion.
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
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
)

FLASH_BASE = 0x08000000
FLASH_BYTES = 0x80000
RAM_BASE = 0x20000000
RAM_BYTES = 0x10000

CONSTRUCTOR = 0x0802644A
OBJECT_LOOP = 0x080283F0
LOOP_BL = 0x08028408
OBJECT_BASE = 0x2000075C
OBJECT_STRIDE = 96
OBJECT_COUNT = 5
DRIVER_CONTEXT_ROOT = OBJECT_BASE - 4
MOCK_MEMSET = 0x0802D1C0
MOCK_RTOS_REGISTER = 0x0802377A
RETURN_SENTINEL = 0x0803B700

# Vtable methods have odd Thumb pointers. This audit does NOT execute
# these unknown callback bodies; only checks constructor assignments.
VFUNCTION_WORDS = {
    0x08026860: 0x080193C5,  # constructor assignment at +0x30
    0x08026864: 0x08019401,  # +0x34
    0x08026868: 0x0801939D,  # +0x38 (RTOS control callback offset)
}
ORIGINAL_LITERAL = {0x08028510: OBJECT_BASE}
FIXED_INS = {
    0x080283F0: ("movs.w", "r4, #0"),
    0x080283F4: ("add.w", "r0, r4, r4, lsl #1"),
    0x080283F8: ("add.w", "r0, r5, r0, lsl #5"),
    0x080283FC: ("ldr", "r2, [pc, #0x110]"),
    0x08028400: ("add.w", "r3, r0, #0x44"),
    0x08028404: ("subs", "r2, r2, #4"),
    0x08028406: ("ldr", "r1, [r0, #0x54]"),
    0x08028408: ("bl", "#0x802644a"),
    0x08028426: ("adds", "r4, r4, #1"),
    0x08028428: ("cmp", "r4, #5"),
    0x0802842A: ("blo", "#0x80283f4"),
    0x0802644A: ("push.w", "{r4, r5, r6, r7, r8, lr}"),
    0x08026456: ("movs", "r2, #0x44"),
    0x08026458: ("movs", "r1, #0"),
    0x0802645A: ("bl", "#0x802d1c0"),
    0x08026466: ("ldr", "r0, [pc, #0x3f8]"),
    0x08026468: ("str", "r0, [r4, #0x30]"),
    0x0802646A: ("ldr", "r0, [pc, #0x3f8]"),
    0x0802646C: ("str", "r0, [r4, #0x34]"),
    0x0802646E: ("ldr", "r0, [pc, #0x3f8]"),
    0x08026470: ("str", "r0, [r4, #0x38]"),
    0x08026472: ("movs", "r0, #0x1d"),
    0x08026474: ("strb", "r0, [r4, #0x14]"),
    0x08026476: ("strd", "r5, r6, [r4, #0x3c]"),
    0x08026482: ("movs", "r2, #3"),
    0x08026484: ("b.w", "#0x802377a"),
    # The generic driver dispatcher documented in draft #19 invokes
    # *an object pointer* at +0x38, but the caller-to-motor object
    # identity remains unknown without a complete dataflow proof.
    0x08023AC2: ("ldr", "r3, [r4, #0x38]"),
    0x08023AD0: ("bx", "r3"),
}

def u32(image: bytes, at: int) -> int:
    p = at - APP_BASE
    if p < 0 or p + 4 > len(image):
        raise ValueError(f"ROM word outside APP: {at:#x}")
    return struct.unpack_from("<I", image, p)[0]


def verify(image: bytes, kind: str) -> dict:
    header = report_image(image, kind)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    ins = []
    for address, target in FIXED_INS.items():
        off = address - APP_BASE
        i = next(cs.disasm(image[off:off + 4], address, count=1), None)
        if i is None or (i.mnemonic, i.op_str) != target:
            raise ValueError(f"original constructor opcode mismatch @ {address:#x}")
        ins.append({"at": hex(address), "instruction": i.mnemonic + " " + i.op_str,
                    "code": i.bytes.hex()})
    ptrs = []
    for address, expected in {**VFUNCTION_WORDS, **ORIGINAL_LITERAL}.items():
        if u32(image, address) != expected:
            raise ValueError(f"original ROM function pointer mismatch @ {address:#x}")
        ptrs.append({"at": hex(address), "word": hex(expected)})
    return {
        "header": header,
        "matched_Thumb_instructions": ins,
        "matched_original_ROM_literals": ptrs,
        "object_stride_bytes": OBJECT_STRIDE,
        "object_count_static": OBJECT_COUNT,
        "actual_motor_runtime_object_identity_proven": False,
    }


def model_constructor(image: bytes, kind: str, index: int) -> dict:
    if not 0 <= index < OBJECT_COUNT:
        raise ValueError("invalid object index")
    obj = OBJECT_BASE + OBJECT_STRIDE * index
    name_ptr = 0x20003000 + 0x20 * index
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(FLASH_BASE, FLASH_BYTES)
    u.mem_map(RAM_BASE, RAM_BYTES)
    u.mem_write(APP_BASE, image)
    u.mem_write(obj, bytes([0xA5]) * OBJECT_STRIDE)
    u.mem_write(obj + 0x54, struct.pack("<I", name_ptr))
    u.mem_write(name_ptr, b"TEST-DEVICE\x00")
    u.reg_write(UC_ARM_REG_SP, 0x2000E000)
    u.reg_write(UC_ARM_REG_LR, RETURN_SENTINEL | 1)
    u.reg_write(UC_ARM_REG_PC, CONSTRUCTOR | 1)
    u.reg_write(UC_ARM_REG_R0, obj)
    u.reg_write(UC_ARM_REG_R1, name_ptr)
    u.reg_write(UC_ARM_REG_R2, DRIVER_CONTEXT_ROOT)
    u.reg_write(UC_ARM_REG_R3, obj + 0x44)
    calls = []
    stops = []

    def _code(uc, pc, size, user):
        if pc == MOCK_MEMSET:
            base = uc.reg_read(UC_ARM_REG_R0)
            fill = uc.reg_read(UC_ARM_REG_R1) & 255
            length = uc.reg_read(UC_ARM_REG_R2)
            if (base, fill, length) != (obj, 0, 0x44):
                raise ValueError("changed original memset contract")
            calls.append({"callee": hex(pc), "object": hex(obj),
                          "zeroed_bytes": length})
            uc.mem_write(base, bytes([fill]) * length)
            uc.reg_write(UC_ARM_REG_R0, base)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif pc == MOCK_RTOS_REGISTER:
            args = [uc.reg_read(x) for x in (
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
            if args != [obj, name_ptr, 3]:
                raise ValueError("changed original register callback parameters")
            calls.append({"callee": hex(pc), "object": hex(obj),
                          "registration_name_RAM": hex(args[1]),
                          "registration_flags": args[2]})
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, RETURN_SENTINEL | 1)
        elif pc == RETURN_SENTINEL:
            stops.append(pc)
            uc.emu_stop()

    u.hook_add(UC_HOOK_CODE, _code)
    u.emu_start(CONSTRUCTOR | 1, 0, count=200)
    if stops != [RETURN_SENTINEL] or len(calls) != 2:
        raise ValueError("constructor did not complete through mocked RTOS register")
    vals = {}
    for offset in (0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40):
        vals[hex(offset)] = struct.unpack("<I", u.mem_read(obj + offset, 4))[0]
    expected = {
        "0x24": 0, "0x28": 0, "0x2c": 0,
        "0x30": VFUNCTION_WORDS[0x08026860],
        "0x34": VFUNCTION_WORDS[0x08026864],
        "0x38": VFUNCTION_WORDS[0x08026868],
        "0x3c": obj + 0x44,
        "0x40": DRIVER_CONTEXT_ROOT,
    }
    if vals != expected:
        raise ValueError("original constructor wrote unexpected function pointers")
    if u.mem_read(obj + 0x14, 1)[0] != 0x1D:
        raise ValueError("constructor type field changed")
    return {
        "index": index,
        "object_address": hex(obj),
        "object_registered_with_mock_OS": True,
        "register_calls": calls,
        "pointer_fields": {k: hex(v) for k, v in vals.items()},
        "field_0x14": hex(0x1D),
        "native_callback_bodies_executed": False,
        "rtos_real_device_registration_executed": False,
        "real_motor_hardware_owner_proven": False,
    }


def mutation_check(image: bytes) -> dict:
    offsets = {
        "strided_object_index": 0x080283F8,
        "call_constructor": 0x08028408,
        "loop_limit": 0x08028428,
        "constructor_entry": 0x0802644A,
        "callback_offset_0x38_store": 0x08026470,
        "callback_pointer_ROM": 0x08026868,
        "registered_object_flags": 0x08026482,
        "generic_callback_load": 0x08023AC2,
    }
    rejected = []
    for name, at in offsets.items():
        altered = bytearray(image)
        altered[at - APP_BASE] ^= 1
        check = bytearray(altered)
        check[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
        struct.pack_into("<H", altered, CRC_OFF, crc16_bypass(check))
        report = report_image(bytes(altered), "running_v322")
        if not report["header_crc_valid"]:
            raise AssertionError("test input must have correct APP CRC")
        try:
            verify(bytes(altered), "running_v322")
        except ValueError:
            rejected.append(name)
        else:
            raise AssertionError("callback constructor mutation accepted: " + name)
    return {"crc_corrected_rejected": rejected, "total": len(rejected)}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v322", type=Path, required=True)
    p.add_argument("--stock", type=Path)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--json-out", type=Path)
    opt = p.parse_args()
    v = pinned(opt.v322, "running_v322")
    s = pinned(opt.stock, "creality_stock_153") if opt.stock else None

    def run(image, kind):
        return {
            "static": verify(image, kind),
            "objects": [model_constructor(image, kind, i)
                        for i in range(OBJECT_COUNT)],
        }
    current = run(v, "running_v322")
    original = run(s, "creality_stock_153") if s is not None else None
    if original:
        if (original["static"]["matched_Thumb_instructions"] !=
                current["static"]["matched_Thumb_instructions"] or
                original["static"]["matched_original_ROM_literals"] !=
                current["static"]["matched_original_ROM_literals"]):
            raise ValueError("stock vs v3.22 original constructor differs")
        if original["objects"] != current["objects"]:
            raise ValueError("stock vs v3.22 object emulator differs")
    out = {
        "scope": "OFFLINE five original object constructors and dummy OS callback",
        "stock_compared": original is not None,
        "v322": current,
        "original": original,
        "real_CFS_motor_instance_identity_proven": False,
        "real_encoder_feedback_observed": False,
        "non_production_test_hardware_or_serial_access": False,
        "firmware_release_allowed": False,
    }
    if opt.self_test:
        out["mutations"] = mutation_check(v)
    result = json.dumps(out, indent=2) + "\n"
    if opt.json_out:
        opt.json_out.write_text(result)
    print(result, end="")


if __name__ == "__main__":
    main()
