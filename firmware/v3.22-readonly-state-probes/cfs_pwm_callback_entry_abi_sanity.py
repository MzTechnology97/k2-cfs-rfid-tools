#!/usr/bin/env python3
"""Offline five-device callback entry ABI sanity, validated v3.13/v3.22.

A conventional RT-Thread function-pointer callback is entered via BLX/BX.
The manufacturer constructor places a Thumb pointer 0x0801939D at
[device+0x38]. That target falls inside a longer decoding block:
it uses callee-saved register r4 and returns via POP {r3,r4,r5,pc}
without a local PUSH. As a standalone ordinary AAPCS call this needs
further verification; DO NOT hook it based on pointer location alone.

This checker proves only raw manufacturer code structure and version
identity. It does NOT simulate actual live MCU or claim motor idle.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import APP_BASE, pinned

CB_PTR_WORD = 0x08026868
CB_THUMB_PTR = 0x0801939D
ENTRY = CB_THUMB_PTR & ~1
SEG_END = 0x080193B4
INSTRUCTION_EXPECTED = (
    (0x0801939C, "ldrb", "r2, [r4, #9]"),
    (0x0801939E, "eors", "r0, r1"),
    (0x080193A0, "ldrb", "r1, [r4, #8]"),
    (0x080193A2, "eors", "r1, r2"),
    (0x080193A4, "eors", "r0, r1"),
    (0x080193A6, "ldrb", "r1, [r4, #0xd]"),
    (0x080193A8, "cmp", "r0, r1"),
    (0x080193AA, "bne", "#0x80193b0"),
    (0x080193AC, "movs", "r0, #0"),
    (0x080193AE, "pop", "{r3, r4, r5, pc}"),
    (0x080193B0, "movs", "r0, #0xf4"),
    (0x080193B2, "pop", "{r3, r4, r5, pc}"),
)

def analyze(image: bytes) -> dict:
    ptr = struct.unpack_from("<I", image, CB_PTR_WORD - APP_BASE)[0]
    if ptr != CB_THUMB_PTR:
        raise ValueError("unexpected manufacturer +0x38 callback pointer")
    c = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    instructions = tuple(
        (i.address, i.mnemonic, i.op_str)
        for i in c.disasm(image[ENTRY - APP_BASE: SEG_END - APP_BASE], ENTRY)
    )
    if instructions != INSTRUCTION_EXPECTED:
        raise ValueError("manufacturer conditional callback opcode sequence differs")
    raw = image[ENTRY-APP_BASE:SEG_END-APP_BASE]
    return {
        "constructor_literal": hex(ptr),
        "thumb_entry": hex(ENTRY),
        "instruction_count": len(instructions),
        "raw_original_Thumb_bytes": raw.hex(),
        "first_instruction": instructions[0][1]+" "+instructions[0][2],
        "has_local_entry_push": instructions[0][1].startswith("push"),
        "returns_with_callee_stack_POP": all(
            x[1] == "pop" and x[2] == "{r3, r4, r5, pc}"
            for x in (instructions[9], instructions[11])
        ),
        "independent_AAPCS_entry_safety_proven": False,
        "normal_BX_dispatch_to_this_exact_object_proven": False,
        "actual_motor_idle_sensing_proven": False,
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--v313", type=Path, required=True)
    p.add_argument("--v322", type=Path, required=True)
    p.add_argument("--json-out", type=Path)
    a=p.parse_args()
    v313=analyze(pinned(a.v313, "intermediate_v313"))
    v322=analyze(pinned(a.v322, "running_v322"))
    if v313 != v322:
        raise ValueError("v3.13/v3.22 original callback body differs")
    result={
        "v313":v313, "v322":v322,
        "code_byte_identical_across_two_versions":True,
        "no_firmware_patch_or_device_IO":True,
        "callback_ABI_compatibility_verified":False,
        "do_not_install_motor_guard_on_this_unverified_address":True,
    }
    body=json.dumps(result,indent=2)+"\n"
    if a.json_out: a.json_out.write_text(body)
    print(body,end="")

if __name__=="__main__":
    main()
