#!/usr/bin/env python3
"""Offline ROM evidence for GD32F303 CFS application Flash driver / callers.

Operates ONLY on previously saved, SHA-pinned original / v3.22 BIN files.
No device, bootloader/RS485, firmware writes, generated BIN or board IO.
Require Capstone 5.x for Thumb instruction identities at exact ROM addresses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

from flash_ram_phase2_audit import (
    APP_BASE, CRC_OFF, META_END, crc16_bypass, pinned, report_image
)

FMC_BASE = 0x40022000
PAGE_BYTES = 2048
PERSISTENCE_CANDIDATE = 0x0807F800
APP_POINTER_TABLE_START = 0x08036D10
APP_POINTER_TABLE_END = 0x08036D48
FLASH_SIZE_REGISTER = 0x1FFFF7E0
KEY0, KEY1 = 0x45670123, 0xCDEF89AB

# Target instructions chosen from the *original* Creality 1.5.3 G32 ROM,
# independently decompiled using the 16/32-bit Thumb instruction boundaries.
# The MCU silicon is identified by Creality's G32 loader identity, not by
# a physical chip marking; this remains a hypothesis until verified.
INVARIANTS = {
    0x0803175A: ("push", "{r4, r5, r6, lr}"),     # erase-page function prologue
    0x08031760: ("ldr", "r4, [pc, #0x2f4]"),     # FMC_BASE pointer
    0x08031764: ("ldrh", "r0, [r0]"),           # silicon Flash size register
    0x08031766: ("cmp.w", "r0, #0x200"),        # 512 KiB Flash
    0x0803177E: ("orr", "r0, r0, #2"),          # FMC_CTL0 PER
    0x08031782: ("str", "r0, [r4, #0x10]"),
    0x08031784: ("str", "r5, [r4, #0x14]"),    # FMC_ADDR0 <- page address
    0x08031788: ("orr", "r0, r0, #0x40"),      # FMC_CTL0 START
    0x0803178C: ("str", "r0, [r4, #0x10]"),
    0x080318BE: ("push", "{r4, r5, r6, r7, lr}"),  # program-word entry
    0x080318E4: ("orr", "r0, r0, #1"),         # FMC_CTL0 PG
    0x080318E8: ("str", "r0, [r4, #0x10]"),
    0x080318EA: ("str", "r6, [r5]"),           # write word to caller address
    0x080319FC: ("ldr", "r0, [pc, #0x58]"),    # FMC_BASE
    0x08031A04: ("ldr", "r1, [pc, #0x54]"),    # 0x45670123
    0x08031A06: ("str", "r1, [r0, #8]"),
    0x08031A08: ("ldr", "r1, [pc, #0x54]"),    # 0xCDEF89AB
    0x08031A0A: ("str", "r1, [r0, #8]"),
    0x0801EA78: ("push", "{r4, r5, r6, lr}"), # higher-level program wrapper
    0x0801EA86: ("bl", "#0x80318be"),         # wrapper -> word-program
    0x0801EAA2: ("push.w", "{r4, r5, r6, r7, r8, sb, sl, lr}"),
    0x0801EAE8: ("add.w", "r0, r6, r5, lsl #11"), # page-size stride
    0x0801EAEC: ("bl", "#0x803175a"),         # wrapper -> page erase
}
# Exact original constant load sites and corresponding ROM literal values.
LITERAL_REFS = {
    0x0803175E: (0x08031A64, FLASH_SIZE_REGISTER),
    0x08031760: (0x08031A58, FMC_BASE),
    0x0803176C: (0x08031A6C, 0x0807FFFF),
    0x080319FC: (0x08031A58, FMC_BASE),
    0x08031A04: (0x08031A5C, KEY0),
    0x08031A08: (0x08031A60, KEY1),
}
TABLE_WORDS = {
    0x08036D2C: PERSISTENCE_CANDIDATE,
    0x08036D30: 1,
    0x08036D34: 0x0802C598,
    0x08036D38: PAGE_BYTES,
    0x08036D3C: 0x20004A20,
    0x08036D40: 0x08011AA3,
    0x08036D44: 0x08011B13,
}


def word(data: bytes, at: int) -> int:
    off = at - APP_BASE
    if off < 0 or off + 4 > len(data):
        raise ValueError("ROM access outside supplied app")
    return struct.unpack_from("<I", data, off)[0]


def instruction(data: bytes, address: int):
    off = address - APP_BASE
    if off < 0 or off + 4 > len(data):
        raise ValueError("Thumb decode outside supplied app")
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    result = next(decoder.disasm(data[off:off + 4], address, count=1), None)
    if result is None:
        raise ValueError("undecodable Thumb at " + hex(address))
    return result


def exact_fmc_instructions(data: bytes) -> dict:
    validated = []
    for at, (mnemonic, operands) in INVARIANTS.items():
        decoded = instruction(data, at)
        if (decoded.mnemonic, decoded.op_str) != (mnemonic, operands):
            raise ValueError(
                f"Thumb instruction altered at {at:#x}: "
                f"{decoded.mnemonic} {decoded.op_str} != {mnemonic} {operands}"
            )
        validated.append({
            "address": hex(at), "mnemonic": mnemonic,
            "operands": operands, "encoding": decoded.bytes.hex(),
        })
    dereferences = []
    for at, (target, expected_word) in LITERAL_REFS.items():
        decoded = instruction(data, at)
        locations = []
        for op in decoded.operands:
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                locations.append(((at + 4) & ~3) + op.mem.disp)
        if locations != [target] or word(data, target) != expected_word:
            raise ValueError(f"misdirected FMC / Flash capacity literal at {at:#x}")
        dereferences.append({
            "ldr_at": hex(at), "rom_word_at": hex(target),
            "validated_value": hex(expected_word)
        })
    return {
        "critical_instruction_count": len(validated),
        "critical_thumb_instructions": validated,
        "resolved_PC_relative_literals": dereferences,
        "higher_level_erasure_wrapper": hex(0x0801EAA2),
        "page_erase_callsite": hex(0x0801EAEC),
        "page_erase_target": hex(0x0803175A),
        "word_program_wrapper": hex(0x0801EA78),
        "word_program_callsite": hex(0x0801EA86),
        "word_program_target": hex(0x080318BE),
        "erase_address_from_caller": True,
        "program_word_address_from_caller": True,
        "direct_last_page_call_reached": False,
        "control_flow_to_0x0807f800_verified": False,
    }


def inspect(data: bytes, label: str) -> dict:
    # Header CRC detects accidental corruption independently of pinned-input
    # SHA validation done by caller. The mutation self-test recomputes CRC.
    m = report_image(data, label)
    table = []
    for address, expected in TABLE_WORDS.items():
        if word(data, address) != expected:
            raise ValueError(f"original table word changed at {address:#x}")
        table.append({"address": hex(address), "word": hex(expected)})
    needle = struct.pack("<I", PERSISTENCE_CANDIDATE)
    hits = [APP_BASE + i for i in range(len(data) - 3)
            if data[i:i + 4] == needle]
    if hits != [0x08036D2C]:
        raise ValueError("last-page address occurs at unexpected locations")
    driver = exact_fmc_instructions(data)
    m.update({
        "last_page_table_sha256": hashlib.sha256(
            data[APP_POINTER_TABLE_START - APP_BASE:
                 APP_POINTER_TABLE_END - APP_BASE]).hexdigest(),
        "matched_table_words": table,
        "last_page_pointer_occurrences": [hex(h) for h in hits],
        "flash_driver": driver,
        "stock_application_contains_flash_erase_and_program_code": True,
        "actual_runtime_erase_or_write_to_last_page_observed": False,
        "stock_last_page_persistence_likely_but_NOT_PROVEN": True,
    })
    return m


def self_test(data: bytes) -> dict:
    cases = {
        "last_page_pointer": 0x08036D2C,
        "last_page_size": 0x08036D38,
        "erase_per_bit": 0x0803177E,
        "word_program_call": 0x0801EA86,
        "fmc_unlock_key": 0x08031A5C,
    }
    rejected = []
    for name, address in cases.items():
        test = bytearray(data)
        test[address - APP_BASE] ^= 1
        # Make header CRC valid; failure must come from the inspected
        # Flash control/dataflow evidence, not from checksum mismatch.
        crc_candidate = bytearray(test)
        crc_candidate[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
        struct.pack_into("<H", test, CRC_OFF, crc16_bypass(crc_candidate))
        try:
            inspect(bytes(test), "running_v322")
        except ValueError:
            rejected.append(name)
        else:
            raise AssertionError("dangerous mutation accepted: " + name)
    return {"crc_valid_mutations_rejected": rejected,
            "total": len(rejected)}


def build(stock: bytes | None, current: bytes, test: bool) -> dict:
    v322 = inspect(current, "running_v322")
    original = inspect(stock, "creality_stock_153") if stock else None
    if original and (v322["last_page_table_sha256"] !=
                     original["last_page_table_sha256"]):
        raise ValueError("v3.22 silently changed stock Flash descriptor table")
    if original and (
        [r["encoding"] for r in v322["flash_driver"]["critical_thumb_instructions"]]
        != [r["encoding"] for r in original["flash_driver"]["critical_thumb_instructions"]]
    ):
        raise ValueError("stock FMC driver not byte-identical to v3.22")
    out = {
        "scope": "OFFLINE static verified original ROM Flash driver. No MCU IO.",
        "creality_stock_compared": original is not None,
        "original_153": original,
        "v322": v322,
        "flash_access_findings": {
            "FMC_BASE": hex(FMC_BASE),
            "unlock_key_order": [hex(KEY0), hex(KEY1)],
            "GD32_FMC_CTL0_PER_bit": 2,
            "GD32_FMC_CTL0_START_bit": 0x40,
            "GD32_FMC_CTL0_PG_bit": 1,
            "flash_erase_page_size_bytes": PAGE_BYTES,
            "flash_erase_page_number_last": 255,
            "stock_app_mcu_FLASH_driver_present": True,
            "stock_direct_callers_to_driver_present": True,
            "last_page_address_explicit_in_stock_ROM": True,
            "connection_of_last_page_descriptor_to_driver_RUNTIME_UNPROVEN": True,
            "actual_app_update_bootloader_max_bytes": None,
            "Flash_above_0x0803B800_free_for_new_code": False,
            "source_bootloader_code_was_dumped": False,
            "safe_to_flash_a_larger_app": False,
            "safe_to_write_flash_runtime": False,
        },
        "no_device_open_or_serial_commands": True,
        "generated_flashable_image": False,
    }
    if test:
        out["fail_closed_mutation_tests"] = self_test(current)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v322", type=Path, required=True)
    parser.add_argument("--stock", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    v322 = pinned(args.v322, "running_v322")
    original = pinned(args.stock, "creality_stock_153") if args.stock else None
    result = build(original, v322, args.self_test)
    data = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(data)
    print(data, end="")


if __name__ == "__main__":
    main()
