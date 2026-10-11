#!/usr/bin/env python3
"""Offline original CFS database reachability and v3.22 source reclaim check.

Read only already-saved, SHA-pinned stock and v3.22 application binaries;
assemble disposable HANDLER-ONLY test objects in an ephemeral directory.
NEVER opens a device, accesses MCU RS485, or emits firmware/application BIN.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB

from flash_ram_phase2_audit import APP_BASE, PINS, pinned, report_image

# Exact original Creality Thumb-2 BL calls and targets, not speculative
# routine names/usage. Some targets use indirect dispatch later.
CALLS = {
    0x080102EE: 0x0801EEBA,  # application startup -> database initialization
    0x0801EEBE: 0x0801ED40,  # initializer -> descriptor / data structure
    0x0801ED50: 0x0801EC72,  # descriptor/data registry lookup
    0x0801C69C: 0x0801ED82,  # stock CFS command -> database read helper
    0x0801C6D2: 0x0801EDB4,  # stock CFS command -> database write helper
    0x08017066: 0x0801EDB4,  # second stock caller -> database write helper
    0x0801EEFA: 0x0801EDB4,  # initializer / repair -> database write helper
    0x0801EA86: 0x080318BE,  # FMC word programmer caller
    0x0801EAEC: 0x0803175A,  # FMC 2048B page eraser caller
    0x0801EBB6: 0x0801EA78,  # FMC higher-level chunk write caller
    0x0801EBCC: 0x0801EA78,  # FMC higher-level full word write caller
}
STRINGS = {
    0x08036CB6: "rfid_mgr_fila_save",
    0x08036CC9: "rfid_mgr_fila_task",
    0x08036D7C: "database_get_value",
    0x08036D8F: "database_set_value",
}
WORDS = {
    0x08036D2C: 0x0807F800,  # last 2 KiB page of GD32F303VE main Flash
    0x08036D38: 0x800,       # 2 KiB metadata next to the last-page word
    0x08036D3C: 0x20004A20,  # application RAM object
    0x0801EC48: 0x20004A20,  # startup routine registers RAM object
    0x0801EC44: 0x08029D2C, # original static format-string pointer
}

# Must never be removed just because "config_v2_ensure" occurs only once
# in the source! "config_ptr" is an alias at the SAME code address.
ALIAS_BLOCK = "config_v2_ensure:\nconfig_ptr:\n"
ALIAS_CALL = "    bl      config_ptr"
LEGACY_SPEED_TABLE = "config_defaults:       .byte 255, 100, 200, 155, 255, 80\n"
ASM_LINK_ADDR = 0x0803AE38
EXACT_WORKING_HANDLER_LENGTH = 2468
# A six-byte table removal yields FOUR binary bytes saved, due to
# subsequent .balign and code relocation.
EXPECTED_TRIMMED_LENGTH = 2464


def word(image: bytes, at: int) -> int:
    off = at - APP_BASE
    if off < 0 or off + 4 > len(image):
        raise ValueError("unexpected ROM word address")
    return struct.unpack_from("<I", image, off)[0]


def stock_database(image: bytes, kind: str) -> dict:
    meta = report_image(image, kind)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    calls = []
    for at, expected in CALLS.items():
        off = at - APP_BASE
        ins = next(cs.disasm(image[off:off + 4], at, count=1), None)
        if ins is None or ins.mnemonic != "bl" or ins.op_str != f"#0x{expected:x}":
            raise ValueError(f"stock BL modified or unexpected @ {at:#x}: {ins}")
        calls.append({"callsite": hex(at), "callee": hex(expected),
                      "instruction_encoding": ins.bytes.hex()})
    names = []
    for at, name in STRINGS.items():
        b = name.encode() + b"\0"
        if image[at - APP_BASE:at - APP_BASE + len(b)] != b:
            raise ValueError("missing original database/RFID string: " + name)
        names.append({"rom_address": hex(at), "literal": name})
    refs = []
    for at, value in WORDS.items():
        if word(image, at) != value:
            raise ValueError(f"stock database / last page descriptor changed @ {at:#x}")
        refs.append({"rom_address": hex(at), "word": hex(value)})
    meta["matched_direct_calls"] = calls
    meta["matched_database_and_RFID_strings"] = names
    meta["matched_original_ROM_words"] = refs
    meta["original_high_page_descriptor_used_at_runtime_PROVEN"] = False
    meta["database_reaches_FMC_last_page_at_runtime_PROVEN"] = False
    return meta


def _tool(*cmd: str) -> str:
    return subprocess.check_output(cmd, text=True)


def compile_handler(source: str, linker: str, where: Path, stem: str) -> dict:
    asm = where / (stem + ".S")
    ld = where / (stem + ".ld")
    obj = where / (stem + ".o")
    elf = where / (stem + ".elf")
    binary = where / (stem + ".bin")   # handler fragment ONLY, auto-removed
    asm.write_text(source)
    ld.write_text(linker)
    subprocess.run(
        ["arm-none-eabi-gcc", "-c", "-mcpu=cortex-m3", "-mthumb",
         "-ffreestanding", "-nostdlib", "-o", str(obj), str(asm)],
        check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["arm-none-eabi-ld", "-T", str(ld), "-o", str(elf), str(obj)],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["arm-none-eabi-objcopy", "-O", "binary",
                    str(elf), str(binary)],
                   check=True, stdout=subprocess.DEVNULL)
    symbols = {}
    for line in _tool("arm-none-eabi-nm", "-n", str(elf)).splitlines():
        parts = line.split()
        if len(parts) == 3:
            try:
                symbols[parts[2]] = int(parts[0], 16)
            except ValueError:
                pass
    data = binary.read_bytes()
    return {"bytes": len(data), "sha256_handler_only": hashlib.sha256(data).hexdigest(),
            "symbols": symbols}


def inspect_handler_optimisation(source_path: Path, linker_path: Path) -> dict:
    src = source_path.read_text()
    ld = linker_path.read_text()
    for anchor in (ALIAS_BLOCK, ALIAS_CALL, LEGACY_SPEED_TABLE):
        if src.count(anchor) != 1:
            raise ValueError("missing/duplicated critical handler alias or legacy data")
    # A line-by-line audit, with both symbol names accounted for. It is unsafe
    # to conclude config_v2_ensure is dead simply from its literal name count.
    assert len(re.findall(r"\bconfig_v2_ensure\b", src)) == 1
    assert src.count("config_ptr") >= 2
    assert src.count("config_expected_ptr") >= 2
    assert src.count("config_defaults") >= 1

    trimmed = src.replace(
        LEGACY_SPEED_TABLE,
        "@ OFFLINE experiment: omit historical six-byte defaults table.\n")
    with tempfile.TemporaryDirectory(prefix="cfs-handler-sizeopt-") as td:
        dirpath = Path(td)
        base = compile_handler(src, ld, dirpath, "original_handler")
        opt = compile_handler(trimmed, ld, dirpath, "trimmed_handler")
    if base["bytes"] != EXACT_WORKING_HANDLER_LENGTH:
        raise ValueError("original assembly size changed unexpectedly")
    if opt["bytes"] != EXPECTED_TRIMMED_LENGTH:
        raise ValueError("unexpected source reclaim size")
    if base["symbols"].get("config_v2_ensure") != base["symbols"].get("config_ptr"):
        raise ValueError("config_ptr should alias config_v2_ensure entry")
    if opt["symbols"].get("config_v2_ensure") != opt["symbols"].get("config_ptr"):
        raise ValueError("source optimization unexpectedly disturbed live pointer alias")
    if base["symbols"].get("handler_start") != ASM_LINK_ADDR:
        raise ValueError("unexpected handler link base")
    return {
        "source_alias_config_v2_ensure": hex(base["symbols"]["config_v2_ensure"]),
        "source_alias_config_ptr": hex(base["symbols"]["config_ptr"]),
        "alias_referenced_by_BL_config_ptr": True,
        "config_v2_ensure_can_be_deleted_safely": False,
        "config_root_ptr_can_be_deleted_safely": False,
        "config_expected_ptr_can_be_deleted_safely": False,
        "legacy_speed_defaults_table_direct_symbol_references": (
            len(re.findall(r"\bconfig_defaults\b", src)) - 1),
        "working_handler_bytes": base["bytes"],
        "unflashed_trimmed_HANDLER_bytes": opt["bytes"],
        "saved_handler_bytes_IN_OFFLINE_EXPERIMENT": base["bytes"] - opt["bytes"],
        "estimated_full_app_bytes_experiment_only": (
            178140 - (base["bytes"] - opt["bytes"])),
        "all_original_28_RFID_routines_same_bytes_after_trimming_PROVEN": False,
        "real_MCU_write_or_emulation_run_by_this_tool": False,
        "tmp_handler_fragments_auto_removed": True,
        "production_optimisation_authorised": False,
    }


def tamper_test(image: bytes) -> dict:
    # The same checksum-corrected mutation must be rejected by the static
    # structural checks (not just rejected by the header CRC).
    from flash_ram_phase2_audit import CRC_OFF, META_END, crc16_bypass
    mutations = {
        "database_startup_BL": 0x080102EE,
        "database_write_BL": 0x0801C6D2,
        "flash_word_program_BL": 0x0801EA86,
        "last_flash_page_descriptor": 0x08036D2C,
        "database_get_value_name": 0x08036D7C,
    }
    rejected = []
    for name, at in mutations.items():
        t = bytearray(image)
        t[at - APP_BASE] ^= 1
        copy = bytearray(t)
        copy[CRC_OFF:META_END] = bytes(META_END - CRC_OFF)
        struct.pack_into("<H", t, CRC_OFF, crc16_bypass(copy))
        try:
            stock_database(bytes(t), "running_v322")
        except ValueError:
            rejected.append(name)
        else:
            raise AssertionError("corrupted v3.22 code/descriptor accepted: " + name)
    return {"mutations_rejected_with_valid_CRC": rejected, "count": len(rejected)}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v322", required=True, type=Path)
    p.add_argument("--original-stock", type=Path)
    p.add_argument("--asm", type=Path)
    p.add_argument("--linker", type=Path)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--json-out", type=Path)
    a = p.parse_args()
    image = pinned(a.v322, "running_v322")
    stock = pinned(a.original_stock, "creality_stock_153") if a.original_stock else None
    original = stock_database(stock, "creality_stock_153") if stock else None
    current = stock_database(image, "running_v322")
    if original:
        for key in ("matched_direct_calls", "matched_database_and_RFID_strings",
                    "matched_original_ROM_words"):
            if original[key] != current[key]:
                raise ValueError("unexpected original vs current database differences")
    if bool(a.asm) != bool(a.linker):
        raise ValueError("must provide both assembler source and linker")
    out = {
        "scope": "READ ONLY, offline saved-image and disposable handler objects",
        "original_stock_compared": original is not None,
        "current": current,
        "original_stock": original,
        "no_vendor_binary_exported": True,
        "no_operational_mcu_access": True,
        "safe_to_flash_larger_app": False,
        "runtime_use_of_last_flash_page_proven": False,
    }
    if a.asm:
        out["sizeopt_alias_and_table"] = inspect_handler_optimisation(a.asm, a.linker)
    if a.self_test:
        out["fail_closed_tests"] = tamper_test(image)
    body = json.dumps(out, indent=2) + "\n"
    if a.json_out:
        a.json_out.write_text(body)
    print(body, end="")


if __name__ == "__main__":
    main()
