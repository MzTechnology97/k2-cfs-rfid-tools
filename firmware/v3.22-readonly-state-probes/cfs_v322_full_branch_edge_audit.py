#!/usr/bin/env python3
"""Offline census of every external branch relocation and all 14 patched v3.22 callsites.

A nominal 0x08010000 builder coordinate is not the real 0x08003000 linked APP
base. Recompile the *unchanged* handler into a temporary ELF and inspect the
relocations, symbols, physical Thumb branches and SHA-locked saved firmware.

No device access, serial traffic, motor commands, firmware or active-host edits.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE

NOMINAL_APP = 0x08010000
NOMINAL_HANDLER = 0x0803AE38
DELTA = NOMINAL_APP - LINK_BASE
PHYSICAL_HANDLER = NOMINAL_HANDLER - DELTA
EXPECTED_EXTERNAL_RELOCS = 15
EXPECTED_PATCHED_CALLS = 14
EXPECTED_EXTERNAL_TARGET_COUNTS = {
    0x0801BAF2: 1,  # SEND_RESPONSE
    0x0801C808: 1,  # STOCK_DONE
    0x0801C704: 1,  # STOCK_51
    0x0801C7F8: 1,  # STOCK_INVALID
    0x0803393C: 3,  # STOCK_MEMCMP
    0x0801A670: 1,  # STOCK_MSG_VALIDATE
    0x080102E2: 1,  # STOCK_REMAIN_GATE
    0x080123E4: 1,  # REMAIN_SET
    0x0801AA14: 1,  # STOCK_REMAIN_INIT
    0x0801245C: 1,  # STOCK_REMAIN_VALID
    0x0801A39E: 1,  # LEGACY_AUTH_READ
    0x08022082: 1,  # ALT_AUTH_READ
    0x080278D4: 1,  # STOCK_HEAP_INIT
}
EXPECTED_PATCHES = [
    (0x0801A4CC, "legacy_read0_wrapper"),
    (0x0801A52C, "legacy_read1_wrapper"),
    (0x0801A590, "legacy_read2_wrapper"),
    (0x080225D0, "alt_read_wrapper"),
    (0x08022604, "alt_read_wrapper"),
    (0x08022638, "alt_read_wrapper"),
    (0x08012DDC, "uid_compare_wrapper"),
    (0x08012E62, "msg_validate_wrapper"),
    (0x08013380, "remaining_gate_wrapper"),
    (0x08013394, "remaining_init_wrapper"),
    (0x0801BF9E, "remaining_valid_wrapper"),
    (0x08011116, "cfg7_r0_wrapper"),
    (0x080112CA, "cfg8_r1_wrapper"),
    (0x0802A5F2, "heap_init_sidecar_wrapper"),
]
RELOC_LINE = re.compile(
    r"(?m)^\s*([0-9a-fA-F]{8})\s+[0-9a-fA-F]{8}\s+"
    r"(R_ARM_[A-Za-z0-9_]+)\s+([0-9a-fA-F]{8})\s+(\S+)"
)
SOURCE_EQU = re.compile(
    r"(?m)^\s*\.equ\s+(\w+),\s*(0x[0-9a-fA-F]+)\b"
)
SOURCE_WORD = re.compile(r"(?m)^\s*(?:[a-zA-Z_][\w]*:\s*)?\.word\s+([^@\n]+)")
SYMBOL_LINE = re.compile(r"^([0-9a-fA-F]{8})\s+[a-zA-Z]\s+(\w+)$")


def run(*args: str) -> str:
    return subprocess.run(args, check=True, text=True,
                          capture_output=True).stdout


def compiled_unchanged(asm: Path, linker: Path) -> tuple[bytes, str, str, str]:
    with tempfile.TemporaryDirectory(prefix="cfs-v322-relocation-audit-") as tmp:
        dest = Path(tmp)
        obj, elf, raw = (dest / x for x in ("handler.o", "handler.elf", "handler.bin"))
        run("arm-none-eabi-gcc", "-c", "-mcpu=cortex-m3", "-mthumb",
            "-ffreestanding", "-nostdlib", "-o", str(obj), str(asm))
        run("arm-none-eabi-ld", "-T", str(linker), "-o", str(elf), str(obj))
        run("arm-none-eabi-objcopy", "-O", "binary", str(elf), str(raw))
        return (raw.read_bytes(), run("arm-none-eabi-readelf", "-r", str(obj)),
                run("arm-none-eabi-nm", "-n", str(elf)),
                run("arm-none-eabi-objdump", "-d", str(elf)))


def patches_from_builder(builder: str) -> list[tuple[int, str]]:
    parsed = ast.parse(builder)
    values = {}
    for statement in ast.walk(parsed):
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id in {
                    "core_patches", "TIMING_HOOKS", "ENABLE_ADVANCED_HOOKS"
                }:
                    values[target.id] = ast.literal_eval(statement.value)
    if values.get("ENABLE_ADVANCED_HOOKS") is not False:
        raise ValueError("advanced hooks enabled or could not be authenticated")
    if "[(0x0802A5F2,'heap_init_sidecar_wrapper')]" not in builder:
        raise ValueError("heap-init patch contract changed")
    patches = (values["core_patches"] + values["TIMING_HOOKS"] +
               [(0x0802A5F2, "heap_init_sidecar_wrapper")])
    if patches != EXPECTED_PATCHES:
        raise ValueError("original v3.22 builder callsite list changed")
    return patches


def flash_word_literals(source: str) -> list[dict]:
    equiv = {name: int(value, 16) for name, value in SOURCE_EQU.findall(source)}
    flagged = []
    for match in SOURCE_WORD.finditer(source):
        for arg in match.group(1).split(","):
            token = arg.strip()
            if not token:
                continue
            try:
                number = int(token, 0)
            except ValueError:
                number = equiv.get(token)
            if number is None:
                raise ValueError(f"unknown .word expression: {token}")
            if 0x08000000 <= number < 0x08100000:
                flagged.append({"word": token, "address": hex(number)})
    return flagged


def inspect(v313: bytes, v322: bytes, handler: bytes,
            relocations: str, symbols: str, source: str, builder: str) -> dict:
    audited(v313)
    audited(v322)
    if DELTA != 0xD000 or PHYSICAL_HANDLER != 0x0802DE38:
        raise ValueError("real APP geometry differs")
    prefix = PHYSICAL_HANDLER - LINK_BASE
    if len(handler) != 2468 or len(v322) != prefix + len(handler):
        raise ValueError("saved v3.22 append length differs")
    if v322[prefix:] != handler:
        raise ValueError("compiled handler does not exactly match saved APP tail")

    suspicious_words = flash_word_literals(source)
    if suspicious_words:
        raise ValueError(f"unchecked absolute Flash .word literal: {suspicious_words}")
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    candidates = RELOC_LINE.findall(relocations)
    if len(candidates) != EXPECTED_EXTERNAL_RELOCS:
        raise ValueError(f"expected 15 external branch relocations, found {len(candidates)}")
    if Counter(int(target, 16) for _, _, target, _ in candidates) != EXPECTED_EXTERNAL_TARGET_COUNTS:
        raise ValueError("external OEM target inventory changed")
    outgoing = []
    for offset_s, kind, target_s, external in candidates:
        if kind not in {"R_ARM_THM_CALL", "R_ARM_THM_JUMP24"}:
            raise ValueError(f"unrecognized external relocation: {kind}")
        off = int(offset_s, 16)
        nominal_target = int(target_s, 16)
        if not external.startswith("*ABS*0x"):
            raise ValueError("expected absolute OEM external relocation reference")
        if int(external.removeprefix("*ABS*0x"), 16) != nominal_target:
            raise ValueError("ELF relocation symbol differs from OEM target")
        nom_pc = NOMINAL_HANDLER + off
        pc = PHYSICAL_HANDLER + off
        raw = handler[off:off+4]
        nominal = list(cs.disasm(raw, nom_pc, count=1))
        real = list(cs.disasm(raw, pc, count=1))
        if len(nominal) != 1 or len(real) != 1:
            raise ValueError("external branch not decodable")
        op = "bl" if kind == "R_ARM_THM_CALL" else "b.w"
        phys_target = nominal_target - DELTA
        if (nominal[0].size != 4 or real[0].size != 4 or
                nominal[0].mnemonic != op or real[0].mnemonic != op or
                nominal[0].op_str != f"#{nominal_target:#x}" or
                real[0].op_str != f"#{phys_target:#x}"):
            raise ValueError(f"external relocation opcode/PC target mismatch at {pc:#x}")
        if not (LINK_BASE <= phys_target < PHYSICAL_HANDLER):
            raise ValueError("external branch leaves preserved vendor ROM")
        target_off = phys_target - LINK_BASE
        if v313[target_off:target_off+4] != v322[target_off:target_off+4]:
            raise ValueError("OEM destination differs across pinned saved generations")
        if not list(cs.disasm(v322[target_off:target_off+4],
                              phys_target, count=1)):
            raise ValueError("OEM target instruction is not decodable")
        outgoing.append({"physical_callsite": hex(pc),
                         "target": hex(phys_target),
                         "kind": op, "original_OEM_target_prefix_same": True})

    names = {}
    for line in symbols.splitlines():
        hit = SYMBOL_LINE.fullmatch(line.strip())
        if hit:
            names[hit.group(2)] = int(hit.group(1), 16)
    patches = patches_from_builder(builder)
    incoming = []
    for nominal, name in patches:
        if name not in names:
            raise ValueError(f"handler entry not found in built ELF: {name}")
        physical_pc = nominal - DELTA
        physical_target = names[name] - DELTA
        if not (LINK_BASE <= physical_pc < PHYSICAL_HANDLER):
            raise ValueError("patched firmware callsite outside preserved original APP")
        if not (PHYSICAL_HANDLER <= physical_target < LINK_BASE + len(v322)):
            raise ValueError("patched wrapper entry outside saved handler")
        candidate = list(cs.disasm(v322[physical_pc-LINK_BASE:
                                        physical_pc-LINK_BASE+4],
                                   physical_pc, count=1))
        if (len(candidate) != 1 or candidate[0].size != 4 or
                candidate[0].mnemonic != "bl" or
                candidate[0].op_str != f"#{physical_target:#x}"):
            raise ValueError(f"patched MCU BL mismatch: {name} at {physical_pc:#x}")
        handler_offset = physical_target - LINK_BASE
        if not list(cs.disasm(v322[handler_offset:handler_offset+4],
                              physical_target, count=1)):
            raise ValueError("wrapper entry Thumb disassembly failed")
        incoming.append({"patched_site": hex(physical_pc),
                         "handler_entry": hex(physical_target), "name": name})

    if len(incoming) != EXPECTED_PATCHED_CALLS or len(outgoing) != EXPECTED_EXTERNAL_RELOCS:
        raise ValueError("incomplete patch/relocation census")
    return {
        "real_saved_APP_base": hex(LINK_BASE),
        "saved_handler_origin": hex(PHYSICAL_HANDLER),
        "compiled_handler_identical_to_SHA_locked_v322": True,
        "external_Thumb_branch_relocations_verified": len(outgoing),
        "modified_original_APP_branch_sites_verified": len(incoming),
        "absolute_Flash_word_literals_in_handler_source": suspicious_words,
        "raw_32bit_opcode_patterns_misclassified_as_literals": False,
        "outgoing_edges": outgoing, "patched_hook_edges": incoming,
        "all_absolute_ROM_loads_across_whole_original_APP_proven": False,
        "whole_device_control_flow_and_interrupt_safety_proven": False,
        "MCU_SET_RESET_or_flash_authorized": False,
        "physical_CFS_access": False,
    }


def regression(v313: bytes, v322: bytes, handler: bytes, relocs: str,
               names: str, source: str, builder: str) -> dict:
    failed = []

    def must_fail(label: str, action) -> None:
        try:
            action()
        except (ValueError, SyntaxError):
            failed.append(label)
        else:
            raise AssertionError(f"unsafe fixture not rejected: {label}")

    altered = bytearray(v322)
    site = EXPECTED_PATCHES[0][0] - DELTA - LINK_BASE
    altered[site] ^= 1
    must_fail("changed_patched_BL_opcode",
              lambda: inspect(v313, bytes(altered), handler, relocs, names, source, builder))
    must_fail("new_external_absolute_relocation_type",
              lambda: inspect(v313, v322, handler,
                              relocs.replace("R_ARM_THM_CALL", "R_ARM_ABS32", 1),
                              names, source, builder))
    must_fail("external_relocation_target_mutated",
              lambda: inspect(v313, v322, handler,
                              relocs.replace("0803393c", "0803393e", 1),
                              names, source, builder))
    must_fail("new_unreviewed_builder_patch",
              lambda: patches_from_builder(
                  builder.replace("[(0x0802A5F2,'heap_init_sidecar_wrapper')]",
                                  "[(0x0802A5F2,'heap_init_sidecar_wrapper'),"
                                  "(0x0801A4CC,'extra_wrapper')]")))
    must_fail("new_absolute_ROM_literal_word",
              lambda: flash_word_literals(source + "\nabsolute_probe: .word 0x0803393C\n")
              and raise_literal_error())
    return {"negative_scenarios_rejected": len(failed),
            "rejected_cases": failed, "MCU_release_allowed": False}


def raise_literal_error():
    raise ValueError("absolute ROM pointer added without relocation audit")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--v313", type=Path, required=True)
    parser.add_argument("--v322", type=Path, required=True)
    parser.add_argument("--asm", type=Path, required=True)
    parser.add_argument("--linker", type=Path, required=True)
    parser.add_argument("--builder", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    source, builder = args.asm.read_text(), args.builder.read_text()
    handler, relocs, names, _ = compiled_unchanged(args.asm, args.linker)
    old, new = pinned(args.v313, "intermediate_v313"), pinned(args.v322, "running_v322")
    result = inspect(old, new, handler, relocs, names, source, builder)
    if args.self_test:
        result["regression"] = regression(old, new, handler, relocs, names, source, builder)
    output = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
