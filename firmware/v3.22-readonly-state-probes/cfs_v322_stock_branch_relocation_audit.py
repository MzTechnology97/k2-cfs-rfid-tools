#!/usr/bin/env python3
"""Verify OEM STOCK_* branch relocation in the exact saved CFS v3.22 image.

The legacy builder assembled at nominal 0x0803AE38 although the physical
saved-app origin is 0x08003000 (not 0x08010000). Prove where each OEM
BL/B.W *actually lands* when those identical bytes execute at the
physical append address. This does not certify unrelated absolute loads,
MCU safety, erase ownership, or firmware release.

Only pinned local files, temporary compilation, and offline disassembly.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE

NOMINAL_APP_BASE = 0x08010000
SHIFT = NOMINAL_APP_BASE - LINK_BASE
NOMINAL_HANDLER = 0x0803AE38
PHYSICAL_HANDLER = NOMINAL_HANDLER - SHIFT
ASSEMBLY_REFERENCES = re.compile(
    r"(?m)^\s*\.equ\s+(STOCK_[A-Z_0-9]+),\s*(0x080[0-9A-Fa-f]{5})\s*$"
)
SOURCE_BRANCHES = re.compile(
    r"(?m)^\s*(bl|b\.w)\s+(STOCK_[A-Z_0-9]+)\s*(?:@[^\n]*)?$"
)
EXPECTED_CALLS = {
    "STOCK_MEMCMP": 3,
    "STOCK_MSG_VALIDATE": 1,
    "STOCK_REMAIN_INIT": 1,
    "STOCK_REMAIN_VALID": 1,
    "STOCK_REMAIN_GATE": 1,
    "STOCK_51": 1,
    "STOCK_INVALID": 1,
    "STOCK_DONE": 1,
    "STOCK_HEAP_INIT": 1,
}


def derive_source_contract(source: str) -> dict[str, tuple[int, str, int]]:
    targets = {name: int(address, 16)
               for name, address in ASSEMBLY_REFERENCES.findall(source)}
    operations = SOURCE_BRANCHES.findall(source)
    counts = Counter(name for opcode, name in operations)
    if dict(counts) != EXPECTED_CALLS:
        raise ValueError(f"STOCK branch use inventory changed: {dict(counts)}")
    if set(targets) != set(EXPECTED_CALLS):
        raise ValueError("new/removed ROM STOCK symbol: requalify relocation")
    result = {}
    for name in EXPECTED_CALLS:
        ops = {opcode for opcode, n in operations if n == name}
        if len(ops) != 1:
            raise ValueError(f"mixed direct/indirect transfer for {name}")
        result[name] = (targets[name], ops.pop(), counts[name])
    return result


def assemble(source: Path, linker: Path) -> tuple[bytes, str]:
    with tempfile.TemporaryDirectory(prefix="cfs-stock-branch-offline-") as td:
        td = Path(td)
        obj = td / "handler.o"
        elf = td / "handler.elf"
        raw = td / "handler.bin"
        subprocess.run(["arm-none-eabi-gcc", "-c", "-mcpu=cortex-m3",
                        "-mthumb", "-ffreestanding", "-nostdlib",
                        "-o", str(obj), str(source)], check=True,
                       capture_output=True)
        subprocess.run(["arm-none-eabi-ld", "-T", str(linker),
                        "-o", str(elf), str(obj)], check=True,
                       capture_output=True)
        subprocess.run(["arm-none-eabi-objcopy", "-O", "binary",
                        str(elf), str(raw)], check=True,
                       capture_output=True)
        listing = subprocess.run(["arm-none-eabi-objdump", "-d", str(elf)],
                                 check=True, capture_output=True, text=True).stdout
        return raw.read_bytes(), listing


def inspect(v313: bytes, v322: bytes, handler: bytes, listing: str,
            contracts: dict[str, tuple[int, str, int]]) -> dict:
    if SHIFT != 0xD000 or PHYSICAL_HANDLER != 0x0802DE38:
        raise ValueError("original firmware origin or append offset changed")
    if not audited(v313) or not audited(v322):
        raise ValueError("original ROM provenance failed")
    pos = PHYSICAL_HANDLER - LINK_BASE
    if pos + len(handler) != len(v322):
        raise ValueError("handler size and exact saved file extent differ")
    if v322[pos:] != handler:
        raise ValueError("compiled handler differs from SHA-pinned v3.22")
    if v313[:pos] != v322[:pos]:
        # v3.13 has prior hooks. We only inspect original target ranges.
        pass

    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    # GNU objdump uses ELF symbols to skip data pools embedded between
    # executable function entries; a linear Capstone walk would lose them.
    regex = re.compile(r"(?m)^\s*([0-9a-f]{7,8}):[^\n]*?\s(bl|b\.w)\s+([0-9a-f]{7,8})\b")
    branches = [(int(m.group(1), 16), m.group(2), int(m.group(3), 16))
                for m in regex.finditer(listing)]
    decoded = Counter((opcode, dest) for _, opcode, dest in branches)
    # Compiler-generated branches must match every used OEM symbol exactly.
    records = []
    for name, (nominal_target, opcode, count) in contracts.items():
        if decoded[(opcode, nominal_target)] != count:
            raise ValueError(f"{name}: expected {count} original {opcode} "
                             f"transfers but found {decoded[(opcode, nominal_target)]}")
        matching = [addr for addr, op, dest in branches
                    if op == opcode and dest == nominal_target]
        for nominal_call in matching:
            physical_source = nominal_call - SHIFT
            physical_target = nominal_target - SHIFT
            if not (LINK_BASE <= physical_target < PHYSICAL_HANDLER):
                raise ValueError(f"{name}: relocated OEM destination outside preserved APP")
            offset = physical_source - PHYSICAL_HANDLER
            nominal_ins = list(cs.disasm(handler[offset:offset+4],
                                         nominal_call, count=1))
            relocated = list(cs.disasm(handler[offset:offset+4],
                                       physical_source, count=1))
            if (len(nominal_ins) != 1 or nominal_ins[0].size != 4 or
                    nominal_ins[0].mnemonic != opcode or
                    nominal_ins[0].op_str != f"#{nominal_target:#x}" or
                    len(relocated) != 1 or relocated[0].size != 4 or
                    relocated[0].mnemonic != opcode or
                    relocated[0].op_str != f"#{physical_target:#x}"):
                raise ValueError(f"{name}: physical PC-relative target mismatch")
            target_offset = physical_target - LINK_BASE
            if v313[target_offset:target_offset+4] != v322[target_offset:target_offset+4]:
                raise ValueError(f"{name}: OEM entry bytes changed across saved baselines")
            entry = list(cs.disasm(v322[target_offset:target_offset+4],
                                   physical_target, count=1))
            if not entry:
                raise ValueError(f"{name}: target is not decodable OEM Thumb source")
            records.append({
                "symbol": name, "branch_kind": opcode,
                "saved_file_call_offset": hex(physical_source-LINK_BASE),
                "nominal_assembly_call": hex(nominal_call),
                "real_execution_call": hex(physical_source),
                "nominal_branch_destination": hex(nominal_target),
                "real_branch_destination": hex(physical_target),
                "saved_vendor_ROM_target_verified": True
            })
    if len(records) != sum(EXPECTED_CALLS.values()):
        raise ValueError("branch coverage unexpectedly incomplete")
    return {
        "verified_legacy_nominal_vs_actual_shift": hex(SHIFT),
        "physical_app_base": hex(LINK_BASE),
        "appended_handler_physical_start": hex(PHYSICAL_HANDLER),
        "compiled_handler_matches_SHA_pinned_saved_v322": True,
        "OEM_direct_branch_targets_source_relocated": records,
        "verified_STOCK_branch_occurrences": len(records),
        "absolute_nonbranch_references_proven_safe": False,
        "loader_and_spare_flash_ownership_proven": False,
        "MCU_motor_safe_or_flash_release_approved": False,
        "live_hardware_or_printer_access": False
    }



def negative_regressions(v313: bytes, v322: bytes, handler: bytes,
                         listing: str, contracts: dict, source: str) -> dict:
    """Offline negative fixtures: every unsafe inference must fail closed."""
    failures = []

    def must_reject(name: str, operation) -> None:
        try:
            operation()
        except ValueError:
            failures.append(name)
        else:
            raise AssertionError(f"unsafe relocation fixture accepted: {name}")

    changed_image = bytearray(v322)
    changed_image[PHYSICAL_HANDLER - LINK_BASE + 12] ^= 1
    must_reject("changed_binary_does_not_match_compiled_handler",
                lambda: inspect(v313, bytes(changed_image), handler,
                                listing, contracts))

    wrong_target = dict(contracts)
    target, op, count = wrong_target["STOCK_MEMCMP"]
    wrong_target["STOCK_MEMCMP"] = (target+4, op, count)
    must_reject("incorrect_memcmp_branch_target",
                lambda: inspect(v313, v322, handler,
                                listing, wrong_target))

    changed_source = source.replace("bl      STOCK_MEMCMP",
                                    "blx     STOCK_MEMCMP", 1)
    if changed_source == source:
        raise AssertionError("cannot prepare indirect-branch negative fixture")
    must_reject("new_indirect_stock_branch_not_authenticated",
                lambda: derive_source_contract(changed_source))

    must_reject("new_unreviewed_absolute_stock_symbol",
                lambda: derive_source_contract(
                    source + "\n.equ STOCK_NEW, 0x08012344\n"))

    return {"total_rejected": len(failures), "rejected_cases": failures,
            "motor_writes_or_firmware_flash_permitted": False}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--v313", type=Path, required=True)
    parser.add_argument("--v322", type=Path, required=True)
    parser.add_argument("--asm", type=Path, required=True)
    parser.add_argument("--linker", type=Path, required=True)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    source = args.asm.read_text()
    contracts = derive_source_contract(source)
    handler, listing = assemble(args.asm, args.linker)
    v313 = pinned(args.v313, "intermediate_v313")
    v322 = pinned(args.v322, "running_v322")
    result = inspect(v313, v322, handler, listing, contracts)
    if args.self_test:
        result["negative_regressions"] = negative_regressions(
            v313, v322, handler, listing, contracts, source)
    output = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
