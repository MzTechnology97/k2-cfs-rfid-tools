#!/usr/bin/env python3
"""Read-only analysis of 5-device CFS PWM name initialization in v3.22.

Show source-accurate Thumb instructions, literal data, and field writes.
Do not infer that a ROM name belongs to a particular runtime object.
No serial/device/hardware operations.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from flash_ram_phase2_audit import APP_BASE, pinned

REGIONS = (
    ("name_preinitializer", 0x08028530, 0x08028578),
    ("five_pwm_object_init", 0x080283BE, 0x08028430),
    ("device_reg_tail", 0x0802644A, 0x08026488),
    ("aux_metadata_init", 0x08028054, 0x080280C0),
)
TARGET_RAM_FIELDS = {0x48, 0x4C, 0x50, 0x54}
NAME_ADDRESSES = (
    0x080399E4, 0x080399EC, 0x080399F4, 0x080399FC, 0x08039A04,
)

def scan(image: bytes):
    cap = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cap.detail = True
    groups, field_ops = [], []
    for label, lo, hi in REGIONS:
        lines = []
        for ins in cap.disasm(image[lo-APP_BASE:hi-APP_BASE], lo):
            lit = None
            for op in ins.operands:
                if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                    pos = ((ins.address + 4) & ~3) + op.mem.disp
                    if APP_BASE <= pos < APP_BASE + len(image) - 3:
                        value = struct.unpack_from("<I", image, pos-APP_BASE)[0]
                        lit = {"at": hex(pos), "word": hex(value)}
                if (op.type == ARM_OP_MEM and op.mem.base != ARM_REG_PC
                        and op.mem.disp in TARGET_RAM_FIELDS):
                    field_ops.append({"at": hex(ins.address), "mnemonic": ins.mnemonic,
                                      "operand": ins.op_str, "region": label,
                                      "offset": hex(op.mem.disp)})
            lines.append({"at": hex(ins.address),
                          "text": ins.mnemonic + " " + ins.op_str, "literal": lit})
        groups.append({"region": label, "instructions": lines})
    names = [
        {"at": hex(a),
         "rom_ascii": image[a-APP_BASE:a-APP_BASE+8].split(b"\x00")[0].decode("ascii", errors="replace"),
         "real_pwm1_object_identity_proven": False}
        for a in NAME_ADDRESSES
    ]
    return {"regions": groups, "metadata_field_ops": field_ops,
            "candidate_name_strings": names,
            "actual_pwm1_object_or_callback_proven": False}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v322", required=True, type=Path)
    p.add_argument("--json-out", type=Path)
    options = p.parse_args()
    b = pinned(options.v322, "running_v322")
    report = scan(b)
    for g in report["regions"]:
        print("REGION", g["region"])
        for line in g["instructions"]:
            print(line["at"], line["text"], line["literal"] or "")
    print("NAMEFIELDS", json.dumps(report["metadata_field_ops"]))
    # Exhaustive halfword scan is deliberately only a CANDIDATE search.
    # Decoder may see plausible instructions inside ROM DATA tables.
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    hits = []
    end = min(len(b), 0x25000)
    for offset in range(0, end - 4, 2):
        addr = APP_BASE + offset
        ins = next(cs.disasm(b[offset:offset+4], addr, count=1), None)
        if ins is None or not ins.mnemonic.startswith(("str", "stm")):
            continue
        for op in ins.operands:
            if (op.type == ARM_OP_MEM and op.mem.base != ARM_REG_PC
                    and op.mem.disp == 0x54):
                hits.append((addr, ins.mnemonic, ins.op_str))
    print("ALL_STR_OFFSET_0x54_CANDIDATES", json.dumps([
        {"at": hex(a), "ins": m+" "+op} for a,m,op in hits]))
    for a,mn,op in hits[:40]:
        print("CANDIDATE_CONTEXT", hex(a), "(may be data!)")
        lo=a-12
        for i in cs.disasm(b[lo-APP_BASE:a+10-APP_BASE],lo):
            print(hex(i.address),i.mnemonic,i.op_str)
    report["global_halfword_54_store_candidates"] = [
        {"at":hex(a),"op":m+" "+op} for a,m,op in hits]
    report["halfword_decode_can_contain_data_false_positives"] = True
    print("NAMES", json.dumps(report["candidate_name_strings"]))
    print("NOTE: 0x080284F8..0x08028530 is treated as DATA, not executable Thumb; earlier STR +0x54 there were false disassembly hits")
    if options.json_out:
        options.json_out.write_text(json.dumps(report, indent=2)+"\n")

if __name__ == "__main__":
    main()
