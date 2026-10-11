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
    ("earlier_gpio_init_code", 0x08027F92, 0x08028006),
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
    # A halfword-wide sweep is NOT a recursively validated code map.
    # It produces hundreds of false positives, especially in ROM DATA.
    print("RAW_HALFWORD_STR54_COUNT", len(hits))
    safe = [{"at":hex(a),"op":m+" "+op} for a,m,op in hits
            if 0x08027F92 <= a < 0x08028006]
    print("TARGETED_EXECUTABLE_STR54", json.dumps(safe))
    candidate_code = {
        0x08027F94: ("ldr", "r4, [pc, #0x98]"),
        0x08027F98: ("subs", "r4, #0x10"),
        0x08027F9C: ("add.w", "r0, r4, #0x70"),
        0x08027FA0: ("str", "r0, [r4, #0x54]"),
        0x08028004: ("pop", "{r4, r5, r6, pc}"),
    }
    for address, expected in candidate_code.items():
        ins = next(cs.disasm(b[address-APP_BASE:address-APP_BASE+4],
                             address,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str) != expected:
            raise ValueError("gpio init Thumb sequence unexpectedly changed")
    gpio_root = struct.unpack_from("<I",b,0x08028030-APP_BASE)[0]
    if gpio_root != 0x200006E8:
        raise ValueError("original gpio-root literal changed")
    gpio_field = gpio_root - 0x10 + 0x54
    expected_name_fields = tuple(0x200007B0 + 96*i for i in range(5))
    if gpio_field != 0x2000072C or gpio_field in expected_name_fields:
        raise ValueError("potential name field alias would invalidate audit")
    report["verified_unrelated_GPIO_field_store"] = {
        "instruction":"0x08027FA0",
        "target_RAM":hex(gpio_field),
        "five_name_fields":[hex(a) for a in expected_name_fields],
        "is_one_of_five_PWM_names":False,
    }
    report["halfword_scan_raw_candidate_count"] = len(hits)
    report["halfword_decode_can_contain_data_false_positives"] = True
    print("NON_PWM_NAME_FIELD_STORE",json.dumps(report["verified_unrelated_GPIO_field_store"]))
    print("NAMES", json.dumps(report["candidate_name_strings"]))
    print("NOTE: 0x080284F8..0x08028530 is treated as DATA, not executable Thumb; earlier STR +0x54 there were false disassembly hits")
    if options.json_out:
        options.json_out.write_text(json.dumps(report, indent=2)+"\n")

if __name__ == "__main__":
    main()
