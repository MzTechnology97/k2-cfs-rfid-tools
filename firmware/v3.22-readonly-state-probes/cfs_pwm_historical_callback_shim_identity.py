#!/usr/bin/env python3
"""Prove/deny historical PWM callback and v3.22 extended-shim identity.

Old CFS historical running RAM registers a common type-9 PWM device
callback 0x08014555, including named pwm1.
A stock-derived v3.22 APP contains a potential extended PWM callback at
0x0802639D that interprets opcodes 0x1E04/1E05.
Compare the WHOLE tiny Thumb code slice and its static ROM references.

CAUTION: byte-identical code in two different firmware generations
does not prove that the v3.22 DEVICE REGISTRY actually invokes this
code. In particular the earlier v3.22 five-object constructor was
seen writing a *different* function 0x0801939D into [object+0x38].
Do not patch/hook or infer motor idle on that basis.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB

from flash_ram_phase2_audit import APP_BASE, pinned
from cfs_historical_bootloader_compare import verify_public_blob, FLASH_BASE
from cfs_scatter_candidate_decompress_audit import verify_image

HISTORICAL_OBSERVED_PTR = 0x08014555
CURRENT_EXTENDED_SHIM = 0x0802639D
CURRENT_OTHER_CONSTRUCTOR_PTR = 0x0801939D
EXACT_BYTES = 0x28
HISTORICAL_ROM_SITE = HISTORICAL_OBSERVED_PTR & ~1
CURRENT_ROM_SITE = CURRENT_EXTENDED_SHIM & ~1


def inspect(blob: bytes, base: int, address: int) -> dict:
    offset = address - base
    part = blob[offset:offset+EXACT_BYTES]
    if len(part) != EXACT_BYTES:
        raise ValueError("ROM snippet out of range")
    capstone = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    rows = [{
        "offset": i.address-address,
        "mnemonic":i.mnemonic,
        "operands":i.op_str,
        "instruction_size":i.size,
    } for i in capstone.disasm(part,address)]
    if not rows or rows[0]["offset"] != 0 or sum(x["instruction_size"] for x in rows)!=EXACT_BYTES:
        raise ValueError("original Thumb snippet does not cover intended function range")
    return {
        "sha256_original_Thumb_bytes":hashlib.sha256(part).hexdigest(),
        "full_function_bytes":len(part),
        "instructions":rows,
        "opcode_count":len(rows),
    }


def literals(blob:bytes,base:int,ptr:int) -> list[str]:
    encoded = struct.pack("<I", ptr)
    return [hex(base+i) for i in range(0,len(blob)-3)
            if blob[i:i+4]==encoded]


def compare(old:bytes,current:bytes,intermediate:bytes):
    verify_public_blob(old,"flash")
    verify_image(current)
    a=inspect(old,FLASH_BASE,HISTORICAL_ROM_SITE)
    b=inspect(current,APP_BASE,CURRENT_ROM_SITE)
    x=old[HISTORICAL_ROM_SITE-FLASH_BASE:HISTORICAL_ROM_SITE-FLASH_BASE+EXACT_BYTES]
    y=current[CURRENT_ROM_SITE-APP_BASE:CURRENT_ROM_SITE-APP_BASE+EXACT_BYTES]
    middle=intermediate[CURRENT_ROM_SITE-APP_BASE:CURRENT_ROM_SITE-APP_BASE+EXACT_BYTES]
    if len(middle)!=EXACT_BYTES:
        raise ValueError("intermediate original Thumb slice incomplete")
    diffs=[{
        "offset":hex(k),
        "historical_byte":hex(z),
        "v322_byte":hex(q)
    } for k,(z,q) in enumerate(zip(x,y)) if z!=q]
    mnemonic_diffs = [{
        "at_instruction_index":k,
        "historical":m["mnemonic"],
        "v322":n["mnemonic"]
    } for k,(m,n) in enumerate(zip(a["instructions"],b["instructions"]))
       if m["mnemonic"] != n["mnemonic"]]
    checks={
        "history_common_callback_ptr":hex(HISTORICAL_OBSERVED_PTR),
        "v322_extended_shim_entry":hex(CURRENT_EXTENDED_SHIM),
        "v322_unrelated_constructor_callback_literal":hex(CURRENT_OTHER_CONSTRUCTOR_PTR),
        "historical_function":a,
        "v322_function":b,
        "exact_40_original_Thumb_bytes_identical":not diffs,
        "v313_exact_extended_shim_matches_v322":middle==y,
        "v313_extended_shim_matches_old_historical_callback":middle==x,
        "v313_extended_shim_SHA256":hashlib.sha256(middle).hexdigest(),
        "original_byte_difference_count":len(diffs),
        "first_byte_differences":diffs[:20],
        "mnemonic_difference_count":len(mnemonic_diffs),
        "mnemonic_differences":mnemonic_diffs,
        "historical_static_ROM_Thumb_ptr_literals":
            literals(old,FLASH_BASE,HISTORICAL_OBSERVED_PTR),
        "v322_static_ROM_Thumb_ptr_literals":
            literals(current,APP_BASE,CURRENT_EXTENDED_SHIM),
        "v322_other_constructor_Thumb_ptr_literals":
            literals(current,APP_BASE,CURRENT_OTHER_CONSTRUCTOR_PTR),
        "historical_device_names_pinned_to_running_RAM":True,
        "v322_registered_pwm1_callback_proven":False,
        "actual_physical_motor_stop_feedback_proven":False,
        "safe_for_v323_firmware_release":False,
        "live_CFS_queried":False,
    }
    return checks


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--public-flash",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    data=compare(args.public_flash.read_bytes(),
                 pinned(args.v322,"running_v322"),
                 pinned(args.v313,"intermediate_v313"))
    out=json.dumps(data,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(out)
    print(out,end="")


if __name__=="__main__":
    main()
