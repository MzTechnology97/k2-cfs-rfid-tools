#!/usr/bin/env python3
"""Audit two original CFS PWM callback pointer *writers*, not just targets.

Historical observed running RAM, independently captured:
  five PWM names use the same +0x38 callback 0x08014555.
  Historical original ROM literal at 0x08014A20 holds that pointer.
Modern v3.13/v3.22:
  original five-object constructor stores 0x0801939D at +0x38,
  loading its literal from 0x08026868.

Read each actual Thumb LDR PC-relative reference to these literals and
the nearby stores to compare provenance; never infer that one pointer
is a replacement for the other, nor a physically idle motor.

All old files are pinned public original historical CFS dumps, the
current APP is pinned exact saved v3.22. Read-only.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

from flash_ram_phase2_audit import APP_BASE, pinned
from cfs_historical_bootloader_compare import FLASH_BASE, verify_public_blob
from cfs_scatter_candidate_decompress_audit import verify_image

OLD_LIT = 0x08014A20
NEW_LIT = 0x08026868
OLD_PTR = 0x08014555
NEW_PTR = 0x0801939D
NEW_WRITER_LDR = 0x0802646E
NEW_WRITER_STR = 0x08026470


def u32(blob, base, address):
    offset=address-base
    if not 0<=offset<=len(blob)-4:raise ValueError("ROM address out of bounds")
    return struct.unpack_from("<I",blob,offset)[0]


def pc_loads_to(blob, base, target):
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    dec.detail=True
    hits=[]
    # A normal Thumb PC-relative LDR has positive offsets; search only
    # preceding 4096 bytes for a candidate, and label halfword decode
    # hits as candidate xrefs, not a validated reachable callgraph.
    lo=max(base,target-4096)
    for pc in range(lo,target,2):
        start=pc-base
        decoded=next(dec.disasm(blob[start:start+4],pc,count=1),None)
        if decoded is None or decoded.mnemonic not in ("ldr","ldr.w"):
            continue
        for op in decoded.operands:
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                resolved=((pc+4)&~3)+op.mem.disp
                if resolved == target:
                    hits.append({
                        "pc":hex(pc),
                        "instruction":decoded.mnemonic+" "+decoded.op_str,
                        "target_ROM_literal":hex(resolved),
                    })
    return hits


def original_nearby(blob,base,pc):
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    before=max(base,pc-12)
    after=min(base+len(blob),pc+20)
    rows=[{"pc":hex(i.address),"mnemonic":i.mnemonic,"operands":i.op_str}
          for i in dec.disasm(blob[before-base:after-base],before)]
    return {"window":hex(before),"instructions":rows,
            "halfword_scan_may_include_data":True}


def compare(old,new,mid):
    verify_public_blob(old,"flash")
    verify_image(new)
    if u32(old,FLASH_BASE,OLD_LIT)!=OLD_PTR:
        raise ValueError("old originally registered callback literal changed")
    if (u32(new,APP_BASE,NEW_LIT)!=NEW_PTR
            or u32(mid,APP_BASE,NEW_LIT)!=NEW_PTR):
        raise ValueError("modern constructor callback literal changed")
    old_hits=pc_loads_to(old,FLASH_BASE,OLD_LIT)
    new_hits=pc_loads_to(new,APP_BASE,NEW_LIT)
    mid_hits=pc_loads_to(mid,APP_BASE,NEW_LIT)
    if not old_hits or not new_hits:
        raise ValueError("original PC-relative load of pointer not found")
    if new_hits!=mid_hits:
        raise ValueError("v3.13/v3.22 pointer literal loads differ")
    new_ldr=next((x for x in new_hits if x["pc"]==hex(NEW_WRITER_LDR)),None)
    if new_ldr is None:
        raise ValueError("modern pointer constructor LDR not found")
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    i=next(dec.disasm(new[NEW_WRITER_STR-APP_BASE:NEW_WRITER_STR-APP_BASE+4],
                       NEW_WRITER_STR,count=1),None)
    if i is None or (i.mnemonic,i.op_str)!=("str","r0, [r4, #0x38]"):
        raise ValueError("modern constructor no longer writes callback field +0x38")
    return {
        "older_actual_pwm_name_to_callback_observed":True,
        "old_original_ROM_callback_thumb_ptr":hex(OLD_PTR),
        "old_original_ROM_literal_field":hex(OLD_LIT),
        "older_original_PC_relative_load_candidates":old_hits,
        "old_first_load_context":original_nearby(old,FLASH_BASE,int(old_hits[0]["pc"],16)),
        "modern_constructor_callback_thumb_ptr":hex(NEW_PTR),
        "modern_original_ROM_literal_field":hex(NEW_LIT),
        "modern_original_PC_relative_load_candidates":new_hits,
        "modern_constructor_writes_plus_0x38_at":hex(NEW_WRITER_STR),
        "v313_and_v322_PC_relative_load_sites_equal":True,
        "modern_first_load_context":original_nearby(new,APP_BASE,NEW_WRITER_LDR),
        "old_and_new_pointer_values_differ":OLD_PTR!=NEW_PTR,
        "modern_name_to_object_binding_proven":False,
        "modern_callback_0x0801939D_standard_entry_proven":False,
        "safe_motor_active_hook_proven":False,
        "independent_rotor_idle_proven":False,
        "live_CFS_access":False,
        "v323_release_authorized":False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--historical-flash",type=Path,required=True)
    parser.add_argument("--v313",type=Path,required=True)
    parser.add_argument("--v322",type=Path,required=True)
    parser.add_argument("--json-out",type=Path)
    opt=parser.parse_args()
    report=compare(opt.historical_flash.read_bytes(),
                   pinned(opt.v322,"running_v322"),
                   pinned(opt.v313,"intermediate_v313"))
    result=json.dumps(report,indent=2)+"\n"
    if opt.json_out: opt.json_out.write_text(result)
    print(result,end="")


if __name__=="__main__":
    main()
