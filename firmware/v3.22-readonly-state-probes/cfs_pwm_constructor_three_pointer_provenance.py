#!/usr/bin/env python3
"""Trace *all three* original constructor operation pointer literals (+0x30/34/38).

The v3.13 and rebuilt v3.22 copies store:
  [object + 0x30] <- ROM[0x08026860] = 0x080193C5
  [object + 0x34] <- ROM[0x08026864] = 0x08019401
  [object + 0x38] <- ROM[0x08026868] = 0x0801939D

Our previous artificial AAPCS call into +0x38 proved a stack POP, but
this study checks the *original predecessor instructions* as well.
That pointer points inside a checksum/equality path which falls through
from LDRB r0,[r4,#6] and LDRB r1,[r4,#7]. The ordinary standalone
entry, actual RT-Thread invocation, and v3.22 pwm1 registry binding
remain unverified. Do NOT rewrite the literal based on this evidence.

No active CFS/CM5 access, no motor commands or firmware edits.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM,ARM_REG_PC,ARM_OP_REG
from flash_ram_phase2_audit import APP_BASE,pinned

SITES = (
    (0x08026466,0x08026468,0x08026860,0x080193C5,0x30),
    (0x0802646A,0x0802646C,0x08026864,0x08019401,0x34),
    (0x0802646E,0x08026470,0x08026868,0x0801939D,0x38),
)
PRELUDE = (
    (0x08019394,"bl","#0x8018e3a"),
    (0x08019398,"ldrb","r0, [r4, #6]"),
    (0x0801939A,"ldrb","r1, [r4, #7]"),
    (0x0801939C,"ldrb","r2, [r4, #9]"),
    (0x0801939E,"eors","r0, r1"),
    (0x080193A0,"ldrb","r1, [r4, #8]"),
    (0x080193AE,"pop","{r3, r4, r5, pc}"),
    (0x080193B2,"pop","{r3, r4, r5, pc}"),
    (0x080193B4,"push","{r3, r4, r5, lr}"),
    (0x080193C2,"movs","r2, #0x80"),
    (0x080193C4,"movs","r1, #0x13"),
    (0x080193FC,"add.w","r4, r0, r4, lsl #4"),
    (0x08019400,"mov","r0, r5"),
)

def instruction_at(image,pc,cs):
    decoded=next(cs.disasm(image[pc-APP_BASE:pc-APP_BASE+4],pc,count=1),None)
    if decoded is None or decoded.address!=pc:
        raise ValueError(f"missing original Thumb instruction at {pc:#x}")
    return decoded

def analyze(image):
    cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    writes=[]
    for loadpc,storepc,litptr,expected,offset in SITES:
        literal=struct.unpack_from("<I",image,litptr-APP_BASE)[0]
        if literal!=expected:
            raise ValueError(f"original constructor literal altered at {litptr:#x}")
        load=instruction_at(image,loadpc,cs)
        store=instruction_at(image,storepc,cs)
        pc_target=((loadpc+4)&~3)+load.operands[1].mem.disp
        if (load.mnemonic!="ldr" or load.operands[1].type!=ARM_OP_MEM
                or load.operands[1].mem.base!=ARM_REG_PC
                or pc_target!=litptr):
            raise ValueError(f"original constructor literal PC-relative load altered: {loadpc:#x}")
        if (store.mnemonic!="str" or
                store.op_str!=f"r0, [r4, #{hex(offset)}]"):
            raise ValueError(f"original constructor store altered at {storepc:#x}")
        writes.append({"object_field":hex(offset),
                       "literal_ROM":hex(litptr),
                       "stored_thumb_pointer":hex(literal),
                       "source_instruction":hex(loadpc),
                       "writer":hex(storepc)})
    instructions=[]
    for pc,mnem,args in PRELUDE:
        ins=instruction_at(image,pc,cs)
        if (ins.mnemonic,ins.op_str)!=(mnem,args):
            raise ValueError(f"original checksum predecessor differs at {pc:#x}")
        instructions.append({"at":hex(pc),"op":mnem+" "+args})
    for predecessor, entry in (
        (0x0801939A,0x0801939C),
        (0x080193C2,0x080193C4),
        (0x080193FC,0x08019400),
    ):
        ins=instruction_at(image,predecessor,cs)
        if predecessor+ins.size!=entry:
            raise ValueError(f"constructor entry {entry:#x} not aligned to source predecessor")
        if ins.mnemonic.startswith(("b","pop","bx")):
            raise ValueError("unexpected control-flow transfer immediately before supposed interior entry")
    return {
        "original_constructor_three_literal_writes":writes,
        "checksum_predecessor_original_Thumb":instructions,
        "plus38_entered_after_two_preregister_loads_by_sequential_flow":True,
        "all_three_original_constructor_pointers_reach_sequential_code_interiors":True,
        "plus30_predecessor":"0x080193C2 movs r2, #0x80",
        "plus34_predecessor":"0x080193FC add.w r4, r0, r4, lsl #4",
        "plus38_returns_by_pop_from_an_earlier_stack_frame":True,
        "constructor_code_proves_which_named_pwm_instance":False,
        "normal_AAPCS_direct_entry_proven":False,
        "caller_stack_preparation_proven":False,
        "actual_motor_idle_feedback_proven":False,
        "do_not_patch_ROM_or_hook_callback":True,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    opt=p.parse_args()
    a=analyze(pinned(opt.v313,"intermediate_v313"))
    b=analyze(pinned(opt.v322,"running_v322"))
    if a!=b:
        raise ValueError("original constructor or checksum predecessor differs v3.13 vs v3.22")
    r={"same_v313_and_v322":True,"original_provenance":b,
       "no_runtime_access":True,"safe_to_flash_v323":False}
    out=json.dumps(r,indent=2)+"\n"
    if opt.json_out:opt.json_out.write_text(out)
    print(out,end="")

if __name__=="__main__":main()
