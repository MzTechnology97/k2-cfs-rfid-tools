#!/usr/bin/env python3
"""Investigate original v3.13/v3.22 callback 0x0801939D code context.

Decode only explicitly bounded, SHA-pinned manufacturer ROM windows.
Print both code and literal pool values to help distinguish:
 - a genuine independent callback entry
 - an interior continuation into a surrounding function
 - a wrong callback literal vs a later overwritten device callback

No presumed executable coverage for halfword scans; no hardware access.
"""
from __future__ import annotations
import argparse, json, struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM,ARM_REG_PC
from flash_ram_phase2_audit import APP_BASE,pinned

WINDOWS=(
    ("suspicious_callback_predecessor",0x08019300,0x080193b8),
    ("pwm_constructor_and_literal",0x08026440,0x08026488),
    ("known_extended_pwm_handler",0x08026380,0x080263d0),
)
TARGETS=(0x0801939c,0x0802639c)
STOCK_PTR=0x0801939d
SHIM_PTR=0x0802639d

def inspect(b):
    c=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    c.detail=True
    windows=[]
    for name,lo,hi in WINDOWS:
        rows=[]
        for ins in c.disasm(b[lo-APP_BASE:hi-APP_BASE],lo):
            d={"pc":hex(ins.address),"bytes":ins.bytes.hex(),"mnemonic":ins.mnemonic,
               "args":ins.op_str}
            for op in ins.operands:
                if op.type==ARM_OP_IMM and op.imm in TARGETS:
                    d["targets_suspicious_entry"]=True
                if op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC:
                    lit=((ins.address+4)&~3)+op.mem.disp
                    if APP_BASE<=lit<=APP_BASE+len(b)-4:
                        d["pc_relative_literal_at"]=hex(lit)
                        d["literal_word"]=hex(struct.unpack_from("<I",b,lit-APP_BASE)[0])
            rows.append(d)
        windows.append({"name":name,"rows":rows})
    raw_refs={}
    for target in (STOCK_PTR,SHIM_PTR):
        encoded=struct.pack("<I",target)
        offsets=[]
        start=0
        while True:
            off=b.find(encoded,start)
            if off<0:break
            offsets.append(hex(APP_BASE+off))
            start=off+1
        raw_refs[hex(target)]=offsets
    return {"original_windows":windows,
            "raw_32bit_value_references":raw_refs,
            "target_addr_is_normal_AAPCS_entry_PROVEN":False,
            "named_pwm_registry_callback_PROVEN":False,
            "physical_rotor_idle_PROVEN":False,
            "runtime_patch_allowed":False}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--v313",required=True,type=Path)
    ap.add_argument("--v322",required=True,type=Path)
    a=ap.parse_args()
    old=inspect(pinned(a.v313,"intermediate_v313"))
    new=inspect(pinned(a.v322,"running_v322"))
    # Comparison requires byte-level identity for printed code windows.
    if old!=new:
        raise ValueError("v3.13/v3.22 original callback code/literal windows differ")
    print("CALLBACK_CONTEXT",json.dumps(new,indent=2))

if __name__=="__main__":main()
