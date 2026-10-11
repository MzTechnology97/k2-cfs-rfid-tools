#!/usr/bin/env python3
"""Determine whether the suspicious CFS scatter table is in the reset path.

Safely inspect exact vector table / Thumb branches for pinned v3.13 and
v3.22 applications and separately SHA-pinned historical CFS Flash.
The existence of source data at 0x0803AA10 does NOT establish the table
is used by deployed application startup. Distinguish static references
from proved control flow. This script performs NO hardware operations.
"""
from __future__ import annotations
import argparse,hashlib,json,struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM
from flash_ram_phase2_audit import pinned,APP_BASE,report_image
from cfs_historical_bootloader_compare import verify_public_blob,FLASH_BASE

ANCHOR_SCATTER=0x08010130
APP_TABLE=0x0803AA10
ROOT_ENTRY_WINDOW=256

def examine(image: bytes,root:int):
    msp,reset=struct.unpack_from("<II",image)
    pc=reset&~1
    in_rom=root<=pc<root+len(image)
    data={
       "vector_SP":hex(msp),
       "vector_reset_thumb":hex(reset),
       "vector_reset_pc":hex(pc),
       "vector_points_into_saved_image":in_rom,
       "startup_code":[],
       "direct_branches_to_scatter_0x08010130":[],
       "same_reset_entry_as_historical":False,
       "actual_MCU_startup_execution_observed":False,
    }
    if not in_rom:
        return data
    length=min(ROOT_ENTRY_WINDOW,root+len(image)-pc)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    for ins in cs.disasm(image[pc-root:pc-root+length],pc):
        record={"pc":hex(ins.address),"op":ins.mnemonic,"args":ins.op_str}
        if ins.mnemonic in ("bl","b","b.w","blx"):
            for op in ins.operands:
                if op.type==ARM_OP_IMM:
                    dest=op.imm
                    record["dest"]=hex(dest)
                    if dest==ANCHOR_SCATTER:
                        data["direct_branches_to_scatter_0x08010130"].append(hex(ins.address))
        data["startup_code"].append(record)
    return data

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--public-flash",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    old_app=pinned(args.v313,"intermediate_v313")
    cur_app=pinned(args.v322,"running_v322")
    historical=args.public_flash.read_bytes()
    verify_public_blob(historical,"flash")
    report_image(cur_app,"running_v322")
    d={
      "v313":examine(old_app,APP_BASE),
      "v322":examine(cur_app,APP_BASE),
      "historical_raw_flash":examine(historical,FLASH_BASE),
      "exact_early_application_vector_pair_same_v313_v322":
         old_app[:8]==cur_app[:8],
      "early_application_entry_256B_identical_v313_v322":
         old_app[(struct.unpack_from("<I",old_app,4)[0]&~1)-APP_BASE:
                 (struct.unpack_from("<I",old_app,4)[0]&~1)-APP_BASE+ROOT_ENTRY_WINDOW] ==
         cur_app[(struct.unpack_from("<I",cur_app,4)[0]&~1)-APP_BASE:
                 (struct.unpack_from("<I",cur_app,4)[0]&~1)-APP_BASE+ROOT_ENTRY_WINDOW],
      "data_scatter_table_proves_executed_startup_path":False,
      "actual_CFS_reset_observed":False,
      "release_approved":False,
    }
    output=json.dumps(d,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(output)
    print(output,end="")

if __name__=="__main__": main()
