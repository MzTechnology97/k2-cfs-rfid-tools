#!/usr/bin/env python3
"""Focused READ-ONLY Thumb trace around original ADC0_CTL1 constant loads.

The broad GD32 register ROM-literal discovery observed a real constant
0x40012408 (=ADC0_CTL1, GD32F30x base 0x40012400 + offset 0x08)
at physical APP address 0x08022C88, with candidate Thumb literal
load sites 0x08022926, 0x08022932, 0x08022988, 0x08022BBC.

This audit checks these original saved instructions against their
actual literal target and disassembles bounded surrounding source,
so a human can determine whether the firmware merely initializes
ADC0 or actually samples the brushed motor currents.

No actual ADC configuration, register reads, motor actions, or patch.
"""
from __future__ import annotations
import argparse,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM,ARM_REG_PC
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE

ADC0_CTL1=0x40012408
ORIGINAL_LITERAL=0x08022C88
CANDIDATE_LOAD_SITES=(0x08022926,0x08022932,0x08022988,0x08022BBC)
WINDOWS=(
    ("adc0_ctl1_config_predecessor",0x08022900,0x080229B0),
    ("adc0_ctl1_second_callsite",0x08022BA0,0x08022BE0),
)
MAX_INSTRUCTIONS_PER_WINDOW=95

def inspect(image):
    audited(image)
    at=ORIGINAL_LITERAL-LINK_BASE
    if not (0<=at<=len(image)-4):
        raise ValueError("original ADC0_CTL1 candidate literal outside physical saved APP")
    if struct.unpack_from("<I",image,at)[0]!=ADC0_CTL1:
        raise ValueError("saved manufacturer ADC0_CTL1 reference changed")
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    loads=[]
    for physical_pc in CANDIDATE_LOAD_SITES:
        i=physical_pc-LINK_BASE
        ins=next(cs.disasm(image[i:i+4],physical_pc,count=1),None)
        if (ins is None or ins.mnemonic!="ldr"
            or len(ins.operands)<2 or ins.operands[1].type!=ARM_OP_MEM
            or ins.operands[1].mem.base!=ARM_REG_PC):
            raise ValueError(f"ADC0_CTL1 site is not original Thumb LDR literal {physical_pc:#x}")
        absolute=((physical_pc+4)&~3)+ins.operands[1].mem.disp
        if absolute!=ORIGINAL_LITERAL:
            raise ValueError(f"ADC0_CTL1 literal site no longer points to pinned ROM slot {physical_pc:#x}")
        loads.append({
            "physical_original_Thumb_PC":hex(physical_pc),
            "disassembly":ins.mnemonic+" "+ins.op_str,
            "literal_PC":hex(absolute),
            "literal_value":hex(ADC0_CTL1),
            "proven_ADC_conversion_result_read":False,
        })
    windows=[]
    for name,start,end in WINDOWS:
        lo=start-LINK_BASE;hi=end-LINK_BASE
        if not 0<=lo<hi<=len(image):
            raise ValueError("bounded context region falls outside saved APP")
        rows=[]
        for x in cs.disasm(image[lo:hi],start):
            rows.append({
                "pc":hex(x.address),
                "opcode":x.mnemonic+" "+x.op_str,
            })
            if len(rows)>=MAX_INSTRUCTIONS_PER_WINDOW:
                break
        windows.append({"window":name,"start":hex(start),
                        "end_exclusive":hex(end),"rows":rows})
    return {
        "original_ADC0_CTL1_MMIO_register":hex(ADC0_CTL1),
        "original_ADC0_CTL1_ROM_literal_PC":hex(ORIGINAL_LITERAL),
        "pinned_literal_loads":loads,
        "bounded_disassembly_contexts":windows,
        "ADC0_initialization_or_read_flow_fully_recovered":False,
        "brushed_M1_M2_M3_M4_ADC_channels_sampled_proven":False,
        "ADC_conversion_RDATA_RAM_consumer_proven":False,
        "safe_to_read_ADC_live_without_side_effects_verified":False,
        "motor_idleness_interlock_proven":False,
        "firmware_flash_or_SET_RESET_permitted":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    old=inspect(pinned(args.v313,"intermediate_v313"))
    now=inspect(pinned(args.v322,"running_v322"))
    if old!=now:
        raise ValueError("original ADC0_CTL1 assembly differs on saved v3.13/v3.22")
    report={"both_saved_versions_same_original_ADC0_CTL1_code":True,
            "v322":now,"live_MCU_access_performed":False,
            "safe_to_flash_v323":False}
    blob=json.dumps(report,indent=2)+"\n"
    if args.json_out:
        args.json_out.write_text(blob)
    print(blob,end="")

if __name__=="__main__":main()
