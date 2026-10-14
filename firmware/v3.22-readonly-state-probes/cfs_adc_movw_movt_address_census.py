#!/usr/bin/env python3
"""Find ADC MMIO addresses constructed from immediate MOVW/MOVT Thumb pairs.

This supplements, but DOES NOT replace, the saved CFS ADC literal
xref analysis. A *strict* adjacent MOVW Rx,#lo16 / MOVT Rx,#hi16
pair is decoded from the actual SHA-pinned source bytes for v3.13 and
v3.22 linked at physical 0x08003000.

The halfword scanner can land inside literal data or unreachable ROM.
An apparent ADC address is an ADDRESS-CONSTRUCTION CANDIDATE ONLY, not
evidence of a live conversion, selected channel, motor-current sampler
or physical motor stop. More complicated computed addresses are not
covered. No live ADC/MMIO reads; no firmware writes or motor activity.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM,ARM_OP_REG
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE
from cfs_adc_gpio_literal_xref_discovery import PERIPHERALS

MAX_CANDIDATES=120


def decode_pair(image:bytes,i:int,cs):
    pc=LINK_BASE+i
    a=next(cs.disasm(image[i:i+4],pc,count=1),None)
    if a is None or a.mnemonic!="movw" or len(a.operands)!=2:
        return None
    if a.operands[0].type!=ARM_OP_REG or a.operands[1].type!=ARM_OP_IMM:
        return None
    at=i+a.size
    if at+4>len(image):
        return None
    b=next(cs.disasm(image[at:at+4],LINK_BASE+at,count=1),None)
    if b is None or b.mnemonic!="movt" or len(b.operands)!=2:
        return None
    if (b.operands[0].type!=ARM_OP_REG or b.operands[1].type!=ARM_OP_IMM
            or b.operands[0].reg!=a.operands[0].reg):
        return None
    literal=(a.operands[1].imm&0xFFFF)|((b.operands[1].imm&0xFFFF)<<16)
    for name,(lo,hi) in PERIPHERALS.items():
        if name.startswith("ADC") and lo<=literal<hi:
            return {
                "candidate_pc":hex(pc),
                "pair_second_pc":hex(LINK_BASE+at),
                "destination_register":a.op_str.split(",")[0],
                "candidate_peripheral":name,
                "reconstructed_MMIO_address":hex(literal),
                "MMIO_offset":hex(literal-lo),
                "candidate_instruction_pair":[
                    a.mnemonic+" "+a.op_str,b.mnemonic+" "+b.op_str],
                "actual_executable_reachability_proven":False,
                "ADC_current_source_channel_proven":False,
            }
    return None


def inspect(image:bytes):
    audited(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    hits=[]
    for i in range(0,len(image)-7,2):
        x=decode_pair(image,i,cs)
        if x is not None:
            hits.append(x)
    if len(hits)>MAX_CANDIDATES:
        raise ValueError("unexpected MOVW/MOVT candidate count; need scope review")
    return {
        "real_saved_APP_origin":hex(LINK_BASE),
        "adjacent_ADC_register_MOVW_MOVT_candidates":hits,
        "candidate_pair_count":len(hits),
        "full_nonadjacent_or_register_arithmetic_coverage_proven":False,
        "reachable_ADC_channel_selector_or_motor_current_sampler_proven":False,
        "read_from_actual_CFS_ADC_register":False,
        "MCU_physical_stop_proven":False,
        "v323_flash_or_MCU_SET_RESET_authorized":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    old=inspect(pinned(args.v313,"intermediate_v313"))
    new=inspect(pinned(args.v322,"running_v322"))
    report={
        "same_original_saved_v313_v322_ADC_MOVW_MOVT_pair_candidates":old==new,
        "saved_v313":old,
        "saved_v322":new,
        "no_CFS_CM5_or_Kalico_interaction":True,
        "release_gate_passed":False,
    }
    data=json.dumps(report,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(data)
    print(data,end="")


if __name__=="__main__":main()
