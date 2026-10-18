#!/usr/bin/env python3
"""CFS saved-image ADC register-operation local dataflow (strict and offline).

Find ROM literals pointing at ADC0/1/2 peripherals, then use the actual
manufacturer Thumb instructions to follow a PC-relative LDR and a
*single straight-line* register base through exact ADD/SUB immediate
and LDR/STR memory operations. Unknown writes / branches / IT and calls
terminate the trace. Only genuine register-address arithmetic is
classified; no motor-current ADC channel owner or code reachability
is inferred from local syntax alone.

This scan is neither a control-flow graph nor hardware instrumentation.
RDATA reads may clear EOC on a live GD32; no live register is sampled.
No MCU / CM5 / Kalico interaction, writes, motion, or flash.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from collections import Counter

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_adc_gpio_literal_xref_discovery import find_original_literals, candidate_pc_load_xrefs, PERIPHERALS

ADC_OFFSETS = {
    0x00:"STAT",
    0x04:"CTL0",
    0x08:"CTL1",
    0x0c:"SAMPT0",
    0x10:"SAMPT1",
    0x2c:"RSQ0",
    0x30:"RSQ1",
    0x34:"RSQ2",
    0x4c:"RDATA",
    0x50:"IDATA0",
    0x54:"IDATA1",
    0x58:"IDATA2",
    0x5c:"IDATA3",
    0x80:"OVSAMPCTL",
}
MAX_FORWARD_INSTRUCTIONS=15
MAX_REPORTED_TRACES=250
CONTROL_FLOW=("b","bl","bx","blx","cbz","cbnz","it","itt","ite","ittt","pop","tbb","tbh","svc")


def actual_peripheral(address:int):
    for name,(lo,hi) in PERIPHERALS.items():
        if name.startswith("ADC") and lo<=address<hi:
            return name, address-lo
    return None


def immediate_arithmetic(ins,base_reg):
    if ins.mnemonic not in ("add","adds","add.w","addw","sub","subs","sub.w","subw"):
        return None
    ops=ins.operands
    if len(ops)==2 and ops[0].type==ARM_OP_REG and ops[0].reg==base_reg and ops[1].type==ARM_OP_IMM:
        return (1 if ins.mnemonic.startswith("add") else -1)*ops[1].imm
    if (len(ops)==3 and ops[0].type==ARM_OP_REG and ops[0].reg==base_reg
            and ops[1].type==ARM_OP_REG and ops[1].reg==base_reg
            and ops[2].type==ARM_OP_IMM):
        return (1 if ins.mnemonic.startswith("add") else -1)*ops[2].imm
    return None


def trace(image:bytes,load_pc:int,rom_literal:int,register:int,cs):
    begin=load_pc-LINK_BASE
    if not 0<=begin<=len(image)-4:
        raise ValueError("original LDR candidate outside saved APP")
    decoder=cs.disasm(image[begin: min(len(image),begin+96)],load_pc)
    first=next(decoder,None)
    if (first is None or first.mnemonic!="ldr" or len(first.operands)<2
            or first.operands[0].type!=ARM_OP_REG
            or first.operands[1].type!=ARM_OP_MEM
            or first.operands[1].mem.base!=ARM_REG_PC
            or ((load_pc+4)&~3)+first.operands[1].mem.disp != rom_literal):
        raise ValueError("literal lookup no longer decodes as expected")

    base_reg=first.operands[0].reg
    current=register
    operations=[]
    boundary="max_instruction_window"
    count=0
    for ins in decoder:
        count+=1
        m=ins.mnemonic
        if (m in CONTROL_FLOW or m.startswith("b.") or m.startswith("it")):
            boundary="flow_control"
            break
        if len(ins.operands)>=2 and ins.operands[1].type==ARM_OP_MEM and ins.operands[1].mem.base==base_reg:
            mem=ins.operands[1].mem
            # Disallow scaled indexed and writeback forms: only direct
            # [base, #disp] access with unchanged base is observable.
            if mem.index == 0 and not ins.writeback and m in ("ldr","ldrh","ldrb","str","strh","strb"):
                target=(current+mem.disp)&0xffffffff
                per=actual_peripheral(target)
                if per:
                    name,offset=per
                    operations.append({
                        "instruction_pc":hex(ins.address),
                        "opcode":m,
                        "register_address":hex(target),
                        "peripheral":name,
                        "register_offset":hex(offset),
                        "register_role":ADC_OFFSETS.get(offset,"unclassified_adc_offset"),
                        "access_direction":"write" if m.startswith("str") else "read",
                        "source_instruction":ins.mnemonic+" "+ins.op_str,
                        "reachable_from_reset_or_motor_task_proven":False,
                        "ADC_motor_current_channel_proven":False,
                    })
        delta=immediate_arithmetic(ins,base_reg)
        if delta is not None:
            current=(current+delta)&0xffffffff
        else:
            # Capstone registers access ensures we never continue
            # propagating a literal base across a mystery clobber.
            try: _,writes=ins.regs_access()
            except Exception:
                boundary="register_effect_unknown"
                break
            if base_reg in writes:
                boundary="tracked_base_overwritten"
                break
        if count>=MAX_FORWARD_INSTRUCTIONS:
            break
    return {
        "literal_loader_pc":hex(load_pc),
        "original_rom_literal_slot":hex(rom_literal),
        "initial_peripheral_address":hex(register),
        "straight_line_instructions_examined":count,
        "trace_boundary":boundary,
        "local_original_thumb_register_operations":operations,
        "full_execution_reachability_proven":False,
    }


def analyze(image:bytes):
    audited(image)
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    decoder.detail=True
    all_traces=[]
    for item in find_original_literals(image):
        if not item["peripheral"].startswith("ADC"):
            continue
        candidates,_=candidate_pc_load_xrefs(image,item["ROM_constant_slot"],decoder)
        for src in candidates:
            all_traces.append(trace(image,int(src["candidate_pc"],16),item["ROM_constant_slot"],item["register_address"],decoder))
    if len(all_traces)>MAX_REPORTED_TRACES:
        raise ValueError("Unexpected ADC candidate trace growth; review before publishing")
    operations=[op for t in all_traces for op in t["local_original_thumb_register_operations"]]
    roles=Counter((r["peripheral"],r["register_role"],r["access_direction"]) for r in operations)
    rdata=[r for r in operations if r["peripheral"]=="ADC0" and r["register_role"]=="RDATA" and r["access_direction"]=="read"]
    known_source=[r for r in rdata if r["instruction_pc"]=="0x8022bc0"]
    if len(known_source)!=1 or known_source[0]["register_address"]!="0x4001244c":
        raise ValueError("Known manufacturer ADC0_RDATA source-accurate dataflow disappeared")
    return {
        "ROM_physical_base":hex(LINK_BASE),
        "ADC_literal_load_candidates":len(all_traces),
        "bounded_register_access_candidates":len(operations),
        "candidate_access_counts_by_peripheral_role":[
            {"peripheral":k[0],"register":k[1],"direction":k[2],"count":v}
            for k,v in sorted(roles.items())
        ],
        "original_ADC0_RDATA_source_instruction_locally_verified":"0x8022bc0",
        "adc_channel_selection_register_access_candidates":[r for r in operations if r["register_role"] in ("RSQ0","RSQ1","RSQ2")],
        "adc_sampling_register_access_candidates":[r for r in operations if r["register_role"] in ("SAMPT0","SAMPT1")],
        "trace_records":all_traces,
        "can_prove_actual_channel_15_10_1_0_conversions":False,
        "can_prove_motor_task_reached_ADC_helpers":False,
        "can_prove_ADC_result_saved_in_motor_RAM":False,
        "can_prove_all_motors_physically_stopped":False,
        "real_MCU_ADC_EOC_or_DMA_touched":False,
        "v323_flash_or_SET_RESET_release":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    x=p.parse_args()
    old=analyze(pinned(x.v313,"intermediate_v313"))
    new=analyze(pinned(x.v322,"running_v322"))
    same=(old==new)
    report={"saved_manufacturer_v313_v322_ADC_local_dataflow_identical":same,
            "v313":old,"v322":new,
            "local_original_Thumb_not_proof_of_reachable_execution":True,
            "no_live_ADC_read_and_no_flash":True}
    content=json.dumps(report,indent=2)+"\n"
    if x.json_out:x.json_out.write_text(content)
    print(content,end="")

if __name__=="__main__":main()
