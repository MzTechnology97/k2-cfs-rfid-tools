#!/usr/bin/env python3
"""Offline CFS GD32F303 ADC / motor GPIO literal-xref discovery.

Purpose: locate *candidate* ADC and GPIO-D direct-register accesses in
the original saved CFS v3.13 and v3.22 manufacturer bytes, linked at
0x08003000, without confusing MCU pin-function availability with
firmware ADC sampling evidence.

A 32-bit constant in ROM may be data, not executable code; a Thumb
PC-relative literal load may be a true use, but can also appear while
disassembling embedded non-code. All matches are DIAGNOSTIC ONLY and
require independent callgraph/flow verification before attributing
any motor current sensor. Discovery is intentionally incomplete if
code synthesizes an address using MOVW/MOVT, PC-relative tables, or
a generic peripheral driver.

NO firmware patch, MCU MMIO access, bootloader writes, or motors.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE

PERIPHERALS = {
    "ADC0":(0x40012400,0x40012500),
    "ADC1":(0x40012800,0x40012900),
    "ADC2":(0x40013C00,0x40013D00),
    "GPIO_D":(0x40011400,0x40011500),
}
CHIP_ADC_MOTOR_PADS={
    "M1":{"pad":"PC5","channel_candidate":15},
    "M2":{"pad":"PC0","channel_candidate":10},
    "M3":{"pad":"PA1","channel_candidate":1},
    "M4":{"pad":"PA0","channel_candidate":0},
}

MAX_XREF_WINDOW=4096
MAX_LITERALS_REPORTED=180
MAX_XREFS_PER_LITERAL=32


def find_original_literals(image:bytes):
    literals=[]
    for offset in range(0,len(image)-3,4):
        value=struct.unpack_from("<I",image,offset)[0]
        for label,(lo,hi) in PERIPHERALS.items():
            if lo<=value<hi and value%4==0:
                literals.append({
                    "peripheral":label,
                    "ROM_constant_slot":LINK_BASE+offset,
                    "register_address":value,
                    "peripheral_offset":value-lo,
                })
                break
    return literals


def candidate_pc_load_xrefs(image:bytes,literal_pc:int,cs):
    # Literal Thumb load bounds: maximum 12-bit positive displacement,
    # and architecture-specific negative forms within this bound.
    center=literal_pc-LINK_BASE
    lo=max(0,(center-MAX_XREF_WINDOW-8)&~1)
    hi=min(len(image)-4,(center+MAX_XREF_WINDOW+8)&~1)
    rows=[]
    for i in range(lo,hi,2):
        address=LINK_BASE+i
        ins=next(cs.disasm(image[i:i+4],address,count=1),None)
        if not ins or ins.address!=address or ins.mnemonic!="ldr":
            continue
        if len(ins.operands)<2:
            continue
        src=ins.operands[1]
        if src.type!=ARM_OP_MEM or src.mem.base!=ARM_REG_PC:
            continue
        target=((address+4)&~3)+src.mem.disp
        if target!=literal_pc:
            continue
        rows.append({"candidate_pc":hex(address),
                     "instruction":ins.mnemonic+" "+ins.op_str,
                     "pc_target_literal":hex(target)})
    return rows[:MAX_XREFS_PER_LITERAL],len(rows)


def analyze(image:bytes):
    audited(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    literals=find_original_literals(image)
    if len(literals)>MAX_LITERALS_REPORTED:
        raise ValueError("More peripheral literal candidates than diagnostic cap: manual scope review")
    records=[]
    for r in literals:
        xrefs,n=candidate_pc_load_xrefs(image,r["ROM_constant_slot"],cs)
        records.append({
            "peripheral":r["peripheral"],
            "candidate_register_address":hex(r["register_address"]),
            "register_offset":hex(r["peripheral_offset"]),
            "literal_ROM_slot":hex(r["ROM_constant_slot"]),
            "candidate_thumb_pc_relative_loads":xrefs,
            "total_candidate_loads_before_display_cap":n,
            "is_confirmed_executed_ADC_conversion":False,
            "is_confirmed_motor_GPIO_command":False,
        })
    group=Counter(x["peripheral"] for x in records)
    referenced=Counter(x["peripheral"] for x in records
                       if x["total_candidate_loads_before_display_cap"]>0)
    return {
      "physical_saved_APP_origin":hex(LINK_BASE),
      "saved_image_sha256":hashlib.sha256(image).hexdigest(),
      "peripheral_register_search_ranges":{
        label:{"start":hex(lo),"end_exclusive":hex(hi)}
        for label,(lo,hi) in PERIPHERALS.items()
      },
      "number_of_aligned_ROM_constant_candidates":len(records),
      "literal_candidates_by_peripheral":dict(group),
      "literal_candidates_with_possible_PC_relative_load":dict(referenced),
      "raw_literal_and_candidate_xref_records":records,
      "physical_motors_to_possible_ADC_channel_numbers_FROM_DATASHEET":
          CHIP_ADC_MOTOR_PADS,
      "ADC0_ADC1_ADC2_initialization_and_config_flow_authenticated":False,
      "motor_current_channel_sequence_proven":False,
      "motor_current_RAM_destinations_proven":False,
      "motor_current_ADC_calibration_or_fault_handling_proven":False,
      "GPIO_D_PD0_PD3_actual_command_ownership_proven":False,
      "any_real_CFS_register_or_RAM_read_performed":False,
      "motor_physical_STOPPED_status_proven":False,
      "v323_flash_or_MCU_SET_RESET_authorized":False,
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--v313",required=True,type=Path)
    ap.add_argument("--v322",required=True,type=Path)
    ap.add_argument("--json-out",type=Path)
    a=ap.parse_args()
    old=analyze(pinned(a.v313,"intermediate_v313"))
    now=analyze(pinned(a.v322,"running_v322"))
    # The experiments changed RFID and sidecar code. If reference
    # counts change, preserve both reports without discarding evidence.
    report={
      "baseline_saved_v313":old,
      "current_saved_v322":now,
      "same_literal_and_candidate_xref_inventory":(
          old["raw_literal_and_candidate_xref_records"]==
          now["raw_literal_and_candidate_xref_records"]
      ),
      "source_only_scoping_not_complete_control_flow":True,
      "no_real_device_interaction":True,
      "safe_to_flash_v323":False,
    }
    out=json.dumps(report,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(out)
    print(out,end="")


if __name__=="__main__":
    main()
