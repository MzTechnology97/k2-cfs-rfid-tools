#!/usr/bin/env python3
"""Inspect two independently pinned original GPIO_D base-literal consumers.

The rebuilt CFS APP is physically linked at 0x08003000. Earlier
read-only ROM scans found two original PC-relative LDR sites using the
GPIO_D base 0x40011400. This script rechecks the exact ARM source and
extracts *bounded* subsequent register accesses and branches.

This is a candidate access-path census, NOT proof that the instruction
sequences are reached from a motor driver, nor that PD0..PD3 are
manipulated during a particular movement. No MCU read or write.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM, ARM_REG_PC, ARM_REG_R4
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE

PORT_D_BASE = 0x40011400
LOCATIONS = (
    ("gpio_d_candidate_1",0x0801B686,0x0801B75C),
    ("gpio_d_candidate_2",0x080236F6,0x08023948),
)
REGISTERS = {
    0x00:"CTL0_configuration_PD0_PD7",
    0x04:"CTL1_configuration_PD8_PD15",
    0x08:"ISTAT_input_status",
    0x0C:"OCTL_output_latch",
    0x10:"BOP_atomic_pin_set_or_reset",
    0x14:"BC_atomic_pin_clear",
    0x18:"LOCK_configuration_lock",
    0x3C:"SPD_speed_selection",
}
MAX_FORWARD_BYTES=128


def inspect(image: bytes) -> dict:
    audited(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    found=[]
    for title,pc,literal in LOCATIONS:
        lp=literal-LINK_BASE
        ix=pc-LINK_BASE
        if min(lp,ix)<0 or lp+4>len(image) or ix+4>len(image):
            raise ValueError("GPIO_D source outside authenticated application")
        word=struct.unpack_from("<I",image,lp)[0]
        if word!=PORT_D_BASE:
            raise ValueError("original GPIO_D literal changed")
        ins=next(cs.disasm(image[ix:ix+4],pc,count=1),None)
        if (ins is None or ins.mnemonic!="ldr" or ins.op_str.split(",")[0]!="r4"
            or len(ins.operands)<2 or ins.operands[1].type!=ARM_OP_MEM
            or ins.operands[1].mem.base!=ARM_REG_PC):
            raise ValueError(f"GPIO_D Thumb LDR encoding differs at {pc:#x}")
        target=((pc+4)&~3)+ins.operands[1].mem.disp
        if target!=literal:
            raise ValueError("PC-relative literal no longer resolves GPIO_D")
        rows=[]
        r4_refs=[]
        for x in cs.disasm(image[ix:min(ix+MAX_FORWARD_BYTES,len(image))],pc):
            if len(rows)>=70:
                break
            row={"pc":hex(x.address),"instruction":x.mnemonic+" "+x.op_str}
            mem_ops=[o for o in x.operands if o.type==ARM_OP_MEM
                     and o.mem.base==ARM_REG_R4]
            if mem_ops:
                for mem in mem_ops:
                    # We do not claim r4 is stable across control-flow
                    # paths, so this is only a *candidate* base+offset.
                    row["candidate_GPIO_D_offset_if_R4_still_base"]=hex(mem.mem.disp)
                    row["candidate_peripheral_register_if_R4_still_base"]=REGISTERS.get(
                        mem.mem.disp,"unknown_GPIO_D_offset")
                r4_refs.append(row.copy())
            rows.append(row)
        if not rows or rows[0]["pc"]!=hex(pc):
            raise ValueError("could not disassemble original GPIO_D consumer")
        found.append({
            "window":title,
            "original_source_instruction":hex(pc),
            "original_ROM_literal_slot":hex(literal),
            "confirmed_literal_value":hex(word),
            "bounded_forward_window_bytes":MAX_FORWARD_BYTES,
            "assembly_window":rows,
            "potential_R4_relative_accesses":r4_refs,
            "definite_control_flow_reachability_from_motor_task_proven":False,
            "R4_register_live_range_proven":False,
            "actual_GPIO_pin_state_observed":False,
        })
    return {
        "real_APP_link_base":hex(LINK_BASE),
        "GPIO_D_base":hex(PORT_D_BASE),
        "original_loads_validated":len(found),
        "confirmed_original_GPIO_D_literal_consumers":found,
        "known_GPIO_D_register_offsets_from_GD32_manual":{
            hex(k):v for k,v in REGISTERS.items()
        },
        "M1_M2_PD0_PD3_motor_driver_control_dataflow_proven":False,
        "motor_running_or_stopped_feedback_proven":False,
        "independent_motor_interlock_safe_for_flash":False,
        "performed_actual_CFS_or_CM5_access":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    old=inspect(pinned(args.v313,"intermediate_v313"))
    cur=inspect(pinned(args.v322,"running_v322"))
    # All the analyzed original source is expected to be unchanged;
    # reject if the two saved generations differ.
    if old!=cur:
        raise ValueError("GPIO_D original literal and bounded Thumb windows differ")
    out={
        "original_saved_v313_v322_windows_match":True,
        "v322":cur,
        "source_only_not_motor_reachability":True,
        "no_hardware_or_firmware_changes":True,
        "v323_flash_release_allowed":False,
    }
    body=json.dumps(out,indent=2)+"\n"
    if args.json_out:
        args.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":
    main()
