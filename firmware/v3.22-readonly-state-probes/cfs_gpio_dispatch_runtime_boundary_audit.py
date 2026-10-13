#!/usr/bin/env python3
"""CFS OEM GPIO dispatcher: prove its callback is runtime-only and census
strict, adjacent immediate-argument BL callsites (offline saved ROM only).

Do not infer motor movement from a GPIO write, nor a physical STOP from
absence of a write. Runtime device callback is installed after BSS init
and cannot be read from a saved APP image.

A candidate BL can occur in data; direct adjacent MOVS registers do not
by themselves prove reachability, motor ownership, or motor state.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_m1_m2_gpio_helper_callsites import inspect as helper_calls, GPIO_HELPER

ROOT_LITERAL_PC=0x0801916C
EXPECTED_ROOT=0x20004C44
DEVICE_FIELD_OFFSET=0x40
EXPECTED_FIELD=EXPECTED_ROOT+DEVICE_FIELD_OFFSET
BRAKE_BL=0x0801119E
# The RT-Thread GPIO table was independently pinned to these exact ids.
PINS={
 0x4d:"BLDC_PWM_PE13",0x4b:"BLDC_FG_PE11",
 0x43:"BLDC_DIRECTION_PE3",0x44:"BLDC_BRAKE_PE4",
 0x30:"M2_IN2_PD0",0x31:"M2_IN1_PD1",
 0x32:"M1_IN2_PD2",0x33:"M1_IN1_PD3",
 0x3c:"M4_IN2_PD12",0x3d:"M4_IN1_PD13",
 0x3e:"M3_IN2_PD14",0x3f:"M3_IN1_PD15",
}

def movs_immediate(image:bytes, pc:int, register:str, cs):
    off=pc-LINK_BASE
    if off<0 or off+2>len(image):
        return None
    ins=next(cs.disasm(image[off:off+2],pc,count=1),None)
    if ins is None or ins.size!=2 or ins.mnemonic!="movs":
        return None
    prefix=f"{register}, #"
    if not ins.op_str.startswith(prefix):
        return None
    try:
        value=int(ins.op_str[len(prefix):],0)
    except ValueError:
        return None
    return value if 0<=value<=255 else None

def immediate_window(image:bytes, call_pc:int, cs):
    # Two contiguous 16bit MOVS instructions immediately before the
    # original 32bit BL. No branch or intervening instruction can
    # change either argument inside this exact 4-byte window.
    for reg_a,reg_b in (("r0","r1"),("r1","r0")):
        va=movs_immediate(image,call_pc-4,reg_a,cs)
        vb=movs_immediate(image,call_pc-2,reg_b,cs)
        if va is None or vb is None:
            continue
        args={reg_a:va,reg_b:vb}
        return {
            "call_pc":hex(call_pc),
            "pin_id":hex(args["r0"]),
            "pin_from_confirmed_gpio_lookup":PINS.get(args["r0"]),
            "value_argument":args["r1"],
            "literal_sites":[hex(call_pc-4),hex(call_pc-2)],
            "four_bytes_are_contiguous_MOVS_before_BL":True,
            "actual_function_reachability_proven":False,
            "physical_pin_state_or_motor_activity_proven":False,
        }
    return None

def inspect(image:bytes)->dict:
    initial=audited(image)
    regions=initial["physical_original_scatter_second"]
    first=initial["physical_original_scatter_first"]
    # Current initialized region ends at 0x20000BC4; next region,
    # specified by the *real physical* APP, is a zero-init BSS.
    zero_start=int(regions[1],16)
    zero_bytes=int(regions[2],16)
    init_end=int(first[1],16)+int(first[2],16)
    root=struct.unpack_from("<I",image,ROOT_LITERAL_PC-LINK_BASE)[0]
    if root!=EXPECTED_ROOT or EXPECTED_FIELD!=0x20004C84:
        raise ValueError("original manufacturer GPIO registration root altered")
    if not (init_end==zero_start
            and zero_start<=root<root+zero_bytes
            and zero_start<=EXPECTED_FIELD<root+zero_bytes
            and EXPECTED_FIELD+4<=zero_start+zero_bytes):
        raise ValueError("GPIO device runtime field no longer inside original zero-init BSS")
    candidates=helper_calls(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    immediate=[]
    for row in candidates["callsites"]:
        pc=int(row["possible_original_helper_call_pc"],16)
        result=immediate_window(image,pc,cs)
        if result is not None:
            immediate.append(result)
    brake=[row for row in immediate if row["call_pc"]==hex(BRAKE_BL)]
    if len(brake)!=1 or brake[0]["pin_id"]!="0x44" or brake[0]["value_argument"]!=1:
        raise ValueError("authenticated original PE4 brake immediate call context changed")
    return {
       "saved_APP_physical_base":hex(LINK_BASE),
       "GPIO_dispatch_root_ROM_literal":hex(ROOT_LITERAL_PC),
       "GPIO_dispatch_root_RAM_object":hex(root),
       "GPIO_dispatch_device_pointer_field":hex(EXPECTED_FIELD),
       "first_initialized_RAM_end_exclusive":hex(init_end),
       "zero_init_RAM_start":hex(zero_start),
       "zero_init_RAM_end_exclusive":hex(zero_start+zero_bytes),
       "device_callback_pointer_requires_runtime_registration":True,
       "saved_APP_image_directly_contains_callback_at_runtime_field":False,
       "original_GPIO_helper_Thumb_PC":hex(GPIO_HELPER),
       "all_halfword_scan_BL_candidates":candidates["BL_candidates_found"],
       "strict_adjacent_immediate_argument_candidates":immediate,
       "strict_candidate_count":len(immediate),
       "strict_candidates_on_known_pins":sum(x["pin_from_confirmed_gpio_lookup"] is not None for x in immediate),
       "PE4_brake_argument_path_source_verified":True,
       "any_M1_M2_driver_command_ownership_proven":False,
       "full_callgraph_and_RTOS_registration_reachability_proven":False,
       "safe_to_read_runtime_GPIO_or_ADC_directly":False,
       "all_motors_stopped_proven":False,
       "safe_to_enable_v323_MCU_writes_or_flash":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=inspect(pinned(a.v313,"intermediate_v313"))
    current=inspect(pinned(a.v322,"running_v322"))
    if old!=current:
        raise ValueError("saved v3.13/v3.22 original GPIO BSS/BL immediate census differs")
    result={
      "saved_v313_v322_source_provenance_identical":True,
      "original_GPIO_dispatch":current,
      "read_or_write_on_actual_CFS_or_CM5_performed":False,
      "v323_flash_authorized":False,
    }
    body=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(body)
    print(body,end="")

if __name__=="__main__":
    main()
