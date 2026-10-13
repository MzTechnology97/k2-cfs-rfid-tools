#!/usr/bin/env python3
"""Discover OEM RT-Thread GPIO write-helper callsites near M1/M2 pin IDs.

The physical GD32 CFS firmware calls a function at 0x08018EEC in an
OEM motor command path when providing r0=0x44 (PE4 brake), r1=1.
Its broader semantics are not fully proven; treat all callsites as
CANDIDATES for related pin-control logic only.

We search original Thumb BL encoding for exact target 0x08018EEC
in saved SHA-pinned CFS v3.13/v3.22 manufacturer APP bytes linked
0x08003000. Nearby r0=0x30..0x33 constants (PD0..PD3 RT pin IDs)
are SCOPING HINTS, NOT dataflow proof or established motor ownership.

No live hardware access or firmware modifications.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE

GPIO_HELPER=0x08018EEC
ORIGINAL_BRAKE_CALL=0x0801119E
PD0_TO_PD3={"0x30":"PD0","0x31":"PD1","0x32":"PD2","0x33":"PD3"}
CAP=150

def inspect(image):
    audited(image)
    c=Cs(CS_ARCH_ARM, CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    calls=[]
    # Only 32-bit BL at halfword boundaries. A binary pattern might
    # coincide with data and must not itself establish reachable code.
    for i in range(0,len(image)-4,2):
        physical=LINK_BASE+i
        ins=next(c.disasm(image[i:i+4],physical,count=1),None)
        if not ins or ins.mnemonic!="bl" or ins.size!=4:
            continue
        if ins.op_str != f"#0x{GPIO_HELPER:x}":
            continue
        candidate_pins=[]
        # Analyze bounded predecessor code as heuristic. Disassembling
        # from an arbitrary 2-byte position can be ambiguous; we do NOT
        # prove that r0 at BL still holds an immediate found here.
        for start in (max(0,i-24),max(0,i-32)):
            lo=start&~1
            for p in c.disasm(image[lo:i],LINK_BASE+lo):
                if p.mnemonic=="movs" and p.op_str.startswith("r0, #"):
                    token=p.op_str.split("#",1)[1]
                    try:value=int(token,0)
                    except ValueError:continue
                    pin=PD0_TO_PD3.get(hex(value))
                    if pin and not any(x["pin"]==pin and x["pc"]==hex(p.address)
                                       for x in candidate_pins):
                        candidate_pins.append({"pin":pin,"pc":hex(p.address),
                                               "instruction":p.mnemonic+" "+p.op_str})
        calls.append({
          "possible_original_helper_call_pc":hex(physical),
          "target":hex(GPIO_HELPER),
          "preceding_nearby_r0_immediate_PD0_PD3_candidates":candidate_pins,
          "true_GPIO_driver_semantics_and_register_value_proven":False,
          "is_necessarily_executable_code_proven":False,
          "M1_M2_motor_owner_and_activity_proven":False,
        })
    if len(calls)>CAP:
        raise ValueError("unexpectedly many BL candidates, tighten audit scope")
    if hex(ORIGINAL_BRAKE_CALL) not in {x["possible_original_helper_call_pc"] for x in calls}:
        raise ValueError("known OEM PE4 brake-related helper BL disappeared")
    return {
        "physical_saved_APP_base":hex(LINK_BASE),
        "target_motor_pin_helper_candidate":hex(GPIO_HELPER),
        "original_brake_related_call_known":hex(ORIGINAL_BRAKE_CALL),
        "BL_candidates_found":len(calls),
        "callsites":calls,
        "candidate_nearby_PD0_PD3_sites":sum(bool(x[
          "preceding_nearby_r0_immediate_PD0_PD3_candidates"]) for x in calls),
        "all_PD0_PD3_owner_control_paths_recovered":False,
        "all_direct_and_indirect_GPIO_writes_exhaustively_discovered":False,
        "hardware_motor_current_or_tach_read_proven":False,
        "v323_MCU_write_or_flash_authorized":False
    }

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--v313",required=True,type=Path)
    a.add_argument("--v322",required=True,type=Path)
    a.add_argument("--json-out",type=Path)
    opt=a.parse_args()
    old=inspect(pinned(opt.v313,"intermediate_v313"))
    now=inspect(pinned(opt.v322,"running_v322"))
    if old!=now:
        raise ValueError("original helper-call candidate inventory differs v3.13/v3.22")
    result={"original_callsite_census_equal":True,"v322":now,
            "no_live_CFS_or_CM5_access":True,"safe_to_flash_v323":False}
    blob=json.dumps(result,indent=2)+"\n"
    if opt.json_out:opt.json_out.write_text(blob)
    print(blob,end="")

if __name__=="__main__":main()
