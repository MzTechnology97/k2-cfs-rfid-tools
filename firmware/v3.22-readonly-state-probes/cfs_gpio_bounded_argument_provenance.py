#!/usr/bin/env python3
"""Source-only bounded GPIO argument provenance, fail-closed.

Unlike the previous 4-byte MOVS census, this identifies registers r0/r1
in a single straight-line Thumb basic-block candidate immediately
preceding each original BL to RT GPIO helper 0x08018EEC.

The scanner stops at calls, conditional/unconditional branches, stack
changes, unclassified register writes and ambiguous instruction
boundaries. It never joins different basic blocks or guesses memory
contents. This cannot prove the candidate BL is reachable executable
code, callback BSS installation, M1/M2 motor ownership or safe STOP.

Only original SHA-pinned saved v3.13/v3.22 APP data is parsed.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE
from cfs_m1_m2_gpio_helper_callsites import inspect as prior
from cfs_gpio_dispatch_runtime_boundary_audit import GPIO_HELPER

MOTOR_PINS={0x30:"M2_PD0",0x31:"M2_PD1",0x32:"M1_PD2",0x33:"M1_PD3"}
MAX_BACK_BYTES=24
SKIP=("nop",)

def trace(image:bytes,call:int,cs):
    start=max(0,call-LINK_BASE-MAX_BACK_BYTES)&~1
    # Multiple disassembly starts because thumb may have mixed 16/32-bit
    # instructions. Accept only a unique unambiguous ending sequence.
    found=[]
    for off in range(start,call-LINK_BASE,2):
        instructions=list(cs.disasm(image[off:call-LINK_BASE],LINK_BASE+off))
        if not instructions or instructions[-1].address+instructions[-1].size !=call:
            continue
        regs={}
        barrier=False
        for ins in instructions:
            m=ins.mnemonic
            if m in SKIP:continue
            if m=="movs" and ins.op_str.startswith(("r0, #","r1, #")):
                reg,val=ins.op_str.split(", #",1)
                try:v=int(val,0)
                except ValueError:barrier=True;break
                regs[reg]=v
            elif m.startswith("b") or m in ("push","pop","cbz","cbnz","it","itt","ite","blx","svc"):
                barrier=True;break
            else:
                # Do not silently continue through arbitrary instructions
                # that can change flags, r0/r1 or memory, or be data.
                barrier=True;break
        if not barrier and {"r0","r1"}<=regs.keys():
            found.append({"pin":regs["r0"],"value":regs["r1"],
                          "start":hex(LINK_BASE+off),"instruction_count":len(instructions)})
    pairs={(x["pin"],x["value"]) for x in found}
    return {
        "call_pc":hex(call),
        "candidate_pin_and_value":(
            {"pin_id":hex(next(iter(pairs))[0]),
             "value":next(iter(pairs))[1],
             "motor_pin":MOTOR_PINS.get(next(iter(pairs))[0])}
            if len(pairs)==1 else None),
        "candidate_disassembly_paths":len(found),
        "ambiguous_candidate_arguments":len(pairs)>1,
        "reachable_original_basic_block_proven":False,
        "live_driver_callback_or_motor_state_proven":False,
    }

def inspect(image):
    audited(image)
    x=prior(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    rows=[trace(image,int(item["possible_original_helper_call_pc"],16),cs)
          for item in x["callsites"]]
    m=[r for r in rows if r["candidate_pin_and_value"] is not None
       and r["candidate_pin_and_value"]["motor_pin"]]
    return {
        "physical_base":hex(LINK_BASE),
        "all_existing_BL_candidates":len(rows),
        "short_straight_line_argument_candidates":sum(
            r["candidate_pin_and_value"] is not None for r in rows),
        "M1_M2_argument_candidates":m,
        "candidate_BLs":rows,
        "all_callers_reachable_proven":False,
        "GPIO_driver_runtime_callback_known":False,
        "actual_M1_M2_owner_and_current_feedback_known":False,
        "safe_to_flash_or_enable_motor_writes":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=inspect(pinned(a.v313,"intermediate_v313"))
    new=inspect(pinned(a.v322,"running_v322"))
    if old!=new:
        raise ValueError("GPIO bounded argument candidates differ between pinned baselines")
    result={"v313_v322_identical":True,"analysis":new,
            "real_hardware_access":False,"flash_release":False}
    body=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(body)
    print(body,end="")
if __name__=="__main__":main()
