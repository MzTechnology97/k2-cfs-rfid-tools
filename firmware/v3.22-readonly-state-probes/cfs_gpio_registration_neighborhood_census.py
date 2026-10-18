#!/usr/bin/env python3
"""Original GPIO registration neighborhood: source-only halfword census.

All 15 independently verified root-literal users for RT GPIO global
0x20004C44 are within 0x08018DFE..0x08018F3A. Search a strictly
bounded surrounding ROM window for candidate [register,#0x40] store
instructions, distinct from seven source-traced device-pointer READs,
and for candidate direct branch targets that may merit further
function-level investigation.

This is not an executable CFG, not a proven BSS registration writer,
and NEVER resolves the runtime driver pointer from zero-init memory.
Halfword scanning can decode embedded data or middle of a 32-bit
instruction, so everything in this neighborhood is *candidate only*.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM,ARM_OP_IMM

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE
from cfs_gpio_runtime_registration_root_census import analyze as root_analyze

BEGIN=0x08018D80
END=0x08019000
MAX_BRANCHES=120
KNOWN_ROOT_LOADS=(
 0x08018DFE,0x08018E24,0x08018E32,0x08018E58,
 0x08018E6A,0x08018E8A,0x08018E96,0x08018EBA,
 0x08018EC6,0x08018EE8,0x08018EEE,0x08018F10,
 0x08018F16,0x08018F34,0x08018F3A
)
KNOWN_READS=(
 0x08018E38,0x08018E6E,0x08018E9C,0x08018ECC,
 0x08018EF4,0x08018F1A,0x08018F3E,
)


def inspect(image):
    audited(image)
    source=root_analyze(image)
    pcs=tuple(int(x["source_candidate_pc"],16)
              for x in source["bounded_candidate_traces"])
    reads=tuple(int(y["at"],16)
                for x in source["bounded_candidate_traces"]
                for y in x["local_GPIO_device_field_accesses"]
                if y["access"]=="read")
    if pcs != KNOWN_ROOT_LOADS or reads!=KNOWN_READS:
        raise ValueError("known OEM GPIO registration neighborhood changed")
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    stores=[]
    loads=[]
    branches=[]
    for pc in range(BEGIN,END,2):
        off=pc-LINK_BASE
        ins=next(cs.disasm(image[off:off+4],pc,count=1),None)
        if ins is None:
            continue
        if ins.mnemonic.startswith(("str","ldr")):
            for op in ins.operands:
                if op.type!=ARM_OP_MEM or op.mem.disp!=0x40 or op.mem.index!=0:
                    continue
                event={"source_halfword":hex(pc),
                       "opcode":ins.mnemonic+" "+ins.op_str,
                       "requires_register_base_validation":True}
                (stores if ins.mnemonic.startswith("str") else loads).append(event)
        if ins.mnemonic in ("bl","blx","b","b.w","bx"):
            target=None
            if ins.operands and ins.operands[0].type==ARM_OP_IMM:
                target=hex(ins.operands[0].imm)
            branches.append({
                "source_halfword":hex(pc),
                "opcode":ins.mnemonic+" "+ins.op_str,
                "direct_candidate_destination":target,
                "executable_reachability_proven":False,
            })
    if len(branches)>MAX_BRANCHES:
        raise ValueError("too many candidate branch forms; manually tighten source window")
    return {
      "physical_original_saved_APP_base":hex(LINK_BASE),
      "diagnostic_ROM_window":[hex(BEGIN),hex(END)],
      "original_ROM_gpio_root_loads":len(pcs),
      "original_local_reads_from_0x20004c84":len(reads),
      "possible_halfword_STORES_with_displacement_0x40":stores,
      "possible_halfword_LOADS_with_displacement_0x40":loads,
      "candidate_B_or_BL_or_BX_in_neighborhood":branches,
      "candidate_control_transfers_by_mnemonic":dict(Counter(
          x["opcode"].split(" ",1)[0] for x in branches)),
      "source_window_is_verified_executable_CFG":False,
      "any_0x40_store_targets_BSS_global_proven":False,
      "actual_GPIO_driver_registration_callback_recovered":False,
      "M1_M2_GPIO_driver_source_paths_recovered":False,
      "motor_idle_or_flash_release_authorized":False,
      "live_CFS_CM5_or_Kalico_access":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    o=inspect(pinned(a.v313,"intermediate_v313"))
    n=inspect(pinned(a.v322,"running_v322"))
    if o!=n:raise ValueError("CFS ROM GPIO registration candidate neighborhood changed")
    result={"v313_v322_unchanged_original_neighborhood":True,
            "v322":n,"offline_only":True,"release_allowed":False}
    s=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(s)
    print(s,end="")


if __name__=="__main__":main()
