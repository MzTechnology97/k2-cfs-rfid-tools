#!/usr/bin/env python3
"""Investigate original CFS GPIO BSS device-registration writer candidate.

The previous bounded scan found:
  0x08018DFE: PC-relative literal LDR into r1 (ROM global 0x20004C44)
  0x08018E1A: STR r4,[r1,#0x40] (possible registered device pointer)

The key question is whether r1 still holds 0x20004C44 when the STR
executes. Inspect every original Thumb instruction between anchors,
reject source-data disassembly gaps, and conservatively track r1
clobbers and branch/call barriers. Never claim a reachable runtime
callsite, actual registered device pointer, or motor stop from this.

Only saved SHA-pinned firmware ROM is touched, no MCU or CM5 IO.
"""
from __future__ import annotations
import argparse,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM,ARM_OP_REG,ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R1

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE

BEGIN=0x08018DE8
ROOT_LOAD=0x08018DFE
STORE=0x08018E1A
END=0x08018E2C
GLOBAL=0x20004C44
DEVICE_FIELD=GLOBAL+0x40


def inspect(image):
    audited(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    def ins_at(pc):
        x=next(cs.disasm(image[pc-LINK_BASE:pc-LINK_BASE+4],pc,count=1),None)
        if not x or x.address!=pc:raise ValueError("original code not decoded")
        return x
    first=ins_at(ROOT_LOAD)
    candidate=ins_at(STORE)
    if (first.mnemonic!="ldr" or first.op_str!="r1, [pc, #0x36c]"
            or candidate.mnemonic!="str" or
            candidate.op_str!="r4, [r1, #0x40]"):
        raise ValueError("original GPIO registration candidate anchor changed")
    lit=((ROOT_LOAD+4)&~3)+0x36c
    if struct.unpack_from("<I",image,lit-LINK_BASE)[0]!=GLOBAL:
        raise ValueError("source GPIO global root literal differs")
    sequential=list(cs.disasm(image[ROOT_LOAD-LINK_BASE:STORE-LINK_BASE+2],
                              ROOT_LOAD))
    contiguous=(sequential and sequential[0].address==ROOT_LOAD and
                sequential[-1].address==STORE and
                all(a.address+a.size==b.address for a,b in zip(
                    sequential,sequential[1:])))
    if not contiguous:
        raise ValueError("original register-root-to-STR sequence not contiguous")
    instructions=[]
    may_clobber=False
    barrier=[]
    for ins in sequential:
        flags=[]
        if ins.address!=ROOT_LOAD:
            if ins.mnemonic.startswith(("b","it")) or ins.mnemonic in (
                "cbz","cbnz","pop","push","svc","tbb","tbh"):
                barrier.append({"at":hex(ins.address),
                                "reason":"control_flow_or_stack"})
            try: _,writes=ins.regs_access()
            except Exception:
                flags.append("unknown_reg_effect")
                may_clobber=True
            else:
                # Capstone uses ARM_REG_R1; UC_* must not be mixed here.
                from capstone.arm import ARM_REG_R1
                if ARM_REG_R1 in writes:
                    flags.append("r1_written")
                    may_clobber=True
        instructions.append({
            "at":hex(ins.address),
            "size":ins.size,
            "op":ins.mnemonic+" "+ins.op_str,
            "trace_flags":flags,
        })
    # Diagnostic ONLY: this region may begin in the middle of a Thumb
    # function or 32-bit instruction. Do not identify r4's origin
    # or a registration entrypoint from linear decoding alone.
    upstream_begin=0x08018DC0
    upstream=[
        {"at":hex(i.address),"bytes":i.bytes.hex(),
         "opcode":i.mnemonic+" "+i.op_str}
        for i in cs.disasm(image[upstream_begin-LINK_BASE:ROOT_LOAD-LINK_BASE],
                           upstream_begin)
    ]
    return {
        "upstream_r4_candidate_context_unqualified":upstream,
        "upstream_context_is_confirmed_function_entry":False,
        "actual_r4_device_pointer_source_proven":False,
        "saved_oem_ROM_region":[hex(BEGIN),hex(END)],
        "root_LDR_source":hex(ROOT_LOAD),
        "original_root_pointer_ROM_slot":hex(lit),
        "original_root_pointer_value":hex(GLOBAL),
        "possible_STR_source":hex(STORE),
        "possible_STR_target_if_r1_unchanged":hex(DEVICE_FIELD),
        "original_thumb_instructions_between_root_and_store":instructions,
        "r1_may_be_clobbered_between_LDR_and_STR":may_clobber,
        "branch_or_stack_barriers_between_LDR_and_STR":barrier,
        "connected_straight_line_source_bytes":True,
        "register_root_to_store_source_proven_without_control_flow":(
             not may_clobber and not barrier),
        "runtime_registration_executed_proven":False,
        "actual_registered_GPIO_device_pointer_recovered":False,
        "M1_M2_driver_callback_or_motor_STOPPED_proven":False,
        "real_CFS_CM5_Kalico_access":False,
        "v323_MCU_write_or_flash_permitted":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=inspect(pinned(a.v313,"intermediate_v313"))
    new=inspect(pinned(a.v322,"running_v322"))
    if old!=new:raise ValueError("OEM GPIO registrar candidate differs in saved v3.13/v3.22")
    result={"v313_equal_to_v322_original_ROM":True,"source_analysis":new,
            "not_a_live_registration_trace":True,
            "release_allowed":False}
    output=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(output)
    print(output,end="")


if __name__=="__main__":main()
