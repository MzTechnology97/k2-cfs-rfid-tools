#!/usr/bin/env python3
"""Offline bounded provenance search for RT-Thread GPIO callback registration.

Original saved v3.13/v3.22 GPIO dispatch:
  ROM[0x0801916C] -> 0x20004C44 (runtime global)
  [global+0x40] = [0x20004C84] (GPIO device pointer, BSS)
  [device+0x04] = indirect pin driver operation, runtime-installed

Scan aligned saved ROM constant words referencing exactly the known
global, its +0x40 field, and (for calibration) known PE4 pin.
Decode candidate PC-relative LDR uses. Follow only a short bounded
straight-line subset of Thumb LDR, ADD, MOV, STR and load-from-base.
Classify direct writes/reads to the field; STOP on any branch, call,
IT/conditional, unknown source register clobber, or instruction whose
semantics are not implemented. Do not infer control-flow reachability
or treat a saved BSS field as initialized at runtime.

This is a source reconnaissance *scope*, not an MCU hook, device
registration proof, or permission to read/write physical hardware.
"""
from __future__ import annotations

import argparse
import json
import struct
from collections import Counter
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_OP_IMM

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_adc_gpio_literal_xref_discovery import candidate_pc_load_xrefs
from cfs_gpio_rt_helper_entry_trace import HELPER, COMMON_GLOBAL_LITERAL_PC

GLOBAL_ADDR=0x20004C44
DEVICE_FIELD=GLOBAL_ADDR+0x40
FIELDS={"global":GLOBAL_ADDR,"GPIO_runtime_device_field":DEVICE_FIELD}
MAX_WINDOW=20
MAX_LITERALS=120
MAX_LOADS=75
KNOWN_LOADS=(0x08018EEE,0x08018F10)


def _read_word(image,pc):
    pos=pc-LINK_BASE
    if pos<0 or pos+4>len(image):
        raise ValueError("ROM word out of bounds")
    return struct.unpack_from("<I",image,pos)[0]


def _collect_words(image):
    out=[]
    for off in range(0,len(image)-3,4):
        word=struct.unpack_from("<I",image,off)[0]
        if word in FIELDS.values():
            out.append({"slot":LINK_BASE+off,"word":word})
    if len(out)>MAX_LITERALS:
        raise ValueError("too many GPIO root constants: manual review")
    if not any(r["slot"]==COMMON_GLOBAL_LITERAL_PC and r["word"]==GLOBAL_ADDR for r in out):
        raise ValueError("original dispatcher global-root literal absent")
    return out


def _peripheral_effect(image,pc,root,cs):
    off=pc-LINK_BASE
    it=cs.disasm(image[off:min(len(image),off+96)],pc)
    first=next(it,None)
    if (first is None or first.mnemonic!="ldr" or len(first.operands)<2
        or first.operands[1].type!=ARM_OP_MEM or
        first.operands[1].mem.base!=ARM_REG_PC):
        raise ValueError("candidate PC-relative root load invalid")
    state={first.operands[0].reg:root}
    events=[]
    stop="max_window"
    # Classify precise *data addresses* only; never interpret the loaded
    # live BSS pointer value or infer actual motor/device object.
    for n,ins in enumerate(it):
        if n>=MAX_WINDOW:
            break
        m=ins.mnemonic
        if (m.startswith(("b","it")) or m in ("cbz","cbnz","pop","push",
              "svc","tbb","tbh","udf") or "." in m and m.startswith("b")):
            stop="control_transfer"
            break
        if len(ins.operands)<2:
            stop="unmodelled_instruction"
            break
        dest=ins.operands[0]
        src=ins.operands[1]
        if dest.type!=ARM_OP_REG:
            stop="unmodelled_destination"
            break
        dr=dest.reg
        if n==0:
            continue
        # Explicit MOV/MOVS register propagation (not immediate).
        if m in ("mov","movs","mov.w") and src.type==ARM_OP_REG:
            if src.reg in state:
                state[dr]=state[src.reg]
            else:state.pop(dr,None)
        elif m in ("add","adds","add.w","addw","sub","subs","sub.w","subw"):
            ops=ins.operands
            if (len(ops)==3 and ops[1].type==ARM_OP_REG
                and ops[1].reg in state and ops[2].type==ARM_OP_IMM):
                signed=1 if m.startswith("add") else -1
                state[dr]=(state[ops[1].reg]+signed*ops[2].imm)&0xffffffff
            elif len(ops)==2 and dr in state and src.type==ARM_OP_IMM:
                signed=1 if m.startswith("add") else -1
                state[dr]=(state[dr]+signed*src.imm)&0xffffffff
            else:
                stop="ambiguous_arithmetic"
                break
        elif m in ("ldr","ldrb","ldrh","str","strb","strh"):
            mem=src if m.startswith("ldr") else (ins.operands[1]
                if len(ins.operands)>1 else None)
            if mem is None or mem.type!=ARM_OP_MEM or mem.mem.base not in state:
                stop="unknown_memory_base"
                break
            if mem.mem.index!=0 or ins.writeback:
                stop="indexed_or_writeback_access"
                break
            target=(state[mem.mem.base]+mem.mem.disp)&0xffffffff
            if target==DEVICE_FIELD:
                events.append({
                    "at":hex(ins.address),
                    "access":"read" if m.startswith("ldr") else "write",
                    "opcode":ins.mnemonic+" "+ins.op_str,
                    "target_runtime_BSS_field":hex(DEVICE_FIELD),
                    "direct_runtime_callback_value_proven":False,
                    "source_control_flow_reachable_proven":False,
                })
            if m.startswith("ldr"):
                # Do not turn a runtime BSS/device read into a known
                # constant; the original ROM has no post-init values.
                state.pop(dr,None)
        else:
            stop="unmodelled_opcode"
            break
    return {"source_candidate_pc":hex(pc),"literal_load_base":hex(root),
            "verified_original_literal_loader":first.mnemonic+" "+first.op_str,
            "local_GPIO_device_field_accesses":events,
            "bounded_trace_stopped_because":stop,
            "run_time_callback_recovered":False}


def analyze(image):
    audited(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    roots=_collect_words(image)
    usage=[]
    for item in roots:
        refs,n=candidate_pc_load_xrefs(image,item["slot"],cs)
        if n>MAX_LOADS:
            raise ValueError("unexpected number of GPIO runtime root loads")
        for ref in refs:
            usage.append(_peripheral_effect(image,int(ref["candidate_pc"],16),item["word"],cs))
    for pc in KNOWN_LOADS:
        if not any(x["source_candidate_pc"]==hex(pc) for x in usage):
            raise ValueError(f"known manufacturer GPIO helper root loader {pc:#x} absent")
    events=[y for x in usage for y in x["local_GPIO_device_field_accesses"]]
    by=Counter(e["access"] for e in events)
    return {
      "physical_saved_APP_base":hex(LINK_BASE),
      "original_gpio_helper":hex(HELPER),
      "runtime_global_address":hex(GLOBAL_ADDR),
      "runtime_GPIO_device_BSS_field":hex(DEVICE_FIELD),
      "number_of_aligned_exact_ROM_root_constants":len(roots),
      "number_of_root_load_candidate_sites":len(usage),
      "local_direct_field_access_counts":dict(by),
      "bounded_candidate_traces":usage,
      "static_BSS_init_value_is_zero_not_runtime_device_pointer":True,
      "actual_registration_writer_found_on_reachable_path":False,
      "runtime_GPIO_device_callback_at_device_plus_0x04_recovered":False,
      "all_motor_pin_write_paths_recovered":False,
      "physical_motor_STOPPED_proven":False,
      "safe_to_enable_v323_writes_or_flash":False,
      "live_CFS_CM5_Kalico_access":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=analyze(pinned(a.v313,"intermediate_v313"))
    current=analyze(pinned(a.v322,"running_v322"))
    same=old==current
    result={"v313_and_v322_original_GPIO_BSS_root_traces_identical":same,
            "v313":old,"v322":current,
            "report_is_bounded_heuristic_not_complete_CFG":True,
            "no_actual_hardware_operation":True,
            "no_v323_release":True}
    body=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":
    main()
