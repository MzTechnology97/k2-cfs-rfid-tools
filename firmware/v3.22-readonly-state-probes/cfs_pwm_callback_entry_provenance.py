#!/usr/bin/env python3
"""CFS v3.13/v3.22 PWM callback entry-point provenance check (offline).

The manufacturer ROM literal at 0x08026868 supplies 0x0801939D to
device field +0x38. At 0x0801939C disassembly seems to start midway
through a function, with a POP instruction shortly afterward.

Before claiming invalid motor callbacks, compare the SAME region
in SHA-pinned v3.13 vs v3.22 and inspect the complete surrounding
Thumb stream, its branches, and backwards instruction boundaries.
No MCU access and no hardware execution: diagnostic only.
"""
from __future__ import annotations
import argparse,hashlib,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import APP_BASE,pinned

START=0x08019350
END=0x080193D0
POINTER_SLOT=0x08026868
EXPECTED_POINTER=0x0801939D
CONSTRUCTOR=0x0802646E

def inspect(blob:bytes,tag:str):
    at=START-APP_BASE;end=END-APP_BASE
    payload=blob[at:end]
    raw=struct.unpack_from("<I",blob,POINTER_SLOT-APP_BASE)[0]
    if raw!=EXPECTED_POINTER:
        raise ValueError("manufacturer callback pointer value changed")
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    rows=[{"pc":hex(i.address),"op":i.mnemonic,"args":i.op_str}
        for i in dec.disasm(payload,START)]
    entry=[i for i in rows if i["pc"]==hex(EXPECTED_POINTER&~1)]
    if len(entry)!=1:
        raise ValueError("Thumb callback entry not an instruction boundary in nearby decode")
    idx=rows.index(entry[0])
    return {
        "flavor":tag,
        "callback_pointer_literal":hex(raw),
        "window_sha256":hashlib.sha256(payload).hexdigest(),
        "code_window_start":hex(START),
        "entry_instruction":entry[0],
        "entry_instruction_index_from_start":idx,
        "immediate_prior_instructions":rows[max(0,idx-10):idx],
        "immediate_after_instructions":rows[idx:idx+18],
        "all_instructions":rows,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    v313=pinned(a.v313,"intermediate_v313")
    v322=pinned(a.v322,"running_v322")
    x=inspect(v313,"v313")
    y=inspect(v322,"v322")
    answer={
       "original_callback_pointer_unchanged":x["callback_pointer_literal"]==y["callback_pointer_literal"],
       "near_callback_code_window_bytes_unchanged":x["window_sha256"]==y["window_sha256"],
       "version_313":x,"version_322":y,
       "valid_independent_callback_entry_behavior_PROVEN":False,
       "historical_callback_equivalence_PROVEN":False,
       "actual_motor_stop_feedback_proven":False,
       "safe_to_flash_v323":False,
       "live_hardware_touched":False,
    }
    body=json.dumps(answer,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(body)
    print(body,end="")

if __name__=="__main__": main()
