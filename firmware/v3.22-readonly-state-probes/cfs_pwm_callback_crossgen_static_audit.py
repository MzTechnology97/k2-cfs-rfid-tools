#!/usr/bin/env python3
"""Review historical vs v3.22 original PWM device dispatch callbacks offline.

Authenticated historical running RAM has the SAME Thumb callback pointer
0x08014555 at [pwm1/pwm3/pwm4/pwm5/pwm8 objects + 0x38]. In rebuilt
v3.22 an authentic callsite writes 0x0801939D to the same object field.
Neither fact says anything about physical motor stop. Historical and
v3.22 firmwares may not have identical callback implementations.

Only parse saved public historical Flash + SHA-pinned APP, no motor IO.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import APP_BASE,pinned
from cfs_historical_bootloader_compare import verify_public_blob,FLASH_BASE
from cfs_scatter_candidate_decompress_audit import verify_image

HISTORICAL_PWM_CALLBACK=0x08014555
V322_PWM_CALLBACK=0x0801939D
HISTORICAL_CODE_START=HISTORICAL_PWM_CALLBACK&~1
V322_CODE_START=V322_PWM_CALLBACK&~1
SPAN=96
def inspected_segment(raw:bytes,root:int,at:int):
    off=at-root
    if off<0 or off+SPAN>len(raw):raise ValueError("callback outside pinned ROM")
    payload=raw[off:off+SPAN]
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    rows=[]
    for i in decoder.disasm(payload,at):
        rows.append({
          "pc":hex(i.address), "mnemonic":i.mnemonic,
          "operand":i.op_str,
          "instruction_bytes":i.size
        })
    return {"offset":hex(at),"nominal_bytes":SPAN,
            "sha256_of_96_original_ROM_bytes":hashlib.sha256(payload).hexdigest(),
            "instructions":rows, "instruction_count":len(rows)}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--public-flash",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=a.public_flash.read_bytes()
    verify_public_blob(old,"flash")
    now=pinned(a.v322,"running_v322")
    verify_image(now)
    earlier=inspected_segment(old,FLASH_BASE,HISTORICAL_CODE_START)
    current=inspected_segment(now,APP_BASE,V322_CODE_START)
    matched=[k for k,(x,y) in enumerate(zip(earlier["instructions"],current["instructions"]))
             if x["mnemonic"]==y["mnemonic"]]
    result={
      "historical_authenticated_runtime_pointer":hex(HISTORICAL_PWM_CALLBACK),
      "v322_original_constructor_callback_pointer":hex(V322_PWM_CALLBACK),
      "historical":earlier, "v322":current,
      "number_of_matching_instruction_mnemonics_at_same_list_index":len(matched),
      "compared_instruction_count":min(earlier["instruction_count"],current["instruction_count"]),
      "same_96_bytes":earlier["sha256_of_96_original_ROM_bytes"]==current["sha256_of_96_original_ROM_bytes"],
      "callback_equivalence_proven":False,
      "physical_motor_stop_proven":False,
      "actual_v322_pwm1_name_association_proven":False,
      "live_device_access":False,
      "safe_to_flash_v323":False,
    }
    text=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(text)
    print(text,end="")

if __name__=="__main__": main()
