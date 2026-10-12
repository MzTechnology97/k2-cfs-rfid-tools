#!/usr/bin/env python3
"""Re-evaluate saved CFS v3.13/v3.22 APP at 0x08003000, not 0x08010000.

The original reset vector, three RT-Thread device callback literals, and
Keil scatter-loader function pointers are ALL 0xD000 below executable
offsets previously inferred using APP_BASE=0x08010000. Instead of
patching firmware, treat the image as linked for 0x08003000.

Strictly offline and SHA-pinned: original image bytes are never changed.
Decode the first original scatter RAM region using exact Thumb grammar
already cross-validated against independent historical CFS ROM + RAM.
No writes to CFS/CM5 or Kalico, no MCU programming.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import APP_BASE,pinned
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar,RejectedStream

LINK_BASE = 0x08003000
PREVIOUS_ASSUMED_BASE = APP_BASE
BASE_ERROR = PREVIOUS_ASSUMED_BASE-LINK_BASE
RESET_TARGET = 0x0801A969
FIRST_SCATTER = 0x0802DA10
SECOND_SCATTER = FIRST_SCATTER+16
REC1=(0x0802DB6C,0x20000000,3012,0x0800316C)
REC2=(0x0802DE38,0x20000BC4,25380,0x080031C8)
OBJECTS=(0x2000075C,0x200007BC,0x2000081C,0x2000087C,0x200008DC)
EXPECTED_NAMES=("pwm1","pwm3","pwm4","pwm5","pwm8")
ORIGINAL_POINTERS=(0x080193C5,0x08019401,0x0801939D)
ORIGINAL_LITERAL_SLOTS=(0x08019860,0x08019864,0x08019868)
STORED_CALLBACK_FIELDS=(0x30,0x34,0x38)

def off(image:bytes, addr:int, size=1):
    i=addr-LINK_BASE
    if not (0<=i<=len(image)-size):
        raise ValueError(f"linked address out of APP image: {addr:#x}")
    return i

def u32(image:bytes, addr:int):
    return struct.unpack_from("<I",image,off(image,addr,4))[0]

def string(image:bytes, addr:int):
    i=off(image,addr)
    v=image[i:i+12].split(b"\0",1)[0]
    if not v or len(v)>8 or any(not 32<=ch<=126 for ch in v):
        return None
    return v.decode("ascii")

def audited(image:bytes):
    if BASE_ERROR!=0xD000:
        raise AssertionError("old APP probe base assumptions unexpectedly changed")
    initial_sp,reset=struct.unpack_from("<II",image,0)
    if initial_sp!=0x20006EE8 or reset!=RESET_TARGET:
        raise ValueError("manufacturer vector table differs")
    if not (LINK_BASE <= (reset&~1) < LINK_BASE+len(image)):
        raise ValueError("real linked reset handler is outside APP")
    rec1=tuple(u32(image,FIRST_SCATTER+i*4) for i in range(4))
    rec2=tuple(u32(image,SECOND_SCATTER+i*4) for i in range(4))
    if rec1!=REC1 or rec2!=REC2:
        raise ValueError("original physical APP linked scatter descriptor mismatch")
    code=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    reset_code=[
        {"address":hex(ins.address),
         "mnemonic":ins.mnemonic,
         "operands":ins.op_str}
        for ins in code.disasm(image[off(image,reset&~1):off(image,reset&~1)+32],reset&~1)
    ]
    # For each address previously labelled "interior" in the
    # 0x08010000 misbased disassembly, test linked physical bytes.
    op_sites=[]
    for field,lit,pointer in zip(STORED_CALLBACK_FIELDS,ORIGINAL_LITERAL_SLOTS,ORIGINAL_POINTERS):
        if u32(image,lit)!=pointer:
            raise ValueError(f"original +{field:#x} callback literal not found under 0x08003000")
        start=pointer&~1
        instructions=list(code.disasm(image[off(image,start):off(image,start)+12],start))
        op_sites.append({
            "object_offset":hex(field),
            "physical_literal_address":hex(lit),
            "stored_real_Thumb_pointer":hex(pointer),
            "decoded_at_REAL_physical_address":hex(start),
            "first_instruction":instructions[0].mnemonic+" "+instructions[0].op_str,
            "old_mislocated_decode_address":hex(start+BASE_ERROR),
        })
    src,end=rec1[0],rec2[0]
    packed=image[off(image,src):off(image,end)]
    result,unpacked=bounded_thumb_grammar(packed,rec1[2])
    if not result["valid"] or len(unpacked)!=rec1[2]:
        raise ValueError("linked 0x08003000 APP failed compressed RAM decoding")
    names=[]
    for obj in OBJECTS:
        field=obj+0x54
        at=field-rec1[1]
        if not (0<=at<=len(unpacked)-4):
            raise ValueError("name field not inside first initialized RAM region")
        pointer=struct.unpack_from("<I",unpacked,at)[0]
        label=string(image,pointer) if LINK_BASE<=pointer<LINK_BASE+len(image) else None
        names.append({"object":hex(obj),"name_field":hex(field),
                      "decoded_ROM_name_pointer":hex(pointer),
                      "decoded_name":label})
    # A full decode is evidence, while name-to-object assertion
    # requires independent pointer/string matching, no guessing.
    complete=[x["decoded_name"] for x in names]
    confirmed=complete==list(EXPECTED_NAMES)
    report={
      "corrected_LINK_BASE":hex(LINK_BASE),
      "previous_probe_BASE":hex(APP_BASE),
      "difference_bytes":BASE_ERROR,
      "saved_image_sha256":hashlib.sha256(image).hexdigest(),
      "genuine_linked_reset_vector":hex(reset),
      "linked_reset_first_instructions":reset_code,
      "physical_original_scatter_first":[hex(v) for v in rec1],
      "physical_original_scatter_second":[hex(v) for v in rec2],
      "original_callback_literal_fields":op_sites,
      "compressed_source_bytes":len(packed),
      "decompression":result,
      "five_PWM_RAM_name_fields":names,
      "five_names_in_expected_historical_order_proven":confirmed,
      "real_bootloader_content_on_user_MCU_authenticated":False,
      "actual_live_CFS_RAM_read":False,
      "actual_motor_running_status_and_safe_stop_PROVEN":False,
      "v323_firmware_release_allowed":False,
      "device_modified":False
    }
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    result={}
    for key,file,tag in (
        ("v313",args.v313,"intermediate_v313"),
        ("v322",args.v322,"running_v322"),
    ):
        result[key]=audited(pinned(file,tag))
    for key in ("v313","v322"):
        if not result[key]["five_names_in_expected_historical_order_proven"]:
            raise ValueError(f"{key} names were not fully corroborated; review raw pointer bounds and scatter")
    answer={"analysis":result,"same_ROM_names_and_three_callbacks_both_versions":
        result["v313"]["five_PWM_RAM_name_fields"]==result["v322"]["five_PWM_RAM_name_fields"]
        and result["v313"]["original_callback_literal_fields"]==result["v322"]["original_callback_literal_fields"],
        "no_active_CFS_or_CM5_access":True,"safe_to_flash_v323":False}
    payload=json.dumps(answer,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(payload)
    print(payload,end="")

if __name__=="__main__":main()
