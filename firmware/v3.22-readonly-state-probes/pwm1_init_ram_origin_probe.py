#!/usr/bin/env python3
"""Offline CFS five-object +0x54 name-field origin preflight.

Inspect ONLY SHA-pinned source bytes and original ROM ARM instructions.
The original startup scatter loader may set up initialized SRAM before
the 5-object constructor. This script does not assert that without data
relocation evidence. No MCU I/O, binary patching, or device operations.
"""
from __future__ import annotations
import argparse, json, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from flash_ram_phase2_audit import APP_BASE, pinned

FIVE = tuple(0x2000075c + i*96 for i in range(5))
NAMES = tuple(a+0x54 for a in FIVE)
SRC_ROM_STRINGS = (0x080399E4, 0x080399EC, 0x080399F4,
                   0x080399FC, 0x08039A04)
REGIONS = (
  ("startup_scatter", 0x08010130, 0x080101B0),
  ("startup_table", 0x08010160, 0x08010220),
  ("pwm_object_origin", 0x080283BE, 0x08028430),
  ("pwm_metadata_prescan", 0x08028054, 0x080280BC),
)

def read32(buf, addr):
  i=addr-APP_BASE
  return struct.unpack_from("<I",buf,i)[0]

def scan(buf):
  c=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
  c.detail=True
  regions=[]
  for name,lo,hi in REGIONS:
    items=[]
    # Startup table is DATA and must not be misidentified as executable code.
    if name == "startup_table":
      for a in range(lo,hi,4):
        items.append({"at":hex(a),"word":hex(read32(buf,a))})
    else:
      for ins in c.disasm(buf[lo-APP_BASE:hi-APP_BASE],lo):
        literal=None
        for op in ins.operands:
          if op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC:
            ptr=((ins.address+4)&~3)+op.mem.disp
            if APP_BASE<=ptr<APP_BASE+len(buf)-3:
              literal={"at":hex(ptr),"word":hex(read32(buf,ptr))}
        items.append({"at":hex(ins.address),"opcode":ins.mnemonic,
                      "operand":ins.op_str,"literal":literal})
    regions.append({"name":name,"rows":items})
  pointers=(FIVE+NAMES+SRC_ROM_STRINGS+(0x2000093c,0x0802639d))
  matches={}
  for ptr in pointers:
    raw=struct.pack("<I",ptr)
    spots=[]
    idx=0
    while True:
      idx=buf.find(raw,idx)
      if idx<0: break
      spots.append(hex(APP_BASE+idx))
      idx+=1
    matches[hex(ptr)]=spots[:40]
  return {
   "object_RAM_addresses":[hex(a) for a in FIVE],
   "pre_existing_device_name_ptr_RAM_fields":[hex(a) for a in NAMES],
   "ROM_data_name_evidence":[{"at":hex(a),"string":
     buf[a-APP_BASE:a-APP_BASE+8].split(b"\x00")[0].decode("ascii",errors="replace")}
     for a in SRC_ROM_STRINGS],
   "absolute_literal_occurrences":matches,
   "regions":regions,
   "static_ROM_does_not_prove_initialized_RAM_content":True,
   "pwm1_runtime_callback_proven":False
  }

def main():
  p=argparse.ArgumentParser()
  p.add_argument("--v322",required=True,type=Path)
  p.add_argument("--json-out",type=Path)
  a=p.parse_args()
  data=scan(pinned(a.v322,"running_v322"))
  print("PREPARED_RAM_FIELDS",json.dumps(data["pre_existing_device_name_ptr_RAM_fields"]))
  print("STATIC_PTR_OCCURRENCES",json.dumps(data["absolute_literal_occurrences"]))
  print("PWM_NAMES_ROM",json.dumps(data["ROM_data_name_evidence"]))
  for region in data["regions"]:
    print("REGION",region["name"])
    for row in region["rows"]:
      print(row)
  if a.json_out:a.json_out.write_text(json.dumps(data,indent=2)+"\n")
if __name__=="__main__":main()
