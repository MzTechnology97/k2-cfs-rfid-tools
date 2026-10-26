"""ABI differential checks for the two new CFG5 stock callsite hooks.
Offline Unicorn (Cortex-M3) on the CFS linked-address image; no hardware.
"""
from pathlib import Path
import json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE
from unicorn.arm_const import *
BASE=0x08010000
root=Path(__file__).resolve().parent
stock=(root.parent/"v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin").read_bytes()
trial=(Path(__file__).resolve().parent/"CFG6-READONLY-DIAG1-NOT-FOR-FLASH.bin").read_bytes()
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,
      UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP)
def run(image,addr,slot=None,value=None,r5=24):
 uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
 uc.mem_map(0x08000000,0x40000)
 uc.mem_write(BASE,image)
 uc.mem_map(0x20000000,0x10000)
 uc.mem_write(0x20000014,struct.pack("<I",0x200037E2))
 uc.mem_write(0x200037E2,bytes([0,255,100,200,0,155,255,80]))
 uc.mem_write(0x200001F2,b"\x04")
 # Set a single valid sidecar override, leaving all other IDs at ROM stock.
 if slot is not None:
  index=slot-7
  uc.mem_write(0x20006EE8,struct.pack("<II",0x35564643,1<<index))
  uc.mem_write(0x20006EE8+8+index*2,struct.pack("<H",value))
 uc.reg_write(UC_ARM_REG_CPSR,0x33)
 for idx,reg in enumerate(REGS):
  uc.reg_write(reg,0x100+idx*0x1234)
 uc.reg_write(UC_ARM_REG_R5,r5)
 uc.reg_write(UC_ARM_REG_SP,0x2000E000)
 uc.reg_write(UC_ARM_REG_LR,0x0803D001)
 uc.reg_write(UC_ARM_REG_APSR,0xA0000000)
 hit=[]
 def hook(cpu,where,size,_):
  if where==addr+4:
   hit.append(True);cpu.emu_stop()
 uc.hook_add(UC_HOOK_CODE,hook)
 uc.emu_start(addr|1,0x0803D001,count=200)
 assert hit,("did not return",hex(addr))
 return {r:uc.reg_read(r) for r in REGS},uc.reg_read(UC_ARM_REG_APSR)&0xf0000000

results=[]
for spec in (("feed_total",0x08032C72,20,UC_ARM_REG_R7,1250,30000,1500),
             ("odometer_stall",0x08032CEC,22,UC_ARM_REG_R5,25,600,25)):
 name,addr,id,output,original,override,expected=spec
 for start_r5 in (23,24,25,26):
  before,bflags=run(stock,addr,r5=start_r5)
  default,dflags=run(trial,addr,r5=start_r5)
  changed,cflags=run(trial,addr,slot=id,value=override,r5=start_r5)
  assert before[output]==default[output]==original if id==20 else (before[output]==default[output]==start_r5+1)
  assert changed[output]==(expected if id==20 else start_r5+1),name
  assert bflags==dflags,(name,"default condition flags",start_r5,hex(bflags),hex(dflags))
  if id==20:assert dflags==cflags,("ID20 unexpectedly modifies flags",start_r5)
  if id==22 and start_r5==24:
   assert cflags!=dflags,("ID22 failed to change compare flags",hex(cflags),hex(dflags))
  for reg in REGS:
   if reg==output:continue
   assert before[reg]==default[reg]==changed[reg],(name,"unexpected changed reg",reg,start_r5)
  assert default[UC_ARM_REG_SP]==changed[UC_ARM_REG_SP]==0x2000E000
  results.append({"hook":name,"callsite":hex(addr),"r5_initial":start_r5,
                  "default_flags_match_stock":True,
                  "custom_output":changed[output],"custom_flags":hex(cflags)})
print(json.dumps({"pass":True,"checks":results},indent=2))
