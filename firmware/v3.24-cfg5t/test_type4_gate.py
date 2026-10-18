"""Offline emulation of type4-only secure-element task gate.
Never calls real CFS hardware and stops BEFORE stock filament task executes.
"""
from pathlib import Path
import json,struct
from unicorn import Uc, UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
p=Path(__file__).resolve().parent/"cfs0_050_G32-cfs0_000_153-runtime-config-v3_24-K2OH-CFG5T-TYPE4-EXPERIMENTAL.bin"
q=Path(__file__).resolve().parent.parent/"v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin"
trial=p.read_bytes()
stock=q.read_bytes()
SITE=0x08013684
TASK=0x0801368C
SKIP=0x0801367A
REGS=(UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,
       UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,
       UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP)
def run(blob, hw=0, slot=1, mode=1, kind=4, valid=1, total=330000, pct=42):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
 u.mem_map(0x08000000,0x40000)
 u.mem_write(0x08010000,blob)
 u.mem_map(0x20000000,0x10000)
 u.mem_write(0x20000000,bytes((hw,)))
 u.mem_write(0x200001F2,bytes((slot,)))
 if slot<4:
  base=0x20004590+100*slot
  u.mem_write(base+23,bytes((valid,)))
  u.mem_write(base+99,bytes((kind,)))
  u.mem_write(base+22,bytes((mode,)))
  u.mem_write(base+20,bytes((pct,)))
  u.mem_write(base+4,struct.pack("<I",total))
 u.reg_write(UC_ARM_REG_CPSR,0x33)
 for idx,r in enumerate(REGS):u.reg_write(r,0x31a4+idx*0x123)
 u.reg_write(UC_ARM_REG_SP,0x2000DF00)
 u.reg_write(UC_ARM_REG_LR,0x0803F001)
 before={r:u.reg_read(r) for r in REGS}
 touched=[];reached=[]
 def code(c,addr,size,user):
  if addr==TASK:reached.append("task");c.emu_stop()
  if addr==SKIP:reached.append("skip");c.emu_stop()
 def writes(c,access,addr,size,value,user):
  touched.append((addr,size))
  assert 0x2000DE00<=addr and addr+size<=0x2000E100,("illegal memory write",hex(addr))
 u.hook_add(UC_HOOK_CODE,code)
 u.hook_add(UC_HOOK_MEM_WRITE,writes)
 u.emu_start(SITE|1,0x0803F001,count=300)
 assert reached,(hw,slot,mode,kind,valid,total,pct)
 assert before=={r:u.reg_read(r) for r in REGS},("ABI changed",reached)
 return reached[0]
tests=[
 ("stock secure",1,1,1,7,1,330000,50,"task"),
 ("no chip no runtime",0,1,1,4,0,330000,50,"skip"),
 ("no chip type4 printing",0,1,1,4,1,330000,50,"task"),
 ("no chip type4 idle",0,1,0,4,1,330000,50,"skip"),
 ("no chip type4 unloading",0,1,2,4,1,330000,50,"skip"),
 ("no chip type7",0,1,1,7,1,330000,50,"skip"),
 ("no chip zero total",0,1,1,4,1,0,50,"skip"),
 ("no chip implausible total",0,1,1,4,1,9999,50,"skip"),
 ("no chip zero percent",0,1,1,4,1,330000,0,"skip"),
 ("no chip percent over 100",0,1,1,4,1,330000,101,"skip"),
 ("no chip invalid slot",0,255,1,4,1,330000,50,"skip"),
 ("no chip slot3 valid",0,3,1,4,1,330000,50,"task"),
]
out=[]
for name,hw,slot,mode,kind,valid,total,pct,expected in tests:
 before=run(stock,hw,slot,mode,kind,valid,total,pct)
 after=run(trial,hw,slot,mode,kind,valid,total,pct)
 assert before==("task" if hw else "skip"),(name,before)
 assert after==expected,(name,after,expected)
 out.append({"case":name,"stock":before,"experimental":after})
print(json.dumps({"pass":True,"cases":out,"tested_no_stock_task_execution":True},indent=2))
