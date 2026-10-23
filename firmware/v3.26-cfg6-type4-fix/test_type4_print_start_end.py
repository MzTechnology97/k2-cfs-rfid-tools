"""Unicorn offline: stock print-start -> gated full type4 accounting -> original percent getter.
The odometer and LOG side-effects are modeled; the real stock start function,
accounting code, percent setter and getter all execute from the linked image.
"""
from pathlib import Path
import json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UcError
from unicorn.arm_const import *
FW=(Path(__file__).resolve().parent/"CFG6-TYPE4-RESCAN-FIX-NOT-FOR-FLASH.bin").read_bytes()
U32=lambda v:struct.unpack("<I",struct.pack("<f",v))[0]
READ=lambda v:struct.unpack("<I",v)[0]
BASE=0x20004590
START=0x0801A8AC
GATE=0x08013684
END=0x0803F001
ODOM=0x0801B730
LOG=0x0802D074
SET=0x080123E4
def one(slot=1,initial=42,delta=4100,kind=4,secure=0):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
 u.mem_map(0x08000000,0x40000)
 u.mem_write(0x08010000,FW)
 u.mem_map(0x20000000,0x10000)
 u.mem_write(0x20000000,bytes([secure]))
 u.mem_write(0x200001F2,bytes([slot]))
 u.mem_write(0x200001F3,bytes([initial]))
 for i in range(4):
  u.mem_write(0x20003974+i,bytes([initial]))
  u.mem_write(0x2000391E+i,b"\x01")
 base=BASE+100*slot
 u.mem_write(base,struct.pack("<II",0,330000))
 u.mem_write(base+12,struct.pack("<f",0))
 u.mem_write(base+20,bytes([initial,0,0,1]))
 u.mem_write(base+99,bytes([kind]))
 u.reg_write(UC_ARM_REG_CPSR,0x33)
 u.reg_write(UC_ARM_REG_FPEXC,0x40000000)
 u.reg_write(UC_ARM_REG_SP,0x2000EE00)
 u.reg_write(UC_ARM_REG_LR,END)
 events=[]
 phase=["start"]
 def ret(c):
  c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
 def callback(c,addr,size,user):
  if addr==0x0803F000:
   c.emu_stop()
  elif addr==ODOM:
   odo=100.0 if phase[0]=="start" else 100.0+delta
   c.reg_write(UC_ARM_REG_S0,U32(odo))
   events.append(("odometer",phase[0],odo))
   ret(c)
  elif addr==LOG:ret(c)
  elif addr==SET:
   events.append(("stock_set",c.reg_read(UC_ARM_REG_R0),c.reg_read(UC_ARM_REG_R1)))
  elif addr==0x0801AE3E:
   events.append(("complete_manager",))
   c.emu_stop()
  elif addr==0x08013690:
   events.append(("complete_gate_loop",))
   c.emu_stop()
  elif addr==0x0801367A:
   events.append(("stock_gate_denied",))
   c.emu_stop()
 u.hook_add(UC_HOOK_CODE,callback)
 # 0x04 START initiates a new accounting checkpoint on this slot.
 u.reg_write(UC_ARM_REG_R0,slot)
 try:
  u.emu_start(START|1,END,count=7000)
 except UcError as exc:raise AssertionError(("start",str(exc),hex(u.reg_read(UC_ARM_REG_PC)),events))
 state1=u.mem_read(base+22,1)[0]
 baseline=struct.unpack("<f",u.mem_read(base+12,4))[0]
 assert state1==1 and baseline==100.0,(state1,baseline,events)
 # Isolated slot task invocation; no fake mode change or percent setter.
 phase[0]="printing"
 u.reg_write(UC_ARM_REG_LR,END)
 try:
  u.emu_start(GATE|1,END,count=12000)
 except UcError as exc:raise AssertionError(("task",str(exc),hex(u.reg_read(UC_ARM_REG_PC)),events))
 used=READ(u.mem_read(base,4))
 pct=u.mem_read(0x20003974+slot,1)[0]
 # Original stock getter backing CMD 0x03 (no stub).
 u.reg_write(UC_ARM_REG_R0,slot)
 u.reg_write(UC_ARM_REG_LR,END)
 u.reg_write(UC_ARM_REG_SP,0x2000EE00)
 u.emu_start(0x080123CE|1,END,count=100)
 getter=u.reg_read(UC_ARM_REG_R0)
 phase[0]="end"
 u.reg_write(UC_ARM_REG_R0,slot)
 u.reg_write(UC_ARM_REG_LR,END)
 u.reg_write(UC_ARM_REG_SP,0x2000EE00)
 u.emu_start(0x0801A940|1,END,count=9000)
 end_used=READ(u.mem_read(base,4))
 end_mode=u.mem_read(base+22,1)[0]
 end_active=u.mem_read(0x200001F2,1)[0]
 return {"slot":slot,"start_mode":state1,"start_odom":baseline,
         "end_used_mm":end_used,"end_mode":end_mode,"end_active":end_active,
         "new_used_mm":used,"new_percent":pct,"stock_getter":getter,
         "other_slot_percent":[u.mem_read(0x20003974+i,1)[0] for i in range(4)],
         "events":events}
cases=[]
for slot,initial,delta in [(0,42,4100),(1,42,4100),(2,42,5),(3,42,25),(1,1,42000)]:
 v=one(slot,initial,delta)
 expected_used=delta if delta>=10 else 0
 assert v["new_used_mm"]==expected_used,(slot,initial,delta,v)
 expected_pct=max(1,initial-(expected_used*100//330000))
 assert v["new_percent"]==expected_pct,(expected_pct,v)
 assert v["stock_getter"]==expected_pct
 assert v["end_mode"]==0,(slot,v)
 assert v["end_active"]==4,(slot,v)
 assert v["end_used_mm"]==delta,(slot,delta,v)
 assert all(x==initial for i,x in enumerate(v["other_slot_percent"]) if i!=slot)
 cases.append(v)
print(json.dumps({"pass":True,"cases":cases},indent=2))
