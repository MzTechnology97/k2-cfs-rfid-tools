#!/usr/bin/env python3
"""Offline regression: RFID reinitialization must not erase live type4 use.
Executes actual CFG6 ARM wrapper with only third-party capture readiness stubbed.
Never contacts printer.
"""
from pathlib import Path
import struct,subprocess,json
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UcError
from unicorn.arm_const import *
HERE=Path(__file__).resolve().parent
FW=HERE/'CFG6-READONLY-DIAG1-NOT-FOR-FLASH.bin'
MAGIC=0x0803F001
ADDR=0x08010000
SLOT=1
ROW=0x20004590+SLOT*100
def symbols():
  data=subprocess.check_output(['arm-none-eabi-nm','-n',str(HERE/'handler-v3_23.elf')],text=True)
  return {x[2]:int(x[0],16) for l in data.splitlines() if len(x:=l.split())==3}
def probe(blob,slot=1,mode=1,initial=35):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
 u.mem_map(0x08000000,0x40000);u.mem_write(ADDR,blob)
 u.mem_map(0x20000000,0x10000)
 u.reg_write(UC_ARM_REG_CPSR,0x33)
 u.reg_write(UC_ARM_REG_SP,0x2000F000)
 u.reg_write(UC_ARM_REG_LR,MAGIC)
 u.reg_write(UC_ARM_REG_R0,slot)
 u.reg_write(UC_ARM_REG_R1,initial)
 # A valid type4 spool is already being accounted during printing.
 row=0x20004590+slot*100
 u.mem_write(row,struct.pack('<I',8200))
 u.mem_write(row+4,struct.pack('<I',330000))
 u.mem_write(row+12,struct.pack('<f',497500.0))
 u.mem_write(row+20,bytes((35,1,mode,1)))
 u.mem_write(row+99,bytes((4,)))
 u.mem_write(0x20003974+slot,bytes((33,)))
 sym=symbols()
 events=[]
 def on_code(c,addr,size,data):
  if addr==sym['thirdparty_ready_slot']:
   events.append('thirdparty_ready')
   c.reg_write(UC_ARM_REG_R0,1)
   c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
  elif addr==0x080123E4:events.append('stock_percent_setter')
  elif addr==0x0803F000:
   events.append('return');c.emu_stop()
 u.hook_add(UC_HOOK_CODE,on_code)
 try:u.emu_start(sym['remaining_init_wrapper']|1,MAGIC,count=1300)
 except UcError as exc:raise AssertionError((str(exc),hex(u.reg_read(UC_ARM_REG_PC)),events))
 return {'used_mm':struct.unpack('<I',u.mem_read(row,4))[0],
         'last_odo':struct.unpack('<f',u.mem_read(row+12,4))[0],
         'mode':u.mem_read(row+22,1)[0],
         'valid':u.mem_read(row+23,1)[0],
         'reported_pct':u.mem_read(0x20003974+slot,1)[0],
         'events':events}
if __name__=='__main__':
 # v3.25 baseline comparison belongs to the independently built v3.26 suite.
 # Its handler symbols differ from this DIAG1 image; never mix addresses.
 for slot in range(4):
  actual=probe(FW.read_bytes(),slot=slot,mode=1,initial=35)
  assert actual['used_mm']==8200,(slot,actual)
  assert actual['last_odo']==497500.0,(slot,actual)
  assert actual['mode']==1,(slot,actual)
  assert actual['reported_pct']==33,(slot,actual)
  assert 'stock_percent_setter' not in actual['events'],(slot,actual)
 print('PASS: all four printing type4 slots preserve used/baseline/pct')
 actual=probe(FW.read_bytes(),slot=1,mode=0,initial=35)
 assert actual['used_mm']==0 and actual['mode']==0,(actual,'IDLE rescan should seed geometry')
 assert actual['reported_pct']==35,(actual,'IDLE rescan should refresh initial percentage')
 print('PASS: idle type4 re-init remains available')
 actual=probe(FW.read_bytes())

 print(json.dumps(actual,indent=2))
 assert actual['used_mm']==8200,'BUG: RFID rescan resets live consumed millimetres'
 assert actual['last_odo']==497500.0,'BUG: RFID rescan loses odometer checkpoint'
 assert actual['mode']==1,'BUG: RFID rescan cancels print mode'
 assert actual['reported_pct']==33,'BUG: RFID rescan resets remaining percentage'
 print('PASS: active print state preserved during repeated RFID initialization')
