#!/usr/bin/env python3
"""Run actual stock 0x0801B730 vneg, stubbing only low-level raw odometer.
Shows host raw negative readings are sign-inverted by stock: avoid abs() hacks.
"""
from arm_addresses import code, physical_symbols, ACTUAL_BASE, RETURN
from pathlib import Path
import struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE
from unicorn.arm_const import *
from paths import BASE_IMAGE, CANDIDATE_IMAGE
ROM=BASE_IMAGE.read_bytes()
PATCHED=CANDIDATE_IMAGE.read_bytes()
def f32_bits(f):return struct.unpack('<I',struct.pack('<f',f))[0]
def bits_f32(f):return struct.unpack('<f',struct.pack('<I',f))[0]
def probe(blob,raw):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
 u.mem_map(0x08000000,0x80000)
 u.mem_write(ACTUAL_BASE,blob)
 u.mem_map(0x20000000,0x10000)
 u.reg_write(UC_ARM_REG_CPSR,0x33)
 u.reg_write(UC_ARM_REG_FPEXC,0x40000000)
 u.reg_write(UC_ARM_REG_SP,0x2000F000)
 u.reg_write(UC_ARM_REG_LR,RETURN)
 seen=[]
 def hook(c,addr,size,_):
  if addr==code(0x08018606):
   c.reg_write(UC_ARM_REG_S0,f32_bits(raw))
   c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
   seen.append("raw_read")
  elif addr==(RETURN & ~1):
   seen.append("finish")
   c.emu_stop()
 u.hook_add(UC_HOOK_CODE,hook)
 u.emu_start(code(0x0801B730)|1,RETURN,count=100)
 assert seen==["raw_read","finish"],seen
 return bits_f32(u.reg_read(UC_ARM_REG_S0))
for raw in (-497000.0,-501100.0,-5.0,0.0,5.0):
 for blob in (ROM,PATCHED):
  obs=probe(blob,raw)
  assert obs==-raw,(raw,obs)
print("PASS: the original stock odometer already converts raw negative positions into positive printing progress")
print("No new absolute-value or blind sign flip in the firmware fix")
