#!/usr/bin/env python3
"""Stage 3 v3.23 exact stock instruction callsite ISA regressions; no hardware access."""
import json
import struct
from pathlib import Path
import sys
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import *
HERE=Path(__file__).resolve().parent
IMAGE=Path(sys.argv[1]) if len(sys.argv)>1 else Path.home()/"cfs-v323-build/v3_23-stage3-true-ms.bin"
BASELINE=HERE.parent/"v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_19-VOLATILE-RAM-BENCH.bin"
assert IMAGE.is_file() and BASELINE.is_file()
fw=IMAGE.read_bytes()
baseline=BASELINE.read_bytes()
APP=0x08010000
SC=0x20006EE8
REGS=[UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
      UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
      UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
      UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR]
cases=[
    (7,0x08011116,UC_ARM_REG_R0,3200,3300,3300),
    (8,0x080112CA,UC_ARM_REG_R1,700,8000,800),
]
def emulate(image,callsite,outreg,id=None,stored=None):
    em=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    em.mem_map(0x08000000,0x40000)
    em.mem_write(APP,image)
    em.mem_map(0x20000000,0x10000)
    em.mem_write(0x20000014,struct.pack("<I",0x200037E2))
    em.mem_write(0x200037E2,bytes([0,255,100,200,0,155,255,80]))
    em.mem_write(0x200001F2,b"\x04")
    if id is not None:
        em.mem_write(SC,struct.pack("<II",0x35564643,1<<(id-7)))
        em.mem_write(SC+8+2*(id-7),struct.pack("<H",stored))
    em.reg_write(UC_ARM_REG_CPSR,0x00000033)
    for z,reg in enumerate(REGS):
        em.reg_write(reg,(0x11110000+z*0x120) if reg not in (UC_ARM_REG_SP,UC_ARM_REG_LR)
                     else (0x2000E000 if reg==UC_ARM_REG_SP else 0x0803D001))
    em.reg_write(UC_ARM_REG_APSR,0xA0000000)
    initial={r:em.reg_read(r) for r in REGS}
    original_apsr=em.reg_read(UC_ARM_REG_APSR)
    executed=[]
    hit=[]
    def hook(uc,addr,size,data):
        executed.append(addr)
        if addr==callsite+4:
            hit.append(addr)
            uc.emu_stop()
        if len(executed)>400:raise RuntimeError("Callsite failed to return in 400 steps")
    em.hook_add(UC_HOOK_CODE,hook)
    em.emu_start(callsite|1,0x0803D001,count=400)
    assert hit and executed[0]==callsite,("callsite failed",hex(callsite),executed[:15])
    vals={r:em.reg_read(r) for r in REGS}
    after=em.reg_read(UC_ARM_REG_APSR)
    assert original_apsr==after,("APSR changed",hex(callsite),hex(original_apsr),hex(after))
    for reg,value in initial.items():
        if reg not in (outreg,UC_ARM_REG_LR):
            assert vals[reg]==value,("REG changed",hex(callsite),reg,hex(value),hex(vals[reg]))
    return vals[outreg],len(executed)
results=[]
for id,site,outreg,expected,custom,wire_output in cases:
    old,n_old=emulate(baseline,site,outreg)
    stage,n_stage=emulate(fw,site,outreg)
    assert old==stage==expected,(id,old,stage,expected)
    override,n_override=emulate(fw,site,outreg,id,custom)
    assert override==wire_output,(id,override,wire_output)
    results.append({"id":id,"callsite":hex(site),"stock_default":old,"new_default":stage,
                    "configured_value":custom,"stock_runtime_value":override,
                    "registers_and_flags_preserved":True,
                    "instruction_counts":{"baseline":n_old,"default":n_stage,"custom":n_override}})
print(json.dumps({"pass":True,"verified":results},indent=2))
(HERE/"v323-stage3-callsite-emulation.json").write_text(json.dumps(results,indent=2)+"\n")
