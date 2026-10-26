#!/usr/bin/env python3
"""Run original motor entry vs synthetic logger-connected ring, offline only."""
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
import struct, json

HERE=Path(__file__).resolve().parent
BASE=0x08010000
ENTRY=0x0801E0CC
CONT=0x0801E0D0
TRAMP=0x08050000
RAM=0x20006F28
CAPACITY=512
MAGIC=0x33544643
STOCK=(HERE.parents[2]/"v3.19-volatile-ram"/"cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin").read_bytes()
REDIRECT=(HERE/"build"/"motor_hook_redirect.bin").read_bytes()
HOOK=(HERE/"build"/"motor_hook_ring_bench.bin").read_bytes()
assert len(REDIRECT)==4 and 300<=len(HOOK)<=700
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
      UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
      UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,
      UC_ARM_REG_R12,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_CPSR)
def sample(hooked,pwm,flags):
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    uc.mem_map(0x08000000,0x00100000)
    uc.mem_map(0x20000000,0x00020000)
    uc.mem_write(BASE,STOCK)
    if hooked:
        uc.mem_write(ENTRY,REDIRECT)
        uc.mem_write(TRAMP,HOOK)
    ring=bytearray(CAPACITY)
    struct.pack_into("<II",ring,0,MAGIC,1)
    uc.mem_write(RAM,bytes(ring))
    uc.mem_write(0x2000DF00,bytes([0xA6])*256)
    init=(pwm,0x11223344,0x22334455,0x33445566,0x44556677,
          0x55667788,0x66778899,0x778899AA,0x8899AABB,0x99AABBCC,
          0xAABBCCDD,0xBBCCDDEE,0xCCDDEEFF,0x08010001,0x2000E000)
    for reg,val in zip(REGS,init):uc.reg_write(reg,val)
    uc.reg_write(UC_ARM_REG_CPSR,(flags&0xF8000000)|0x33)
    entered=[]
    writes=[]
    stack_low=0x2000DE80
    stack_high=0x2000E000
    def step(u,addr,size,user):
        if addr==CONT:
            entered.append(addr)
            u.emu_stop()
    def written(u,access,addr,size,value,user):
        writes.append((addr,size))
        assert ((RAM<=addr and addr+size<=RAM+CAPACITY)
                or (stack_low<=addr and addr+size<=stack_high)),(hex(addr),size)
    uc.hook_add(UC_HOOK_CODE,step)
    uc.hook_add(UC_HOOK_MEM_WRITE,written)
    uc.emu_start(ENTRY|1,0,count=600)
    assert entered==[CONT],(entered,hex(uc.reg_read(UC_ARM_REG_PC)))
    regs=[uc.reg_read(x) for x in REGS]
    live_stack=bytes(uc.mem_read(0x2000DFE8,24))
    data=bytes(uc.mem_read(RAM,CAPACITY))
    header=struct.unpack_from("<IIHHHHI",data,0)
    event=struct.unpack_from("<IHBBHHHH",data,32)
    return regs,live_stack,header,event,writes

count=0
peak_writes=0
for pwm in (0,1,100,155,255,0x12345678):
    for flags in (0,0x10000000,0x20000000,0x60000000,0xF0000000):
        before=sample(False,pwm,flags)
        after=sample(True,pwm,flags)
        assert before[:2]==after[:2],("REG_OR_LIVE_STACK_MISMATCH",pwm,hex(flags))
        assert before[2][2:]==(0,0,0,0,0),before[2]
        assert before[3]==(0,0,0,0,0,0,0,0),before[3]
        assert after[2]==(MAGIC,1,1,1,0,0,1),("BAD_RING_HEADER",after[2])
        assert after[3]==(1,0,1,0,pwm&0xffff,0x1234,0x5678,0x9abc),("BAD_EVENT",pwm,after[3])
        assert any(RAM<=a<RAM+CAPACITY for a,_ in after[4]),("NO_RING_WRITES",pwm)
        assert all(not(RAM<=a<RAM+CAPACITY) for a,_ in before[4])
        peak_writes=max(peak_writes,len(after[4]))
        count+=1

result={"pass":True,"cases":count,"hook_and_ring_code_bytes":len(HOOK),
        "synthetic_event_during_mock_motor_entry":True,
        "return_registers_cpsr_sp_and_live_stack_match_stock":True,
        "writes_restricted_to_ring_and_stack":True,
        "ring_header_and_16byte_event_exact":True,"max_memory_write_instructions":peak_writes,
        "not_validated":["actual motor control runtime","interrupt nesting and latency",
         "all CFS motor paths","512B SRAM safe reservation",
         "real bootloader flash map","RTOS task stack headroom",
         "fixed motor-active flag and atomic SET/RESET gate"],
        "flashed":False}
(HERE/"V323_RING_INTEGRATION_ARM_EMULATION.json").write_text(json.dumps(result,indent=2)+"\n")
print("PASS",count,"offline Thumb motor hook + REAL C ring logger differential cases; bytes",len(HOOK))