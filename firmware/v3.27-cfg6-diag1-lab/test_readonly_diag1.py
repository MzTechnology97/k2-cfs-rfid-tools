#!/usr/bin/env python3
"""CFG6 DIAG1 frame/ABI/read-only regression; ARM Unicorn only. No hardware."""
import struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
    UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_PC,
)
BASE = 0x08010000
ROM = (Path(__file__).parent / "CFG6-READONLY-DIAG1-NOT-FOR-FLASH.bin").read_bytes()
ENTRY = 0x0803AE38
SEND = 0x0801BAF2
DONE = 0x0801C808
ROW = 0x20004590
STACK = 0x2000E000
FMT = "<4s8BIIff4B"
assert struct.calcsize(FMT) == 32

def call(slot, frame_len=5, active_slot=None, runtime_mode=1, valid=1,
         runtime_type=4, hw_flag=0, used=7541, percent=59):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(0x08000000, 0x40000)
    u.mem_write(BASE, ROM)
    u.mem_map(0x20000000, 0x10000)
    if active_slot is None:
        active_slot = slot if slot < 4 else 0
    u.mem_write(0x200001F2, bytes([active_slot]))
    u.mem_write(0x200037D2, b"\x02")
    u.mem_write(0x20000000, bytes([hw_flag]))
    u.mem_write(0x200001AC, struct.pack("<f", -498001.5))
    for i in range(4):
        row = ROW + 100 * i
        u.mem_write(row, struct.pack("<II", used+i, 330000))
        u.mem_write(row+12, struct.pack("<f", 497500.0+i))
        u.mem_write(row+20, bytes([60+i, 1, runtime_mode, valid]))
        u.mem_write(row+40, b"\x00")
        u.mem_write(row+99, bytes([runtime_type]))
        u.mem_write(0x20003974+i, bytes([percent-i]))
        u.mem_write(0x2000391E+i, b"\x01")
    request = bytearray(16)
    request[1] = frame_len
    request[4:6] = bytes([0x15, slot & 0xff])
    u.mem_write(0x20008000, bytes(request))
    before = bytes(u.mem_read(0x20000000, 0x8100))  # includes request
    regs = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7]
    sentinels = [0x20008000, 0xF57D31A4, 0xC0FFEE11, 0xABCDEFAA]
    for reg, value in zip(regs, sentinels):
        u.reg_write(reg, value)
    u.reg_write(UC_ARM_REG_CPSR, 0x33)
    u.reg_write(UC_ARM_REG_SP, STACK)
    u.reg_write(UC_ARM_REG_LR, 0x0803F001)
    u.reg_write(UC_ARM_REG_R0, 0x57)
    messages, unexpected_calls, writes = [], [], []

    def on_code(c, addr, size, unused):
        if addr == SEND:
            length = c.reg_read(UC_ARM_REG_R3)
            ptr = c.reg_read(UC_ARM_REG_R2)
            data = bytes(c.mem_read(ptr, length)) if length else b""
            messages.append((c.reg_read(UC_ARM_REG_R0), c.reg_read(UC_ARM_REG_R1), data))
            c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))
        elif addr == DONE:
            c.emu_stop()
        elif addr == 0x0803F000:
            raise AssertionError("unexpected return")
        elif addr in (0x08018606, 0x0801B730, 0x080123E4, 0x0801AA14):
            unexpected_calls.append(hex(addr))

    def on_write(c, access, addr, size, value, unused):
        writes.append((addr, size))
        assert 0x2000DE00 <= addr < addr+size <= 0x2000E100, (
            "non-stack RAM write", hex(addr), size)

    u.hook_add(UC_HOOK_CODE, on_code)
    u.hook_add(UC_HOOK_MEM_WRITE, on_write)
    u.emu_start(ENTRY | 1, 0x0803F001, count=2000)
    assert len(messages) == 1 and not unexpected_calls, (messages, unexpected_calls)
    assert bytes(u.mem_read(0x20000000, 0x8100)) == before, "global RAM changed"
    assert u.reg_read(UC_ARM_REG_SP) == STACK, "stack leak"
    assert [u.reg_read(x) for x in regs] == sentinels, "callee-saved ABI changed"
    assert writes, "did not exercise stack"
    return messages[0]

checks = []
for slot in range(4):
    cmd,status,packet = call(slot,used=7000+slot*100,percent=60)
    assert cmd == 0x57 and status == 0 and len(packet) == 32
    (magic,requested,active,box,hw,valid,kind,mode,latch,used,total,
      last_odom,raw,initial,cfs,marker,error) = struct.unpack(FMT,packet)
    assert (magic,requested,active,box,hw) == (b"RDG1",slot,slot,2,0)
    assert (valid,kind,mode,latch,used,total) == (1,4,1,1,7000+slot*100+slot,330000)
    assert (last_odom,raw,initial,cfs,marker,error) == (
        497500.0+slot,-498001.5,60+slot,60-slot,1,0)
    checks.append(slot)
for kwargs in [
    dict(slot=4),dict(slot=255),dict(slot=2,frame_len=4),
    dict(slot=2,frame_len=6),dict(slot=0,frame_len=0),
]:
    assert call(**kwargs) == (0x57,1,b""),kwargs
for params in [
    dict(runtime_mode=0),dict(runtime_mode=2),dict(valid=0),
    dict(runtime_type=7),dict(hw_flag=1),dict(active_slot=3)
]:
    assert call(1,**params)[1] == 0,params

print("PASS: DIAG1 fixed 32-byte frame, four slots, invalid-frame rejection")
print("PASS: raw odometer, used/total, runtime gates, percentages match exact RAM")
print("PASS: only stack RAM writes, no RFID, motor, stock odometer or global RAM writes")
print("PASS: response return unwinds stack and preserves r4-r7")
