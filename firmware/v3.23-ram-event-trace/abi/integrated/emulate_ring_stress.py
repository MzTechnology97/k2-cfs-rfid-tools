#!/usr/bin/env python3
"""OFFLINE stress of synthesized CFS Thumb hook + *real* C ring logger.

This exercises 85 callbacks on the same emulated 512B ring, frozen/invalid
headers, 16-bit sequence rollover and stack high-water estimation. All
memory and executable placement is synthetic. NEVER generates an MCU BIN.
"""
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR,
)

HERE = Path(__file__).resolve().parent
STOCK_PATH = HERE.parents[2] / "v3.19-volatile-ram" / "cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin"
if not STOCK_PATH.exists():
    raise FileNotFoundError("Exact v3.13 stock baseline missing from repository")
STOCK = STOCK_PATH.read_bytes()
REDIRECT_PATH = HERE.parent / "build" / "motor_hook_redirect.bin"
HOOK_PATH = HERE / "build" / "motor_hook_ring_bench.bin"
if not REDIRECT_PATH.exists():
    REDIRECT_PATH = HERE / "motor_hook_redirect.bin"
    HOOK_PATH = HERE / "motor_hook_ring_bench.bin"
REDIRECT = REDIRECT_PATH.read_bytes()
HOOK = HOOK_PATH.read_bytes()
ENTRY, CONT, TRAMP = 0x0801E0CC, 0x0801E0D0, 0x08050000
RAM, SRAM_STACK_TOP = 0x20006F28, 0x2000E000
RING_BYTES, CAPACITY, MAGIC = 512, 30, 0x33544643
HEADER = struct.Struct("<IIHHHHI")
EVENT = struct.Struct("<IHBBHHHH")
REGS = (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR,
)
assert len(REDIRECT) == 4 and 300 <= len(HOOK) <= 700

def init():
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(0x08000000, 0x00100000)
    u.mem_map(0x20000000, 0x00020000)
    u.mem_write(0x08010000, STOCK)
    u.mem_write(ENTRY, REDIRECT)
    u.mem_write(TRAMP, HOOK)
    # Guard previously allocated 64-byte settings sidecar and post-ring heap.
    u.mem_write(RAM-64, b"\xCB"*64)
    u.mem_write(RAM+RING_BYTES, b"\xBC"*128)
    # Put a canary stack region below synthetic SP.
    u.mem_write(SRAM_STACK_TOP-1024, b"\xA6"*1024)
    return u

def put_ring(u, head=0, count=0, overwritten=0, frozen=0, tick=0, previous=None):
    b = bytearray(RING_BYTES)
    HEADER.pack_into(b, 0, MAGIC, 1, head, count, overwritten, frozen, tick)
    if previous is not None:
        previous_index = (head-1) % CAPACITY
        EVENT.pack_into(b, 32 + previous_index*16,
                        tick, previous, 1, 0, 5, 0, 0, 0)
    u.mem_write(RAM, bytes(b))

def state(u):
    b = bytes(u.mem_read(RAM, RING_BYTES))
    head = HEADER.unpack_from(b, 0)
    return head, [
        EVENT.unpack_from(b, 32 + i*16) for i in range(CAPACITY)
    ], b

def call(u, pwm, index, record):
    # Restore caller-owned synthetic registers and flags for this invocation.
    initial = (
        pwm, 0x11223344, 0x22334455, 0x33445566,
        0x44556677, 0x55667788, 0x66778899, 0x778899AA,
        0x8899AABB, 0x99AABBCC, 0xAABBCCDD, 0xBBCCDDEE,
        0xCCDDEEFF, 0x08010001, SRAM_STACK_TOP,
    )
    for r, val in zip(REGS, initial):
        u.reg_write(r, val)
    u.reg_write(UC_ARM_REG_CPSR, (((index%4)<<28)&0xF0000000)|0x33)
    sp_min = [SRAM_STACK_TOP]
    arrived = []
    writes = []

    def on_insn(unicorn, addr, size, user):
        sp_min[0] = min(sp_min[0], unicorn.reg_read(UC_ARM_REG_SP))
        if addr == CONT:
            arrived.append(addr)
            unicorn.emu_stop()

    def on_write(unicorn, access, addr, size, val, user):
        writes.append((addr, size))
        assert (
            RAM <= addr and addr+size <= RAM+RING_BYTES
        ) or (
            SRAM_STACK_TOP-1024 <= addr and addr+size <= SRAM_STACK_TOP
        ), (hex(addr), size)

    h1 = u.hook_add(UC_HOOK_CODE, on_insn)
    h2 = u.hook_add(UC_HOOK_MEM_WRITE, on_write)
    try:
        u.emu_start(ENTRY|1, 0, count=2000)
    finally:
        u.hook_del(h1)
        u.hook_del(h2)
    assert arrived == [CONT], ("continuation", arrived, index)
    got = tuple(u.reg_read(reg) for reg in REGS)
    want = tuple(initial[:-1]) + (SRAM_STACK_TOP-24, ((((index%4)<<28)&0xF0000000)|0x33))
    assert got == want, ("ABI register discrepancy", index, got, want)
    live = bytes(u.mem_read(SRAM_STACK_TOP-24, 24))
    # Original entry instruction was push.w {r4-r8,lr}.
    assert struct.unpack("<IIIIII", live) == (
        initial[4], initial[5], initial[6], initial[7], initial[8], initial[13]
    )
    record["worst_extra_stack_bytes"] = max(
        record["worst_extra_stack_bytes"], SRAM_STACK_TOP-sp_min[0]-24
    )
    record["max_write_operations"] = max(record["max_write_operations"], len(writes))
    assert bytes(u.mem_read(RAM-64, 64)) == b"\xCB"*64
    assert bytes(u.mem_read(RAM+RING_BYTES, 128)) == b"\xBC"*128

def main():
    u=init()
    put_ring(u)
    report={"passed":False, "tests":[], "worst_extra_stack_bytes":0,
            "max_write_operations":0, "code_bytes":len(HOOK)}
    # Emulate 85 operations, preserving the ring between operations.
    for i in range(85):
        call(u, 0x100+i, i, report)
        head, data, _ = state(u)
        assert head[2] == (i+1)%CAPACITY, ("head", i, head)
        assert head[3] == min(i+1, CAPACITY)
        assert head[4] == max(0, i+1-CAPACITY)
        assert head[6] == i+1, ("tick", i, head)
    head, data, _ = state(u)
    for i in range(CAPACITY):
        oldest = (head[2]-head[3]+i)%CAPACITY
        tick, sequence, kind, flags, motor0, motor1, task0, task1 = data[oldest]
        expected = 85-CAPACITY+i
        assert (tick,sequence,kind,motor0,motor1,task0,task1) == (
            expected+1,expected,1,0x100+expected,0x1234,0x5678,0x9ABC
        ), (i, data[oldest])
    report["tests"].append("85 callbacks across 2 full ring wraps; correct 55 overwritten and latest 30 chronological records")
    # Freeze should prevent all later writes to the ring.
    b=bytearray(state(u)[2])
    struct.pack_into("<H", b, 14, 1)
    u.mem_write(RAM, bytes(b))
    frozen=state(u)[2]
    call(u, 0xFFFF, 85, report)
    assert state(u)[2] == frozen, "frozen ring mutated"
    report["tests"].append("freeze blocks ring mutation, while caller ABI remains intact")
    # Corrupted head should refuse to access any event buffer element.
    put_ring(u, head=30, count=1, previous=None)
    invalid=state(u)[2]
    call(u, 0xAAAA, 86, report)
    assert state(u)[2] == invalid
    report["tests"].append("malformed header rejected before event array access")
    # Sequence wrap: last index has 65532, next events 65533, 65534,
    # 65535, 0, 1, 2, 3. No count-as-sequence bug.
    put_ring(u, head=1, count=1, tick=200, previous=65532)
    for i in range(7):
        call(u, 300+i, i+90, report)
        head, data, _ = state(u)
        idx=(head[2]-1)%CAPACITY
        assert data[idx][1] == (65533+i)&0xffff, data[idx]
        assert data[idx][0] == 201+i
    report["tests"].append("16-bit sequence 65535→0 rollover across seven events")
    report["passed"]=True
    report["flashable_firmware_produced"]=False
    report["unverified"]=[
        "actual MCU flash partition", "512-byte real SRAM reservation",
        "actual worst-case RTOS/interrupt stack", "motor callback deadlines",
        "full feeder/hub task coverage", "post-movement GET-only transport"
    ]
    target=HERE / "V323_RING_STRESS_ARM.json"
    target.write_text(json.dumps(report, indent=2)+"\n")
    print("PASS",len(report["tests"]),"offline stress scenarios",
          "max extra stack bytes",report["worst_extra_stack_bytes"],
          "mock ARM code",report["code_bytes"])
    return report

if __name__ == "__main__":
    main()
