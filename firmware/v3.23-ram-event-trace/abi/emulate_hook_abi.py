#!/usr/bin/env python3
"""Offline Thumb-2 motor hook ABI differential, without a CFS flashable BIN.

This verifies ONLY caller registers, CPSR, current SP and the live stack
at the original continuation. It does not check concurrency, real logger,
FPU/IRQ stack usage, motor coverage, peripheral effects, or MCU code placement.
"""
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR,
)

HERE = Path(__file__).resolve().parent
STOCK = (
    HERE.parents[1] / "v3.19-volatile-ram"
    / "cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin"
).read_bytes()
REDIRECT = (HERE / "build" / "motor_hook_redirect.bin").read_bytes()
HOOK = (HERE / "build" / "motor_hook_abi_prototype.bin").read_bytes()
BASE, ENTRY, CONT, TRAMP = 0x08010000, 0x0801E0CC, 0x0801E0D0, 0x08050000
assert len(REDIRECT) == 4 and len(HOOK) == 48
assert STOCK[ENTRY - BASE : CONT - BASE].hex() == "2de9f041"
REGS = (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR,
)
NAMES = (
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
    "R8", "R9", "R10", "R11", "R12", "LR", "SP", "CPSR",
)

def run(hooked, pwm, flags):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(0x08000000, 0x00100000)
    uc.mem_map(0x20000000, 0x00020000)
    uc.mem_write(BASE, STOCK)
    if hooked:
        uc.mem_write(ENTRY, REDIRECT)
        uc.mem_write(TRAMP, HOOK)
    # Scratch below SP is not guaranteed to remain unchanged.
    uc.mem_write(0x2000DF80, bytes([0xA6]) * 128)
    values = (
        pwm, 0x11223344, 0x22334455, 0x33445566,
        0x44556677, 0x55667788, 0x66778899, 0x778899AA,
        0x8899AABB, 0x99AABBCC, 0xAABBCCDD, 0xBBCCDDEE,
        0xCCDDEEFF, 0x08010001, 0x2000E000,
    )
    for reg, value in zip(REGS, values):
        uc.reg_write(reg, value)
    uc.reg_write(UC_ARM_REG_CPSR, (flags & 0xF8000000) | 0x33)
    arrived = []

    def on_insn(u, address, size, user):
        if address == CONT:
            arrived.append(address)
            u.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_insn)
    uc.emu_start(ENTRY | 1, 0, count=100)
    assert arrived == [CONT], (hooked, arrived, hex(uc.reg_read(UC_ARM_REG_PC)))
    registers = [uc.reg_read(reg) for reg in REGS]
    live_stack = bytes(uc.mem_read(0x2000DFE8, 24))
    freed_scratch = bytes(uc.mem_read(0x2000DFC0, 40))
    return registers, live_stack, freed_scratch

tested = 0
scratch_changed = 0
for pwm in (0, 1, 100, 155, 255, 0x12345678):
    for flags in (0, 0x10000000, 0x20000000, 0x60000000, 0xF0000000):
        original = run(False, pwm, flags)
        modified = run(True, pwm, flags)
        if original[:2] != modified[:2]:
            difference = [
                (NAMES[i], hex(a), hex(b))
                for i, (a, b) in enumerate(zip(original[0], modified[0]))
                if a != b
            ]
            raise AssertionError(
                ("trampoline ABI mismatch", pwm, hex(flags), difference,
                 original[1].hex(), modified[1].hex())
            )
        scratch_changed += original[2] != modified[2]
        tested += 1

result = {
    "passed": True,
    "cases": tested,
    "hook_bytes": len(HOOK),
    "redirect_bytes": len(REDIRECT),
    "registers_flags_live_stack_match": True,
    "freed_stack_scratch_changed_cases": scratch_changed,
    "extra_temporary_stack_bytes": 32,
    "not_validated": [
        "real ring logger", "IRQ/FPU/task concurrency", "motor task stack headroom",
        "all motor paths", "real MCU timing", "app flash address", "SRAM allocation",
    ],
    "flashed": False,
}
(HERE / "V323_ABI_EMULATION.json").write_text(json.dumps(result, indent=2) + "\n")
print(f"PASS: {tested} ARM ABI differential cases; changed freed stack: {scratch_changed}")
