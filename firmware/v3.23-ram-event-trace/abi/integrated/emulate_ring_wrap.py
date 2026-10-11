#!/usr/bin/env python3
"""Regression: real compiled C ring logger across 70 synthetic motor entries.

This is a RAM-only Unicorn bench at fake flash address 0x08050000.
It does not validate real motor timing, ISR reentrancy or flash placement.
"""
import json
import struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP,
    UC_ARM_REG_LR,
)

HERE = Path(__file__).resolve().parent
BASE = 0x08010000
ENTRY = 0x0801E0CC
CONT = 0x0801E0D0
TRAMP = 0x08050000
RAM = 0x20006F28
LIMIT = RAM + 512
MAGIC = 0x33544643
STOCK = (
    HERE.parents[2] / "v3.19-volatile-ram"
    / "cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin"
).read_bytes()
REDIRECT = (HERE / "build" / "motor_hook_redirect.bin").read_bytes()
HOOK = (HERE / "build" / "motor_hook_ring_bench.bin").read_bytes()

def bench(count, seed_last_sequence=None):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(0x08000000, 0x00100000)
    uc.mem_map(0x20000000, 0x00020000)
    uc.mem_write(BASE, STOCK)
    uc.mem_write(ENTRY, REDIRECT)
    uc.mem_write(TRAMP, HOOK)
    ring = bytearray(512)
    struct.pack_into("<II", ring, 0, MAGIC, 1)
    if seed_last_sequence is not None:
        struct.pack_into("<HHHHI", ring, 8, 1, 1, 0, 0, 100)
        struct.pack_into("<IHBBHHHH", ring, 32, 100, seed_last_sequence, 1, 0, 0, 0, 0, 0)
    uc.mem_write(RAM, bytes(ring))
    writes = []
    stops = []
    def on_code(u, address, size, user):
        if address == CONT:
            stops.append(address)
            u.emu_stop()
    def on_write(u, access, addr, size, value, user):
        assert ((RAM <= addr and addr + size <= LIMIT)
                or (0x2000DE80 <= addr and addr + size <= 0x2000E000)), (
                    "unexpected write", hex(addr), size
                )
        writes.append((addr, size))
    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    for i in range(count):
        uc.reg_write(UC_ARM_REG_R0, (i * 23) & 0xFFFFFFFF)
        uc.reg_write(UC_ARM_REG_SP, 0x2000E000)
        uc.reg_write(UC_ARM_REG_LR, 0x08010001)
        uc.reg_write(UC_ARM_REG_CPSR, 0x33)
        uc.emu_start(ENTRY | 1, 0, count=550)
        assert len(stops) == i + 1, ("did not return", i, hex(uc.reg_read(UC_ARM_REG_PC)))
    data = bytes(uc.mem_read(RAM, 512))
    magic, generation, head, occupied, overwritten, frozen, last_tick = struct.unpack_from(
        "<IIHHHHI", data, 0
    )
    assert magic == MAGIC and generation == 1 and not frozen
    previous_count = 1 if seed_last_sequence is not None else 0
    total = count + previous_count
    assert head == total % 30 and occupied == min(total, 30)
    assert overwritten == max(0, total - 30)
    assert last_tick == (100 + count if seed_last_sequence is not None else count)
    oldest = (head + 30 - occupied) % 30
    events = [
        struct.unpack_from("<IHBBHHHH", data, 32 + ((oldest + i) % 30) * 16)
        for i in range(occupied)
    ]
    for left, right in zip(events, events[1:]):
        assert ((left[1] + 1) & 0xFFFF) == right[1], (left, right)
    if seed_last_sequence is None:
        assert [event[1] for event in events] == list(range(total - 30, total))
        assert [event[4] for event in events] == [
            ((i * 23) & 0xFFFF) for i in range(count - 30, count)
        ]
    else:
        assert events[0][1] == (seed_last_sequence & 0xFFFF)
        assert events[-1][1] == ((seed_last_sequence + count) & 0xFFFF)
    assert writes and any(RAM <= addr < LIMIT for addr, _ in writes)
    return {"events_written": count, "ring_count": occupied,
            "overwritten": overwritten, "first_sequence": events[0][1],
            "last_sequence": events[-1][1], "memory_write_calls": len(writes)}

results = [bench(70), bench(5, seed_last_sequence=65533)]
report = {"pass": True, "offline_only": True, "cases": results,
          "cfs_firmware_build_generated": False,
          "unverified": ["motor and ISR timing", "real SRAM bounds",
                         "real flash code bounds", "ring readout during actual movement"]}
(HERE / "V323_RING_WRAP_ARM_EMULATION.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("PASS synthetic MCU consecutive ring sequences after 70 events and 16-bit wrap")
