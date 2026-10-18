#!/usr/bin/env python3
"""Run the built v3.23 image on an emulated Cortex-M3 (Unicorn). No printer access.

    emulate_v3_23.py IMAGE.bin

Needs arm-none-eabi-nm (for handler-v3_23.elf, left by build-v3_23.py) and
the unicorn Python package. Addresses are the builder's nominal ones
(application at 0x08010000), as in emulate_v3_22.py.
"""
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_THUMB, Uc
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_R4, UC_ARM_REG_SP)

HERE = Path(__file__).resolve().parent
BASE = 0x08010000
SEND_RESPONSE = 0x0801BAF2
STOCK_INVALID = 0x0801C7F8
STOCK_51 = 0x0801C704
RETURN = 0x0803F001
SIDECAR = (0x20006EE8, 0x20006F28)
STACK = (0x2000DF00, 0x2000E100)

image = Path(sys.argv[1]).read_bytes()
nm = subprocess.check_output(
    ["arm-none-eabi-nm", "-n", str(HERE / "handler-v3_23.elf")], text=True)
SYM = {z[2]: int(z[0], 16) for line in nm.splitlines()
       if len(z := line.split()) == 3 and re.fullmatch("[0-9a-f]+", z[0])}


def cpu():
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(0x08000000, 0x40000)
    u.mem_write(BASE, image)
    u.mem_map(0x20000000, 0x10000)
    # Stock config root -> speed table, as in emulate_v3_22.py.
    u.mem_write(0x20000014, struct.pack("<I", 0x200037E2))
    u.mem_write(0x200037E2, bytes([0, 255, 100, 200, 0, 155, 255, 80]))
    u.mem_write(0x200001F2, bytes([4]))
    return u


def call(u, command, frame_len, payload=b""):
    """Dispatch one RS-485 command; return ('send', cmd, status, bytes) or ('stock', addr)."""
    request = bytearray(16)
    request[1] = frame_len
    request[4:4 + len(payload)] = payload
    u.mem_write(0x20008000, bytes(request))
    u.reg_write(UC_ARM_REG_R4, 0x20008000)
    u.reg_write(UC_ARM_REG_R0, command)
    u.reg_write(UC_ARM_REG_SP, 0x2000E000)
    u.reg_write(UC_ARM_REG_LR, RETURN)
    result = []

    def on_code(uc, addr, size, user):
        if addr == SEND_RESPONSE:
            ptr = uc.reg_read(UC_ARM_REG_R2)
            n = uc.reg_read(UC_ARM_REG_R3)
            result.append(("send", uc.reg_read(UC_ARM_REG_R0),
                           uc.reg_read(UC_ARM_REG_R1), bytes(uc.mem_read(ptr, n))))
            uc.emu_stop()
        elif addr in (STOCK_INVALID, STOCK_51):
            result.append(("stock", addr))
            uc.emu_stop()

    def on_write(uc, access, addr, size, value, user):
        ok = (SIDECAR[0] <= addr and addr + size <= SIDECAR[1]) or \
             (STACK[0] <= addr and addr + size <= STACK[1])
        assert ok, ("unexpected RAM write", hex(addr), size)

    h1 = u.hook_add(UC_HOOK_CODE, on_code)
    h2 = u.hook_add(UC_HOOK_MEM_WRITE, on_write)
    try:
        u.emu_start(SYM["handler_start"] | 1, RETURN, count=2000)
    finally:
        u.hook_del(h1)
        u.hook_del(h2)
    assert result, ("no response", hex(command))
    return result[0]


checks = {}
u = cpu()

# 0x7A identity.
kind, cmd, status, data = call(u, 0x7A, 3)
assert (kind, cmd, status, len(data)) == ("send", 0x7A, 0, 32), (kind, cmd, status, data)
assert data[0:4] == b"K2OH" and data[4] == 1 and data[5] == 4 and data[6] == 0
assert data[7] == 0x02
assert data[8:20] == b"v3.23-k2oh\0\0", data[8:20]
assert data[20:32] == image[0x200:0x20C] == b"cfs0_000_153", data[20:32]
checks["identity"] = data.hex()

kind, cmd, status, data = call(u, 0x7A, 4, b"\x00")
assert (kind, cmd, status, data) == ("send", 0x7A, 1, b""), (kind, cmd, status, data)
checks["identity_bad_length"] = "status 1"

# 0x57 INFO still answers on 0x57.
kind, cmd, status, data = call(u, 0x57, 4, b"\x10")
assert (kind, cmd, status) == ("send", 0x57, 0), (kind, cmd, status)
checks["config_info"] = data.hex()

# Unknown command and 0x51 still go to the stock paths.
assert call(u, 0x60, 3) == ("stock", STOCK_INVALID)
assert call(u, 0x51, 3) == ("stock", STOCK_51)
checks["stock_paths"] = "0x60 -> invalid, 0x51 -> stock"

print(json.dumps({"pass": True, "checks": checks}, indent=2))
