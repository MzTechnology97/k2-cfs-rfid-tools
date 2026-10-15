#!/usr/bin/env python3
"""Source-authenticated RT-Thread GPIO pin registration and physical PD0-PD3 writer.

All inputs are SHA-pinned saved original CFS v3.13 and v3.22 APP files.
Proves the OEM *source* chain from "pin" initialization -> six-function
pin_ops -> global BSS registry -> GPIO write -> GPIOD BOP/BC.
Does NOT prove actual boot registration ran, which motor task requested
a PD0-PD3 write, output pin voltage, driver current or safe motor stop.

No remote MCU access, Flash, host changes, serial, pins or motor commands.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_REG_R1, ARM_REG_R4

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE

PIN_INIT = 0x0801AE2A
ROOT_LITERAL = 0x0801AE5C
PIN_NAME = 0x0801AE60
REGISTRAR = 0x08018DFA
ROOT_GLOBAL_LITERAL = 0x0801916C
ROOT_GLOBAL = 0x20004C44
DEVICE_FIELD = ROOT_GLOBAL + 0x40
OPS_TABLE = 0x0802B49C
OPS_BASE_LITERAL = 0x0802B45C
PIN_LOOKUP = 0x0801AB38
PIN_MAP_LITERAL = 0x0801AE54
PIN_MAP = 0x0802AD5C
WRITER = 0x0801AB90
PERIPHERAL_WRITE = 0x0802381E
DISPATCH = 0x08018EEC
PIN_OPS = (
    ("mode", 0x0801AB4E),
    ("write", WRITER),
    ("read", 0x0801ABAA),
    ("attach_irq", 0x0801ABC6),
    ("detach_irq", 0x0801AC3E),
    ("irq_enable", 0x0801AC86),
)
PIN_ROWS = (
    (0x30, "M2_PD0", 0x06050030, 0x0001, 0x0003),
    (0x31, "M2_PD1", 0x06050031, 0x0002, 0x0103),
    (0x32, "M1_PD2", 0x06050032, 0x0004, 0x0203),
    (0x33, "M1_PD3", 0x06050033, 0x0008, 0x0303),
)
PERIPHERAL_GPIOD = 0x40011400
OPS_POINTER_OFFSET = 0x40
BOP_OFFSET = 0x10
BC_OFFSET = 0x14


def read32(data: bytes, addr: int) -> int:
    if not (LINK_BASE <= addr and addr + 4 <= LINK_BASE + len(data)):
        raise ValueError(f"ROM address out of bounds: {addr:#x}")
    return struct.unpack_from("<I", data, addr - LINK_BASE)[0]


def readbytes(data: bytes, addr: int, length: int) -> bytes:
    if not (LINK_BASE <= addr and addr + length <= LINK_BASE + len(data)):
        raise ValueError(f"ROM range out of bounds: {addr:#x}")
    return data[addr-LINK_BASE:addr-LINK_BASE+length]


def decoder() -> Cs:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    return cs


def at(data: bytes, pc: int, cs: Cs, expected: tuple[str, str]):
    got = next(cs.disasm(readbytes(data, pc, 4), pc, count=1), None)
    if got is None or (got.mnemonic, got.op_str) != expected:
        raise ValueError(
            f"OEM instruction at {pc:#x} changed: "
            f"{(got.mnemonic, got.op_str) if got else None} != {expected}")
    return got


def source_audit(data: bytes) -> dict:
    cs = decoder()

    # The OEM board init function at 0x0801AE2A tail-jumps (B.W) to
    # rt_device_pin_register. The earlier BL-only census could not find it.
    pin_init = (
        (0x0801AE2A, ("ldr", "r1, [pc, #0x30]")),
        (0x0801AE2C, ("movs", "r2, #0")),
        (0x0801AE2E, ("adds", "r1, #0x40")),
        (0x0801AE30, ("adr", "r0, #0x2c")),
        (0x0801AE32, ("b.w", f"#{REGISTRAR:#x}")),
    )
    for pc, op in pin_init:
        at(data, pc, cs, op)
    if read32(data, ROOT_LITERAL) + OPS_POINTER_OFFSET != OPS_TABLE:
        raise ValueError("pin_ops pointer arithmetic does not resolve")
    if readbytes(data, PIN_NAME, 4) != b"pin\0":
        raise ValueError("registered OEM GPIO name is not 'pin'")
    if ROOT_LITERAL != ((PIN_INIT + 4) & ~3) + 0x30:
        raise ValueError("LDR base/offset not tied to literal")
    if PIN_NAME != ((0x0801AE30 + 4) & ~3) + 0x2c:
        raise ValueError("ADR does not address the 'pin' string")

    # Six consecutive device callbacks. No heuristic about what r4 contains:
    # the real registrar gets r1 from exact previous source instructions.
    callback_ptrs = []
    for n, (name, address) in enumerate(PIN_OPS):
        v = read32(data, OPS_TABLE + 4*n)
        if v != address | 1:
            raise ValueError(f"unexpected {name} pin_ops Thumb pointer")
        if at(data, address, cs,
              {
                  "mode": ("push", "{r4, r5, r6, lr}"),
                  "write": ("push", "{r4, lr}"),
                  "read": ("push", "{r4, lr}"),
                  "attach_irq": ("push.w", "{r4, r5, r6, r7, r8, sb, sl, lr}"),
                  "detach_irq": ("push", "{r4, r5, r6, lr}"),
                  "irq_enable": ("push.w", "{r4, r5, r6, r7, r8, lr}"),
              }[name]).address != address:
            raise ValueError("not a function entry")
        callback_ptrs.append({"operation": name,
                              "ROM_table_slot": hex(OPS_TABLE + n*4),
                              "Thumb_callback": hex(v)})

    # Prove saved source r1 -> callee-saved r4 -> registered BSS device.
    at(data, REGISTRAR, cs, ("push", "{r4, lr}"))
    at(data, REGISTRAR + 2, cs, ("mov", "r4, r1"))
    at(data, REGISTRAR + 4, cs, ("ldr", "r1, [pc, #0x36c]"))
    at(data, 0x08018E1A, cs, ("str", "r4, [r1, #0x40]"))
    if read32(data, ROOT_GLOBAL_LITERAL) != ROOT_GLOBAL:
        raise ValueError("BSS global root literal wrong")
    block = list(cs.disasm(readbytes(data, REGISTRAR + 4,
                                    0x08018E1A - (REGISTRAR+4) + 2),
                           REGISTRAR+4))
    if (not block or block[0].address != REGISTRAR+4 or
            block[-1].address != 0x08018E1A or
            any(x.address+x.size!=y.address for x,y in zip(block,block[1:]))):
        raise ValueError("registrar register-preservation chain not contiguous")
    for ins in block[1:-1]:
        if ins.mnemonic.startswith("b") or ins.mnemonic in {"it", "cbz", "cbnz", "pop", "push"}:
            raise ValueError("registrar contains unexpected control-flow barrier")
        _, writes = ins.regs_access()
        if ARM_REG_R1 in writes or ARM_REG_R4 in writes:
            raise ValueError("registrar unexpectedly overwrites root or callback")

    # RT-Thread GPIO write dispatcher uses the registered device +4 slot.
    for pc, op in (
        (0x08018EEE, ("ldr", "r4, [pc, #0x27c]")),
        (0x08018EF4, ("ldr", "r0, [r4, #0x40]")),
        (0x08018F04, ("ldr", "r0, [r4, #0x40]")),
        (0x08018F06, ("mov", "r2, r5")),
        (0x08018F08, ("mov", "r1, r6")),
        (0x08018F0A, ("ldr", "r3, [r0, #4]")),
        (0x08018F12, ("bx", "r3")),
    ):
        at(data, pc, cs, op)

    # Pin write callback calls board pin-lookup and tail-calls the set/reset
    # peripheral helper with r0=GPIOx base, r1=pin mask, r2=requested bit.
    for pc, op in (
        (0x0801AB92, ("uxtb", "r0, r1")),
        (0x0801AB94, ("bl", f"#{PIN_LOOKUP:#x}")),
        (0x0801AB9C, ("ldr", "r1, [r0, #8]")),
        (0x0801AB9E, ("ldr", "r0, [r0, #4]")),
        (0x0801ABA4, ("b.w", f"#{PERIPHERAL_WRITE:#x}")),
        (0x0801AB3C, ("ldr", "r1, [pc, #0x314]")),
        (0x0801AB3E, ("add.w", "r0, r1, r0, lsl #4")),
    ):
        at(data, pc, cs, op)
    if read32(data, PIN_MAP_LITERAL) != PIN_MAP:
        raise ValueError("manufacturer pin lookup table origin changed")

    for pc, op in (
        (PERIPHERAL_WRITE, ("cbz", "r2, #0x8023824")),
        (PERIPHERAL_WRITE + 2, ("str", "r1, [r0, #0x10]")),
        (PERIPHERAL_WRITE + 4, ("bx", "lr")),
        (PERIPHERAL_WRITE + 6, ("str", "r1, [r0, #0x14]")),
        (PERIPHERAL_WRITE + 8, ("bx", "lr")),
    ):
        at(data, pc, cs, op)
    rows = []
    for pin, label, word0, mask, field3 in PIN_ROWS:
        location = PIN_MAP + pin*16
        actual = tuple(read32(data, location + 4*n) for n in range(4))
        if actual != (word0, PERIPHERAL_GPIOD, mask, field3):
            raise ValueError(f"OEM {label} pin data differs from pinned expected record")
        rows.append({"OEM_logical_pin": hex(pin), "PCB_pin": label,
                     "ROM_table_record": hex(location),
                     "GPIO_base": hex(actual[1]),
                     "GPIO_BOP_set_register": hex(actual[1]+BOP_OFFSET),
                     "GPIO_BC_clear_register": hex(actual[1]+BC_OFFSET),
                     "onehot_mask": hex(actual[2])})

    return {
        "saved_image_real_APP_base": hex(LINK_BASE),
        "OEM_board_initialization_tail_branch": hex(0x0801AE32),
        "RT_Thread_GPIO_registrar": hex(REGISTRAR),
        "configured_device_name_from_ROM": "pin",
        "pin_ops_ROM_table": hex(OPS_TABLE),
        "all_six_pin_ops_function_pointers": callback_ptrs,
        "pin_ops_pointer_loaded_from_ROM_not_BSS_dump": True,
        "registered_global_BSS_field": hex(DEVICE_FIELD),
        "dispatcher_callback_offset": 4,
        "GPIO_write_callback": hex(WRITER),
        "GPIO_write_peripheral_helper": hex(PERIPHERAL_WRITE),
        "GPIO_write_nonzero_sets_BOP_zero_clears_BC": True,
        "original_PD0_PD3_GPIO_records": rows,
        "manufacturer_source_flow_confirmed": True,
        "board_initializer_executed_on_live_CFS_proven": False,
        "live_register_value_or_GPIO_level_measured": False,
        "all_M1_M2_motor_start_stop_callers_recovered": False,
        "motor_current_and_physical_stop_verified": False,
        "MCU_SET_RESET_or_flash_authorized": False,
    }


def negative_fixtures(original: bytes) -> list[str]:
    rejected = []
    sites = (
        ("corrupted_GPIO_pin_ops_function_pointer", OPS_TABLE + 4),
        ("corrupted_GPIO_registration_tail_branch", 0x0801AE32),
        ("corrupted_GPIO_write_callback_tail_branch", 0x0801ABA4),
        ("corrupted_GPIOD_BOP_write", PERIPHERAL_WRITE + 2),
        ("corrupted_PD0_record_port_base", PIN_MAP + 0x30*16 + 4),
        ("corrupted_pin_name", PIN_NAME),
    )
    for label, location in sites:
        changed = bytearray(original)
        changed[location - LINK_BASE] ^= 1
        try:
            source_audit(bytes(changed))
        except ValueError:
            rejected.append(label)
        else:
            raise AssertionError(f"unreviewed manufacturer mutation accepted: {label}")
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v313", type=Path, required=True)
    parser.add_argument("--v322", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    old = pinned(args.v313, "intermediate_v313")
    new = pinned(args.v322, "running_v322")
    audited(old)
    audited(new)
    a = source_audit(old)
    b = source_audit(new)
    if a != b:
        raise ValueError("GPIO source flow changed across stock and v3.22")
    result = {
        "v313_v322_GPIO_ops_source_bytes_agree": True,
        "original_rom_evidence": b,
        "live_CFS_connected_or_tested": False,
        "v323_release_permitted": False,
    }
    if args.self_test:
        failed = negative_fixtures(new)
        if len(failed) != 6:
            raise ValueError("not all GPIO negative cases were rejected")
        result["negative_fixtures_rejected"] = failed
    body = json.dumps(result, indent=2)+"\n"
    if args.json_out:
        args.json_out.write_text(body)
    print(body, end="")


if __name__ == "__main__":
    main()
