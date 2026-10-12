#!/usr/bin/env python3
"""Synthetic entry-contract test for CFS ROM pointer 0x0801939D.

Execute *unaltered original v3.13/v3.22 Thumb instructions* beginning
at that address, deliberately simulating an ordinary direct BLX-style
AAPCS callback: LR contains one synthetic return address, while stack
contains a different return address.

The observed code has no local PUSH and returns through POP {...,PC}.
This test demonstrates why caller/stack provenance must be proved
before treating it as an independently callable RT-Thread PWM callback.

The test is entirely emulated: no CFS, USART, driver, MMIO, motors,
production Kalico, firmware modifications or flash writes.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_SP,
)

from flash_ram_phase2_audit import APP_BASE, pinned
from cfs_pwm_callback_entry_abi_sanity import analyze as pinned_static, ENTRY

FLASH_BASE = 0x08000000
FLASH_SIZE = 0x80000
RAM_BASE = 0x20000000
RAM_SIZE = 0x10000
FAKE_REQUEST = 0x20002000
FAKE_STACK = 0x2000D000
FAKE_LR_RETURN = 0x08060001
FAKE_STACK_RETURN = 0x08050001
FAKE_STACK_VALUES = (0xF00D0003, 0xF00D0004, 0xF00D0005, FAKE_STACK_RETURN)

CASES = (("matching_checksum", 0, 0),
         ("mismatching_checksum", 1, 0xF4))


def emulate_entry(image: bytes, name: str, observed_checksum: int,
                  expected_return_value: int):
    # Require exact original instructions and original constructor literal.
    pinned_static(image)
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(FLASH_BASE, FLASH_SIZE)
    uc.mem_map(RAM_BASE, RAM_SIZE)
    uc.mem_write(APP_BASE, image)
    request = bytearray(32)
    request[0x08] = 0
    request[0x09] = 0
    request[0x0D] = observed_checksum
    uc.mem_write(FAKE_REQUEST, bytes(request))
    uc.mem_write(FAKE_STACK, struct.pack("<IIII", *FAKE_STACK_VALUES))
    uc.reg_write(UC_ARM_REG_SP, FAKE_STACK)
    uc.reg_write(UC_ARM_REG_R0, 0)
    uc.reg_write(UC_ARM_REG_R1, 0)
    uc.reg_write(UC_ARM_REG_R4, FAKE_REQUEST)
    uc.reg_write(UC_ARM_REG_LR, FAKE_LR_RETURN)
    observations = {"stack_return_reached": False, "LR_return_reached": False,
                    "stack_reads": [], "executed_original_addresses": []}

    def trace_code(u, pc, size, _):
        if pc == (FAKE_STACK_RETURN & ~1):
            observations["stack_return_reached"] = True
            u.emu_stop()
        elif pc == (FAKE_LR_RETURN & ~1):
            observations["LR_return_reached"] = True
            u.emu_stop()
        else:
            observations["executed_original_addresses"].append(hex(pc))

    def trace_read(u, access, address, size, value, _):
        if FAKE_STACK <= address < FAKE_STACK + 16:
            observations["stack_reads"].append([address, size])

    uc.hook_add(UC_HOOK_CODE, trace_code)
    uc.hook_add(UC_HOOK_MEM_READ, trace_read)
    uc.emu_start(ENTRY | 1, 0, count=40)
    if (not observations["stack_return_reached"]
            or observations["LR_return_reached"]):
        raise ValueError("0x0801939D synthetic return changed: manual review required")
    if uc.reg_read(UC_ARM_REG_R0) != expected_return_value:
        raise ValueError("0x0801939D checksum-path return changed")
    if uc.reg_read(UC_ARM_REG_SP) != FAKE_STACK + 16:
        raise ValueError("0x0801939D did not consume four caller stack words")
    for reg, expected in ((UC_ARM_REG_R3, FAKE_STACK_VALUES[0]),
                          (UC_ARM_REG_R4, FAKE_STACK_VALUES[1]),
                          (UC_ARM_REG_R5, FAKE_STACK_VALUES[2])):
        if uc.reg_read(reg) != expected:
            raise ValueError("callback restored registers from synthetic stack incorrectly")
    if not any(start <= FAKE_STACK+12 < start+size\n               for start, size in observations["stack_reads"]):
        raise ValueError("original callback return PC was not popped from stack")
    if ENTRY not in [int(a,16) for a in observations["executed_original_addresses"]]:
        raise ValueError("entrypoint not executed as original saved Thumb")
    return {
        "synthetic_case": name,
        "original_thumb_entry": hex(ENTRY),
        "synthetic_expected_checksum": observed_checksum,
        "return_value": hex(expected_return_value),
        "stack_return_address_used": observations["stack_return_reached"],
        "independent_LR_return_address_used": observations["LR_return_reached"],
        "original_POP_reads_caller_stack": True,
        "caller_stack_bytes_consumed": 16,
        "original_instructions_executed": len(observations["executed_original_addresses"]),
        "this_is_synthetic_not_actual_RT_Thread_dispatch": True,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v313", required=True, type=Path)
    parser.add_argument("--v322", required=True, type=Path)
    parser.add_argument("--json-out", type=Path)
    args=parser.parse_args()
    old=pinned(args.v313,"intermediate_v313")
    now=pinned(args.v322,"running_v322")
    a=[emulate_entry(old,*c) for c in CASES]
    b=[emulate_entry(now,*c) for c in CASES]
    if a!=b:
        raise ValueError("v3.13 / v3.22 synthetic callback Thumb traces changed")
    result={
        "scope":"Emulated original 0x0801939D under an ordinary independent callback entry assumption",
        "original_v313_and_v322_results_match":True,
        "cases":b,
        "assumed_entry_does_not_return_via_LR_in_any_case":True,
        "normal_direct_AAPCS_callback_contract_proven":False,
        "actual_RTThread_calling_context_proven":False,
        "real_PWM1_device_callback_binding_proven":False,
        "physical_motor_idle_signal_proven":False,
        "safe_to_hook_or_flash_v323":False,
        "real_device_or_serial_accessed":False,
    }
    payload=json.dumps(result,indent=2)+"\n"
    if args.json_out:
        args.json_out.write_text(payload)
    print(payload,end="")


if __name__=="__main__":
    main()
