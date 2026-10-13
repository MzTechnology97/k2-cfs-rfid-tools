#!/usr/bin/env python3
"""Manufacturer GPIO pin helper entry and known BLDC brake caller — source audit.

Inspect original saved v3.13/v3.22 Thumb code at the GPIO-helper target
0x08018EEC, which is used by the known PE4 brake callsite 0x0801119E.
The intent is to find the actual RT-Thread logical-pin-to-physical-GPIO
dispatch, rather than treating unrelated occurrences of the GPIOD base
literal as motor writes.

Only verified source bytes are decoded; linear disassembly is not a
callgraph or register-liveness proof. No RTOS hooks or real MCU access.
"""
from __future__ import annotations
import argparse,json,struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE

HELPER=0x08018EEC
KNOWN_BLDC_BRAKE_CALL=0x0801119E
CONTEXTS=(
    ("gpio_pin_helper_entry",HELPER,HELPER+160),
    ("known_brake_caller_predecessor",0x08011188,0x080111B0),
)
MEM_OP_LIMIT=35
# Actual manufacturer Thumb disassembly verified by GitHub CI, not
# source reconstructed from an assumed C signature.
ORIGINAL_DISPATCH = (
    (0x08018EEC, "push", "{r4, r5, r6, lr}"),
    (0x08018EEE, "ldr", "r4, [pc, #0x27c]"),
    (0x08018EF0, "mov", "r6, r0"),
    (0x08018EF2, "mov", "r5, r1"),
    (0x08018EF4, "ldr", "r0, [r4, #0x40]"),
    (0x08018F04, "ldr", "r0, [r4, #0x40]"),
    (0x08018F06, "mov", "r2, r5"),
    (0x08018F08, "mov", "r1, r6"),
    (0x08018F0A, "ldr", "r3, [r0, #4]"),
    (0x08018F0C, "pop.w", "{r4, r5, r6, lr}"),
    (0x08018F10, "ldr", "r0, [pc, #0x258]"),
    (0x08018F12, "bx", "r3"),
)
BRAKE_CALL_INSTRUCTIONS = (
    (0x08011198,"push","{r4, lr}"),
    (0x0801119A,"movs","r1, #1"),
    (0x0801119C,"movs","r0, #0x44"),
    (0x0801119E,"bl","#0x8018eec"),
)
COMMON_GLOBAL_LITERAL_PC=0x0801916C



def inspect(image):
    audited(image)
    c=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    c.detail=True
    call=KNOWN_BLDC_BRAKE_CALL-LINK_BASE
    i=next(c.disasm(image[call:call+4],KNOWN_BLDC_BRAKE_CALL,count=1),None)
    if i is None or i.mnemonic!="bl" or i.op_str!=f"#0x{HELPER:x}":
        raise ValueError("known original BLDC brake GPIO helper BL changed")
    for pc,mnemonic,operands in ORIGINAL_DISPATCH + BRAKE_CALL_INSTRUCTIONS:
        pos=pc-LINK_BASE
        original=next(c.disasm(image[pos:pos+4],pc,count=1),None)
        if original is None or (original.mnemonic,original.op_str)!=(mnemonic,operands):
            raise ValueError(f"verified OEM RT-Thread GPIO dispatch source changed at {pc:#x}")
    # Two different OEM LDR literal instructions reference this exact
    # global object pointer; its live data/callback contents remain unknown.
    for pc,disp in ((0x08018EEE,0x27C),(0x08018F10,0x258)):
        if ((pc+4)&~3)+disp != COMMON_GLOBAL_LITERAL_PC:
            raise ValueError("GPIO helper global pointer literal derivation changed")
    root=struct.unpack_from("<I",image,COMMON_GLOBAL_LITERAL_PC-LINK_BASE)[0]
    views=[]
    for label,start,end in CONTEXTS:
        lo,hi=start-LINK_BASE,end-LINK_BASE
        if not 0<=lo<hi<=len(image):
            raise ValueError("original bounded Thumb window invalid")
        rows=[]
        accesses=[]
        for instruction in c.disasm(image[lo:hi],start):
            row={"pc":hex(instruction.address),
                 "mnemonic":instruction.mnemonic,
                 "operands":instruction.op_str}
            rows.append(row)
            if any(o.type==ARM_OP_MEM for o in instruction.operands):
                if len(accesses)<MEM_OP_LIMIT:
                    accesses.append(row)
        if not rows or rows[0]["pc"]!=hex(start):
            raise ValueError(f"OEM GPIO helper Thumb window {label} did not decode")
        views.append({"window":label,"first_instruction":rows[0],
                      "bounded_instructions":rows,"memory_operand_candidates":accesses,
                      "register_liveness_through_branches_PROVEN":False,
                      "GPIO_driver_register_side_effect_PROVEN":False})
    return {
        "physical_oem_APP_link_base":hex(LINK_BASE),
        "brake_known_GPIO_helper_BL_source":hex(KNOWN_BLDC_BRAKE_CALL),
        "original_helper_entry":hex(HELPER),
        "known_BL_thumb_encoding_verified":True,
        "original_callback_dispatch_instruction_sites_checked":len(ORIGINAL_DISPATCH),
        "known_PE4_brake_caller_sites_checked":len(BRAKE_CALL_INSTRUCTIONS),
        "original_global_object_literal_ROM_PC":hex(COMMON_GLOBAL_LITERAL_PC),
        "saved_original_global_object_root_constant":hex(root),
        "recovered_call_arguments":"r0=logical_RT_pin, r1=value",
        "pin_argument_copied_into_callback_r1":True,
        "value_argument_copied_into_callback_r2":True,
        "GPIO_device_loaded_from_global_object_plus_0x40":True,
        "device_callback_pointer_loaded_from_device_plus_0x04":True,
        "callback_invoked_by_indirect_BX_r3":True,
        "original_PE4_brake_call_r0":hex(0x44),
        "original_PE4_brake_call_r1_value":1,
        "effective_runtime_device_callback_pointer_resolved":False,
        "driver_MMIO_write_reached_in_this_static_study":False,
        "contexts":views,
        "rt_gpio_id_0x44_PE4_brake_context_unmodified":True,
        "pin_table_conversion_or_M1_M2_owner_proven":False,
        "all_M1_M2_write_callers_identified":False,
        "real_GPIO_MMIO_access_or_motor_state_measured":False,
        "safe_to_flash_v323":False,
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--v313",required=True,type=Path)
    ap.add_argument("--v322",required=True,type=Path)
    ap.add_argument("--json-out",type=Path)
    args=ap.parse_args()
    old=inspect(pinned(args.v313,"intermediate_v313"))
    cur=inspect(pinned(args.v322,"running_v322"))
    if old!=cur:
        raise ValueError("saved OEM GPIO helper Thumb context differs")
    result={"v313_v322_original_helper_contexts_identical":True,"v322":cur,
            "live_CFS_or_CM5_access":False,"MCU_SET_RESET_motor_active_authorized":False}
    data=json.dumps(result,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(data)
    print(data,end="")


if __name__=="__main__":
    main()
