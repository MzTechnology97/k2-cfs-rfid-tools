#!/usr/bin/env python3
"""CFS original PWM GPIO vs commanded-duty/flag signal provenance.

Decode the authentic, SHA-pinned v3.13 and v3.22 compressed initial
RAM using the verified physical APP origin 0x08003000. Pin precise
manufacturer Thumb instructions for:
  * five named PWM objects with port/mask in initial SRAM,
  * motor duty controller and its PWM calls,
  * RAM flag set/read by motor command code,
  * float metric read (not authenticated rotor measurement),
  * generic GPIO input read (not proof of motion).
All signals are classified by evidence, not by assumed semantics.

No Flash patch, no hardware reads, no RT-Thread hook, no CFS movement,
no Kalico edits. Hardware motor-stop authority remains UNPROVEN.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE, audited
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar

NAME_MAP=(
    ("pwm1",0x2000075C,0x40011800,0x2000,"E",13,0x0802C9E4),
    ("pwm3",0x200007BC,0x40011400,0x1000,"D",12,0x0802C9EC),
    ("pwm4",0x2000081C,0x40011400,0x2000,"D",13,0x0802C9F4),
    ("pwm5",0x2000087C,0x40011400,0x8000,"D",15,0x0802C9FC),
    ("pwm8",0x200008DC,0x40011400,0x4000,"D",14,0x0802CA04),
)
SRC_START=0x0802DB6C
SRC_END=0x0802DE38
OUTPUT_LEN=3012
SHARED_RAM_BASE=0x20004960
FLAG_ADDR=SHARED_RAM_BASE+0x3C
FLOAT_ADDR=SHARED_RAM_BASE+0x2C
# Exact instructions at actual physical PCs; fail if either CFS image differs.
INSTRUCTIONS={
    0x080110CC:("push.w","{r4, r5, r6, r7, r8, lr}"),
    0x080110EA:("ldr","r7, [pc, #0x158]"),
    0x08011116:("bl","#0x8019516"),
    0x0801111E:("bl","#0x8019488"),
    0x0801114A:("movs","r0, #0x14"),
    0x0801114C:("strb.w","r0, [r7, #0x3c]"),
    0x080111AA:("ldr","r0, [pc, #0x98]"),
    0x080111AC:("ldrb.w","r0, [r0, #0x3c]"),
    0x080111B0:("cbz","r0, #0x80111b6"),
    0x080111B2:("movs","r0, #0"),
    0x080111B4:("bx","lr"),
    0x080111B6:("movs","r0, #1"),
    0x080111B8:("bx","lr"),
    0x080111F4:("ldr","r0, [pc, #0x4c]"),
    0x080111F6:("vldr","s0, [r0, #0x2c]"),
    0x080111FA:("vabs.f32","s0, s0"),
    0x08011202:("vmov","r0, s0"),
    0x08019488:("push","{r4, r5, lr}"),
    0x08019516:("push","{r4, r5, r6, r7, lr}"),
    0x0801ABBA:("bl","#0x802382c"),
    0x0802382C:("ldr","r0, [r0, #8]"),
    0x0802382E:("ands","r0, r1"),
    0x08023830:("beq","#0x8023834"),
}
EXPECTED_FLAG_QUERY_BL=(0x080038AE,0x08003932,0x08003C8A)


def word(raw:bytes,address:int):
    at=address-LINK_BASE
    if not 0<=at<=len(raw)-4:
        raise ValueError(f"ROM literal out of bounds at {address:#x}")
    return struct.unpack_from("<I",raw,at)[0]


def check_code(raw:bytes):
    cap=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    pinned_instructions=[]
    for pc,expected in INSTRUCTIONS.items():
        at=pc-LINK_BASE
        ins=next(cap.disasm(raw[at:at+4],pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=expected:
            raise ValueError(f"original Thumb mismatch at {pc:#x}: "+
                             (ins.mnemonic+" "+ins.op_str if ins else "no instruction"))
        pinned_instructions.append(hex(pc))
    # PC-relative pointer loads at the motor command flag writer and
    # readers resolve to the SAME original initialized RAM global.
    for at, displacement in ((0x080110EA,0x158),
                             (0x080111AA,0x98),
                             (0x080111F4,0x4C)):
        literal=((at+4)&~3)+displacement
        if literal!=0x08011244 or word(raw,literal)!=SHARED_RAM_BASE:
            raise ValueError("original command flag and float share pointer changed")
    for site in EXPECTED_FLAG_QUERY_BL:
        offset=site-LINK_BASE
        ins=next(cap.disasm(raw[offset:offset+4],site,count=1),None)
        if ins is None or ins.mnemonic!="bl" or ins.op_str!="#0x80111aa":
            raise ValueError("real command flag query BL callsite changed")
    return {"verified_physical_Thumb_instructions":pinned_instructions,
            "original_command_flag_query_callers":[hex(s) for s in EXPECTED_FLAG_QUERY_BL],
            "original_shared_RAM_pointer_literal":"0x08011244",
            "command_RAM_base":hex(SHARED_RAM_BASE),
            "command_flag_RAM":hex(FLAG_ADDR),
            "separate_float_RAM":hex(FLOAT_ADDR),
            "flag_nonzero_returns_zero":True,
            "flag_zero_returns_one":True,
            "flag_proven_to_be_actual_motor_rotor_stop":False,
            "float_proven_independent_encoder_feedback":False,
            "GPIO_input_helper_at":"0x0802382C",
            "GPIO_input_helper_reads_port_ISTAT_at_offset":8,
            "GPIO_input_proven_connected_to_motor_feedback":False,
            "motor_command_controller_at":"0x080110CC"}


def analyze(image:bytes):
    # Also checks vector, reset, original scatter and all five names.
    init=audited(image)
    if not init["five_names_in_expected_historical_order_proven"]:
        raise ValueError("cannot use unverified PWM name ordering")
    end=SRC_END-LINK_BASE
    begin=SRC_START-LINK_BASE
    decoder,ram=bounded_thumb_grammar(image[begin:end],OUTPUT_LEN)
    if not decoder["valid"] or decoder["source_consumed"]!=716:
        raise ValueError("CFS original initialization source not fully decoded")
    named=[]
    for name,base,port,pin,gpio_letter,gpio_num,string_ptr in NAME_MAP:
        offset=base-0x20000000
        values={o:struct.unpack_from("<I",ram,offset+o)[0]
                for o in (0x44,0x48,0x4C,0x50,0x54,0x5C)}
        if (values[0x48],values[0x4C],values[0x54])!=(port,pin,string_ptr):
            raise ValueError(f"original {name} GPIO mapping differs")
        if pin != (1<<gpio_num):
            raise ValueError("pin mask and bit position inconsistent")
        end_string=string_ptr-LINK_BASE
        if image[end_string:end_string+len(name)+1]!=name.encode()+b"\0":
            raise ValueError("PWM ROM string does not match compressed initializer")
        named.append({
            "name":name,"RT_Thread_object":hex(base),
            "port_base":hex(port),"pin_mask":hex(pin),
            "nominal_GPIO":f"P{gpio_letter}{gpio_num}",
            "GPIO_configuration_field_plus_0x50":hex(values[0x50]),
            "GPIO_configuration_field_plus_0x5c":hex(values[0x5C]),
            "ROM_name_pointer":hex(string_ptr),
            "pin_reports_rotor_movement":False,
        })
    return {"origin":hex(LINK_BASE),
            "named_GPIO_port_pin":named,
            "hardware_and_cached_signal_routines":check_code(image),
            "physical_motor_busy_feedback_qualified":False,
            "motor_stop_safeguard_can_be_enabled":False,
            "pin_input_is_independent_encoder_state":False,
            "all_motor_paths_and_ISRs_covered":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    earlier=analyze(pinned(a.v313,"intermediate_v313"))
    latest=analyze(pinned(a.v322,"running_v322"))
    if earlier!=latest:
        raise ValueError("v3.13 and v3.22 verified physical GPIO/command structures differ")
    result={"both_original_firmwares_identical":True,"v322":latest,
            "actual_installed_CFS_RAM_or_GPIO_read":False,
            "no_device_or_Kalico_commands":True,
            "v323_firmware_flash_release_allowed":False}
    payload=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(payload)
    print(payload,end="")


if __name__=="__main__":
    main()
