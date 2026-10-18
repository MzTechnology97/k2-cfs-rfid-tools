#!/usr/bin/env python3
"""CFS v3.22: GPIO-bound RT-Thread PWM devices versus commanded motor state.

SHA-pinned original APP (physically linked at 0x08003000) only.
Recover initial SRAM using ORIGINAL scatter stream; validate five GPIO
descriptors and EXACT manufacturer Thumb instructions, then trace the
motor-command state byte 0x2000499C and its three direct callers.

This is COMMAND/STATUS PROVENANCE ONLY. GPIO output-readback, a zero-duty
command, a state-byte countdown, and a returned Boolean cannot prove
physical motor stop. Do not use this audit to authorize MCU writes/flash.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar

NAMES=("pwm1","pwm3","pwm4","pwm5","pwm8")
BASES=tuple(0x2000075c+96*i for i in range(5))
GPIO_REGS=((0x40011800,0x2000),(0x40011400,0x1000),
           (0x40011400,0x2000),(0x40011400,0x8000),
           (0x40011400,0x4000))
GPIO_PORTS={"0x40011800":"GPIOE","0x40011400":"GPIOD"}
MOTOR_ROOT=0x20004960
CANDIDATE_FLAG=MOTOR_ROOT+0x3c
SHARED_DUTY=0x080110cc
GETTER=0x080111aa
GETTER_CALLS=(0x080038ae,0x08003932,0x08003c8a)
GPIO_INPUT_HELPER=0x0802382c
GPIO_READ_DISPATCH=0x0801abba
SCATTER_START=0x0802db6c
SCATTER_END=0x0802de38
ORIGINAL_APP_LINK_END=0x0802e7dc

def i32(data,location):
    off=location-LINK_BASE
    if not 0<=off<=len(data)-4:
        raise ValueError("physical code/ROM literal address outside CFS APP")
    return struct.unpack_from("<I",data,off)[0]

def decode_at(data,address):
    off=address-LINK_BASE
    if not 0<=off<len(data)-4:
        raise ValueError("original Thumb PC out of saved application")
    ins=next(Cs(CS_ARCH_ARM, CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
             .disasm(data[off:off+4],address,count=1),None)
    if ins is None or ins.address!=address:
        raise ValueError(f"missing original code at {address:#x}")
    return ins

def check(data,address,mnemonic,operand):
    ins=decode_at(data,address)
    if (ins.mnemonic,ins.op_str)!=(mnemonic,operand):
        raise ValueError(f"manufacturer Thumb differs at {address:#x}: "
                         f"{ins.mnemonic} {ins.op_str}")
    return {"pc":hex(address),"opcode":ins.bytes.hex(),
            "instruction":mnemonic+" "+operand}

def audit(data):
    baseline=audited(data)
    if LINK_BASE+len(data)!=ORIGINAL_APP_LINK_END:
        raise ValueError("the v3.22 source APP length/link base differs")
    packed=data[SCATTER_START-LINK_BASE:SCATTER_END-LINK_BASE]
    status,ram=bounded_thumb_grammar(packed,3012)
    if not status["valid"] or len(ram)!=3012 or status["source_consumed"]!=716:
        raise ValueError("actual linked SRAM did not fully reconstruct")
    if not baseline["five_names_in_expected_historical_order_proven"]:
        raise ValueError("five original PWM names not independently pinned")
    devices=[]
    for name,object_base,(gpio,mask) in zip(NAMES,BASES,GPIO_REGS):
        offset=object_base-0x20000000
        if offset<0 or offset+0x58>len(ram):
            raise ValueError("saved PWM object outside original scatter region")
        stored_gpio,stored_mask=struct.unpack_from("<II",ram,offset+0x48)
        stored_name=struct.unpack_from("<I",ram,offset+0x54)[0]
        at=stored_name-LINK_BASE
        resolved=data[at:at+len(name)+1]
        if (stored_gpio,stored_mask)!=(gpio,mask) or resolved!=name.encode()+b"\x00":
            raise ValueError(f"PWM original GPIO name/register mapping differs: {name}")
        devices.append({
          "name":name, "original_object_RAM":hex(object_base),
          "name_field_RAM":hex(object_base+0x54),
          "GPIO_register_base":hex(gpio),
          "GPIO_port_name":GPIO_PORTS[hex(gpio)],
          "GPIO_pin_bit_mask":hex(mask),
          "GPIO_pin_number":mask.bit_length()-1,
          "pin_setup_fields_initialised_before_RT_device_register":True,
          "GPIO_level_proves_physical_motor_stop":False
        })
    # The five named objects are initialised as GPIO fields, then
    # registered through a separate RT-Thread device constructor.
    pins=[
      check(data,0x0801b3d8,"movs","r2, #3"),
      check(data,0x0801b3da,"ldr","r3, [r0, #0x4c]"),
      check(data,0x0801b3dc,"ldr","r0, [r0, #0x48]"),
      check(data,0x0801b3de,"movs","r1, #0x18"),
      check(data,0x0801b3e0,"bl","#0x8023770"),
      check(data,0x0801b406,"ldr","r1, [r0, #0x54]"),
      check(data,0x0801b408,"bl","#0x801944a"),
      check(data,0x08016ac2,"ldr","r3, [r4, #0x38]"),
      check(data,0x08016ad0,"bx","r3"),
      check(data,0x0802382c,"ldr","r0, [r0, #8]"),
      check(data,0x0802383c,"ldr","r0, [r0, #0xc]"),
      check(data,0x0801abba,"bl","#0x802382c"),
      check(data,0x08010e60,"push","{r4, r5, r6, r7, lr}"),
      check(data,0x08010e62,"ldr","r4, [pc, #0x3e0]"),
      check(data,0x08010ebe,"ldrb.w","r0, [r4, #0x3c]"),
      check(data,0x08010ec2,"cbz","r0, #0x8010ed8"),
      check(data,0x08010ec4,"subs","r0, r0, #1"),
      check(data,0x08010ec6,"b","#0x8010ed4"),
      check(data,0x08010ed2,"movs","r0, #0x14"),
      check(data,0x08010ed4,"strb.w","r0, [r4, #0x3c]"),
      check(data,0x080110e8,"ldr","r4, [pc, #0x158]"),
      check(data,0x080110ea,"ldr","r7, [pc, #0x158]"),
      check(data,0x080110ec,"adds","r4, #0xb4"),
      check(data,0x0801114a,"movs","r0, #0x14"),
      check(data,0x0801114c,"strb.w","r0, [r7, #0x3c]"),
      check(data,0x080111aa,"ldr","r0, [pc, #0x98]"),
      check(data,0x080111ac,"ldrb.w","r0, [r0, #0x3c]"),
      check(data,0x080111b0,"cbz","r0, #0x80111b6"),
      check(data,0x080111b2,"movs","r0, #0"),
      check(data,0x080111b4,"bx","lr"),
      check(data,0x080111b6,"movs","r0, #1"),
      check(data,0x080111b8,"bx","lr"),
    ]
    # Literal shared by the original duty controller and status getter.
    if i32(data,0x08011244)!=MOTOR_ROOT:
        raise ValueError("manufacturer motor state RAM base literal changed")
    for site in GETTER_CALLS:
        pins.append(check(data,site,"bl",f"#0x{GETTER:x}"))
    return {
      "corrected_saved_APP_base":hex(LINK_BASE),
      "saved_ROM_end":hex(LINK_BASE+len(data)),
      "objects":devices,
      "original_Thumb_instructions_pinned":pins,
      "pinned_instruction_count":len(pins),
      "GPIO_input_data_register_offset":8,
      "GPIO_output_data_register_offset":12,
      "GPIO_READ_helper_direct_motor_feedback_proven":False,
      "original_motor_shared_duty_controller":hex(SHARED_DUTY),
      "motor_RAM_root_from_original_PC_literal":hex(MOTOR_ROOT),
      "motor_possible_status_or_timeout_byte":hex(CANDIDATE_FLAG),
      "original_periodic_state_root_load_PC":"0x8010e62",
      "software_countdown_read_PC":"0x8010ebe",
      "software_countdown_subtract_one_PC":"0x8010ec4",
      "software_countdown_writeback_PC":"0x8010ed4",
      "software_countdown_reload_0x14_PC":"0x8010ed2",
      "observed_set_nonzero_0x14_PC":"0x801114c",
      "software_countdown_semantics_proven":True,
      "counter_zero_proves_all_rotors_stopped":False,
      "getter_PC":hex(GETTER),
      "getter_return_when_byte_nonzero":0,
      "getter_return_when_byte_zero":1,
      "getter_3_verified_BL_call_sites":[hex(i) for i in GETTER_CALLS],
      "all_motors_and_ISR_paths_covered_proven":False,
      "byte_represents_hardware_encoder_or_rotor_stop_proven":False,
      "readable_status_has_atomicity_with_motor_start_proven":False,
      "can_authorize_volatile_MCU_SET_RESET":False,
      "can_authorize_flash_v323":False,
      "performed_real_MCU_or_CM5_writes":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    source=pinned(a.v322,"running_v322")
    result=audit(source)
    text=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(text)
    print(text,end="")

if __name__=="__main__":main()
