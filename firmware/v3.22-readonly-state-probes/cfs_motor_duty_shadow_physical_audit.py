#!/usr/bin/env python3
"""Pin the real OEM CFS PWM duty-command SRAM shadow, offline only.

The CFS v3.13/v3.22 manufacturer command controller at 0x080110CC
(clamped 8-bit duty) writes a requested PWM value to a *volatile
software command shadow*, not to a measured rotor-position sensor.

Physical APP base = 0x08003000. Original v3.22 scatter zero-region:
  0x20000BC4..0x20006EE8, including both duty fields below.

Saved ROM bytes, original PC-relative literal values and each Thumb
instruction are SHA-pinned. No runtime MCU reads, motor commands,
flash writes or validation of actual physical motor-STOPPED.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path

from capstone import Cs,CS_ARCH_ARM,CS_MODE_LITTLE_ENDIAN,CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM,ARM_REG_PC
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE

CONTROLLER=0x080110CC
GLOBAL_LITERAL=0x08011244
GLOBAL_RAM=0x20004960
MOTOR_STRUCT_OFFSET=0xB4
MOTOR_STRUCT=GLOBAL_RAM+MOTOR_STRUCT_OFFSET
DUTY_FIELD=MOTOR_STRUCT+0x06
PREVIOUS_FIELD=MOTOR_STRUCT+0x08
RECORD_LITERAL=0x08011258
RECORD_RAM=0x20003778
BSS_BEGIN=0x20000BC4
BSS_END=0x20006EE8

# Full original source/opcode contract for a bounded straight-line subset.
PINS=(
    (0x080110CC,"push.w","{r4, r5, r6, r7, r8, lr}"),
    (0x080110D0,"mov","r5, r0"),
    (0x080110D2,"cmp","r0, #0xff"),
    (0x080110D6,"movs","r5, #0xff"),
    (0x080110E8,"ldr","r4, [pc, #0x158]"),
    (0x080110EA,"ldr","r7, [pc, #0x158]"),
    (0x080110EC,"adds","r4, #0xb4"),
    (0x080110F0,"ldrh","r1, [r4, #6]"),
    (0x080110F2,"strh","r1, [r4, #8]"),
    (0x08011124,"ldr","r5, [pc, #0x130]"),
    (0x08011126,"strh","r0, [r4, #6]"),
    (0x0801112C,"ldrb","r0, [r4, #4]"),
)
def word(image,addr):
    at=addr-LINK_BASE
    if at<0 or at+4>len(image):raise ValueError("outside saved OEM ROM")
    return struct.unpack_from("<I",image,at)[0]

def analyze(image):
    root=audited(image)
    if word(image,GLOBAL_LITERAL)!=GLOBAL_RAM or word(image,RECORD_LITERAL)!=RECORD_RAM:
        raise ValueError("original manufacturer motor command structure root literal changed")
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    instructions=[]
    for pc,expected_mnemonic,expected_args in PINS:
        i=pc-LINK_BASE
        inst=next(cs.disasm(image[i:i+4],pc,count=1),None)
        if not inst or (inst.mnemonic,inst.op_str)!=(expected_mnemonic,expected_args):
            raise ValueError(f"manufacturer PWM command Thumb changed at {pc:#x}")
        if pc in (0x080110E8,0x080110EA,0x08011124):
            if len(inst.operands)<2 or inst.operands[1].type!=ARM_OP_MEM or inst.operands[1].mem.base!=ARM_REG_PC:
                raise ValueError("root literal instruction no longer PC-relative")
            physical_word=((pc+4)&~3)+inst.operands[1].mem.disp
            if physical_word != (RECORD_LITERAL if pc==0x08011124 else GLOBAL_LITERAL):
                raise ValueError("PC-relative OEM data root literal address changed")
        instructions.append({"pc":hex(pc),"op":inst.mnemonic+" "+inst.op_str})
    if not (BSS_BEGIN<=DUTY_FIELD and PREVIOUS_FIELD+2<=BSS_END):
        raise ValueError("motor command SRAM shadow is not in zero-init region")
    if not root["five_names_in_expected_historical_order_proven"]:
        raise ValueError("OEM v3.22 names no longer source-proven")
    return {
        "source_verified_instructions":instructions,
        "original_motor_duty_controller_entry":hex(CONTROLLER),
        "zero_initialized_motor_data_root":hex(GLOBAL_RAM),
        "motor_command_structure_base":hex(MOTOR_STRUCT),
        "current_requested_duty_field":hex(DUTY_FIELD),
        "previous_requested_duty_field":hex(PREVIOUS_FIELD),
        "record_RAM_root":hex(RECORD_RAM),
        "source_data_region_BSS":[hex(BSS_BEGIN),hex(BSS_END)],
        "duty_values_are_software_command_history_only":True,
        "zero_command_means_real_motor_stopped":False,
        "feedback_from_encoder_OR_timer_state_found_here":False,
        "other_motor_controller_paths_and_IRQ_exhaustive":False,
        "no_actual_motor_activity_measured":True,
        "MCU_set_reset_gate_ready":False,
        "v323_safe_to_flash":False,
    }

def command_duty_fixtures():
    # Pure modeling: a requested stop may precede mechanical stop.
    scenarios=[
        ("requested_nonzero",255,False,False),
        ("commanded_zero_but_rotor_inertia",0,True,False),
        ("commanded_zero_no_independent_feedback",0,None,False),
        ("zero_brake_command_followed_by_new_start",0,True,False),
        ("known_motor_stop_independent_sensor",0,False,True),
    ]
    out=[]
    for label,command,physical_busy,qualified in scenarios:
        allowed=(command==0 and physical_busy is False and qualified)
        should=label=="known_motor_stop_independent_sensor"
        if allowed!=should:raise AssertionError("synthetic motor duty / physical state separation changed")
        out.append({"scenario":label,"commanded_duty":command,
                    "synthetic_physical_motor_busy":physical_busy,
                    "independent_sensor_qualified":qualified,
                    "synthetic_stop_status_possible":allowed,
                    "production_flash_or_write_authorized":False})
    return out

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--v313",type=Path,required=True)
    ap.add_argument("--v322",type=Path,required=True)
    ap.add_argument("--json-out",type=Path)
    o=ap.parse_args()
    before=analyze(pinned(o.v313,"intermediate_v313"))
    now=analyze(pinned(o.v322,"running_v322"))
    if before!=now:raise ValueError("OEM requested-duty BSS shadow changed between 3.13 and 3.22")
    d={"v313_equals_v322_original_motor_command_shadow":True,
       "manufacturer_original_software_command_shadow":now,
       "synthetic_command_vs_physical_feedback_cases":command_duty_fixtures(),
       "actual_MCU_motor_STOP_feedback_proven":False,
       "eligible_v323_motor_guard_release":False,
       "live_CFS_CM5_accessed":False}
    payload=json.dumps(d,indent=2)+"\n"
    if o.json_out:o.json_out.write_text(payload)
    print(payload,end="")
if __name__=="__main__":main()
