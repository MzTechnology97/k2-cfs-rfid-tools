#!/usr/bin/env python3
"""Trace CFS original GPIO IRQ pulse -> RAM counter -> motion metric (offline).

The original v3.13/v3.22 application is physically linked at 0x08003000.
At motor initialization GPIO device ID 0x4B registers Thumb callback
0x08010FDD through a driver operation table. That callback increments
RAM[0x20004990]. A separate task calculates the absolute difference
from the previous count stored at RAM[0x20004994], updates a derived
float at RAM[0x2000498C], and also changes a status byte at RAM[0x2000499C].

This proves firmware signal provenance and a GPIO callback configured
by the motor subsystem. It does NOT prove independent rotor motion, that
the IRQ fired on the actual installed CFS, that the pin is an encoder,
that every motor is observed, or that zero pulses imply hardware idle.

Strictly no MCU/serial/device access, no firmware writes, no hooks.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE, audited

RAM_GLOBAL=0x20004960
ROM_GLOBAL_LITERAL=0x08011244
ROM_IRQ_CALLBACK_LITERAL=0x0801125C
IRQ_THUMB_CALLBACK=0x08010FDD

# Pin original ROM executable locations and exact instructions.
PINNED={
    0x08010FE6:("push","{r2, r3, r4, lr}"),
    0x08011018:("movs","r1, #2"),
    0x0801101A:("movs","r0, #0x4b"),
    0x0801101C:("bl","#0x8018ec4"),
    0x08011020:("movs","r3, #0"),
    0x08011022:("ldr","r2, [pc, #0x238]"),
    0x08011024:("movs","r1, #1"),
    0x08011026:("movs","r0, #0x4b"),
    0x08011028:("bl","#0x8018e2e"),
    0x0801102C:("movs","r1, #1"),
    0x0801102E:("movs","r0, #0x4b"),
    0x08011030:("bl","#0x8018e94"),
    0x08018E2E:("push.w","{r3, r4, r5, r6, r7, r8, sb, lr}"),
    0x08018E4E:("ldr","r4, [r0, #0xc]"),
    0x08018E5C:("blx","r4"),
    0x08018EAE:("ldr","r3, [r0, #0x14]"),
    0x08018EBC:("bx","r3"),
    0x08010FDC:("ldr","r0, [pc, #0x264]"),
    0x08010FDE:("ldr","r1, [r0, #0x30]"),
    0x08010FE0:("adds","r1, r1, #1"),
    0x08010FE2:("str","r1, [r0, #0x30]"),
    0x08010FE4:("bx","lr"),
    0x08010E60:("push","{r4, r5, r6, r7, lr}"),
    0x08010E62:("ldr","r4, [pc, #0x3e0]"),
    0x08010E6A:("ldrd","r5, r0, [r4, #0x30]"),
    0x08010E6E:("cmp","r5, r0"),
    0x08010E72:("subs","r0, r5, r0"),
    0x08010E76:("mvns","r0, r0"),
    0x08010E78:("add","r0, r5"),
    0x08010E7A:("adds","r0, r0, #1"),
    0x08010E9C:("vstr","s1, [r4, #0x2c]"),
    0x08010ED4:("strb.w","r0, [r4, #0x3c]"),
    0x08010F44:("str","r5, [r4, #0x34]"),
    0x0801110A:("str","r6, [r7, #0x30]"),
    0x0801110C:("str","r6, [r7, #0x34]"),
    0x080111AC:("ldrb.w","r0, [r0, #0x3c]"),
}


def word(b:bytes,pc:int):
    o=pc-LINK_BASE
    if not 0<=o<=len(b)-4:
        raise ValueError("ROM literal outside pinned original CFS application")
    return struct.unpack_from("<I",b,o)[0]


def pinned_thumb(b:bytes):
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    for pc, pair in PINNED.items():
        o=pc-LINK_BASE
        if not 0<=o<=len(b)-4:
            raise ValueError(f"Thumb PC outside original image {pc:#x}")
        i=next(cs.disasm(b[o:o+4],pc,count=1),None)
        if i is None or (i.mnemonic,i.op_str)!=pair:
            raise ValueError(f"original Thumb changed at {pc:#x}: "
                             + (i.mnemonic+" "+i.op_str if i else "no code"))
    if word(b,ROM_GLOBAL_LITERAL)!=RAM_GLOBAL:
        raise ValueError("pulse-counter RAM base literal unexpectedly changed")
    if word(b,ROM_IRQ_CALLBACK_LITERAL)!=IRQ_THUMB_CALLBACK:
        raise ValueError("pin-0x4B IRQ callback pointer unexpectedly changed")
    for pc,disp in [(0x08011022,0x238)]:
        derived=((pc+4)&~3)+disp
        if derived!=ROM_IRQ_CALLBACK_LITERAL:
            raise ValueError("GPIO IRQ handler literal slot no longer linked")
    for pc,disp in [(0x08010FDC,0x264),(0x08010E62,0x3E0)]:
        derived=((pc+4)&~3)+disp
        if derived!=ROM_GLOBAL_LITERAL:
            raise ValueError("IRQ or sample loop no longer addresses shared counter")
    return [hex(p) for p in PINNED]


def analog_counter_model(now:int, previous:int):
    # Original ARM CMP and reverse-subtract logic gives *unsigned
    # distance*, not signed direction; wrap can exaggerate difference.
    return abs((now&0xffffffff)-(previous&0xffffffff))


def fail_closed_policy(motor_command_active:bool,pulses_delta:int,
                       source_authenticated:bool,isr_coverage_verified:bool):
    # This is a test of a future *hypothetical* MCU policy. No actual
    # write is enabled, even if a synthetic case looks safely idle.
    if motor_command_active:
        return False,"energized_or_commanded_motor_even_if_stalled"
    if not source_authenticated or not isr_coverage_verified:
        return False,"unknown_motor_state_or_incomplete_irq_coverage"
    if pulses_delta:
        return False,"observed_motion_pulses"
    return False,"physical_idle_not_authorized_by_this_probe"


def fixtures():
    expected=[
      (True,0,True,True,"energized_or_commanded_motor_even_if_stalled"),
      (True,10,True,True,"energized_or_commanded_motor_even_if_stalled"),
      (False,10,True,True,"observed_motion_pulses"),
      (False,0,False,True,"unknown_motor_state_or_incomplete_irq_coverage"),
      (False,0,True,False,"unknown_motor_state_or_incomplete_irq_coverage"),
      (False,0,True,True,"physical_idle_not_authorized_by_this_probe"),
    ]
    out=[]
    for active,pulses,verified,irq_ok,reason in expected:
        accept,why=fail_closed_policy(active,pulses,verified,irq_ok)
        if accept or why!=reason:
            raise AssertionError("motor busy fail-closed synthetic contract changed")
        out.append({"motor_command_active":active,"pulse_delta":pulses,
                    "sensor_authenticated":verified,
                    "ISR_coverage":irq_ok,"rejection_reason":why,
                    "write_approved":accept})
    for before,after,want in [
        (10,20,10),(20,10,10),(0,0,0),
        (0xfffffffe,0x00000001,0xfffffffd)
    ]:
        if analog_counter_model(before,after)!=want:
            raise AssertionError("original unsigned ARM delta model changed")
    return out


def analyze(image:bytes):
    base=audited(image)
    if not base["five_names_in_expected_historical_order_proven"]:
        raise ValueError("PWM initialization mapping not proven")
    instructions=pinned_thumb(image)
    return {
      "genuine_PIN_ID_for_GPIO_interrupt":"0x4b",
      "GPIO_interrupt_config_API_PC":"0x08018E2E",
      "GPIO_interrupt_enable_API_PC":"0x08018E94",
      "gpio_driver_indirect_registration_op_offset":"0x0C",
      "gpio_driver_indirect_enable_op_offset":"0x14",
      "saved_IRQ_callback_Thumb":hex(IRQ_THUMB_CALLBACK),
      "original_counter_increment_PC":"0x08010FDC",
      "original_counter_RAM":hex(RAM_GLOBAL+0x30),
      "sampled_previous_counter_RAM":hex(RAM_GLOBAL+0x34),
      "sampled_difference_float_RAM":hex(RAM_GLOBAL+0x2C),
      "software_activity_flag_RAM":hex(RAM_GLOBAL+0x3C),
      "counter_to_delta_calc_PC":"0x08010E60",
      "old_sample_update_PC":"0x08010F44",
      "counter_reset_when_duty_commanded_PC":"0x0801110A",
      "pinned_original_thumb_instructions":instructions,
      "counter_increment_reachable_by_configured_GPIO_callback":True,
      "physical_pulse_occurrence_measured_on_user_CFS":False,
      "pin_0x4B_verified_as_encoder_not_filament_or_other_sensor":False,
      "covers_feeder_hub_buffer_and_async_tasks":False,
      "zero_pulses_prove_motor_stopped":False,
      "MCU_WRITE_interlock_safe_to_activate":False
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--v313",type=Path,required=True)
    ap.add_argument("--v322",type=Path,required=True)
    ap.add_argument("--json-out",type=Path)
    a=ap.parse_args()
    older=analyze(pinned(a.v313,"intermediate_v313"))
    now=analyze(pinned(a.v322,"running_v322"))
    if older!=now:
        raise ValueError("original GPIO pulse producer differs between v3.13 and v3.22")
    tests=fixtures()
    result={
        "same_original_GPIO_irq_counter_and_sampler_both_versions":True,
        "v322":now,
        "fail_closed_stalled_motor_and_pulse_cases":tests,
        "synthetic_test_count":len(tests),
        "no_hardware_or_CM5_mutation":True,
        "flashable_v323_produced":False,
        "MCU_motor_guard_verified":False,
    }
    body=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":main()
