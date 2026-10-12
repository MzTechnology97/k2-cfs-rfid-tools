#!/usr/bin/env python3
"""Offline v3.22 CFS actual GPIO configuration and command-shadow map.

Discover exact five original RT-Thread pwm* device objects by decoding
real manufacturer 716B scatter blob under actual APP link 0x08003000.
Pin original *physical* Thumb GPIO init loop and common motor-duty
software shadow writes. These are COMMANDED output signals, NOT an
authenticated rotor/encoder state or a motor-active write interlock.

No live CFS/CM5 IO, UART, MCU peripheral reads, firmware modifications,
motor actions or vendor BIN published.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE, OBJECTS, EXPECTED_NAMES
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar

GPIO_BANKS = {0x40011400: "D", 0x40011800: "E"}
PHYSICAL_EXPECTED = (
    ("pwm1",0x2000075C,0x40011800,0x2000,2),
    ("pwm3",0x200007BC,0x40011400,0x1000,0),
    ("pwm4",0x2000081C,0x40011400,0x2000,1),
    ("pwm5",0x2000087C,0x40011400,0x8000,3),
    ("pwm8",0x200008DC,0x40011400,0x4000,2),
)
# Literal at physical 0x0801B510 is the RAM pointer for five objects.
DEVICE_ARRAY_LITERAL_ADDR = 0x0801B510
DEVICE_ARRAY_PTR = 0x2000075C
MOTOR_DUTY_RAM_ROOT_LITERAL = 0x08011244
MOTOR_DUTY_RAM_ROOT = 0x20004960
DUTY_STORED = MOTOR_DUTY_RAM_ROOT + 0xB4 + 6
DUTY_PREVIOUS = MOTOR_DUTY_RAM_ROOT + 0xB4 + 8
SW_SHADOW_STATE_A = MOTOR_DUTY_RAM_ROOT + 0x30
SW_SHADOW_STATE_B = MOTOR_DUTY_RAM_ROOT + 0x34
# Fixed instruction sites referenced by physical MCU addresses.
INS = {
    0x0801B3D0: ("add.w", "r0, r4, r4, lsl #1"),
    0x0801B3D4: ("add.w", "r0, r5, r0, lsl #5"),
    0x0801B3D8: ("movs", "r2, #3"),
    0x0801B3DA: ("ldr", "r3, [r0, #0x4c]"),
    0x0801B3DC: ("ldr", "r0, [r0, #0x48]"),
    0x0801B3DE: ("movs", "r1, #0x18"),
    0x0801B3E0: ("bl", "#0x8023770"),
    0x0801B3FC: ("ldr", "r2, [pc, #0x110]"),
    0x0801B406: ("ldr", "r1, [r0, #0x54]"),
    0x0801B408: ("bl", "#0x801944a"),
    0x080110CC: ("push.w", "{r4, r5, r6, r7, r8, lr}"),
    0x080110E8: ("ldr", "r4, [pc, #0x158]"),
    0x080110EA: ("ldr", "r7, [pc, #0x158]"),
    0x080110EC: ("adds", "r4, #0xb4"),
    0x080110F0: ("ldrh", "r1, [r4, #6]"),
    0x080110F2: ("strh", "r1, [r4, #8]"),
    0x0801110A: ("str", "r6, [r7, #0x30]"),
    0x0801110C: ("str", "r6, [r7, #0x34]"),
    0x08011116: ("bl", "#0x8019516"),
    0x0801111E: ("bl", "#0x8019488"),
    0x08011126: ("strh", "r0, [r4, #6]"),
    0x08011198: ("push", "{r4, lr}"),
    0x0801119A: ("movs", "r1, #1"),
    0x0801119C: ("movs", "r0, #0x44"),
    0x0801119E: ("bl", "#0x8018eec"),
    0x080111A6: ("movs", "r0, #0"),
    0x080111A8: ("b", "#0x80110cc"),
}
SOURCE_START = 0x0802DB6C
SOURCE_END = 0x0802DE38
INITIALIZED_BYTES = 3012


def read_word(image: bytes, physical_addr: int) -> int:
    off = physical_addr - LINK_BASE
    if not 0 <= off <= len(image) - 4:
        raise ValueError("original Thumb literal outside saved real-linked APP")
    return struct.unpack_from("<I", image, off)[0]


def check_instr(image: bytes) -> list[dict]:
    c = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    matches = []
    for pc, (mnemonic, operands) in INS.items():
        at = pc - LINK_BASE
        inst = next(c.disasm(image[at:at + 4], pc, count=1), None)
        if inst is None or (inst.mnemonic, inst.op_str) != (mnemonic, operands):
            actual = "undecodable" if inst is None else inst.mnemonic + " " + inst.op_str
            raise ValueError(f"changed original GPIO/driver instruction {pc:#x}: {actual}")
        matches.append({"PC": hex(pc), "opcode": inst.mnemonic + " " + inst.op_str,
                        "original_machine_bytes": inst.bytes.hex()})
    # The two PC-relative literal loads of r4/r7 in the common motor
    # duty controller point to EXACTLY the same SRAM root, not hardware
    # TIMER enable or physical motor tachometer registers.
    for pc in (0x080110E8, 0x080110EA):
        # Both use a Thumb LDR literal with displacement 0x158.
        literal_addr = ((pc + 4) & ~3) + 0x158
        if literal_addr != MOTOR_DUTY_RAM_ROOT_LITERAL:
            raise AssertionError("shared motor software shadow PC-relative literal shifted")
    if read_word(image, MOTOR_DUTY_RAM_ROOT_LITERAL) != MOTOR_DUTY_RAM_ROOT:
        raise ValueError("original common motor RAM shadow root changed")
    if read_word(image, DEVICE_ARRAY_LITERAL_ADDR) != DEVICE_ARRAY_PTR:
        raise ValueError("five original pwm array root changed")
    return matches


def verify_objects(image: bytes):
    # This saved image has a proven, bounded, original 716-byte scatter
    # region at the correct physical Flash origin.
    packed = image[SOURCE_START-LINK_BASE:SOURCE_END-LINK_BASE]
    result, out = bounded_thumb_grammar(packed, INITIALIZED_BYTES)
    if (not result["valid"] or result["source_consumed"] != 716
            or result["tokens"] != 251 or len(out) != INITIALIZED_BYTES):
        raise ValueError("authentic SRAM layout changed")
    descriptions = []
    for idx, (expected_name, expected_obj, gpio_base, pin_mask, chan) in enumerate(PHYSICAL_EXPECTED):
        if expected_obj != OBJECTS[idx] or expected_name != EXPECTED_NAMES[idx]:
            raise ValueError("original PWM object ordering changed")
        pos = expected_obj - 0x20000000
        bank, bitmask, index, name_ptr = struct.unpack_from("<IIII", out, pos + 0x48)
        if (bank, bitmask, index) != (gpio_base, pin_mask, chan):
            raise ValueError(f"{expected_name} GPIO pin or channel descriptor changed")
        if not bitmask or bitmask & (bitmask - 1):
            raise ValueError("GPIO pin mask not one-hot")
        pin = bitmask.bit_length() - 1
        name_off = name_ptr - LINK_BASE
        if not 0 <= name_off < len(image) - 5:
            raise ValueError("PWM name pointer outside original APP ROM")
        actual_name = image[name_off:name_off+5].split(b"\x00")[0].decode("ascii")
        if actual_name != expected_name:
            raise ValueError("PWM GPIO descriptor is not linked to its real original ROM name")
        descriptions.append({
            "name":actual_name,"original_object":hex(expected_obj),
            "gpio_bank":"GPIO"+GPIO_BANKS[bank],
            "gpio_base":hex(bank),"pin":pin,"pin_mask":hex(bitmask),
            "object_channel_metadata":index,
            "descriptor_source":"authentic v3.22 initialized SRAM",
            "actual_motor_signal_function_proven":False
        })
    return descriptions, result


def model_command_vs_feedback():
    # No actual hardware is used: demonstrate that even a zero request
    # cannot be promoted to physical IDLE/STOPPED evidence.
    scenarios=[]
    for request, physical in [
        (0, "moving_due_to_inertia"),
        (0, "jammed_while_driver_enabled"),
        (125, "motor_running"),
        (255, "motor_stalled"),
    ]:
        inferred_physical_stop = None
        scenarios.append({
            "requested_duty":request,
            "possible_actual_motor_situation":physical,
            "physical_STOPPED_inferred_from_SOFTWARE_command":inferred_physical_stop,
            "MCU_write_allowed":False,
        })
    return scenarios


def report(image: bytes) -> dict:
    verified=audited(image)
    if not verified["five_names_in_expected_historical_order_proven"]:
        raise ValueError("original name relationship not corroborated")
    instructions=check_instr(image)
    devices, decoder=verify_objects(image)
    return {
        "image_SHA256":hashlib.sha256(image).hexdigest(),
        "real_link_base":hex(LINK_BASE),
        "complete_PWM_devices":devices,
        "verified_instruction_count":len(instructions),
        "verified_original_Thumb_instructions":instructions,
        "five_init_GPIO_pin_config_requests_verified":True,
        "real_init_call":"0x0801B3E0 -> 0x08023770",
        "original_array_root_literal":hex(DEVICE_ARRAY_LITERAL_ADDR),
        "motor_duty_command_controller_PC":hex(0x080110CC),
        "motor_duty_root_RAM_pointer":hex(MOTOR_DUTY_RAM_ROOT),
        "motor_command_shadow_Current":hex(DUTY_STORED),
        "motor_command_shadow_Previous":hex(DUTY_PREVIOUS),
        "motor_shadow_flags_written":[hex(SW_SHADOW_STATE_A), hex(SW_SHADOW_STATE_B)],
        "motor_duty_output_callbacks":[hex(0x08019516),hex(0x08019488)],
        "motor_zero_command_wrapper":"0x08011198",
        "command_zero_is_physical_STOP_proven":False,
        "gpio_pin_is_real_motion_feedback_proven":False,
        "full_feeder_hub_ISR_coverage_proven":False,
        "motor_stopped_race_free_guard_proven":False,
        "synthetic_command_vs_feedback_cases":model_command_vs_feedback(),
        "any_real_CFS_or_CM5_peripheral_access":False,
        "flashable_v323_generated":False,
        "approve_motor_active_write_or_flash":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    old=report(pinned(args.v313,"intermediate_v313"))
    new=report(pinned(args.v322,"running_v322"))
    # Explicitly separate binary SHA differences from original common
    # firmware GPIO/motor command logic.
    o=dict(old);n=dict(new)
    o.pop("image_SHA256");n.pop("image_SHA256")
    if o!=n:
        raise ValueError("original v3.13 and v3.22 pin config / command shadow diverged")
    result={"v322":new,"original_v313_matches":True,
            "physical_CFS_motor_feedback_authenticated":False,
            "v323_flash_safe":False}
    body=json.dumps(result,indent=2)+"\n"
    if args.json_out:
        args.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":
    main()
