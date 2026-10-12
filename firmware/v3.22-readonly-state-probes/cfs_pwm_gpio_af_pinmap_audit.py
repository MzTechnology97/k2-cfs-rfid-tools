#!/usr/bin/env python3
"""Identify actual GD32 GPIO alternate-function output pins for CFS PWM devices.

The original CFS v3.13 and v3.22 images share their real physical APP
link base 0x08003000. A 716-byte original scatter region decompresses
to 3012 bytes of initialized RAM and contains five named RT-Thread
PWM objects. Their [obj+0x48] and [obj+0x4c] metadata are, respectively,
the GPIO PORT BASE and PIN BITMASK passed by the original PWM initializer
to GD32 gpio_init(port, 0x18, 3, mask).

GD32F30x GPIO_MODE_AF_PP=0x18: alternate-function push-pull output.
GPIOx_ISTAT +0x08 and OCTL +0x0C register addresses are identified,
but reading an alternate-function pin / output latch is NOT evidence
that the real motor rotor is stopped. No peripheral reads are made.

Only immutable pinned APP images, Python in-memory buffers and exact
Thumb disassembly are used; no serial/MCU/CM5 writes/flash/motion.
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

ROM_INPUT_START=0x0802DB6C
ROM_INPUT_END=0x0802DE38
RAM_BASE=0x20000000
RAM_BYTES=3012

# Independently decoded manufacturer RAM: obj + 0x48 port; obj + 0x4c pins.
OEM_OBJECTS = (
    ("pwm1",0x2000075C,0x0802C9E4,0x40011800,0x2000,"GPIOE",13),
    ("pwm3",0x200007BC,0x0802C9EC,0x40011400,0x1000,"GPIOD",12),
    ("pwm4",0x2000081C,0x0802C9F4,0x40011400,0x2000,"GPIOD",13),
    ("pwm5",0x2000087C,0x0802C9FC,0x40011400,0x8000,"GPIOD",15),
    ("pwm8",0x200008DC,0x0802CA04,0x40011400,0x4000,"GPIOD",14),
)

# Original v3.22 firmware instruction pins, physically decoded.
# Physically indexed manufacturer TIMER pointers. A ROM reference to
# a TIMER base is NOT proof that a specific alternate-function pin is
# wired to that timer, nor that the timer running implies motor rotation.
TIMER_ROM_WORDS={
    0x0801B4C4:(0x40012C00,"TIMER0"),
    0x0801B4CC:(0x40000800,"TIMER3"),
    0x08023E54:(0x40012C00,"TIMER0"),
    0x08023E5C:(0x40000800,"TIMER3"),
}

INIT_PINS={
    0x0801B3D8:("movs","r2, #3"),
    0x0801B3DA:("ldr","r3, [r0, #0x4c]"),
    0x0801B3DC:("ldr","r0, [r0, #0x48]"),
    0x0801B3DE:("movs","r1, #0x18"),
    0x0801B3E0:("bl","#0x8023770"),
    0x08023770:("push.w","{r4, r5, r6, r7, r8, sb, lr}"),
    0x08023794:("ldr","r7, [r0]"),
    0x080237AA:("cmp","r1, #0x28"),
    0x080237C6:("str.w","r8, [r0]"),
    0x080237DC:("ldr","r7, [r0, #4]"),
    0x08023806:("str.w","ip, [r0, #4]"),
    0x0802382C:("ldr","r0, [r0, #8]"),  # GPIO ISTAT accessor
    0x0802383C:("ldr","r0, [r0, #0xc]"), # GPIO OCTL accessor
}

def halfword_and_word(image, pc):
    ci=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    off=pc-LINK_BASE
    instruction=next(ci.disasm(image[off:off+4],pc,count=1),None)
    if instruction is None:
        raise ValueError(f"invalid manufacturer Thumb at physical PC {pc:#x}")
    return instruction

def original_RAM(image):
    ins=halfword_and_word(image,0x0801B3E0)
    if (ins.mnemonic,ins.op_str)!=("bl","#0x8023770"):
        raise ValueError("OEM GPIO initializer call relocated/missing")
    stream=image[ROM_INPUT_START-LINK_BASE:ROM_INPUT_END-LINK_BASE]
    status,ram=bounded_thumb_grammar(stream,RAM_BYTES)
    if not status["valid"] or len(ram)!=RAM_BYTES or status["source_consumed"]!=716:
        raise ValueError("OEM scatter decoder did not reconstruct exact RAM")
    return ram

def verify_pinmap(ram):
    output=[]
    for name,obj,rom,periph,mask,port,pin in OEM_OBJECTS:
        start=obj-RAM_BASE
        if start<0 or start+0x58>len(ram):
            raise ValueError(f"{name}: OEM object outside original RAM")
        actual_rom,actual_periph,actual_mask=(
            struct.unpack_from("<I",ram,start+offset)[0]
            for offset in (0x54,0x48,0x4c)
        )
        if (actual_rom,actual_periph,actual_mask)!=(rom,periph,mask):
            raise ValueError(f"{name}: original ROM string/AF GPIO port/pin provenance changed")
        if mask != 1<<pin:
            raise ValueError(f"{name}: not a valid one-bit GPIO mask")
        output.append({
            "RTThread_PWM_name":name,
            "OEM_object":hex(obj),
            "ROM_name_pointer":hex(rom),
            "GPIO_port":port,
            "port_base":hex(periph),
            "pin_index":pin,
            "gpio_pin":port[-1]+str(pin),
            "pin_mask":hex(mask),
            "gpio_ISTAT_reg_READ_ONLY":hex(periph+8),
            "gpio_OCTL_reg_READ_ONLY":hex(periph+12),
            "port_is_a_TIMER_peripheral":False,
            "pin_configured_for_AF_output_not_independent_feedback":True,
            "pin_input_status_implies_rotor_idle":False,
            "output_control_latch_implies_rotor_idle":False,
        })
    if len({x["gpio_pin"] for x in output}) != 5:
        raise ValueError("duplicated OEM pin in decoded objects")
    return output

def fail_closed_ram_mutants(ram):
    rejected=[]
    for label,which,at,val in (
        ("pwm1_wrong_port",0,0x48,0x40011400),
        ("pwm3_wrong_mask",1,0x4c,0x4000),
        ("pwm4_wrong_rom_pointer",2,0x54,0x0802C9EC),
        ("pwm5_zero_mask",3,0x4c,0),
        ("pwm8_wrong_port",4,0x48,0x40011800),
    ):
        buf=bytearray(ram)
        obj=OEM_OBJECTS[which][1]
        struct.pack_into("<I",buf,obj-RAM_BASE+at,val)
        try:verify_pinmap(buf)
        except ValueError:rejected.append(label)
        else:raise AssertionError(f"mutated decoded RAM accepted: {label}")
    return rejected

def check_instruction_contract(image):
    checked=[]
    for pc,(mnemonic,operand) in INIT_PINS.items():
        ins=halfword_and_word(image,pc)
        if (ins.mnemonic,ins.op_str)!=(mnemonic,operand):
            raise ValueError(f"original GPIO initialization/MMIO accessor changed @{pc:#x}: {ins.mnemonic} {ins.op_str}")
        checked.append({"physical_pc":hex(pc),"operation":mnemonic+" "+operand})
    return checked

def inspect(image):
    audited(image)
    detected_timer_literals=[]
    for physical_pc,(expected,timer) in TIMER_ROM_WORDS.items():
        ofs=physical_pc-LINK_BASE
        found=struct.unpack_from("<I",image,ofs)[0]
        if found!=expected:
            raise ValueError(f"{timer}: original ROM pointer differs at {physical_pc:#x}")
        detected_timer_literals.append({
            "timer":timer,"literal_PC":hex(physical_pc),
            "peripheral_BASE":hex(found),
            "proven_PWM_device_channel_or_motor":False,
        })
    checked=check_instruction_contract(image)
    ram=original_RAM(image)
    pins=verify_pinmap(ram)
    rejected=fail_closed_ram_mutants(ram)
    return {
      "OEM_PWM_descriptors":pins,
      "original_GPIO_init_mode_value":hex(0x18),
      "mode_per_GD32F30x_header":"GPIO_MODE_AF_PP",
      "GD32F30x_GPIO_init_speed_value":3,
      "original_Thumb_instruction_pins":checked,
      "original_TIMER0_and_TIMER3_ROM_references":detected_timer_literals,
      "timer_peripheral_register_reads_performed":False,
      "TIMER0_or_TIMER3_counter_enable_proves_rotor_stop":False,
      "in_memory_decoded_RAM_mutations_rejected":rejected,
      "mutations_rejected_count":len(rejected),
      "GD32_GPIO_port_mode_function_read_only":True,
      "actual_TIMER_instance_or_channel_identified":False,
      "does_not_identify_feeder_or_hub_motor_feedback":True,
      "motor_physical_stopped_detected":False,
      "safe_MCU_SET_RESET_interlock_found":False,
      "MCU_read_or_write_performed":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=inspect(pinned(a.v313,"intermediate_v313"))
    new=inspect(pinned(a.v322,"running_v322"))
    if old!=new:raise ValueError("manufacturer GPIO PWM pin configuration changed v3.13 vs v3.22")
    report={"same_for_v313_and_v322":True,"v322":new,
            "GD32F30x_reference":
              "https://github.com/CommunityGD32Cores/ArduinoCore-GD32/blob/main/system/GD32F30x_firmware/GD32F30x_standard_peripheral/Include/gd32f30x_gpio.h",
            "safe_to_flash_v323":False,
            "active_CFS_access":False}
    out=json.dumps(report,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(out)
    print(out,end="")

if __name__=="__main__":main()
