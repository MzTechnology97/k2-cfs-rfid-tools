#!/usr/bin/env python3
"""Read-only CFS v3.13/v3.22 TIMER0/TIMER3 AFIO remap provenance.

Proof consists of: exact original ROM constants + original Thumb
branches selecting them + original GD32 AFIO_PCF0 read/modify/write
instructions. Confirms *configured firmware intent*, not the state
on the user's physical CFS or any feedback that proves motor stopped.

The original saved APP is linked at physical 0x08003000, not the
legacy artificial 0x08010000 coordinate frame.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE,audited
from cfs_pwm_gpio_af_pinmap_audit import inspect as five_pwm_pinmap

AFIO_BASE=0x40010000
AFIO_PCF0=AFIO_BASE+4
TIMER0_FULL_REMAP=0x001600C0
TIMER3_REMAP=0x00001000
ROM_AFIO_BASE=0x08023950
ROM_TIMER0_REMAP=0x0801B514
SOURCE_SEL_ADDR=0x0801B2A2
REMAP_API=0x0802384C

THUMB={
    0x0801B28E:("push.w","{r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}"),
    0x0801B296:("ldrd","r0, r3, [r6, #4]"),
    0x0801B2A2:("ldrb","r0, [r6, #0x18]"),
    0x0801B2A4:("cmp","r0, #1"),
    0x0801B2A6:("beq","#0x801b2ae"),
    0x0801B2A8:("cmp","r0, #2"),
    0x0801B2AA:("beq","#0x801b2b4"),
    0x0801B2AE:("movs","r1, #1"),
    0x0801B2B0:("lsls","r0, r1, #0xc"),
    0x0801B2B4:("movs","r1, #1"),
    0x0801B2B6:("ldr","r0, [pc, #0x25c]"),
    0x0801B2B8:("bl","#0x802384c"),
    0x0802384C:("push","{r4, r5, r6, r7, lr}"),
    0x0802384E:("ldr","r4, [pc, #0x100]"),
    0x08023850:("cmp","r0, #0"),
    0x08023858:("ldr","r3, [r4, #4]"),
    0x0802385A:("lsrs","r2, r0, #0x15"),
    0x0802385E:("uxth","r5, r0"),
    0x08023860:("ubfx","r7, r0, #0x14, #2"),
    0x08023866:("ubfx","r6, r0, #0x10, #4"),
    0x08023888:("bics","r3, r5"),
    0x08023890:("orrs","r2, r5"),
    0x0802389A:("str","r2, [r4, #4]"),
}

def word(image:bytes,pc:int) -> int:
    off=pc-LINK_BASE
    if not 0<=off<=len(image)-4:
        raise ValueError("physical ROM literal outside saved CFS APP")
    return struct.unpack_from("<I",image,off)[0]

def verify(image:bytes)->dict:
    baseline=audited(image)
    if not baseline["five_names_in_expected_historical_order_proven"]:
        raise ValueError("five original PWM objects not verified")
    groups=five_pwm_pinmap(image)["OEM_PWM_descriptors"]
    if [(g["RTThread_PWM_name"],g["gpio_pin"]) for g in groups]!=[
        ("pwm1","E13"),("pwm3","D12"),("pwm4","D13"),
        ("pwm5","D15"),("pwm8","D14")
    ]:
        raise ValueError("original AF GPIO/pin descriptors unexpectedly differ")
    if word(image,ROM_AFIO_BASE)!=AFIO_BASE:
        raise ValueError("original GD32 AFIO peripheral base changed")
    if word(image,ROM_TIMER0_REMAP)!=TIMER0_FULL_REMAP:
        raise ValueError("original TIMER0 full remap request constant changed")
    if ((0x0801B2B6+4)&~3)+0x25C!=ROM_TIMER0_REMAP:
        raise ValueError("TIMER0 request PC-relative literal location changed")
    if ((0x0802384E+4)&~3)+0x100!=ROM_AFIO_BASE:
        raise ValueError("GPIO remap function no longer uses AFIO base")
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    pinned_pc=[]
    for pc,exp in THUMB.items():
        off=pc-LINK_BASE
        ins=next(cs.disasm(image[off:off+4],pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=exp:
            raise ValueError(f"original remap Thumb mismatch {pc:#x}: "
                             +(f"{ins.mnemonic} {ins.op_str}" if ins else "undecodable"))
        pinned_pc.append(hex(pc))
    # At 0x0801B2A4..B8 OEM dispatch:
    # r6+0x18 =1 -> r0=1<<12; r6+0x18=2 -> r0=0x001600C0;
    # both paths use r1=1 and call AFIO remap helper.
    cases=[]
    for group,expected,pads,channels in (
        (1,TIMER3_REMAP,("D12","D13","D14","D15"),
         ("TIMER3_CH0","TIMER3_CH1","TIMER3_CH2","TIMER3_CH3")),
        (2,TIMER0_FULL_REMAP,("E13",),("TIMER0_CH2",))
    ):
        if group==1:
            computed=1<<12
        else:
            computed=word(image,ROM_TIMER0_REMAP)
        if computed!=expected:
            raise AssertionError("manufacturer GPIO TIMER remap group selection incorrect")
        cases.append({
          "original_selector_r6_plus_0x18":group,
          "original_gpio_pin_remap_config_argument_r0":hex(computed),
          "original_remap_enable_r1":1,
          "GD32_AFIO_PCF0_register":hex(AFIO_PCF0),
          "required_AFIO_PCF0_bits":hex(
              0x1000 if group==1 else 0xC0),
          "applies_to_GPIO_pin_candidates":list(pads),
          "TIMER_channel_if_correct_AFIO_register_state":list(channels),
          "actual_live_AFIO_register_value_observed":False,
          "actual_motor_stop_feedback_verified":False
        })
    return {
      "physical_image_link_base":hex(LINK_BASE),
      "AFIO_hardware_base_from_original_ROM":hex(AFIO_BASE),
      "AFIO_PCF0_physical_register":hex(AFIO_PCF0),
      "AFIO_PCF0_original_RMW_instructions_pinned":True,
      "verified_manufacturer_thumb_instructions":pinned_pc,
      "two_OEM_mux_configuration_paths":cases,
      "OEM_saved_PWM_name_PIN_map_verified":True,
      "TIMER0_full_remap_requested_in_original_code":True,
      "TIMER3_remap_requested_in_original_code":True,
      "live_AFIO_and_TIMER_channel_configuration_read":False,
      "motor_energized_state_independently_known":False,
      "hardware_motor_stopped_proven":False,
      "covers_all_motor_start_and_ISR_paths":False,
      "motor_active_MCU_WRITE_safe":False,
      "v323_flash_approved":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=verify(pinned(a.v313,"intermediate_v313"))
    now=verify(pinned(a.v322,"running_v322"))
    if old!=now:
        raise ValueError("original TIMER AFIO remap chain differs between v3.13/v3.22")
    out={"same_oem_AFIO_code_on_v313_and_v322":True,"v322":now,
         "active_CFS_or_Kalico_modified":False}
    payload=json.dumps(out,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(payload)
    print(payload,end="")

if __name__=="__main__":main()
