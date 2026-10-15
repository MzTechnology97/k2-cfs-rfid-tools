#!/usr/bin/env python3
"""Classify saved OEM GPIO-D / ADC0 helper paths without claiming motor feedback.

A GD32 peripheral base constant in a pin table is NOT a live motor
status read. This audit pins genuine manufacturer Thumb instructions,
ROM pointer values and the narrowly decoded direct BL relationships.

No live MCU/MMIO access, commands, motor motion, firmware or Kalico
patching. Zero direct BLs is *not* proof of no indirect calls.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE

GPIO_D_BASE = 0x40011400
ADC0_CTRL1_OR_STATUS = 0x40012408
ADC0_DATA_WORD = ADC0_CTRL1_OR_STATUS + 0x44
GPIOD_ROM_LITERALS = (0x0801B75C,0x08023948)
ADC0_ROM_LITERAL = 0x08022C88
GPIO_CLOCK_INIT_CALL = 0x0801B53E
GPIO_CLOCK_HELPER = 0x0801B684
ADC0_DIRECT_READ_HELPER = 0x08022BBC
GPIO_SECOND_HELPER = 0x080236F4
ADC_CONTROL_HELPERS = (0x08022926,0x08022932)

# Not a full CFG: pin individual original instructions at known function
# entries only. Old image nominal analysis base 0x08010000 is NOT used.
THUMB = {
  0x0801B530:("push","{r4, r5, r6, lr}"),
  0x0801B538:("ldr.w","r0, [r5, r4, lsl #2]"),
  0x0801B53C:("cbz","r0, #0x801b54a"),
  0x0801B53E:("bl","#0x801b684"),
  0x0801B684:("push","{r4, lr}"),
  0x0801B686:("ldr","r4, [pc, #0xd4]"),
  0x080236F4:("push","{r4, lr}"),
  0x080236F6:("ldr","r4, [pc, #0x250]"),
  0x08022926:("ldr","r0, [pc, #0x360]"),
  0x0802292A:("orr","r1, r1, #0x800000"),
  0x0802292E:("str","r1, [r0]"),
  0x08022932:("ldr","r0, [pc, #0x354]"),
  0x08022936:("bic","r1, r1, #0x800000"),
  0x0802293A:("str","r1, [r0]"),
  0x08022BBC:("ldr","r0, [pc, #0xc8]"),
  0x08022BBE:("adds","r0, #0x44"),
  0x08022BC0:("ldr","r0, [r0]"),
  0x08022BC2:("bx","lr"),
}

def single(data:bytes, pc:int, cs):
    off=pc-LINK_BASE
    if not (0<=off<=len(data)-4):
        raise ValueError("physical CFS PC out of image")
    ins=next(cs.disasm(data[off:off+4],pc,count=1),None)
    if not ins or ins.address!=pc:
        raise ValueError(f"undecodable CFS Thumb at {pc:#x}")
    return ins

def word(data:bytes,addr:int):
    off=addr-LINK_BASE
    if not (0<=off<=len(data)-4):
        raise ValueError("saved ROM literal outside image")
    return struct.unpack_from("<I",data,off)[0]

def literal_load_destination(ins):
    if ins.mnemonic!="ldr" or len(ins.operands)<2:
        raise ValueError("not an ARM Thumb PC relative LDR")
    src=ins.operands[1]
    if src.type!=ARM_OP_MEM or src.mem.base!=ARM_REG_PC:
        raise ValueError("not PC relative LDR")
    return ((ins.address+4)&~3)+src.mem.disp

def callsite_census(image:bytes,targets:set[int],cs):
    result={t:[] for t in targets}
    for off in range(0,len(image)-3,2):
        ins=next(cs.disasm(image[off:off+4],LINK_BASE+off,count=1),None)
        if not ins or ins.mnemonic!="bl" or ins.size!=4:
            continue
        for t in targets:
            if ins.op_str==f"#0x{t:x}":
                result[t].append(ins.address)
    return result

def inspect(image:bytes):
    audited(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    for pc,expected in THUMB.items():
        ins=single(image,pc,cs)
        if (ins.mnemonic,ins.op_str)!=expected:
            raise ValueError(f"OEM Thumb changed at {pc:#x}: "
                             f"{ins.mnemonic} {ins.op_str} vs {expected}")
    for addr in GPIOD_ROM_LITERALS:
        if word(image,addr)!=GPIO_D_BASE:
            raise ValueError("OEM GPIO-D physical base constant changed")
    if word(image,ADC0_ROM_LITERAL)!=ADC0_CTRL1_OR_STATUS:
        raise ValueError("OEM ADC0 control literal changed")
    if literal_load_destination(single(image,0x0801B686,cs))!=0x0801B75C:
        raise ValueError("GPIO-D first helper literal origin altered")
    if literal_load_destination(single(image,0x080236F6,cs))!=0x08023948:
        raise ValueError("GPIO-D second helper literal origin altered")
    for a in (0x08022926,0x08022932,ADC0_DIRECT_READ_HELPER):
        if literal_load_destination(single(image,a,cs))!=ADC0_ROM_LITERAL:
            raise ValueError("ADC0 control/read helper ROM pointer changed")
    targets=set((GPIO_CLOCK_HELPER,GPIO_SECOND_HELPER,
                 ADC0_DIRECT_READ_HELPER,*ADC_CONTROL_HELPERS))
    sites=callsite_census(image,targets,cs)
    if sites[GPIO_CLOCK_HELPER]!=[GPIO_CLOCK_INIT_CALL]:
        raise ValueError("GPIO-D generic clock helper callers unexpectedly changed")
    # This is a deliberate *bounded direct-BL-only* negative finding:
    # indirect BLX / function pointers / ROM tables are not excluded.
    for t in targets-{GPIO_CLOCK_HELPER}:
        if sites[t]:
            raise ValueError(f"OEM helper direct BL census changed at {t:#x}")
    # Exact aligned full-word pointers, not a reachability test.
    aligned_refs={}
    for t in targets:
        found=[]
        for off in range(0,len(image)-3,4):
            value=struct.unpack_from("<I",image,off)[0]
            if value==t or value==(t|1):
                found.append(hex(LINK_BASE+off))
        aligned_refs[hex(t)]=found
    return {
      "app_physical_origin":hex(LINK_BASE),
      "gpio_d_literal_addresses":[hex(a) for a in GPIOD_ROM_LITERALS],
      "gpio_d_hardware_base":hex(GPIO_D_BASE),
      "gpio_d_generic_setup_helper":hex(GPIO_CLOCK_HELPER),
      "gpio_d_generic_setup_only_direct_bl":hex(GPIO_CLOCK_INIT_CALL),
      "gpio_d_second_helper":hex(GPIO_SECOND_HELPER),
      "adc0_literal_address":hex(ADC0_ROM_LITERAL),
      "adc0_base_literal":hex(ADC0_CTRL1_OR_STATUS),
      "adc0_reader_pc":hex(ADC0_DIRECT_READ_HELPER),
      "adc0_effective_read_addr_if_called":hex(ADC0_DATA_WORD),
      "direct_BL_candidate_sites":{
        hex(target):[hex(s) for s in sites[target]] for target in sorted(sites)
      },
      "aligned_full_word_function_pointer_candidates":aligned_refs,
      "verified_OEM_Thumb_pins":len(THUMB),
      "GPIOD_base_in_generic_config_is_NOT_M1_M2_feedback":True,
      "ADC0_direct_read_helper_is_not_proven_to_be_invoked":True,
      "zero_direct_BL_does_NOT_prove_zero_indirect_calls":True,
      "ADC0_motor_current_channels_configured_and_sampled_proven":False,
      "M1_M2_active_drive_state_proven":False,
      "independent_stop_status_for_all_motors_proven":False,
      "safe_MCU_write_interlock_implemented":False,
      "v323_flash_or_motor_write_permitted":False,
      "live_CFS_read_or_write":False,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--v313",type=Path,required=True)
    ap.add_argument("--v322",type=Path,required=True)
    ap.add_argument("--json-out",type=Path)
    opt=ap.parse_args()
    old=inspect(pinned(opt.v313,"intermediate_v313"))
    cur=inspect(pinned(opt.v322,"running_v322"))
    if old!=cur:
        raise ValueError("GPIO-D / ADC0 helper provenance differs between pinned CFS v3.13 and v3.22")
    result={
       "v313_v322_original_helper_provenance_equal":True,
       "OEM_GPIO_and_ADC_helper_audit":cur,
       "actual_hardware_not_interrogated":True,
       "no_v323_release":True,
    }
    payload=json.dumps(result,indent=2)+"\n"
    if opt.json_out:
        opt.json_out.write_text(payload)
    print(payload,end="")

if __name__=="__main__":
    main()
