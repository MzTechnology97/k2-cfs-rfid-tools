#!/usr/bin/env python3
"""Original CFS five-PWM TIMER/channel/CHCV/CHCTL2 chain (offline only).

This verifies that the original manufacturer loop reads each decoded
RT-Thread PWM descriptor's timer-selector byte +0x44 and channel-index
word +0x50, dispatches to its TIMER0 or TIMER3 peripheral, and invokes
the GD32 timer channel compare and channel-enable helpers.

A PWM output-enable bit, timer compare register and GPIO remap are
configuration/state of a command OUTPUT, not physical rotor stop or
a motor-driver "unenergized" guarantee. No hardware is accessed.
"""
from __future__ import annotations
import argparse,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE,audited
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar

IMAGE_SRC_LO=0x0802DB6C
IMAGE_SRC_HI=0x0802DE38
TIMER0=0x40012C00
TIMER3=0x40000800
PINNED={
  0x0801B128:("push","{r4, lr}"),
  0x0801B12C:("ldr","r4, [pc, #0x394]"),
  0x0801B152:("ldr","r0, [pc, #0x378]"),
  0x0801B196:("ldr","r7, [pc, #0x378]"),
  0x0801B1A4:("add.w","r4, r7, r0, lsl #5"),
  0x0801B1A8:("ldrsb","r0, [r4, #0x44]!"),
  0x0801B1AC:("bl","#0x801b128"),
  0x0801B1B2:("ldrh","r1, [r4, #0xc]"),
  0x0801B1B6:("bl","#0x8023d2c"),
  0x0801B1BC:("ldrh","r1, [r4, #0xc]"),
  0x0801B1C0:("bl","#0x8023f62"),
  0x0801B1C4:("ldrh","r1, [r4, #0xc]"),
  0x0801B1CA:("bl","#0x8023f14"),
  0x0801B1D0:("movs","r2, #0"),
  0x0801B1DE:("bl","#0x80240f2"),
  0x08023F62:("cbz","r1, #0x8023f74"),
  0x08023F70:("str","r2, [r0, #0x40]"),
  0x08023F74:("str","r2, [r0, #0x34]"),
  0x08023F78:("str","r2, [r0, #0x38]"),
  0x08023F7C:("str","r2, [r0, #0x3c]"),
  0x080240F2:("cbz","r1, #0x8024112"),
  0x08024100:("ldr","r1, [r0, #0x20]"),
  0x08024106:("str","r1, [r0, #0x20]"),
  0x08024112:("ldr","r1, [r0, #0x20]"),
  0x08024118:("str","r1, [r0, #0x20]"),
  0x08024120:("ldr","r1, [r0, #0x20]"),
  0x08024126:("str","r1, [r0, #0x20]"),
  0x08024130:("ldr","r1, [r0, #0x20]"),
  0x08024136:("str","r1, [r0, #0x20]"),
}
OBJECTS=(
 ("pwm1",0x2000075C,0,2,TIMER0,"PE13"),
 ("pwm3",0x200007BC,3,0,TIMER3,"PD12"),
 ("pwm4",0x2000081C,3,1,TIMER3,"PD13"),
 ("pwm5",0x2000087C,3,3,TIMER3,"PD15"),
 ("pwm8",0x200008DC,3,2,TIMER3,"PD14"),
)
def rom32(b,addr):
 o=addr-LINK_BASE
 if not 0<=o<=len(b)-4:raise ValueError("ROM pointer beyond APP bounds")
 return struct.unpack_from("<I",b,o)[0]

def inspect(b):
 a=audited(b)
 if not a["five_names_in_expected_historical_order_proven"]:
  raise ValueError("OEM five PWM names not independently authenticated")
 if rom32(b,0x0801B4C4)!=TIMER0 or rom32(b,0x0801B4CC)!=TIMER3:
  raise ValueError("original TIMER0/TIMER3 switch-table constants changed")
 if rom32(b,0x0801B510)!=0x2000075C:
  raise ValueError("five PWM descriptor RAM base original literal changed")
 if (((0x0801B196+4)&~3)+0x378)!=0x0801B510:
  raise ValueError("five PWM object initial pointer lookup changed")
 if (((0x0801B12C+4)&~3)+0x394)!=0x0801B4C4:
  raise ValueError("OEM TIMER0 channel-selector literal PC changed")
 if (((0x0801B152+4)&~3)+0x378)!=0x0801B4CC:
  raise ValueError("OEM TIMER3 channel-selector literal PC changed")
 c=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
 checked=[]
 for pc,expected in PINNED.items():
  o=pc-LINK_BASE
  i=next(c.disasm(b[o:o+4],pc,count=1),None)
  if i is None or (i.mnemonic,i.op_str)!=expected:
   raise ValueError(f"original TIM/channel ARM Thumb mismatch at {pc:#x}: "
                    +(i.mnemonic+" "+i.op_str if i else "no opcode"))
  checked.append(hex(pc))
 src=b[IMAGE_SRC_LO-LINK_BASE:IMAGE_SRC_HI-LINK_BASE]
 status,ram=bounded_thumb_grammar(src,3012)
 if not status["valid"] or len(ram)!=3012 or status["source_consumed"]!=716:
  raise ValueError("manufacturer PWM source RAM reconstruction changed")
 pins=[]
 for name,obj,selector,channel,timer,gpio in OBJECTS:
  o=obj-0x20000000
  value=struct.unpack_from("<i",ram,o+0x44)[0]
  ch=struct.unpack_from("<I",ram,o+0x50)[0]
  if (value,ch)!=(selector,channel):
   raise ValueError(f"{name} original timer selector/channel differs")
  pins.append({
    "RTThread_device_name":name,"OEM_GPIO_AF_output":gpio,
    "original_object_RAM":hex(obj),
    "original_timer_selector_from_plus_0x44":selector,
    "original_channel_index_from_plus_0x50":channel,
    "OEM_TIMER_peripheral_base":hex(timer),
    "TIMER_channel":f"TIMER{0 if selector==0 else 3}_CH{channel}",
    "original_channel_compare_register":hex(timer+0x34+4*channel),
    "original_channel_output_enable_register":hex(timer+0x20),
    "channel_output_enable_bit":1<<(channel*4),
    "actual_timer_registers_read_on_CFS":False,
    "is_confirmed_motor_energized_or_stopped_feedback":False,
  })
 return {
   "saved_APP_origin":hex(LINK_BASE),
   "OEM_peripheral_timer_selectors_and_channel_indices_proven":True,
   "full_oem_timer_channel_register_map":pins,
   "original_read_modify_write_CHCTL2_at_plus_0x20_pinned":True,
   "original_compare_value_register_writes_at_plus_0x34_to_0x40_pinned":True,
   "original_pwm_init_calls_output_state_helper_with_zero":True,
   "verified_manufacturer_Thumb_PCs":checked,
   "verified_manufacturer_Thumb_count":len(checked),
   "independent_rotor_stop_sensor_identified":False,
   "driver_enable_all_motors_verified":False,
   "no_duty_or_channel_enable_bit_is_valid_STOP_proof":True,
   "safe_MCU_SET_RESET_interlock_implemented":False,
   "safe_to_flash_v323":False,
 }
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument("--v313",type=Path,required=True)
 ap.add_argument("--v322",type=Path,required=True)
 ap.add_argument("--json-out",type=Path)
 args=ap.parse_args()
 old=inspect(pinned(args.v313,"intermediate_v313"))
 cur=inspect(pinned(args.v322,"running_v322"))
 if old!=cur:raise ValueError("original TIMER CHx/enable register chain differs between v3.13 and v3.22")
 result={"same_original_five_timer_channel_bases_both_versions":True,"v322":cur,
         "real_CFS_or_Kalico_touched":False,"firmware_patched":False}
 out=json.dumps(result,indent=2)+"\n"
 if args.json_out:args.json_out.write_text(out)
 print(out,end="")
if __name__=="__main__":main()
