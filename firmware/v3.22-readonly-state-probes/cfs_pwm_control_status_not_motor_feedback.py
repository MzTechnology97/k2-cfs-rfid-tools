#!/usr/bin/env python3
"""Read-only real CFS PWM dispatcher: 0x1E04/0x1E05 are NOT motor stop sensing.

Follow original physical 0x08003000-linked v3.13/v3.22 ARM Thumb:
  common duty at 0x080110CC
    -> generic request adapters at 0x08019516 and 0x08019488
    -> 0x08016A92 RT-Thread device dispatch using object+0x38
    -> original control callback 0x0801939C.
For requests 0x1E04 and 0x1E05 the callback sets a *constant*
at caller buffer +0x14; it does not read GPIO/TIMER/encoder state.
Other requests may use the indirect object+0x40 driver callback and
therefore are NOT classified by this narrow experiment.

The two callback branches execute real original ARM instructions
on synthetic SRAM using Unicorn; no peripheral bus is mapped.
No live MCU, serial, movement, Kalico or firmware writes.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_SP
)
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE, audited

FLASH_START=0x08000000
FLASH_BYTES=0x80000
RAM_START=0x20000000
RAM_BYTES=0x10000
RETURN_STOP=0x08050000
TEST_OBJECT=0x20001500
TEST_BUFFER=0x20002500
INITIAL_FIELD=0xA5A5A5A5

PINS={
    0x080110CC:("push.w","{r4, r5, r6, r7, r8, lr}"),
    0x08011116:("bl","#0x8019516"),
    0x0801111E:("bl","#0x8019488"),
    0x08019538:("movw","r1, #0x1e02"),
    0x08019540:("bl","#0x8016a92"),
    0x080194AA:("movw","r1, #0x1e05"),
    0x080194B8:("movw","r1, #0x1e04"),
    0x080194BE:("bl","#0x8016a92"),
    0x080194C4:("mov.w","r1, #0x1e00"),
    0x080194CA:("bl","#0x8016a92"),
    0x08016AC2:("ldr","r3, [r4, #0x38]"),
    0x08016AD0:("bx","r3"),
    0x0801939C:("push","{r4, lr}"),
    0x080193A0:("sub.w","r4, r1, #0x1e00"),
    0x080193A4:("subs","r4, #4"),
    0x080193A6:("beq","#0x80193ba"),
    0x080193A8:("cmp","r4, #1"),
    0x080193AA:("beq","#0x80193be"),
    0x080193BA:("movs","r0, #1"),
    0x080193BE:("movs","r0, #0"),
    0x080193C0:("str","r0, [r2, #0x14]"),
    0x080193B8:("pop","{r4, pc}"),
}


def pin(image:bytes):
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    result=[]
    for pc,(op,args) in PINS.items():
        i=pc-LINK_BASE
        instruction=next(cs.disasm(image[i:i+4],pc,count=1),None)
        if instruction is None or (instruction.mnemonic,instruction.op_str)!=(op,args):
            found="not disassembled" if instruction is None else instruction.mnemonic+" "+instruction.op_str
            raise ValueError(f"manufacturer PWM dispatcher changed at {pc:#x}: {found}")
        result.append({"pc":hex(pc),"opcode":instruction.bytes.hex()})
    return result


def run(image:bytes,command:int,expect:int):
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    u.mem_map(FLASH_START, FLASH_BYTES)
    u.mem_map(RAM_START,RAM_BYTES)
    u.mem_write(LINK_BASE,image)
    u.mem_write(TEST_BUFFER+0x14,struct.pack("<I",INITIAL_FIELD))
    u.reg_write(UC_ARM_REG_SP,0x2000E000)
    u.reg_write(UC_ARM_REG_LR,RETURN_STOP|1)
    u.reg_write(UC_ARM_REG_R0,TEST_OBJECT)
    u.reg_write(UC_ARM_REG_R1,command)
    u.reg_write(UC_ARM_REG_R2,TEST_BUFFER)
    u.reg_write(UC_ARM_REG_R3,0x11223344)
    out={"returned":False,"pc_seen":[],"peripheral_read_count":0,"indirect_driver_dispatch_seen":False}
    def code(uc,pc,size,_):
        if pc==RETURN_STOP:
            out["returned"]=True
            uc.emu_stop()
            return
        out["pc_seen"].append(hex(pc))
        if pc in (0x080193AC,0x080193AE,0x080193B2):
            out["indirect_driver_dispatch_seen"]=True
    def read(uc,access,address,size,value,_):
        if 0x40000000 <= address < 0x60000000:
            out["peripheral_read_count"]+=1
    u.hook_add(UC_HOOK_CODE,code)
    u.hook_add(UC_HOOK_MEM_READ,read)
    u.emu_start(0x0801939D,0,count=100)
    if not out["returned"] or out["indirect_driver_dispatch_seen"]:
        raise ValueError("constant PWM query returned via unexpected indirect driver path")
    word=struct.unpack("<I",u.mem_read(TEST_BUFFER+0x14,4))[0]
    if word!=expect or u.reg_read(UC_ARM_REG_R0)!=0:
        raise ValueError("original PWM callback no longer returns expected constant")
    if out["peripheral_read_count"]!=0:
        raise ValueError("original constant request unexpectedly reads hardware peripherals")
    return {"request":hex(command),"caller_buffer_plus_0x14":expect,
            "callback_status":0,"original_thumb_executed":len(out["pc_seen"]),
            "hardware_MMIO_read_count":0,
            "actual_motor_running_or_stopped_proven":False}


def report(image:bytes):
    original=audited(image)
    if not original["five_names_in_expected_historical_order_proven"]:
        raise ValueError("PWM object name identities not verified")
    ins=pin(image)
    probes=[run(image,0x1E04,1),run(image,0x1E05,0)]
    return {
      "pinned_Thumb_sites":ins,
      "original_callbacks_reached_from_shared_duty":True,
      "generic_RTThread_dispatch_uses_object_field_plus_0x38":True,
      "original_physical_PWM_control_callback":"0x0801939C",
      "synthetic_original_opcode_probes":probes,
      "1E04_1E05_reads_physical_motor_feedback":False,
      "1E02_indirect_driver_hardware_behavior_proven":False,
      "GPIO_or_encoder_motor_IDLE_signal_proven":False,
      "full_movement_task_ISR_coverage_proven":False,
      "v323_MCU_motor_busy_guard_implemented":False,
      "v323_flash_approved":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    from hashlib import sha256
    older=report(pinned(args.v313,"intermediate_v313"))
    current=report(pinned(args.v322,"running_v322"))
    if older!=current:
        raise ValueError("pinned original v3.13 and v3.22 PWM control dispatch diverged")
    result={"pwm_control_dispatch_equal_in_v313_v322":True,"v322":current,
            "hardware_motor_STOP_confirmed":False,
            "real_CFS_CM5_accessed":False,
            "firmware_writes_performed":False}
    body=json.dumps(result,indent=2)+"\n"
    if args.json_out:
        args.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":
    main()
