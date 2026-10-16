#!/usr/bin/env python3
"""Experimental v3.23 OEM GPIO-D feeder-drive / GPIO-E hub-command snapshot.

Stacks on PR #49 OEM hub duty/FG telemetry; appends 0x57/0x18.
Returns 8 bytes: GPIOD_OCTL (0x4001140C) and GPIOE_OCTL
(0x4001180C), raw LE32. This is GPIO *output latch*, NOT
pin feedback, AT8236 electrical state, actual rotation or stop proof.

All 4 saved OEM motor records use GPIOD pin pairs, initialized
PWM flag zero; TIMER3 enable bits alone cannot audit motor drive.
No register writes, new global SRAM, firmware file, live Kalico, CFS.
CONFIG SET/RESET remains blocked at original MCU entry.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE
from cfs_oem_four_brushed_motor_pin_provenance_audit import inspect as motor_source, decode_ram, MOTOR_BASE, MOTOR_STRIDE
from cfs_v323_oem_hub_command_fg_snapshot_candidate import (
    build as parent_hub_build, ENTRY_ASM as HUB_ENTRY, DISPATCH_ADD as HUB_DISPATCH,
    sample as hub_sample, DUTY_FIELD, PREVIOUS_FIELD, COUNTER,
)
from cfs_v323_raw_pwm_output_snapshot_candidate import (
    build as base_build, run_diag as pwm_sample,
    T0_CHCTL2,T3_CHCTL2,MSG,SENTINEL,OEM_SEND,OEM_DONE,
)
from cfs_v323_safe_config_readonly_preview import invoke_host_config,invoke_heap_boot_reset

OPCODE=0x18
REQ_LEN=4
BYTES=8
GPIOD_OCTL=0x4001140C
GPIOE_OCTL=0x4001180C
FEEDER_PAIRS=((2,3),(0,1),(14,15),(12,13))
HUB_DIR=3
HUB_BRAKE=4
DISPATCH_ADD="    cmp     r5, #0x18\n    beq.w   op_raw_gpio_motor_latches\n"
ENTRY_ASM="""@ CFS v3.23 experimental read-only GPIO output latch snapshot.
@ GPIO_D bits are AT8236 driver *commands*, NOT electrical/rotor feedback.
@ GPIO_E contains hub BRAKE/DIR command bits, NOT confirmed stop.
.thumb_func
op_raw_gpio_motor_latches:
    ldrb    r0, [r4, #1]
    cmp     r0, #4
    bne.w   status_bad
    ldr     r0, gpio_d_out_ptr
    ldr     r0, [r0]
    str     r0, [sp, #0]
    ldr     r0, gpio_e_out_ptr
    ldr     r0, [r0]
    str     r0, [sp, #4]
    mov     r2, sp
    movs    r3, #8
    movs    r1, #0
    b.w     send
.balign 4
gpio_d_out_ptr: .word 0x4001140C
gpio_e_out_ptr: .word 0x4001180C

"""

def pinproof(v313:bytes,v322:bytes)->dict:
    for name,b in (("v313",v313),("v322",v322)):
        r=motor_source(b)
        if len(r["original_brushed_motor_records"])!=4:
            raise ValueError("source-proven four OEM AT8236 record census changed")
        ram=decode_ram(b)
        for slot,pair in enumerate(FEEDER_PAIRS):
            base=MOTOR_BASE+slot*MOTOR_STRIDE
            stored=ram[base-0x20000000]
            if stored!=0:
                raise ValueError(f"{name} manufacturer feeder {slot} PWM flag nonzero")
            got=tuple(int(x["physical_GPIO"][2:]) for x in r["original_brushed_motor_records"][slot]["GPIO_board_mapping"])
            if got!=pair:
                raise ValueError(f"{name} original GPIOD motor pair source changed {got}")
    return {
      "four_saved_OEM_PWM_flags_are_zero":True,
      "four_feed_pairs_on_GPIOD":[list(p) for p in FEEDER_PAIRS],
      "motor_GPIO_D_bits":[f"PD{p}" for pair in FEEDER_PAIRS for p in pair],
      "GPIOE_PE3_hub_direction":True,
      "GPIOE_PE4_hub_brake_command":True,
      "GPIOD_OCTL_raw_output_latch":hex(GPIOD_OCTL),
      "GPIOE_OCTL_raw_output_latch":hex(GPIOE_OCTL),
      "output_latch_proves_all_feeders_unelectrified":False,
      "GPIOOCTL_is_independent_external_pin_measurement":False,
    }

def build(v313:bytes,v322:bytes,asm:str,linker:str,builder:str,builder_path:Path):
    motor=pinproof(v313,v322)
    parent,pmeta,_=parent_hub_build(v313,v322,asm,linker,builder,builder_path)
    image,meta,syms=base_build(
        v313,v322,asm,linker,builder,builder_path,
        extra_dispatch=HUB_DISPATCH+DISPATCH_ADD,
        extra_entry=HUB_ENTRY+ENTRY_ASM,
    )
    if len(image)<=len(parent):
        raise ValueError("new GPIO snapshot was not appended")
    for sym,expected in (("gpio_d_out_ptr",GPIOD_OCTL),("gpio_e_out_ptr",GPIOE_OCTL)):
        at=syms[sym]-LINK_BASE
        if struct.unpack_from("<I",image,at)[0]!=expected:
            raise ValueError("new GPIO read source not linked at original physical address")
    if meta["incoming_original_manufacturer_hooks"]!=18 or meta["outgoing_original_manufacturer_calls"]!=21:
        raise ValueError("original Creality hook/call census changed")
    if not meta["manufacturer_command_or_GPIO_behavior_unchanged"]:
        raise ValueError("manufacturer motor GPIO code altered")
    return image,{
        "previous_hub_FG_preview_APP_bytes":len(parent),
        "new_gpio_latch_preview_APP_bytes":len(image),
        "delta_bytes":len(image)-len(parent),
        "physical_APP_base":hex(LINK_BASE),
        "end_exclusive":hex(LINK_BASE+len(image)),
        "last_flash_page":(LINK_BASE+len(image)-1-0x08000000)//0x800,
        "param_page_unchanged":meta["historical_parameter_page_reserved"],
        "old_readonly_PWM_opcode_0x16_preserved":True,
        "old_readonly_hub_FG_opcode_0x17_preserved":True,
        "new_opcode":"0x57/0x18",
        "new_entry":hex(syms["op_raw_gpio_motor_latches"]),
        "incoming_original_hooks":meta["incoming_original_manufacturer_hooks"],
        "outgoing_original_calls":meta["outgoing_original_manufacturer_calls"],
        "raw_GPIO_read_addresses":[hex(GPIOD_OCTL),hex(GPIOE_OCTL)],
        "output_bytes":BYTES,
        "motor_source":motor,
        "CONFIG_SET_RESET_fenced":True,
        "RTThread_motor_ISR_mutex_qualified":False,
        "safe_to_apply_motor_RAM_profile":False,
        "MCU_flash_approved":False,
        "persistent_firmware_binary_emitted":False,
        "crc16_in_memory_only":meta["crc16_in_memory_only"],
        "sha256_in_memory_only":hashlib.sha256(image).hexdigest(),
    },syms

def run(image:bytes,syms:dict[str,int],d:int,e:int,length:int=4,opcode:int=OPCODE)->dict:
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    cpu.mem_map(0x08000000,0x40000);cpu.mem_write(LINK_BASE,image)
    cpu.mem_map(0x20000000,0x10000)
    cpu.mem_map(0x40011000,0x1000)
    cpu.mem_write(GPIOD_OCTL,struct.pack("<I",d))
    cpu.mem_write(GPIOE_OCTL,struct.pack("<I",e))
    cpu.reg_write(UC_ARM_REG_SP,0x2000F000)
    cpu.reg_write(UC_ARM_REG_LR,SENTINEL|1)
    cpu.reg_write(UC_ARM_REG_R0,0x57)
    cpu.reg_write(UC_ARM_REG_R4,MSG)
    msg=bytearray(16);msg[1]=length;msg[4]=opcode
    cpu.mem_write(MSG,bytes(msg))
    reads=[];writes=[];responses=[]
    def oncode(c,pc,n,ctx):
        if pc==OEM_SEND:
            size=c.reg_read(UC_ARM_REG_R3)
            if size>8:raise ValueError("GPIO command response unbounded")
            payload=bytes(c.mem_read(c.reg_read(UC_ARM_REG_R2),size)) if size else b""
            responses.append((c.reg_read(UC_ARM_REG_R1),payload))
            c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_DONE:
            c.reg_write(UC_ARM_REG_PC,SENTINEL)
    def onread(c,access,addr,n,val,ctx):
        if 0x40000000<=addr<0x50000000:
            reads.append((addr,n))
    def onwrite(c,access,addr,n,val,ctx):
        if not (0x2000E000<=addr and addr+n<=0x20010000):
            writes.append((addr,n))
    cpu.hook_add(UC_HOOK_CODE,oncode)
    cpu.hook_add(UC_HOOK_MEM_READ,onread)
    cpu.hook_add(UC_HOOK_MEM_WRITE,onwrite)
    cpu.emu_start(syms["handler_start"]|1,SENTINEL,count=2600)
    if len(responses)!=1 or writes:
        raise ValueError("unexpected GPIO diagnostic response or any nonstack write")
    valid=(length==REQ_LEN and opcode==OPCODE)
    if reads!=([(GPIOD_OCTL,4),(GPIOE_OCTL,4)] if valid else []):
        raise ValueError("GPIO output snapshot read incorrect peripheral register")
    expected=(0,struct.pack("<II",d,e)) if valid else (1,b"")
    if responses[0]!=expected:
        raise ValueError("GPIO output latch snapshot payload/status changed")
    return {
      "command":hex(opcode),"length":length,"status":responses[0][0],
      "reply_hex":responses[0][1].hex(),
      "GPIO_MMIO_reads":[hex(x) for x,n in reads],
      "nonstack_writes":0,
      "feeder_raw_latch_pairs":[
         [int(bool(d&(1<<x))),int(bool(d&(1<<y)))] for x,y in FEEDER_PAIRS
      ] if valid else [],
      "hub_command_direction_latch":bool(e&(1<<HUB_DIR)) if valid else None,
      "hub_command_brake_latch":bool(e&(1<<HUB_BRAKE)) if valid else None,
      "physical_motor_stop_proven":False,
      "CONFIG_WRITE_authorized":False,
    }

def mutants(image:bytes,syms:dict[str,int])->list[str]:
    cases=[]
    for name,symbol,replacement in (
       ("swap_D_to_E", "gpio_d_out_ptr",GPIOE_OCTL),
       ("swap_E_to_D", "gpio_e_out_ptr",GPIOD_OCTL),
       ("bypass_request_size_guard", "op_raw_gpio_motor_latches",None),
    ):
       bad=bytearray(image)
       off=syms[symbol]-LINK_BASE
       if replacement is None:
           # Neutralize the 32-bit conditional branch *after* request
           # length CMP (not the length load, which could still reject).
           bad[off+4:off+8]=b"\xaf\xf3\x00\x80"  # NOP.W
       else:
           struct.pack_into("<I",bad,off,replacement)
       try:
           run(bytes(bad),syms,0xA503,0x18,3 if replacement is None else 4)
       except ValueError:
           cases.append(name)
       else:
           raise AssertionError(f"invalid raw GPIO source unrecognized: {name}")
    if len(cases)!=3:
        raise ValueError("GPIO read-only mutation census changed")
    return cases

def main():
    p=argparse.ArgumentParser()
    for x in ("v313","v322","asm","linker","builder"):
        p.add_argument("--"+x,required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    v313=pinned(a.v313,"intermediate_v313")
    v322=pinned(a.v322,"running_v322")
    image,meta,syms=build(v313,v322,a.asm.read_text(),a.linker.read_text(),a.builder.read_text(),a.builder)
    cases=[
        ("all_zero",0,0,4,0x18),
        ("all_high_feeder_bits",0xf00f,0,4,0x18),
        ("feeder_A_pin_first",1<<2,0,4,0x18),
        ("feeder_A_pin_second",1<<3,0,4,0x18),
        ("feeder_B_pin_first",1<<0,0,4,0x18),
        ("feeder_C_pin_first",1<<14,0,4,0x18),
        ("feeder_D_pin_second",1<<13,0,4,0x18),
        ("hub_brake_command",0,1<<HUB_BRAKE,4,0x18),
        ("hub_dir_command",0,1<<HUB_DIR,4,0x18),
        ("mixed_GPIO_all_32bit_echoed",0xABCD1234,0xEEFFBBAA,4,0x18),
        ("wrong_short_length",0xf00f,0x18,3,0x18),
        ("wrong_long_length",0xf00f,0x18,5,0x18),
        ("unknown_next_opcode",0,0,4,0x19),
    ]
    sample=[{"name":name,**run(image,syms,d,e,n,op)}
            for name,d,e,n,op in cases]
    pwm=pwm_sample(image,syms,0x100,0x1111,4,0x16)
    hub=hub_sample(image,syms,250,80,0x1234,4,0x17)
    conf=[invoke_host_config(image,syms,cmd,state,0x35564643,0xffffffff)
          for state in range(6) for cmd in (0x12,0x13)]
    if any(x["status"]!=7 or x["sidecar_changed"] or x["nonstack_writes"] for x in conf):
        raise ValueError("previous failclosed MCU config writes unexpectedly enabled")
    if len(sample)!=13:
        raise ValueError("new GPIO diagnostic regression matrix changed")
    report={
        "candidate":meta,
        "raw_feeder_and_hub_GPIO_output_latch_Thumb_cases":sample,
        "previous_PWM_mmio_snapshot":pwm,
        "previous_hub_command_FG_snapshot":hub,
        "still_denied_CONFIG_SET_RESET_all_six_BOX_STATES":conf,
        "old_OEM_heap_boot_profile_reset":invoke_heap_boot_reset(image,syms),
        "mutated_GPIO_sources_or_length_guards_rejected":mutants(image,syms),
        "no_live_CFS_motor_or_serial_IO":True,
        "Kalico_source_untouched":True,
        "firmware_file_emitted":False,
        "motor_safe_write_interlock_complete":False,
    }
    body=json.dumps(report,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(body)
    print(body,end="")
if __name__=="__main__":main()
