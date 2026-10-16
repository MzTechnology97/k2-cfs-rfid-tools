#!/usr/bin/env python3
"""CFS v3.23 source-only integrated motor-write fence regression.

Proves the 102 inventoried OEM motor BL callsites and three tail branches
stay byte-identical to the saved, SHA-pinned v3.22 manufacturer APP,
while 0x57/0x16 raw PWM reads and 0x57/0x12,0x13 SET/RESET denial
execute *in sequence on one synthetic Cortex-M4 Unicorn MCU instance*.

A zero PWM enable mask or OEM BOX_STATE=IDLE never grants SET/RESET.
This is not a finished motor interlock: direct-call inventory is not
complete task/ISR/indirect-motor-start coverage, and output bits are
not mechanical feedback. No real CFS, Kalico, motors, RS485 or Flash.
Only JSON, never creates BIN/HEX/ELF.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from collections import Counter

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from unicorn import (
    Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,
)
from unicorn.arm_const import (
    UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_R0,UC_ARM_REG_R1,
    UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_SP,
)

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE
from cfs_motor_command_real_address_audit import DELTA
from motor_command_callgraph_audit import CALLS,TAILS
from cfs_v323_raw_pwm_output_snapshot_candidate import (
    build as build_v323,T0_CHCTL2,T3_CHCTL2,
    OEM_SEND,OEM_DONE,SENTINEL,MSG,
)

RAM_SIDECAR=0x20006EE8
RAM_BOX_STATE=0x200037D2
FIRMWARE_COMPARE_PAIRS=102
FIRMWARE_COMPARE_TAILS=3
SYNTH_RAM_STACK=0x2000F000

def assert_original_motor_call_sites(v322:bytes,live:bytes)->dict:
    """Fail closed if any known original motor start/stop branch is edited."""
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    touched=[]
    counts=Counter()
    for original_target,source_list in CALLS.items():
        for artificial_pc in source_list:
            pc=artificial_pc-DELTA
            target=original_target-DELTA
            off=pc-LINK_BASE
            old=v322[off:off+4]
            new=live[off:off+4]
            if len(new)!=4 or old!=new:
                raise ValueError(f"v3.23 changed saved OEM motor control BL at {pc:#x}")
            ins=next(cs.disasm(new,pc,count=1),None)
            if ins is None or (ins.mnemonic,ins.op_str)!=("bl",f"#{target:#x}"):
                raise ValueError(f"v3.23 motor branch target changed at {pc:#x}")
            touched.append(pc)
            counts[target]+=1
    tail_sites=[]
    for nominal,nominal_target in TAILS.items():
        pc=nominal-DELTA
        off=pc-LINK_BASE
        op=live[off:off+4]
        if op!=v322[off:off+4]:
            raise ValueError("v3.23 original motor wrapper tail changed")
        ins=next(cs.disasm(op,pc,count=1),None)
        if ins is None or not ins.mnemonic.startswith("b") or ins.op_str!=f"#{nominal_target-DELTA:#x}":
            raise ValueError("v3.23 original motor wrapper tail branch changed")
        tail_sites.append(pc)
    if len(touched)!=FIRMWARE_COMPARE_PAIRS or len(tail_sites)!=FIRMWARE_COMPARE_TAILS:
        raise ValueError("saved OEM motor source count unexpectedly changed")
    if len(set(touched))!=FIRMWARE_COMPARE_PAIRS:
        raise ValueError("duplicate manufacturer motor callsite")
    return {
        "manufacturer_known_direct_motor_BL_preserved":len(touched),
        "manufacturer_known_tail_branches_preserved":len(tail_sites),
        "physical_motor_command_targets":{hex(k):v for k,v in sorted(counts.items())},
        "does_not_prove_all_indirect_ISR_task_paths_are_covered":True,
        "no_movement_permission_granted":True,
    }

def sequential_single_mcu(image:bytes,syms:dict[str,int],
                          *,name:str,box_state:int,
                          timer0:int,timer3:int)->dict:
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    cpu.mem_map(0x08000000,0x40000)
    cpu.mem_write(LINK_BASE,image)
    cpu.mem_map(0x20000000,0x10000)
    cpu.mem_map(0x40012000,0x1000)
    cpu.mem_map(0x40000000,0x1000)
    cpu.mem_write(T0_CHCTL2,struct.pack("<I",timer0))
    cpu.mem_write(T3_CHCTL2,struct.pack("<I",timer3))
    cpu.mem_write(RAM_BOX_STATE,bytes([box_state]))
    prev_sidecar=bytearray([0x5a]*64)
    prev_sidecar[0:4]=struct.pack("<I",0x35564643)
    prev_sidecar[4:8]=struct.pack("<I",0xffffffff)
    cpu.mem_write(RAM_SIDECAR,bytes(prev_sidecar))
    exchanges=[]
    current_reads=[]
    current_global_writes=[]
    current_regs=[]
    captures=[]

    def oncode(uc,pc,size,user):
        if pc==OEM_SEND:
            length=uc.reg_read(UC_ARM_REG_R3)
            if length>16:
                raise ValueError("manufacturer CFS response length unexpectedly large")
            data=(bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R2),length))
                  if length else b"")
            captures.append((uc.reg_read(UC_ARM_REG_R1),data))
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        if pc==OEM_DONE:
            uc.reg_write(UC_ARM_REG_PC,SENTINEL)
    def onread(uc,access,addr,size,value,user):
        if 0x40000000<=addr<0x50000000:
            current_reads.append((addr,size))
    def onwrite(uc,access,addr,size,value,user):
        if not (0x2000E000<=addr and addr+size<=0x20010000):
            current_global_writes.append((addr,size))
    cpu.hook_add(UC_HOOK_CODE,oncode)
    cpu.hook_add(UC_HOOK_MEM_READ,onread)
    cpu.hook_add(UC_HOOK_MEM_WRITE,onwrite)

    for subcmd,req_length in ((0x16,4),(0x12,7),(0x13,5)):
        current_reads.clear()
        current_global_writes.clear()
        current_regs.clear()
        captures.clear()
        req=bytearray(16)
        req[1]=req_length
        req[4]=subcmd
        req[5]=7
        req[6:8]=struct.pack("<H",2500)
        cpu.mem_write(MSG,bytes(req))
        cpu.reg_write(UC_ARM_REG_R4,MSG)
        cpu.reg_write(UC_ARM_REG_R0,0x57)
        cpu.reg_write(UC_ARM_REG_SP,SYNTH_RAM_STACK)
        cpu.reg_write(UC_ARM_REG_LR,SENTINEL|1)
        cpu.emu_start(syms["handler_start"]|1,SENTINEL,count=3000)
        if cpu.reg_read(UC_ARM_REG_PC)!=SENTINEL or len(captures)!=1:
            raise ValueError("OEM MCU command failed to return expected reply")
        status,data=captures[0]
        if subcmd==0x16:
            if (status,data)!=(0,struct.pack("<II",timer0,timer3)):
                raise ValueError("PWM diagnostic corrupted register snapshot")
            if current_reads!=[(T0_CHCTL2,4),(T3_CHCTL2,4)]:
                raise ValueError("raw PWM read did not inspect exact two TIMER registers")
        else:
            if (status,data)!=(7,b""):
                raise ValueError("unsafe CONFIG SET/RESET admitted by CFS MCU")
            if current_reads:
                raise ValueError("CONFIG SET/RESET unexpectedly accessed MMIO")
        if current_global_writes:
            raise ValueError(f"unapproved non-stack or peripheral write from 0x57/{subcmd:02x}")
        if bytes(cpu.mem_read(RAM_SIDECAR,64))!=bytes(prev_sidecar):
            raise ValueError(f"unsafe CONFIG modified SRAM profile despite write fence: {subcmd:#x}")
        if bytes(cpu.mem_read(T0_CHCTL2,4))!=struct.pack("<I",timer0):
            raise ValueError("MCU command changed TIMER0 enable control")
        if bytes(cpu.mem_read(T3_CHCTL2,4))!=struct.pack("<I",timer3):
            raise ValueError("MCU command changed TIMER3 enable control")
        exchanges.append({
            "op":f"0x57/{subcmd:02x}","status":status,
            "reply_hex":data.hex(),
            "MMIO_reads":[hex(addr) for addr,size in current_reads],
            "global_writes":len(current_global_writes),
            "sidecar_still_unchanged":True,
        })
    return {
        "case":name,
        "BOX_STATE":box_state,
        "TIMER0_CHCTL2":hex(timer0),
        "TIMER3_CHCTL2":hex(timer3),
        "single_MCU_used_for_all_three_requests":True,
        "commands":exchanges,
        "motor_active_or_idle_physically_proven":False,
        "config_WRITE_permitted":False,
    }

def negative_motor_callsite_mutant(v322:bytes,image:bytes)->dict:
    """Alter one saved motor BL in memory, ensure unchanged-ROM gate refuses."""
    site=next(iter(CALLS.values()))[0]-DELTA
    off=site-LINK_BASE
    if image[off:off+4]!=v322[off:off+4]:
        raise ValueError("known motor callsite unexpectedly differed before mutation")
    tampered=bytearray(image)
    tampered[off]^=0x01
    try:
        assert_original_motor_call_sites(v322,bytes(tampered))
    except ValueError:
        return {"mutated_OEM_motor_PC":hex(site),
                "known_original_command_change_rejected":True}
    raise AssertionError("motor control callsite mutation passed")

def main()->None:
    p=argparse.ArgumentParser()
    for arg in ("v313","v322","asm","linker","builder"):
        p.add_argument("--"+arg,required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    v313=pinned(a.v313,"intermediate_v313")
    v322=pinned(a.v322,"running_v322")
    image,meta,syms=build_v323(
        v313,v322,a.asm.read_text(),a.linker.read_text(),
        a.builder.read_text(),a.builder)
    calls=assert_original_motor_call_sites(v322,image)
    test_inputs=[
        ("false_idle_all_output_enable_bits_zero",0,0,0),
        ("false_idle_hub_pwm_enabled",0,0x100,0),
        ("false_idle_feederA_pwm_enabled",0,0,0x001),
        ("false_idle_feederB_pwm_enabled",0,0,0x010),
        ("false_idle_feederC_pwm_enabled",0,0,0x1000),
        ("false_idle_feederD_pwm_enabled",0,0,0x100),
        ("false_idle_all_outputs_enabled",0,0x100,0x1111),
        ("busy_all_pwm_enable_bits_zero",2,0,0),
        ("busy_all_pwm_enabled",2,0x100,0x1111),
        ("state5_all_pwm_enabled",5,0x100,0x1111),
    ]
    cases=[sequential_single_mcu(image,syms,
            name=name,box_state=state,timer0=t0,timer3=t3)
           for name,state,t0,t3 in test_inputs]
    result={
        "underlying_in_memory_preview_APP_length":len(image),
        "underlying_in_memory_preview_APP_sha256":
            hashlib.sha256(image).hexdigest(),
        "original_102_motor_callsite_inventory":calls,
        "sequential_single_MCU_PWM_then_SET_then_RESET":cases,
        "single_removed_motor_callsite_mutation_rejected":
            negative_motor_callsite_mutant(v322,image),
        "no_complete_ISR_task_or_indirect_start_coverage":True,
        "independent_hardware_motor_stop_proven":False,
        "future_RTTHREAD_atomic_busy_interlock_implemented":False,
        "v323_config_RAM_WRITE_authorized":False,
        "v323_FLASH_authorized":False,
        "physical_CFS_Kalico_or_motor_IO":False,
        "firmware_binary_exported":False,
    }
    output=json.dumps(result,indent=2)+"\n"
    if a.json_out:
        a.json_out.write_text(output)
    print(output,end="")

if __name__=="__main__":
    main()
