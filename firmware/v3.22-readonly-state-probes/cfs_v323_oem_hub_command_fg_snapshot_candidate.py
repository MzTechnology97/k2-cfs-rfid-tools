#!/usr/bin/env python3
"""CFS v3.23 experimental OEM motor command/FG sample, strictly READ ONLY.

Adds 0x57/0x17 (8 bytes) to stacked 0x16 PWM-enable diagnostic:
current commanded hub duty (u16), previous commanded duty (u16),
and hub PE11 IRQ pulse counter (u32), all little endian.
Values are not atomic and do not prove that any motor has stopped.

Compiles the entire historical-OEM-based APP in memory only. Runs the
actual Thumb diagnostic and motor-unsafe CONFIG fence in Unicorn.
Never touches physical MCU/serial/GPIO, Kalico, or Flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE
from cfs_motor_duty_shadow_physical_audit import (
    analyze as motor_oem_source,
    DUTY_FIELD, PREVIOUS_FIELD,
)
from cfs_motor_multisignal_observation_plan import (
    manifest as original_fg_source, COUNTER,
)
from cfs_v323_raw_pwm_output_snapshot_candidate import (
    build as build_original_plus_pwm,run_diag as original_pwm_case,
    T0_CHCTL2,T3_CHCTL2,MSG,SENTINEL,OEM_SEND,OEM_DONE,
)
from cfs_v323_safe_config_readonly_preview import (
    invoke_host_config,invoke_heap_boot_reset,
)

OPCODE=0x17
REQ_LEN=4
SAMPLE_SIZE=8
DISPATCH_ADD="    cmp     r5, #0x17\n    beq.w   op_motor_command_fg_snapshot\n"
ENTRY_ASM="""@ Raw original OEM hub command shadow plus PE11 IRQ pulse counter.
@ Not a physical STOP, not atomic across threads/interrupts.
@ 0x57/0x17 response: LE16 duty + LE16 previous + LE32 pulses.
.thumb_func
op_motor_command_fg_snapshot:
    ldrb    r0, [r4, #1]
    cmp     r0, #4
    bne.w   status_bad
    ldr     r0, hub_duty_source_ptr
    ldrh    r1, [r0, #0]
    strh    r1, [sp, #0]
    ldrh    r1, [r0, #2]
    strh    r1, [sp, #2]
    ldr     r0, hub_irq_counter_ptr
    ldr     r1, [r0]
    str     r1, [sp, #4]
    mov     r2, sp
    movs    r3, #8
    movs    r1, #0
    b.w     send

.balign 4
hub_duty_source_ptr: .word 0x20004A1A
hub_irq_counter_ptr: .word 0x20004990

"""

def build(v313:bytes,v322:bytes,asm:str,linker:str,builder:str,
          builder_path:Path)->tuple[bytes,dict,dict[str,int]]:
    a=motor_oem_source(v313)
    b=motor_oem_source(v322)
    if a!=b:
        raise ValueError("stock command duty/previous RAM field changed across OEM vintages")
    c=original_fg_source(v322)
    if c["pulse_counter_RAM"]!=hex(COUNTER) or not c["read_only_diagnostic_manifest_not_a_live_sample"]:
        raise ValueError("manufacturer FG IRQ pulse counter not source proven")
    if (DUTY_FIELD,PREVIOUS_FIELD,COUNTER)!=(0x20004A1A,0x20004A1C,0x20004990):
        raise ValueError("unexpected motor command/IRQ physical SRAM location")
    first,mapping,_=build_original_plus_pwm(v313,v322,asm,linker,builder,builder_path)
    image,meta,syms=build_original_plus_pwm(
        v313,v322,asm,linker,builder,builder_path,
        extra_dispatch=DISPATCH_ADD,extra_entry=ENTRY_ASM)
    if len(image)<=len(first) or syms.get("op_motor_command_fg_snapshot") is None:
        raise ValueError("original firmware motor sample entry not appended")
    # Validate new literal operands directly in the physically linked APP.
    for label,ptr in (("hub_duty_source_ptr",DUTY_FIELD),
                      ("hub_irq_counter_ptr",COUNTER)):
        found=struct.unpack_from("<I",image,syms[label]-LINK_BASE)[0]
        if found!=ptr:
            raise ValueError("raw manufacturer motor SRAM source literal corrupted")
    if image[:0xC0]!=first[:0xC0]:
        # firmware header should be the only allowed change in this region
        changed=[i for i,(x,y) in enumerate(zip(image[:0xC0],first[:0xC0])) if x!=y]
        if not set(changed).issubset(set(range(0x20C,0x212))):
            raise ValueError("unexpected original APP start drift")
    result={
        "previous_pwm_only_APP_bytes":len(first),
        "new_hub_command_FG_APP_bytes":len(image),
        "new_source_bytes":len(image)-len(first),
        "physical_APP_base":hex(LINK_BASE),
        "APP_end_exclusive":hex(LINK_BASE+len(image)),
        "last_2KiB_flash_page":(LINK_BASE+len(image)-1-0x08000000)//0x800,
        "original_manufacturer_incoming_hooks":meta["incoming_original_manufacturer_hooks"],
        "original_manufacturer_outgoing_calls":meta["outgoing_original_manufacturer_calls"],
        "config_SET_RESET_entry_guards_still_present":meta["config_SET_RESET_entry_guards_shifted_and_still_active"],
        "new_opcode":"0x57/0x17",
        "new_entry":hex(syms["op_motor_command_fg_snapshot"]),
        "payload_bytes":SAMPLE_SIZE,
        "oem_hub_requested_duty_RAM":hex(DUTY_FIELD),
        "oem_hub_previous_requested_duty_RAM":hex(PREVIOUS_FIELD),
        "oem_hub_FG_irq_pulse_counter_RAM":hex(COUNTER),
        "word_reads_are_RTOS_atomic_as_a_group":False,
        "hub_FG_covers_four_feeders":False,
        "zero_duty_and_zero_pulse_means_motor_stopped":False,
        "zero_duty_means_motor_deenergized":False,
        "motor_safe_SET_RESET_approved":False,
        "Kalico_source_and_config_unchanged":True,
        "flash_approved":False,
        "persistent_BIN_output":False,
        "transient_crc16":meta["crc16_in_memory_only"],
        "transient_sha256":hashlib.sha256(image).hexdigest(),
    }
    return image,result,syms

def sample(image:bytes,syms:dict[str,int],curr:int,previous:int,pulses:int,
           length:int=4,command:int=OPCODE)->dict:
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    u.mem_map(0x08000000,0x40000);u.mem_write(LINK_BASE,image)
    u.mem_map(0x20000000,0x10000)
    u.reg_write(UC_ARM_REG_SP,0x2000F000)
    u.reg_write(UC_ARM_REG_LR,SENTINEL|1)
    u.reg_write(UC_ARM_REG_R0,0x57)
    u.reg_write(UC_ARM_REG_R4,MSG)
    req=bytearray(12);req[1]=length;req[4]=command
    u.mem_write(MSG,bytes(req))
    u.mem_write(DUTY_FIELD,struct.pack("<HH",curr,previous))
    u.mem_write(COUNTER,struct.pack("<I",pulses))
    reads=[]
    writes=[]
    sends=[]
    def onread(c,access,address,size,val,ctx):
        if address in (DUTY_FIELD,PREVIOUS_FIELD,COUNTER):
            reads.append((address,size))
    def onwrite(c,access,address,size,val,ctx):
        if not (0x2000E000<=address and address+size<=0x20010000):
            writes.append((address,size))
    def oncode(c,pc,n,ctx):
        if pc==OEM_SEND:
            size=c.reg_read(UC_ARM_REG_R3)
            if size>8:raise ValueError("unexpected 0x57 hub motor sample length")
            sends.append((c.reg_read(UC_ARM_REG_R1),
                          bytes(c.mem_read(c.reg_read(UC_ARM_REG_R2),size)) if size else b""))
            c.reg_write(UC_ARM_REG_PC,c.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_DONE:
            c.reg_write(UC_ARM_REG_PC,SENTINEL)
    u.hook_add(UC_HOOK_CODE,oncode)
    u.hook_add(UC_HOOK_MEM_READ,onread)
    u.hook_add(UC_HOOK_MEM_WRITE,onwrite)
    u.emu_start(syms["handler_start"]|1,SENTINEL,count=2300)
    valid=length==REQ_LEN and command==OPCODE
    expected_reads=[(DUTY_FIELD,2),(PREVIOUS_FIELD,2),(COUNTER,4)] if valid else []
    if reads!=expected_reads or writes:
        raise ValueError(f"hub/FG read-only source or SRAM modification mismatch: {reads} {writes}")
    if len(sends)!=1:
        raise ValueError("missing or duplicated OEM response")
    status,payload=sends[0]
    if valid and (status,payload)!=(0,struct.pack("<HHI",curr,previous,pulses)):
        raise ValueError("raw hub command and pulse payload mismatch")
    if not valid and (status,payload)!=(1,b""):
        raise ValueError("invalid hub command snapshot request not rejected")
    return {
        "subcmd":hex(command),
        "request_length":length,
        "status":status,
        "payload_hex":payload.hex(),
        "SRAM_reads":[(hex(p),n) for p,n in reads],
        "SRAM_MMIO_nonstack_writes":0,
        "hub_requested_duty_commanded":curr if valid else None,
        "hub_previous_duty_commanded":previous if valid else None,
        "hub_FG_pulse_counter":pulses if valid else None,
        "hub_and_feeder_motors_stopped":False,
        "safe_to_apply_RAM_parameters":False,
    }

def mutations(image:bytes,syms:dict[str,int])->list[str]:
    bad=[]
    original=(1,2,3,4,0x17)
    for label,entry,variant in (
        ("swap_hub_command_source","hub_duty_source_ptr",PREVIOUS_FIELD),
        ("swap_hub_FG_counter_source","hub_irq_counter_ptr",DUTY_FIELD),
        ("skip_payload_length_validation","op_motor_command_fg_snapshot",None),
    ):
        damaged=bytearray(image)
        off=syms[entry]-LINK_BASE
        if variant is None:damaged[off:off+2]=b"\x00\xbf"
        else:struct.pack_into("<I",damaged,off,variant)
        try:
            sample(bytes(damaged),syms,*original)
        except ValueError:
            bad.append(label)
        else:
            raise AssertionError("raw manufacturer source mutation was accepted "+label)
    if len(bad)!=3:
        raise ValueError("three original motor/FG source negative fixtures changed")
    return bad

def main()->None:
    ap=argparse.ArgumentParser()
    for x in ("v313","v322","asm","linker","builder"):
        ap.add_argument("--"+x,type=Path,required=True)
    ap.add_argument("--json-out",type=Path)
    a=ap.parse_args()
    v313=pinned(a.v313,"intermediate_v313")
    v322=pinned(a.v322,"running_v322")
    image,meta,syms=build(v313,v322,a.asm.read_text(),a.linker.read_text(),a.builder.read_text(),a.builder)
    cases=[
        ("both_zero_no_pulses",0,0,0,4,0x17),
        ("command_nonzero_stalled",240,120,0,4,0x17),
        ("previous_command_nonzero",0,180,0,4,0x17),
        ("pulses_after_zero_duty",0,0,19,4,0x17),
        ("nonzero_all",256,65535,0x12345678,4,0x17),
        ("full_width",65535,65535,0xFFFFFFFF,4,0x17),
        ("short_request",240,0,10,3,0x17),
        ("long_request",240,0,10,5,0x17),
        ("reserved_opcode",0,0,0,4,0x18),
    ]
    result=[{"case":name,**sample(image,syms,x,y,z,n,op)}
            for name,x,y,z,n,op in cases]
    if len(result)!=9:
        raise ValueError("OEM hub motor command snapshot matrix changed")
    # Regression proving the old raw PWM MMIO extension remains byte-correct.
    pwm=original_pwm_case(image,syms,0x100,0x1111,4,0x16)
    if len(pwm["known_PWM_OUTPUT_ENABLE_bits_set"])!=5:
        raise ValueError("previous five OEM PWM command outputs not visible")
    cfg=[]
    for state in range(6):
        for op in (0x12,0x13):
            cfg.append(invoke_host_config(image,syms,op,state,0x35564643,0xFFFFFFFF))
    if any(v["status"]!=7 or v["sidecar_changed"] or v["nonstack_writes"] for v in cfg):
        raise ValueError("motor-unsafe CONFIG changed previous fail-closed behavior")
    cold=invoke_heap_boot_reset(image,syms)
    report={
        "candidate":meta,
        "hub_motor_command_FG_original_Thumb_cases":result,
        "previous_PWM_snapshot_preserved":pwm,
        "CONFIG_SET_RESET_denied_all_BOX_STATES":cfg,
        "original_heap_boot_sidecar_still_cleared":cold,
        "source_mutation_fixtures_rejected":mutations(image,syms),
        "real_CFS_hardware_io":False,
        "Kalico_touched":False,
        "firmware_BIN_emitted":False,
        "motor_interlock_qualified":False,
    }
    s=json.dumps(report,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(s)
    print(s,end="")

if __name__=="__main__":main()
