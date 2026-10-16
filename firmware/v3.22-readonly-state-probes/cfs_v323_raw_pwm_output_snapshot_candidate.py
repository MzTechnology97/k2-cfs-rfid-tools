#!/usr/bin/env python3
"""CFS v3.23 first-test MCU read-only raw PWM enable snapshot.

Adds a new isolated diagnostic opcode 0x57/0x16, 8 byte payload:
TIMER0_CHCTL2 (0x40012C20) and TIMER3_CHCTL2 (0x40000820), each LE32.
The values are *output-enable commands*, NOT motor feedback or motor-stop
proofs; the handler never writes to MMIO or grants CONFIG SET/RESET.

Rebuilds stacked type4, spool-removal and FM15L013 guards from exact
SHA-pinned original manufacturer inputs entirely in memory. Reapplies
the stage #45 fail-closed CONFIG 0x12/0x13 entry branches, preserving
the real OEM prefix except known inbound BL, heap and CRC/length.
No firmware file, Klipper/Kalico, UART, SWD, bootloader, real MMIO.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import runpy
import struct
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from unicorn import (
    Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE, audited
from cfs_v323_physical_relink_baseline import (
    DELTA, PHYSICAL_HANDLER, physically_relocate_source, assemble,
    symbol_dict,
)
from cfs_v322_full_branch_edge_audit import (
    patches_from_builder, RELOC_LINE, EXPECTED_EXTERNAL_TARGET_COUNTS,
)
from cfs_v323_physical_full_image_parity import (
    APP_PREFIX, CRC_OFF, LEN_OFF, META_END,
    PHYSICAL_HEAP_LITERAL, EXPECTED_AFTER_HEAP,
)
from cfs_v323_legacy_type4_live_usage_candidate import (
    extend_source as live_source, INSERT_ANCHOR, OEM_PRELOAD_GATE_SITE,
    NEW_GATE_SYMBOL,
)
from cfs_v323_type4_secure_sink_guards_candidate import (
    DEFENSE_CODE, NEW_HOOKS,
    OEM_USAGE_DETECT_TARGET, OEM_USAGE_SECURE_WRITE_TARGET,
)
from cfs_v323_type4_spool_lifecycle_candidate import (
    compiled as spool_candidate, WRAPPER_ASM,
    OEM_REMOVAL_EVENT_CALLSITE, OEM_REMOVAL_EVENT_TARGET,
    OEM_CLEAR_RUNTIME, OEM_REPORT_PERCENT, NEW_SYMBOL,
)
from cfs_v323_safe_config_readonly_preview import (
    release_preview as fail_closed_preview,
    thumb_b_w,
    invoke_host_config,
    invoke_heap_boot_reset,
)

T0_CHCTL2=0x40012C20
T3_CHCTL2=0x40000820
SNAPSHOT_SUBCMD=0x16
SNAPSHOT_SIZE=8
MSG=0x20000200
SENTINEL=0x0802F000
OEM_SEND=0x0800EAF2
OEM_DONE=0x0800F808
PARAM_PAGE=0x0807F800
EXPECTED_WRAPPER_HOOKS=18
EXPECTED_EXTERNAL_CALLS=21

DISPATCH_BEFORE="""    cmp     r5, #0x13
    beq     op_config_v2_reset
    cmp     r5, #0x15
    beq.w   op_v323_readonly_snapshot
    b       status_bad
"""
DISPATCH_AFTER="""    cmp     r5, #0x13
    beq     op_config_v2_reset
    cmp     r5, #0x15
    beq.w   op_v323_readonly_snapshot
    cmp     r5, #0x16
    beq.w   op_raw_pwm_enable_snapshot
    b       status_bad
"""
NEW_ENTRY="""@ Extension 0x57/0x16: raw TIMER0 and TIMER3 output-enable registers.
@ Never infer motor STOP or grant write permission from raw values.
@ Read-only, bounded 8-byte response using existing 8-byte stack.
.thumb_func
op_raw_pwm_enable_snapshot:
    ldrb    r0, [r4, #1]
    cmp     r0, #4
    bne.w   status_bad
    ldr     r0, raw_t0_chctl2_ptr
    ldr     r0, [r0]
    str     r0, [sp, #0]
    ldr     r0, raw_t3_chctl2_ptr
    ldr     r0, [r0]
    str     r0, [sp, #4]
    mov     r2, sp
    movs    r3, #8
    movs    r1, #0
    b.w     send

raw_t0_chctl2_ptr: .word 0x40012C20
raw_t3_chctl2_ptr: .word 0x40000820

"""

MOTOR_ENABLE_MASKS={
    "pwm1_hub_PE13_TIMER0_CH2":(0,0x100),
    "pwm3_feeder_PD12_TIMER3_CH0":(1,0x001),
    "pwm4_feeder_PD13_TIMER3_CH1":(1,0x010),
    "pwm5_feeder_PD15_TIMER3_CH3":(1,0x1000),
    "pwm8_feeder_PD14_TIMER3_CH2":(1,0x100),
}

def extend_with_readonly_pwm(asm:str,*,extra_dispatch:str="",
                             extra_entry:str="")->str:
    text=live_source(asm)
    if text.count(DISPATCH_BEFORE)!=1:
        raise ValueError("0x57 extended dispatch source changed")
    text=text.replace(DISPATCH_BEFORE,DISPATCH_AFTER,1)
    if extra_dispatch:
        anchor="    cmp     r5, #0x16\n    beq.w   op_raw_pwm_enable_snapshot\n    b       status_bad\n"
        if text.count(anchor)!=1 or not extra_entry:
            raise ValueError("further read-only MCU dispatcher extension invalid")
        replacement=anchor.replace("    b       status_bad\n",extra_dispatch+"    b       status_bad\n",1)
        text=text.replace(anchor,replacement,1)
    elif extra_entry:
        raise ValueError("unreachable extra MCU command")
    if text.count(INSERT_ANCHOR)!=1:
        raise ValueError("old v3.22 assembly append anchor changed")
    return text.replace(INSERT_ANCHOR,
        DEFENSE_CODE+WRAPPER_ASM+NEW_ENTRY+extra_entry+INSERT_ANCHOR,1)

def build(v313:bytes,v322:bytes,asm:str,ld:str,builder:str,
          builder_path:Path,*,extra_dispatch:str="",
          extra_entry:str="")->tuple[bytes,dict,dict[str,int]]:
    audited(v313)
    audited(v322)
    _,spool,spool_meta,spool_syms=spool_candidate(
        v313,v322,asm,ld,builder,builder_path
    )
    protected,ro_meta=fail_closed_preview(spool,spool_syms)
    physical,linked,refs=physically_relocate_source(
        extend_with_readonly_pwm(asm,extra_dispatch=extra_dispatch,
                                 extra_entry=extra_entry),ld
    )
    handler,relocs,syms_text=assemble(physical,linked)
    syms=symbol_dict(syms_text)
    if len(refs)!=13:
        raise ValueError("unexpected stock external OEM symbol inventory")
    expected=Counter({x-DELTA:n for x,n in EXPECTED_EXTERNAL_TARGET_COUNTS.items()})
    expected[0x080032E2]+=1
    expected[OEM_USAGE_DETECT_TARGET]+=1
    expected[OEM_USAGE_SECURE_WRITE_TARGET]+=1
    for dst in (OEM_REMOVAL_EVENT_TARGET,OEM_CLEAR_RUNTIME,OEM_REPORT_PERCENT):
        expected[dst]+=1
    actual=[]
    insns=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    for raw_off,kind,dst_text,_ in RELOC_LINE.findall(relocs):
        off=int(raw_off,16);pc=PHYSICAL_HANDLER+off;dst=int(dst_text,16)
        inst=next(insns.disasm(handler[off:off+4],pc,count=1),None)
        mnemonic="bl" if kind=="R_ARM_THM_CALL" else "b.w"
        if inst is None or (inst.mnemonic,inst.op_str)!=(mnemonic,f"#{dst:#x}"):
            raise ValueError("new read-only handler changed manufacturer outward ABI")
        actual.append(dst)
    if len(actual)!=EXPECTED_EXTERNAL_CALLS or Counter(actual)!=expected:
        raise ValueError("old 21 outward manufacturer branches not preserved")
    hooks={}
    for nominal,name in patches_from_builder(builder):
        hooks[nominal-DELTA]=syms[name]
    hooks[OEM_PRELOAD_GATE_SITE]=syms[NEW_GATE_SYMBOL]
    for pc,name,_ in NEW_HOOKS:
        hooks[pc]=syms[name]
    hooks[OEM_REMOVAL_EVENT_CALLSITE]=syms[NEW_SYMBOL]
    if len(hooks)!=EXPECTED_WRAPPER_HOOKS:
        raise ValueError("old 18 manufacturer inbound hooks changed")

    image=bytearray(v313[:APP_PREFIX]+handler)
    helpers=runpy.run_path(str(builder_path))
    for pc,target in hooks.items():
        patch=helpers["thumb_bl"](pc,target)
        inst=next(insns.disasm(patch,pc,count=1),None)
        if inst is None or (inst.mnemonic,inst.op_str)!=("bl",f"#{target:#x}"):
            raise ValueError("invalid original OEM physical BL relocation")
        image[pc-LINK_BASE:pc-LINK_BASE+4]=patch

    heap=PHYSICAL_HEAP_LITERAL-LINK_BASE
    if struct.unpack_from("<I",image,heap)[0]!=0x20006EE8:
        raise ValueError("OEM heap origin changed")
    struct.pack_into("<I",image,heap,EXPECTED_AFTER_HEAP)
    # The CONFIG write entry addresses shift when the original dispatcher
    # grows. Re-encode branches with updated physical PC and same destination.
    changes=[]
    for entry in ("op_config_v2_set","op_config_v2_reset"):
        pc=syms[entry]
        ins=next(insns.disasm(image[pc-LINK_BASE:pc-LINK_BASE+4],pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=("ldrb","r0, [r4, #1]"):
            raise ValueError("unexpected CONFIG SET/RESET first instruction")
        op=thumb_b_w(pc,syms["status_busy"])
        image[pc-LINK_BASE:pc-LINK_BASE+4]=op
        changes.append(pc)

    if LINK_BASE+len(image)!=PHYSICAL_HANDLER+len(handler):
        raise ValueError("new physical APP length disagrees with handler")
    if LINK_BASE+len(image)>PARAM_PAGE:
        raise ValueError("candidate crosses historical OEM parameter Flash")
    struct.pack_into("<I",image,LEN_OFF,len(image))
    for_crc=bytearray(image)
    for_crc[CRC_OFF:META_END]=bytes(META_END-CRC_OFF)
    crc=helpers["crc16_bypass"](for_crc)
    struct.pack_into("<H",image,CRC_OFF,crc)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    if helpers["crc16_bypass"](bytearray(image[:CRC_OFF]+bytes(META_END-CRC_OFF)+image[META_END:]))!=crc:
        raise ValueError("image final checksum disagreement")
    allowed=set(range(CRC_OFF,META_END))
    allowed.update(range(heap,heap+4))
    for pc in hooks:
        allowed.update(range(pc-LINK_BASE,pc-LINK_BASE+4))
    deviations=[i for i,(a,b) in enumerate(zip(v313[:APP_PREFIX],image[:APP_PREFIX]))
                if a!=b and i not in allowed]
    if deviations:
        raise ValueError("unexpected manufacturer OEM prefix drift")
    parent_unexpected=[i for i,(a,b) in enumerate(zip(protected[:APP_PREFIX],image[:APP_PREFIX]))
                       if a!=b and i not in allowed]
    if parent_unexpected:
        raise ValueError("unexpected extra changes to previous protected APP")
    if len(image)<=len(protected):
        raise ValueError("missing read-only MCU diagnostic implementation")

    # Pinned physical Thumb instruction and register-source proof.
    source=bytes(image)
    pc=syms["op_raw_pwm_enable_snapshot"]
    first=next(insns.disasm(source[pc-LINK_BASE:pc-LINK_BASE+4],pc,count=1),None)
    if first is None or (first.mnemonic,first.op_str)!=("ldrb","r0, [r4, #1]"):
        raise ValueError("new diagnostic command lacks request-length check")
    for name,expected_literal in (("raw_t0_chctl2_ptr",T0_CHCTL2),
                                  ("raw_t3_chctl2_ptr",T3_CHCTL2)):
        if struct.unpack_from("<I",source,syms[name]-LINK_BASE)[0]!=expected_literal:
            raise ValueError("wrong read-only TIMER peripheral address")
    summary={
        "original_APP_base":hex(LINK_BASE),
        "prior_safe_CONFIG_APP_bytes":len(protected),
        "new_read_only_PWM_snapshot_APP_bytes":len(image),
        "new_source_bytes":len(image)-len(protected),
        "end_exclusive":hex(LINK_BASE+len(image)),
        "last_flash_page":(LINK_BASE+len(image)-1-0x08000000)//0x800,
        "historical_parameter_page_reserved":hex(PARAM_PAGE),
        "incoming_original_manufacturer_hooks":len(hooks),
        "outgoing_original_manufacturer_calls":len(actual),
        "new_opcode":"0x57/0x16",
        "new_opcode_handler_PC":hex(syms["op_raw_pwm_enable_snapshot"]),
        "snapshot_length":SNAPSHOT_SIZE,
        "TIMER0_raw_output_enable_register":hex(T0_CHCTL2),
        "TIMER3_raw_output_enable_register":hex(T3_CHCTL2),
        "config_SET_RESET_entry_guards_shifted_and_still_active":[hex(x) for x in changes],
        "original_CMD_0x57_CONFIG_ID_28_31_preserved":True,
        "manufacturer_command_or_GPIO_behavior_unchanged":True,
        "raw_output_enable_registers_prove_physical_motor_STOP":False,
        "inferred_absent_PWM_proves_all_motors_deenergized":False,
        "can_apply_RAM_config_profile_on_boot":False,
        "MCU_motor_write_allowed":False,
        "flash_qualified":False,
        "firmware_file_exported":False,
        "sha256_in_memory_only":hashlib.sha256(image).hexdigest(),
        "crc16_in_memory_only":hex(crc),
    }
    return source,summary,syms

def run_diag(image:bytes,symbols:dict[str,int],first:int,second:int,req_len:int,
             subcmd:int=SNAPSHOT_SUBCMD)->dict:
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    cpu.mem_map(0x08000000,0x40000)
    cpu.mem_write(LINK_BASE,image)
    cpu.mem_map(0x20000000,0x10000)
    cpu.mem_map(0x40012000,0x1000)
    cpu.mem_map(0x40000000,0x1000)
    cpu.mem_write(T0_CHCTL2,struct.pack("<I",first))
    cpu.mem_write(T3_CHCTL2,struct.pack("<I",second))
    req=bytearray(16)
    req[1]=req_len
    req[4]=subcmd
    cpu.mem_write(MSG,bytes(req))
    cpu.reg_write(UC_ARM_REG_R0,0x57)
    cpu.reg_write(UC_ARM_REG_R4,MSG)
    cpu.reg_write(UC_ARM_REG_SP,0x2000F000)
    cpu.reg_write(UC_ARM_REG_LR,SENTINEL|1)
    reads=[]
    writes=[]
    replies=[]
    def code(uc,pc,size,_user):
        if pc==OEM_SEND:
            n=uc.reg_read(UC_ARM_REG_R3)
            if n>8:
                raise ValueError("diagnostic response unexpectedly too long")
            replies.append({
                "status":uc.reg_read(UC_ARM_REG_R1),
                "data":bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R2),n))
                       if n else b"",
            })
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_DONE:
            uc.reg_write(UC_ARM_REG_PC,SENTINEL)
    def on_read(uc,access,address,size,value,_user):
        if 0x40000000<=address<0x50000000:
            reads.append((address,size))
    def on_write(uc,access,address,size,value,_user):
        if not (0x2000E000<=address and address+size<=0x20010000):
            writes.append((address,size))
    cpu.hook_add(UC_HOOK_CODE,code)
    cpu.hook_add(UC_HOOK_MEM_READ,on_read)
    cpu.hook_add(UC_HOOK_MEM_WRITE,on_write)
    cpu.emu_start(symbols["handler_start"]|1,SENTINEL,count=2500)
    if len(replies)!=1:
        raise ValueError("OEM diagnostic response count changed")
    valid=(req_len==4 and subcmd==SNAPSHOT_SUBCMD)
    expected=[(T0_CHCTL2,4),(T3_CHCTL2,4)] if valid else []
    if reads!=expected:
        raise ValueError(f"unapproved TIMER MMIO sample path: {reads} != {expected}")
    if writes:
        raise ValueError(f"read-only PWM snapshot wrote nonstack or peripheral memory: {writes}")
    got=replies[0]
    if valid:
        if got["status"]!=0 or got["data"]!=struct.pack("<II",first,second):
            raise ValueError("raw TIM0/TIM3 snapshot misencoded")
    elif subcmd==0x15 and req_len==4:
        if got["status"]!=0 or got["data"]!=b"\x23\x00":
            raise ValueError("original v3.23 readonly BOX_STATE snapshot regressed")
    else:
        if got["status"]!=1 or got["data"]!=b"":
            raise ValueError("malformed or unknown snapshot opcode not rejected")
    enabled=[name for name,(device,mask) in MOTOR_ENABLE_MASKS.items()
             if ((first,second)[device]&mask)] if valid else []
    return {
        "subcmd":hex(subcmd),
        "request_payload_len":req_len,
        "MMIO_reads":[hex(p) for p,_ in reads],
        "MMIO_writes":0,
        "other_nonstack_writes":0,
        "raw_snapshot_words":[hex(first),hex(second)] if valid else [],
        "replied_status":got["status"],
        "reply_hex":got["data"].hex(),
        "known_PWM_OUTPUT_ENABLE_bits_set":enabled,
        "motor_STOP_verified":False,
        "permission_to_write_RAM_overrides":False,
    }

def negative_fixtures(image:bytes,syms:dict[str,int])->list[str]:
    """Each in-memory mutation must fail the same raw-IO regression.

    No v3.23 real binary image is emitted; corruptions are ephemeral.
    """
    test_args=(0x10203040,0x50607080,4,0x16)
    rejects=[]
    for label,target,new in (
        ("crosswire_T0_register", "raw_t0_chctl2_ptr", T3_CHCTL2),
        ("crosswire_T3_register", "raw_t3_chctl2_ptr", T0_CHCTL2),
        ("corrupt_diagnostic_entry", "op_raw_pwm_enable_snapshot", None),
    ):
        altered=bytearray(image)
        off=syms[target]-LINK_BASE
        if new is None:
            altered[off:off+2]=b"\x00\xbf"  # Thumb NOP replaces ldrb len
        else:
            struct.pack_into("<I",altered,off,new)
        try:
            run_diag(bytes(altered),syms,*test_args)
        except (ValueError,RuntimeError):
            rejects.append(label)
        else:
            raise AssertionError("corrupted OEM read-only diagnostic accepted "+label)
    if len(rejects)!=3:
        raise ValueError("PWM raw-read source mutation tests unexpectedly changed")
    return rejects


def main()->None:
    ap=argparse.ArgumentParser()
    for x in ("v313","v322","asm","linker","builder"):
        ap.add_argument("--"+x,required=True,type=Path)
    ap.add_argument("--json-out",type=Path)
    a=ap.parse_args()
    v313=pinned(a.v313,"intermediate_v313")
    v322=pinned(a.v322,"running_v322")
    image,summ,syms=build(v313,v322,a.asm.read_text(),a.linker.read_text(),
                          a.builder.read_text(),a.builder)
    scenarios=[
        ("all_outputs_off",0,0,4,0x16),
        ("hub_output_enabled",0x100,0,4,0x16),
        ("feeder0_enabled",0,0x001,4,0x16),
        ("feeder1_enabled",0,0x010,4,0x16),
        ("feeder2_enabled",0,0x1000,4,0x16),
        ("feeder3_enabled",0,0x100,4,0x16),
        ("all_outputs_enabled",0x100,0x1111,4,0x16),
        ("all_32bit_bits_echoed",0xFA5A1234,0x0BADF00D,4,0x16),
        ("bad_length_short",0x100,0x1111,3,0x16),
        ("bad_length_long",0x100,0x1111,5,0x16),
        ("existing_READONLY_BOX_STATE_snapshot",0,0,4,0x15),
        ("unknown_DESCRIBE_opcode",0,0,4,0x14),
        ("unknown_next_opcode",0,0,4,0x17),
    ]
    cases=[{"case":label,**run_diag(image,syms,t0,t3,n,command)}
           for label,t0,t3,n,command in scenarios]
    if len(cases)!=13:
        raise ValueError("read-only status fixture census changed")
    checks=[]
    # Ensure the previous fail-closed configuration cannot be bypassed by
    # register values or B.W relocations shifted by the new opcode.
    for state in (0,1,2,3,4,5):
        for cmd in (0x12,0x13):
            checks.append(invoke_host_config(image,syms,cmd,state,0x35564643,
                                             0xFFFFFFFF))
    if len(checks)!=12 or any(x["status"]!=7 or x["sidecar_changed"]
                              or x["nonstack_writes"] for x in checks):
        raise ValueError("CONFIG motor-unsafe SET/RESET fence regressed")
    for cmd in (0x10,0x11):
        checks.append(invoke_host_config(image,syms,cmd,0,0,0))
    if checks[-2]["status"] or checks[-1]["payload_hex"]!="07800c":
        raise ValueError("original CONFIG GET/INFO regressed")
    boot=invoke_heap_boot_reset(image,syms)
    report={
        "candidate":summ,
        "new_RAW_PWM_snapshot_emulator_matrix":cases,
        "raw_MMIO_source_and_opcode_mutations_rejected":negative_fixtures(image,syms),
        "still_denied_CONFIG_and_diagnostic_GET_matrix":checks,
        "unchanged_original_heap_boot_reset":boot,
        "exposed_sensor_feedback_is_raw_pwm_outputs_not_motor_STOP":True,
        "firmware_BIN_HEX_ELF_generated":False,
        "Kalico_source_or_config_touched":False,
        "CFS_hardware_serial_MMIO_accessed":False,
        "MCU_flash_approved":False,
    }
    text=json.dumps(report,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(text)
    print(text,end="")

if __name__=="__main__":
    main()
