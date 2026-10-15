#!/usr/bin/env python3
"""Build and emulate the FIRST v3.23 read-only delta in volatile memory only.

A zero-actuation new 0x57/0x15 command returns exactly:
  byte 0: 0x23 experimental build marker
  byte 1: original OEM BOX_OPER_STATE raw byte from [0x200037D0+2]
Neither is independent motor-stop evidence. Deliberately no BIN/ELF saved,
no serial, RFID, GPIO, PWM, CFS or real Kalico I/O.

All 14 old hook sites and 15 external handler branches are revalidated
after moving assembly to physical APP 0x08003000, with the tested v3.22
exact-image baseline a strict prerequisite.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import runpy
import struct

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_SP
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE
from cfs_v322_full_branch_edge_audit import (
    patches_from_builder,RELOC_LINE,EXPECTED_EXTERNAL_RELOCS,
    EXPECTED_EXTERNAL_TARGET_COUNTS,
)
from cfs_v323_physical_relink_baseline import (
    DELTA,PHYSICAL_HANDLER,physically_relocate_source,assemble,
    symbol_dict,verify_physical,EXPECTED_V322_SHA,
)
from cfs_v323_physical_full_image_parity import (
    replay,APP_PREFIX,CRC_OFF,LEN_OFF,META_END,PHYSICAL_HEAP_LITERAL,
    EXPECTED_AFTER_HEAP,
)

# Historical source-level size policy (physical absolute address), NOT a
# certified loader-boundary. The v3.23 experiment ends at 0x0802E800
# only because this is its actual compiled length / a 2KiB page boundary.
HISTORICAL_UNVERIFIED_POLICY_END=0x0803B800
EXPECTED_CANDIDATE_END=0x0802E800
MARKER=0x23
COMMAND=0x15
BOX_STATE=0x200037D2
SEND_RESPONSE=0x0800EAF2
DISPATCH_OLD="""    cmp     r5, #0x13
    beq     op_config_v2_reset
    b       status_bad
"""
DISPATCH_NEW="""    cmp     r5, #0x13
    beq     op_config_v2_reset
    cmp     r5, #0x15
    beq.w   op_v323_readonly_snapshot
    b       status_bad
"""
ANCHOR="@ Runtime CFS configuration.\n"
READ_ONLY_CODE="""@ v3.23 trial: read-only build ID and *raw* OEM BOX_OPER_STATE.
@ Never interpret BOX_STATE==IDLE as motor physically STOPPED.
@ No SRAM writes except two bytes in existing 8-byte SP response scratch.
op_v323_readonly_snapshot:
    ldrb    r0, [r4, #1]
    cmp     r0, #4
    bne.w   status_bad
    movs    r0, #0x23
    strb    r0, [sp, #0]
    ldr     r0, box_operating_state_ptr
    ldrb    r0, [r0, #2]
    strb    r0, [sp, #1]
    mov     r2, sp
    movs    r3, #2
    movs    r1, #0
    b       send

"""

def extend(source:str)->str:
    if source.count(DISPATCH_OLD)!=1 or source.count(ANCHOR)!=1:
        raise ValueError("original 0x57 dispatch or OEM CFS source anchor changed")
    if "op_v323_readonly_snapshot:" in source:
        raise ValueError("v3.23 diagnostic handler already exists")
    changed=source.replace(DISPATCH_OLD,DISPATCH_NEW)
    return changed.replace(ANCHOR,READ_ONLY_CODE+ANCHOR)

def compile_candidate(v313:bytes,v322:bytes,asm:str,ld:str,builder:str,
                      builder_file:Path)->tuple[bytes,dict]:
    # Full exact-known source check is a prerequisite; if original v3.22
    # replay fails, no new candidate can be evaluated.
    old=replay(v313,v322,asm,ld,builder,trusted_builder_file=builder_file)
    if not old["physical_relinked_full_v322_matches_reference_byte_for_byte"]:
        raise ValueError("source saved baseline not proven")
    updated=extend(asm)
    relocated,physical_ld,known_refs=physically_relocate_source(updated,ld)
    new_handler,relocs,nm=assemble(relocated,physical_ld)
    if len(new_handler)!=2504 or len(known_refs)!=13:
        raise ValueError("read-only feature changed handler byte count or external symbols")
    end=PHYSICAL_HANDLER+len(new_handler)
    if end>HISTORICAL_UNVERIFIED_POLICY_END:
        raise ValueError("candidate exceeded conservative, unqualified Flash budget")
    syms=symbol_dict(nm)
    if "op_v323_readonly_snapshot" not in syms:
        raise ValueError("new read-only command handler symbol missing")
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    external=RELOC_LINE.findall(relocs)
    if len(external)!=EXPECTED_EXTERNAL_RELOCS:
        raise ValueError("handler->original OEM relocation count changed")
    verified_out=[]
    for off,kind,target,_ in external:
        pc=PHYSICAL_HANDLER+int(off,16)
        dst=int(target,16)
        expected=("bl" if kind=="R_ARM_THM_CALL" else "b.w")
        ins=list(decoder.disasm(new_handler[int(off,16):int(off,16)+4],pc,count=1))
        if len(ins)!=1 or (ins[0].mnemonic,ins[0].op_str)!=(expected,f"#{dst:#x}"):
            raise ValueError("changed handler-to-OEM Thumb branch ABI")
        verified_out.append(dst)
    old_expected=Counter({int(p)-DELTA:v for p,v in EXPECTED_EXTERNAL_TARGET_COUNTS.items()})
    if Counter(verified_out)!=old_expected:
        raise ValueError("known 15 stock ABI branches shifted to wrong OEM targets")
    helpers=runpy.run_path(str(builder_file))
    image=bytearray(v313[:APP_PREFIX]+new_handler)
    hooks=patches_from_builder(builder)
    if len(hooks)!=14:
        raise ValueError("unreviewed OEM hook count")
    original_writes=set()
    for old_pc,label in hooks:
        src=old_pc-DELTA
        target=syms.get(label)
        if target is None or not PHYSICAL_HANDLER<=target<end:
            raise ValueError("unknown relocated OEM wrapper")
        pos=src-LINK_BASE
        bl=helpers["thumb_bl"](src,target)
        d=list(decoder.disasm(bl,src,count=1))
        if len(d)!=1 or (d[0].mnemonic,d[0].op_str)!=("bl",f"#{target:#x}"):
            raise ValueError("hook BL does not decode at physical callsite")
        image[pos:pos+4]=bl
        original_writes.update(range(pos,pos+4))
    # Original *known* heap root patch retained, no new data reservation.
    heapoff=PHYSICAL_HEAP_LITERAL-LINK_BASE
    if struct.unpack_from("<I",image,heapoff)[0]!=0x20006EE8:
        raise ValueError("v3.13 heap source literal moved")
    struct.pack_into("<I",image,heapoff,EXPECTED_AFTER_HEAP)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    temp=bytearray(image)
    temp[CRC_OFF:META_END]=bytes(META_END-CRC_OFF)
    crc=helpers["crc16_bypass"](temp)
    struct.pack_into("<H",image,CRC_OFF,crc)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    allowed=original_writes|set(range(CRC_OFF,META_END))
    if any(a!=b and i not in allowed for i,(a,b) in enumerate(zip(image[:APP_PREFIX],v322[:APP_PREFIX]))):
        raise ValueError("v3.23 changed original OEM APP outside previously patched BL and metadata")
    changed_oem_bytes=sum(a!=b for a,b in zip(image[:APP_PREFIX],v322[:APP_PREFIX]))
    if struct.unpack_from("<I",image,heapoff)[0]!=EXPECTED_AFTER_HEAP:
        raise ValueError("v3.22 heap patch no longer identical")
    if len(image)!=178176 or end!=EXPECTED_CANDIDATE_END:
        raise ValueError("total length / unqualified conservative flash end drift")
    metadata={
        "APP_base":hex(LINK_BASE),
        "handler_entry":hex(PHYSICAL_HANDLER),
        "saved_v322_sha":hashlib.sha256(v322).hexdigest(),
        "candidate_v323_SHA256_not_a_release":hashlib.sha256(image).hexdigest(),
        "known_v322_handler_bytes":2468,
        "candidate_v323_handler_bytes":len(new_handler),
        "handler_added_bytes":len(new_handler)-2468,
        "in_memory_candidate_APP_bytes":len(image),
        "source_13_OEM_equ_pointers":len(known_refs),
        "15_outgoing_OEM_Thumb_branches":len(external),
        "14_incoming_OEM_Thumb_hooks":len(hooks),
        "original_OEM_prefix_changed_bytes":changed_oem_bytes,
        "original_prefix_changes_confined_to_old_hooks_and_metadata":True,
        "historical_arbitrary_policy_end_NOT_LOADER_PROVEN":hex(HISTORICAL_UNVERIFIED_POLICY_END),
        "candidate_end_exclusive":hex(end),
        "last_occupied_2KiB_flash_page":(end-1-0x08000000)//2048,
        "arithmetic_headroom_to_unverified_policy_NOT_CERTIFIED_FREE":HISTORICAL_UNVERIFIED_POLICY_END-end,
        "candidate_crc16":hex(crc),
        "new_op":hex(COMMAND),
        "new_read_only_response_layout":"[0x23,raw_box_oper_state]",
        "no_new_peripheral_reads":True,
        "no_new_nonstack_SRAM_writes":True,
        "motor_state_independent_STOP_evidence":False,
        "real_bootloader_flash_limit_verified":False,
        "MCU_flash_permitted":False,
        "production_Kalico_or_CFS_touched":False,
    }
    return bytes(image),metadata

def emulate(image:bytes, length_field:int, state:int, op:int=COMMAND)->dict:
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    u.mem_map(0x08000000,0x40000)
    u.mem_write(LINK_BASE,image)
    u.mem_map(0x20000000,0x10000)
    u.mem_write(BOX_STATE,bytes([state]))
    req=bytearray(16)
    req[1]=length_field
    req[4]=op
    u.mem_write(0x20000100,bytes(req))
    u.reg_write(UC_ARM_REG_R0,0x57)
    u.reg_write(UC_ARM_REG_R4,0x20000100)
    u.reg_write(UC_ARM_REG_SP,0x2000F000)
    reached=[]
    writes=[]
    def codehook(emu,address,size,ctx):
        if address==SEND_RESPONSE:
            r1=emu.reg_read(UC_ARM_REG_R1)
            r2=emu.reg_read(UC_ARM_REG_R2)
            r3=emu.reg_read(UC_ARM_REG_R3)
            if r3>8:raise ValueError("response length exceeds existing scratch buffer")
            reached.append((r1,r3,bytes(emu.mem_read(r2,r3)) if r3 else b""))
            emu.emu_stop()
    def writehook(emu,access,address,size,value,ctx):
        if not (0x2000E000<=address and address+size<=0x20010000):
            raise ValueError(f"runtime firmware write escaped caller stack: {address:#x}")
        writes.append((address,size))
    u.hook_add(UC_HOOK_CODE,codehook)
    u.hook_add(UC_HOOK_MEM_WRITE,writehook)
    u.emu_start(PHYSICAL_HANDLER|1,0,count=600)
    if len(reached)!=1:raise ValueError("read-only diagnostic did not reach OEM response dispatcher")
    status,n,payload=reached[0]
    # Both success and invalid request flows are entirely stack local.
    if op==COMMAND and length_field==4:
        if (status,n,payload)!=(0,2,bytes([MARKER,state])):
            raise ValueError(f"read-only snapshot response mismatch {(status,n,payload)}")
    elif (status,n,payload)!=(1,0,b""):
        raise ValueError("bad-length or unknown opcode did not fail closed")
    return {"request_op":hex(op),"request_length":length_field,
            "raw_state":hex(state),"status":status,"response":payload.hex(),
            "RAM_writes_all_stack_local":True}

def reject_fixtures(v313,v322,asm,ld,builder,builder_file):
    # Synthetic corruption of handler insertion anchor, original source,
    # and known fixed-ABI targets must abort before becoming a candidate.
    checks=[]
    cases=[
        ("deleted_dispatch",asm.replace(DISPATCH_OLD,"    b status_bad\n",1),ld),
        ("changed_oem_target",asm.replace("0x0803393C","0x0803393E",1),ld),
        ("changed_linker_origin",asm,ld.replace("0x0803AE38","0x0803AE3A",1)),
    ]
    for name,source,linker in cases:
        try:compile_candidate(v313,v322,source,linker,builder,builder_file)
        except (ValueError,AssertionError):checks.append(name)
        else:raise AssertionError("unsafe source accepted: "+name)
    corrupt=bytearray(v322)
    corrupt[0x3000]^=1
    try:compile_candidate(v313,bytes(corrupt),asm,ld,builder,builder_file)
    except (ValueError,AssertionError):checks.append("mutated_saved_v322")
    else:raise AssertionError("wrong stock reference accepted")
    if len(checks)!=4:raise ValueError("not all four source rejections occurred")
    return checks

def main():
    p=argparse.ArgumentParser()
    for name in ("v313","v322","asm","linker","builder"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=pinned(a.v313,"intermediate_v313")
    known=pinned(a.v322,"running_v322")
    source=a.asm.read_text()
    linker=a.linker.read_text()
    builder=a.builder.read_text()
    candidate,metadata=compile_candidate(old,known,source,linker,builder,a.builder)
    checks=[emulate(candidate,4,state) for state in (0,1,2,3,4,5,0xFF)]
    checks.extend((emulate(candidate,3,1),emulate(candidate,5,1),
                   emulate(candidate,4,0,op=0x14)))
    result={"candidate":metadata,
            "emulated_offline_cases":checks,
            "no_persistent_BIN_or_ELF_output":True,
            "v323_firmware_flashable":False}
    if a.self_test:
        result["fail_closed_source_mutations"]=reject_fixtures(
            old,known,source,linker,builder,a.builder)
    payload=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(payload)
    print(payload,end="")
if __name__=="__main__":
    main()
