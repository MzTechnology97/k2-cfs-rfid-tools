#!/usr/bin/env python3
"""Offline source-only CFS v3.23 legacy type4 secure-sink second guard.

Stacked strictly on the in-memory type4+Creality candidate. Redirect only
TWO original OEM RFID manager task calls to wrappers that reject secure-
element usage (return failure) when no FM15L013 hardware is present.
On secure CFS the wrappers tail-branch to the EXACT original functions.

Does NOT patch RFID reader backend selection, chip init, motor control,
live MCU firmware, Kalico, UART or SWD. No BIN exported. Concurrency
qualifications and physical validation remain release blockers.
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
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R3,UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE,audited
from cfs_v323_physical_relink_baseline import (
    DELTA,PHYSICAL_HANDLER,physically_relocate_source,assemble,symbol_dict,
)
from cfs_v322_full_branch_edge_audit import (
    patches_from_builder,RELOC_LINE,EXPECTED_EXTERNAL_TARGET_COUNTS,
)
from cfs_v323_physical_full_image_parity import (
    APP_PREFIX,LEN_OFF,CRC_OFF,META_END,PHYSICAL_HEAP_LITERAL,EXPECTED_AFTER_HEAP,
)
from cfs_v323_legacy_type4_live_usage_candidate import (
    build_candidate as original_live_type4_candidate,
    extend_source as live_type4_source,
    INSERT_ANCHOR,OEM_PRELOAD_GATE_SITE,HW_FLAG,EMU_STACK,NEW_GATE_SYMBOL,
)

# Physical, original OEM code PCs in both saved v3.13/v3.22.
OEM_USAGE_DETECT_SITE=0x0800DE68
OEM_USAGE_DETECT_TARGET=0x0800D83E
OEM_USAGE_SECURE_WRITE_SITE=0x0800DEC2
OEM_USAGE_SECURE_WRITE_TARGET=0x08015A42
# Downstream no-record reread is reachable through successful detect.
OEM_USAGE_REREAD_SITE=0x0800DFDA
OEM_USAGE_REREAD_TARGET=0x0800D670
LOADER_POLICY_UNKNOWN=0x0803B800
EMU_RETURN=0x0802F000

DEFENSE_CODE="""@ OEM RFID usage-manager secure-target defense, stage 2:
@ With no FM15L013 chip, don't enter either OEM secure call even
@ if mode/valid/type changed after the outer live gate check.
@ Manufacturer FM15L013 boards use the exact original function tail.
.thumb_func
live_usage_detect_secure_guard:
    ldr     r3, hw_flag_ptr
    ldrb    r3, [r3]
    cmp     r3, #1
    beq     live_usage_detect_stock
    movs    r0, #2             @ nonzero failure, no OEM secure lookup
    bx      lr
live_usage_detect_stock:
    b.w     0x0800D83E

.thumb_func
live_usage_write_secure_guard:
    ldr     r3, hw_flag_ptr
    ldrb    r3, [r3]
    cmp     r3, #1
    beq     live_usage_write_stock
    movs    r0, #2             @ nonzero failure, no OEM secure writer
    bx      lr
live_usage_write_stock:
    b.w     0x08015A42

"""
NEW_HOOKS=[
    (OEM_USAGE_DETECT_SITE,"live_usage_detect_secure_guard",OEM_USAGE_DETECT_TARGET),
    (OEM_USAGE_SECURE_WRITE_SITE,"live_usage_write_secure_guard",OEM_USAGE_SECURE_WRITE_TARGET),
]

def known_oem_callsite_check(v313:bytes,v322:bytes)->None:
    dis=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    src=[
        (OEM_USAGE_DETECT_SITE,OEM_USAGE_DETECT_TARGET),
        (OEM_USAGE_SECURE_WRITE_SITE,OEM_USAGE_SECURE_WRITE_TARGET),
        (OEM_USAGE_REREAD_SITE,OEM_USAGE_REREAD_TARGET),
    ]
    for image in (v313,v322):
        for pc,target in src:
            off=pc-LINK_BASE
            ins=next(dis.disasm(image[off:off+4],pc,count=1),None)
            if ins is None or (ins.mnemonic,ins.op_str)!=("bl",f"#{target:#x}"):
                raise ValueError(f"OEM secure manager branch changed: {pc:#x}")

def compile_defended(v313:bytes,v322:bytes,asm:str,ld:str,builder:str,
                     builder_file:Path)->tuple[bytes,dict,dict[str,int]]:
    original,base_report,old_syms=original_live_type4_candidate(
        v313,v322,asm,ld,builder,builder_file
    )
    known_oem_callsite_check(v313,v322)
    source=live_type4_source(asm)
    if source.count(INSERT_ANCHOR)!=1 or "live_usage_detect_secure_guard:" in source:
        raise ValueError("source anchor or marker changed")
    source=source.replace(INSERT_ANCHOR,DEFENSE_CODE+INSERT_ANCHOR,1)
    physical_asm,linker,refs=physically_relocate_source(source,ld)
    handler,reloc_text,nm=assemble(physical_asm,linker)
    syms=symbol_dict(nm)
    if len(refs)!=13:
        raise ValueError("unexpected original external OEM source references")
    if PHYSICAL_HANDLER+len(handler)>LOADER_POLICY_UNKNOWN:
        raise ValueError("expanded image beyond uncertified historical build limit")
    decoded=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    relocs=RELOC_LINE.findall(reloc_text)
    expected=Counter({pc-DELTA:n for pc,n in EXPECTED_EXTERNAL_TARGET_COUNTS.items()})
    expected[0x080032E2]+=1
    expected[OEM_USAGE_DETECT_TARGET]+=1
    expected[OEM_USAGE_SECURE_WRITE_TARGET]+=1
    actual=[]
    for rel_off,rel_type,target_text,_ in relocs:
        offset=int(rel_off,16);pc=PHYSICAL_HANDLER+offset
        target=int(target_text,16)
        mnemonic="bl" if rel_type=="R_ARM_THM_CALL" else "b.w"
        ins=next(decoded.disasm(handler[offset:offset+4],pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=(mnemonic,f"#{target:#x}"):
            raise ValueError(f"bad relocated OEM call from new guarded handler PC {pc:#x}")
        actual.append(target)
    if Counter(actual)!=expected or len(actual)!=18:
        raise ValueError("original external OEM call census changed in second guard")
    in_hooks=patches_from_builder(builder)
    if len(in_hooks)!=14:
        raise ValueError("unexpected old 14 OEM hook census")
    hook_addrs={}
    for nominal,label in in_hooks:
        hook_addrs[nominal-DELTA]=syms[label]
    hook_addrs[OEM_PRELOAD_GATE_SITE]=syms[NEW_GATE_SYMBOL]
    for pc,symbol,_ in NEW_HOOKS:
        if pc in hook_addrs or symbol not in syms:
            raise ValueError("missing or clashing secure-sink guard hook")
        hook_addrs[pc]=syms[symbol]
    if len(hook_addrs)!=17:
        raise ValueError("new OEM hook census changed")
    image=bytearray(v313[:APP_PREFIX]+handler)
    helpers=runpy.run_path(str(builder_file))
    for pc,target in hook_addrs.items():
        bl=helpers["thumb_bl"](pc,target)
        ins=next(decoded.disasm(bl,pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=("bl",f"#{target:#x}"):
            raise ValueError("hook target mismatch")
        image[pc-LINK_BASE:pc-LINK_BASE+4]=bl
    heapoff=PHYSICAL_HEAP_LITERAL-LINK_BASE
    if struct.unpack_from("<I",image,heapoff)[0]!=0x20006EE8:
        raise ValueError("expected OEM heap source literal missing")
    struct.pack_into("<I",image,heapoff,EXPECTED_AFTER_HEAP)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    image_copy=bytearray(image)
    image_copy[CRC_OFF:META_END]=bytes(META_END-CRC_OFF)
    crc=helpers["crc16_bypass"](image_copy)
    struct.pack_into("<H",image,CRC_OFF,crc)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    if LINK_BASE+len(image)!=PHYSICAL_HANDLER+len(handler):
        raise ValueError("image handler physical end not exact")
    allowed=set(range(CRC_OFF,META_END))
    for pc in hook_addrs:
        allowed.update(range(pc-LINK_BASE,pc-LINK_BASE+4))
    if any(a!=b and i not in allowed for i,(a,b) in enumerate(zip(image[:APP_PREFIX],original[:APP_PREFIX]))):
        raise ValueError("modified prior APP outside original patches and two new callsites")
    report={
        "old_in_memory_type4_APP_bytes":len(original),
        "new_in_memory_type4_guarded_APP_bytes":len(image),
        "added_guard_bytes":len(image)-len(original),
        "new_code_end_exclusive":hex(LINK_BASE+len(image)),
        "last_Flash_page_index":(len(image)+LINK_BASE-1-0x08000000)//2048,
        "first_guard_site":hex(OEM_USAGE_DETECT_SITE),
        "second_guard_site":hex(OEM_USAGE_SECURE_WRITE_SITE),
        "OEM_manager_reread_callsite_unmodified":hex(OEM_USAGE_REREAD_SITE),
        "source_proven_legacy_no_chip_paths_return_nonzero_failure":True,
        "secure_board_tail_calls_original_OEM_addresses":True,
        "old_15_OEM_hooks_preserved":True,
        "total_OEM_inbound_hooks":len(hook_addrs),
        "outgoing_external_OEM_targets":len(actual),
        "candidate_only_crc16":hex(crc),
        "candidate_only_sha256":hashlib.sha256(image).hexdigest(),
        "hardware_chip_gate_dynamic_race_qualified":False,
        "installed_CFS_bootloader_authenticated":False,
        "release_approved":False,
        "no_tag_or_Flash_writes_executed":True,
        "no_output_firmware_file":True,
    }
    return bytes(image),report,syms

def emu_guard(image:bytes,pc:int,hw:int,params:tuple[int,int])->dict:
    m=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    m.mem_map(0x08000000,0x40000)
    m.mem_write(LINK_BASE,image)
    m.mem_map(0x20000000,0x10000)
    m.mem_write(HW_FLAG,bytes([hw]))
    m.reg_write(UC_ARM_REG_SP,EMU_STACK)
    m.reg_write(UC_ARM_REG_LR,EMU_RETURN|1)
    m.reg_write(UC_ARM_REG_R0,params[0])
    m.reg_write(UC_ARM_REG_R1,params[1])
    visits=[]
    unsafe_writes=[]
    def oncode(uc,at,size,user):
        if at in (OEM_USAGE_DETECT_TARGET,OEM_USAGE_SECURE_WRITE_TARGET):
            if uc.reg_read(UC_ARM_REG_R0)!=params[0] or uc.reg_read(UC_ARM_REG_R1)!=params[1]:
                raise ValueError("secure-chip original call ABI argument was clobbered")
            visits.append(at)
            uc.reg_write(UC_ARM_REG_R0,0xAB)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        if at in (0x0800D670,0x0801AA14):
            raise ValueError("unexpected OEM RFID detect/scan path")
    def onwrite(uc,access,addr,size,val,user):
        if not(0x2000E000<=addr and addr+size<=0x20010000):
            unsafe_writes.append((addr,size))
            raise ValueError(f"secure sink wrote OEM/global SRAM {addr:#x}")
    m.hook_add(UC_HOOK_CODE,oncode)
    m.hook_add(UC_HOOK_MEM_WRITE,onwrite)
    m.emu_start(pc|1,EMU_RETURN,count=220)
    expected_return=0xAB if hw==1 else 2
    if m.reg_read(UC_ARM_REG_R0)!=expected_return:
        raise ValueError("secure MCU sink gate result mismatch")
    if (hw==1 and len(visits)!=1) or (hw!=1 and visits):
        raise ValueError("secure-chip OEM original call must only run on FM15L013")
    if unsafe_writes:
        raise ValueError("guard unexpectedly wrote memory")
    return {"hook_entry_pc":hex(pc),"FM15L013_hw_flag":hw,
            "returned":expected_return,
            "original_OEM_secure_sink_called":hw==1,
            "global_or_peripheral_writes":False}

def main():
    a=argparse.ArgumentParser()
    for key in ("v313","v322","asm","linker","builder"):
        a.add_argument("--"+key,required=True,type=Path)
    a.add_argument("--json-out",type=Path)
    opts=a.parse_args()
    old=pinned(opts.v313,"intermediate_v313")
    known=pinned(opts.v322,"running_v322")
    image,metadata,syms=compile_defended(
        old,known,opts.asm.read_text(),opts.linker.read_text(),
        opts.builder.read_text(),opts.builder)
    matrix=[
        emu_guard(image,syms[label],hw,(2,5))
        for label in ("live_usage_detect_secure_guard","live_usage_write_secure_guard")
        for hw in (0,1,2)
    ]
    out={"candidate":metadata,"offline_secure_sink_emulator_cases":matrix,
         "hardware_write_test_performed":False,
         "CI_releasing_flash_image":False}
    report=json.dumps(out,indent=2)+"\n"
    if opts.json_out:opts.json_out.write_text(report)
    print(report,end="")
if __name__=="__main__":main()
