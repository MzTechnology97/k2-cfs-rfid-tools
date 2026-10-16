#!/usr/bin/env python3
"""OFFLINE Creality CFS v3.23 type4 spool-removal lifecycle candidate.

Additional BL at OEM in-use sensor removal event callsite 0x080064A6:
always run unmodified Creality slot-removed notifier (0x08005654).
Only on legacy no-FM15L013 hardware, valid runtime type4 and mode!=PRINT,
run stock runtime clear (0x0800DC70) and set reported percent FF via
stock percent setter (0x080053E4).

A removal while still PRINTING must not erase an active usage record:
its RUNOUT signal (0x50) and host policy are separate, still unpatched.
The original FM15L013 equipped boards and type7 stock paths unchanged.

Builds both previous exact in-memory v3.23 type4+secure sinks and
one new experiment, then verifies original app prefix and an actual
ARM/Thumb execution matrix. No BIN/firmware export; no GPIO/serial/flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
import runpy
import struct

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_R0,UC_ARM_REG_R4,
    UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_SP,
)

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
    extend_source as live_type4_source,
    INSERT_ANCHOR,OEM_PRELOAD_GATE_SITE,NEW_GATE_SYMBOL,
)
from cfs_v323_type4_secure_sink_guards_candidate import (
    compile_defended,DEFENSE_CODE,NEW_HOOKS,
    OEM_USAGE_DETECT_TARGET,OEM_USAGE_SECURE_WRITE_TARGET,
)

OEM_REMOVAL_EVENT_CALLSITE=0x080064A6
OEM_REMOVAL_EVENT_TARGET=0x08005654
OEM_CLEAR_RUNTIME=0x0800DC70
OEM_REPORT_PERCENT=0x080053E4
RAM_HW=0x20000000
RAM_EVENT=0x20000024
RAM_DISPLAY=0x2000391C
RAM_RUNTIME=0x20004590
SLOT_STRIDE=100
RETURN_PC=0x0802F000
EMU_STACK=0x2000F000
NEW_SYMBOL="legacy_type4_spool_removed_wrapper"

WRAPPER_ASM="""@ Stage3 type4 lifecycle: stock OEM event, and ONLY legacy non-print
@ type4 record cleanup. Preserve disabled state for secure boards.
@ The event has already passed OEM filtered sensor transition logic.
.thumb_func
legacy_type4_spool_removed_wrapper:
    push    {r4, lr}
    mov     r4, r0
    bl      0x08005654              @ always preserve OEM removed event
    cmp     r4, #4                 @ four slots only
    bcs     legacy_spool_return
    ldr     r0, hw_flag_ptr
    ldrb    r0, [r0]
    cmp     r0, #0
    bne     legacy_spool_return    @ stock secure board unchanged
    mov     r0, r4
    bl      remaining_runtime_ptr
    ldrb    r1, [r0, #23]          @ record.valid
    cmp     r1, #1
    bne     legacy_spool_return
    ldrb    r1, [r0, #99]          @ volatile record.type4
    cmp     r1, #4
    bne     legacy_spool_return
    ldrb    r1, [r0, #22]          @ record.mode
    cmp     r1, #1
    beq     legacy_spool_return    @ printing/runout deferred to host
    mov     r0, r4
    bl      0x0800DC70              @ original record clear
    mov     r0, r4
    movs    r1, #255
    bl      0x080053E4              @ original percent setter, 0xFF
legacy_spool_return:
    pop     {r4, pc}

"""

def check_original_source(app:bytes)->None:
    d=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    pinned_sites={
        OEM_REMOVAL_EVENT_CALLSITE:("bl","#0x8005654"),
        0x080064AA:("mov","r0, r6"),
        0x080064AC:("bl","#0x80063d4"),
        0x08005654:("push","{r4, lr}"),
        0x0800565E:("strb","r0, [r1, r4]"),
        0x08005664:("strb","r0, [r1, r4]"),
        0x0800DC70:("cmp","r0, #4"),
        0x0800DC88:("strb","r1, [r0, #0x17]"),
        0x0800DC8C:("strb","r1, [r0, #0x15]"),
        0x0800DC8E:("strb","r1, [r0, #0x16]"),
        0x080053E4:("cbnz","r1, #0x80053e8"),
        0x080053EC:("strb.w","r1, [r0, #0x58]"),
    }
    for pc,expect in pinned_sites.items():
        off=pc-LINK_BASE
        got=next(d.disasm(app[off:off+4],pc,count=1),None)
        if got is None or (got.mnemonic,got.op_str)!=expect:
            raise ValueError(f"OEM removal source changed at {pc:#x}: {got} expected {expect}")

def compiled(v313:bytes,v322:bytes,asm:str,ld:str,builder:str,builder_file:Path)->tuple[bytes,bytes,dict,dict[str,int]]:
    audited(v313);audited(v322)
    check_original_source(v313);check_original_source(v322)
    parent,parent_meta,old_symbols=compile_defended(
        v313,v322,asm,ld,builder,builder_file
    )
    src=live_type4_source(asm)
    if src.count(INSERT_ANCHOR)!=1:
        raise ValueError("unexpected source anchor")
    src=src.replace(INSERT_ANCHOR,DEFENSE_CODE+WRAPPER_ASM+INSERT_ANCHOR,1)
    physical,linker,refs=physically_relocate_source(src,ld)
    handler,relocs,nm=assemble(physical,linker)
    syms=symbol_dict(nm)
    if len(refs)!=13 or NEW_SYMBOL not in syms:
        raise ValueError("OEM original source/candidate wrapper not found")
    expected=Counter({x-DELTA:n for x,n in EXPECTED_EXTERNAL_TARGET_COUNTS.items()})
    expected[0x080032E2]+=1
    expected[OEM_USAGE_DETECT_TARGET]+=1
    expected[OEM_USAGE_SECURE_WRITE_TARGET]+=1
    for target in (OEM_REMOVAL_EVENT_TARGET,OEM_CLEAR_RUNTIME,OEM_REPORT_PERCENT):
        expected[target]+=1
    d=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    actual=[]
    for pos,kind,target_text,_ in RELOC_LINE.findall(relocs):
        off=int(pos,16);pc=PHYSICAL_HANDLER+off;dst=int(target_text,16)
        mnemonic="bl" if kind=="R_ARM_THM_CALL" else "b.w"
        ins=next(d.disasm(handler[off:off+4],pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=(mnemonic,f"#{dst:#x}"):
            raise ValueError(f"bad relocated OEM edge {pc:#x} -> {dst:#x}")
        actual.append(dst)
    if Counter(actual)!=expected or len(actual)!=21:
        raise ValueError("expected original 18 external OEM edges plus three removal helpers")
    sites={}
    for nominal,label in patches_from_builder(builder):
        sites[nominal-DELTA]=syms[label]
    if len(sites)!=14:
        raise ValueError("v3.22 original 14 hook ABI changed")
    sites[OEM_PRELOAD_GATE_SITE]=syms[NEW_GATE_SYMBOL]
    for pc,name,_ in NEW_HOOKS:
        sites[pc]=syms[name]
    sites[OEM_REMOVAL_EVENT_CALLSITE]=syms[NEW_SYMBOL]
    if len(sites)!=18:
        raise ValueError("expected 14 original hooks, one live gate, two sink guards and one new removal hook")
    helpers=runpy.run_path(str(builder_file))
    image=bytearray(v313[:APP_PREFIX]+handler)
    for pc,target in sites.items():
        op=helpers["thumb_bl"](pc,target)
        ins=next(d.disasm(op,pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=("bl",f"#{target:#x}"):
            raise ValueError("hook Thumb BL invalid")
        image[pc-LINK_BASE:pc-LINK_BASE+4]=op
    heap_off=PHYSICAL_HEAP_LITERAL-LINK_BASE
    if struct.unpack_from("<I",image,heap_off)[0]!=0x20006EE8:
        raise ValueError("underlying OEM heap pointer changed")
    struct.pack_into("<I",image,heap_off,EXPECTED_AFTER_HEAP)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    raw=bytearray(image);raw[CRC_OFF:META_END]=b"\0"*(META_END-CRC_OFF)
    crc=helpers["crc16_bypass"](raw)
    struct.pack_into("<H",image,CRC_OFF,crc)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    if LINK_BASE+len(image)!=PHYSICAL_HANDLER+len(handler):
        raise ValueError("physical APP handler end mismatch")
    allow=set(range(CRC_OFF,META_END))
    for pc in sites:allow.update(range(pc-LINK_BASE,pc-LINK_BASE+4))
    for i,(a,b) in enumerate(zip(parent[:APP_PREFIX],image[:APP_PREFIX])):
        if a!=b and i not in allow:
            raise ValueError(f"OEM ROM unexpectedly mutated outside new hook, header {i:#x}")
    parent_deltas=[i for i,(a,b) in enumerate(zip(parent[:APP_PREFIX],image[:APP_PREFIX])) if a!=b and i not in set(range(CRC_OFF,META_END))]
    if not parent_deltas or not set(parent_deltas).issubset(allow):
        raise ValueError("OEM patches outside 18 known inbound hook sites")
    if not any(i in range(OEM_REMOVAL_EVENT_CALLSITE-LINK_BASE,OEM_REMOVAL_EVENT_CALLSITE-LINK_BASE+4) for i in parent_deltas):
        raise ValueError("new slot removal hook was not installed")
    return parent,bytes(image),{
        "previous_TYPE4_candidate_bytes":len(parent),
        "new_spool_lifecycle_candidate_bytes":len(image),
        "extra_bytes":len(image)-len(parent),
        "image_end_exclusive":hex(LINK_BASE+len(image)),
        "last_flash_page":(LINK_BASE+len(image)-1-0x08000000)//0x800,
        "new_OEM_hook_site":hex(OEM_REMOVAL_EVENT_CALLSITE),
        "new_wrapper_entry":hex(syms[NEW_SYMBOL]),
        "total_incoming_hooks":len(sites),
        "total_outgoing_OEM_edges":len(actual),
        "no_other_OEM_prefix_changes":True,
        "reserved_param_page_start":hex(0x0807F800),
        "no_RFID_reader_or_motor_or_secure_backend_change":True,
        "no_flash_authorization":True,
        "sha256_unflashed_transient_image":hashlib.sha256(image).hexdigest(),
        "crc16_unflashed_transient_image":hex(crc),
    },syms

def emulate_removal(image:bytes,entry:int,*,slot:int,hw:int,typ:int,mode:int,
                    valid:int,percent:int=62,expect_clear:bool|None=None,
                    at_original_OEM_callsite:bool=True)->dict:
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    cpu.mem_map(0x08000000,0x40000);cpu.mem_write(LINK_BASE,image)
    cpu.mem_map(0x20000000,0x10000)
    cpu.reg_write(UC_ARM_REG_SP,EMU_STACK);cpu.reg_write(UC_ARM_REG_LR,RETURN_PC|1)
    cpu.reg_write(UC_ARM_REG_R0,slot)
    cpu.reg_write(UC_ARM_REG_R4,0xCAFEBABE)
    cpu.reg_write(UC_ARM_REG_R5,0xACACACAC)
    cpu.reg_write(UC_ARM_REG_R6,slot if at_original_OEM_callsite else 0xABABABAB)
    cpu.mem_write(RAM_HW,bytes([hw]))
    cpu.mem_write(RAM_DISPLAY+0x58+min(slot,3),bytes([percent]))
    p=RAM_RUNTIME+SLOT_STRIDE*min(slot,3)
    cpu.mem_write(p+23,bytes([valid]))
    cpu.mem_write(p+22,bytes([mode]))
    cpu.mem_write(p+99,bytes([typ]))
    cpu.mem_write(p+21,b"\x01")
    cpu.mem_write(p,struct.pack("<I",25400))
    calls=[]
    def oncode(uc,pc,size,user):
        if pc==0x08020074:
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        if pc in (0x0800D83E,0x08015A42,0x0800D670,0x0800DC94):
            raise ValueError("removal wrapper unexpectedly called secure or usage task")
        if pc in (OEM_REMOVAL_EVENT_TARGET,OEM_CLEAR_RUNTIME,OEM_REPORT_PERCENT):
            calls.append(pc)
    def onwrite(uc,access,address,size,value,user):
        if not (0x20000000<=address and address+size<=0x20010000):
            raise ValueError("unexpected OEM SRAM address")
    cpu.hook_add(UC_HOOK_CODE,oncode)
    cpu.hook_add(UC_HOOK_MEM_WRITE,onwrite)
    # Execute original caller's mov r0,r6 + physical BL at 0x080064A6
    # rather than only calling the wrapper directly.
    start=0x080064A4 if at_original_OEM_callsite else entry
    stop=0x080064AA if at_original_OEM_callsite else RETURN_PC
    cpu.emu_start(start|1,stop,count=500)
    if cpu.reg_read(UC_ARM_REG_PC)!=stop:
        raise ValueError("original OEM callsite did not return to its correct next instruction")
    event=bytes(cpu.mem_read(RAM_EVENT+8+slot,1))[0] if slot<4 else -1
    active=bytes(cpu.mem_read(p+23,1))[0]
    got_percent=bytes(cpu.mem_read(RAM_DISPLAY+0x58+min(slot,3),1))[0]
    clear=bool(hw==0 and slot<4 and typ==4 and valid==1 and mode!=1) if expect_clear is None else expect_clear
    exp_calls=[OEM_REMOVAL_EVENT_TARGET]+([OEM_CLEAR_RUNTIME,OEM_REPORT_PERCENT] if clear else [])
    if calls!=exp_calls:
        raise ValueError(f"slot-remove event/clear sequence changed: {slot,hw,typ,mode,valid}: {calls}")
    if slot<4:
        if event!=2 or bytes(cpu.mem_read(RAM_EVENT+4+slot,1))[0]!=0:
            raise ValueError("stock OEM slot-removed event no longer present")
    if active!=(0 if clear else valid) or got_percent!=(255 if clear else percent):
        raise ValueError("type4 record/percent unexpected after OEM sensor event")
    if cpu.reg_read(UC_ARM_REG_R4)!=0xCAFEBABE or cpu.reg_read(UC_ARM_REG_R5)!=0xACACACAC or cpu.reg_read(UC_ARM_REG_R6)!=(slot if at_original_OEM_callsite else 0xABABABAB):
        raise ValueError("slot removal wrapper clobbered callee-save registers")
    return {
        "slot":slot,"FM15L013_flag":hw,"type":typ,"mode":mode,"valid":valid,
        "OEM_remove_notifier_invoked":True,
        "OEM_clear_called":clear,
        "OEM_percent_set_to_0xFF":clear,
        "post_event":event,
        "post_record_valid":active,
        "post_report_percent":got_percent,
        "actual_manufacturer_calls":[hex(x) for x in calls],
    }

def run_tests(parent:bytes,child:bytes,syms:dict[str,int])->dict:
    # Child is tested under many configurations: four physical slots,
    # valid/invalid, legacy/secure, print/idle/unload, type4/type7.
    cases=[]
    for slot in range(4):
        for hw,typ,mode,valid in (
            (0,4,0,1),(0,4,2,1),(0,4,1,1),
            (0,4,0,0),(0,7,0,1),(1,4,0,1),
            (1,7,1,1),(2,4,0,1),
        ):
            cases.append(emulate_removal(child,syms[NEW_SYMBOL],slot=slot,hw=hw,typ=typ,mode=mode,valid=valid))
    if len(cases)!=32:raise ValueError("slot removal matrix unexpectedly changed")
    # Revert the only newly hooked original incoming BL and execute
    # the same original OEM instruction at 0x080064A6. This must lose
    # type4 cleanup while still firing the original removed event.
    off=OEM_REMOVAL_EVENT_CALLSITE-LINK_BASE
    if parent[off:off+4]==child[off:off+4]:
        raise ValueError("new stage3 OEM hook was not installed")
    m=bytearray(child)
    m[off:off+4]=parent[off:off+4]
    previous=emulate_removal(bytes(m),syms[NEW_SYMBOL],slot=2,hw=0,typ=4,mode=0,valid=1,expect_clear=False)
    intact=emulate_removal(child,syms[NEW_SYMBOL],slot=2,hw=0,typ=4,mode=0,valid=1)
    if (previous["post_record_valid"],previous["post_report_percent"])!=(1,62):
        raise ValueError("removed original hook did not reproduce stale record")
    if (intact["post_record_valid"],intact["post_report_percent"])!=(0,255):
        raise ValueError("intact hook does not clear obsolete record")
    return {"test_cases":cases,
            "old_unpatched_removal_leaves_stale_record":True,
            "one_new_OEM_callsite_mutant_detected":True}

def main()->None:
    p=argparse.ArgumentParser()
    for key in ("v313","v322","asm","linker","builder"):
        p.add_argument("--"+key,required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    v313=pinned(a.v313,"intermediate_v313")
    v322=pinned(a.v322,"running_v322")
    parent,child,metadata,syms=compiled(v313,v322,a.asm.read_text(),a.linker.read_text(),a.builder.read_text(),a.builder)
    tested=run_tests(parent,child,syms)
    result={
        "candidate":metadata,**tested,
        "runout_during_print_handled_in_host_not_automatically_cleared":True,
        "spool_removal_uses_original_sensor_filter_and_OEM_notifier":True,
        "does_not_prove_inlet_absence_is_spool_runout":True,
        "does_not_prove_RTOS_interrupt_atomicity":True,
        "CFS_hardware_io":False,"flash_approved":False,
        "firmware_BIN_exported":False,
    }
    j=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(j)
    print(j,end="")
if __name__=="__main__":main()
