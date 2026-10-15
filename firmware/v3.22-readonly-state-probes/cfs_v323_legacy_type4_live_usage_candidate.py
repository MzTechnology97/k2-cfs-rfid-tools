#!/usr/bin/env python3
"""OFFLINE proof-of-concept for CFS v3.23 legacy type-4 LIVE consumption.

For already-initialized type-4 remaining-runtime records only, permit the
stock OEM usage-accounting task from the original preload task call site
0x08006684 while the current slot is in mode=PRINT and record validates.

The legacy no-record, type-7, idle/unload, or corrupted-record paths FAIL
CLOSED. On a secure-element board preserve the existing OEM hardware gate.
No RFID tag writes, hardware enable, motor command, firmware BIN or flash.
Uses original physical APP base and exact SHA-pinned v3.13/v3.22 inputs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4,
    UC_ARM_REG_R8,UC_ARM_REG_R9, UC_ARM_REG_SP,
)

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE,audited
from cfs_v322_full_branch_edge_audit import patches_from_builder,RELOC_LINE,EXPECTED_EXTERNAL_TARGET_COUNTS
from cfs_v323_physical_relink_baseline import (
    DELTA,PHYSICAL_HANDLER,physically_relocate_source,assemble,symbol_dict,
)
from cfs_v323_physical_full_image_parity import (
    APP_PREFIX,CRC_OFF,LEN_OFF,META_END,PHYSICAL_HEAP_LITERAL,
    EXPECTED_AFTER_HEAP,
)
from cfs_v323_readonly_snapshot_candidate import (
    compile_candidate as known_snapshot_candidate,extend as snapshot_source,
)

STOCK_GATE_PC=0x080032E2
STOCK_TASK_PC=0x0800DC94
OEM_PRELOAD_GATE_SITE=0x08006684
OEM_PRELOAD_GATE_SUCCESS_BRANCH=0x0800668C
OEM_PRELOAD_NEXT_COMPARE=0x08006688
APP_END_MAX_POLICY_UNAUTHENTICATED=0x0803B800
NEW_GATE_SYMBOL="live_type4_usage_gate"
INSERT_ANCHOR="@ v3.14 runtime-parameter wrappers for stock hardcoded callsites."

# These are anchored stock v3.22 wrapper sections; every other existing
# source byte is preserved. The original Creality caller uses SB==R9
# to indicate that an original manufacturer tag was decoded.
LEGACY_GATE_ORIGINAL="""    bl      STOCK_REMAIN_GATE
    cmp     r0, #1
    beq     remain_gate_return

    mov     r0, r8                  @ RFID manager logical slot
    cmp     r0, #4
    bcs     remain_gate_zero
    bl      thirdparty_ready_slot
    cbz     r0, remain_gate_zero

    movs    r0, #1
    pop     {r4, pc}
"""
LEGACY_GATE_NEW="""    bl      STOCK_REMAIN_GATE
    cmp     r0, #1
    beq     remain_gate_return
    cmp     r0, #0
    bne     remain_gate_zero

    mov     r0, r8                  @ existing OEM RFID slot
    cmp     r0, #4
    bcs     remain_gate_zero
    bl      thirdparty_ready_slot
    cbnz    r0, remain_gate_ready

    @ Original caller at 0x08006388 tests SB (r9) as tag-read valid.
    cmp     r9, #0
    beq     remain_gate_zero
remain_gate_ready:
    movs    r0, #1
    pop     {r4, pc}
"""
LEGACY_INIT_ORIGINAL="""remain_init_stock:
    mov     r0, r4
    mov     r1, r5
    bl      STOCK_REMAIN_INIT
    pop     {r4-r7, pc}
"""
LEGACY_INIT_NEW="""remain_init_stock:
    mov     r0, r4
    mov     r1, r5
    bl      STOCK_REMAIN_INIT

    @ Preserve the stock Creality tag length measurement; only on
    @ legacy hardware and non-null manufacturer tag (r9), convert
    @ a successfully initialized runtime from secure type 7 to
    @ volatile type 4. No RFID tag or FM15L013 writes.
    ldr     r0, hw_flag_ptr
    ldrb    r0, [r0]
    cmp     r0, #0
    bne     remain_init_stock_exit
    cmp     r9, #0
    beq     remain_init_stock_exit
    mov     r0, r4
    bl      remaining_runtime_ptr
    ldrb    r1, [r0, #23]
    cmp     r1, #1
    bne     remain_init_stock_exit
    ldr     r1, [r0, #4]
    movw    r2, #10000
    cmp     r1, r2
    blo     remain_init_stock_exit
    ldrb    r1, [r0, #20]
    cmp     r1, #1
    blo     remain_init_stock_exit
    cmp     r1, #100
    bhi     remain_init_stock_exit
    movs    r1, #4
    strb    r1, [r0, #99]
remain_init_stock_exit:
    pop     {r4-r7, pc}
"""

EXPECTED_TOTAL=330000
# These records are the original OEM RAM layout, NOT newly allocated globals.
SLOT_ROOT=0x200001F0
REMAIN_RUNTIME=0x20004590
HW_FLAG=0x20000000
SLOT_STRIDE=100
EMU_STACK=0x2000F000
EMU_RETURN=0x0802F000
EXPECTED_HANDLER_BYTES=2648  # set by source-length ABI check, verify offline
EXPECTED_FULL_APP_BYTES=APP_PREFIX+EXPECTED_HANDLER_BYTES

NEW_CODE="""@ 3.23 trial: run OEM used-mm accounting on legacy type4 current slot
@ only with a valid, well-formed printing record. Secure hardware stays stock.
@ Entry ABI same as original STOCK_REMAIN_GATE (r0 answer).
@ No motor / RFID writer / peripheral register call from this guard.
.thumb_func
live_type4_usage_gate:
    push    {r4, lr}
    bl      STOCK_REMAIN_GATE
    cmp     r0, #1
    beq     live_type4_return
    cmp     r0, #0
    bne     live_type4_return
    ldr     r0, state_base
    ldrb    r0, [r0, #2]
    cmp     r0, #4
    bcs     live_type4_no
    bl      remaining_runtime_ptr
    ldrb    r1, [r0, #23]        @ valid
    cmp     r1, #1
    bne     live_type4_no
    ldrb    r1, [r0, #22]        @ mode 1 PRINT only
    cmp     r1, #1
    bne     live_type4_no
    ldrb    r1, [r0, #99]        @ runtime type 4 only
    cmp     r1, #4
    bne     live_type4_no
    ldr     r1, [r0, #4]         @ total_mm
    movw    r2, #10000
    cmp     r1, r2
    blo     live_type4_no
    ldrb    r1, [r0, #20]        @ measured starting percent
    cmp     r1, #1
    blo     live_type4_no
    cmp     r1, #100
    bhi     live_type4_no
    movs    r0, #1
    pop     {r4, pc}
live_type4_no:
    movs    r0, #0
live_type4_return:
    pop     {r4, pc}

"""

def extend_source(asm:str)->str:
    base=snapshot_source(asm)
    if base.count(INSERT_ANCHOR)!=1 or NEW_GATE_SYMBOL+":" in base:
        raise ValueError("unreviewed original v3.22 asm or duplicate legacy gate")
    if base.count(LEGACY_GATE_ORIGINAL)!=1 or base.count(LEGACY_INIT_ORIGINAL)!=1:
        raise ValueError("manufacturer wrapper anchoring failed")
    base=base.replace(LEGACY_GATE_ORIGINAL,LEGACY_GATE_NEW,1)
    base=base.replace(LEGACY_INIT_ORIGINAL,LEGACY_INIT_NEW,1)
    return base.replace(INSERT_ANCHOR,NEW_CODE+INSERT_ANCHOR,1)

def verify_oem_gate_source(v313:bytes,v322:bytes)->dict:
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    expected={
        OEM_PRELOAD_GATE_SITE:("bl","#0x80032e2"),
        OEM_PRELOAD_NEXT_COMPARE:("cmp","r0, #1"),
        0x0800668A:("bne","#0x800667a"),
        OEM_PRELOAD_GATE_SUCCESS_BRANCH:("bl","#0x800dc94"),
        STOCK_GATE_PC:("ldr","r0, [pc, #0x170]"),
        0x080032E4:("ldrb","r0, [r0]"),
        0x080032E6:("bx","lr"),
        0x08006384:("cmp","r0, #1"),
        0x08006388:("cmp.w","sb, #0"),
        0x0800638C:("bne","#0x8006390"),
        0x08006390:("mov","r1, r4"),
        0x08006392:("mov","r0, r8"),
        0x08006398:("b","#0x80063a8"),
    }
    # The two CALL SITES already point into our own v3.13/v3.22
    # handler overlays; we must retain those inbound hook mappings.
    existing_wrappers={
        0x08006380:(0x0802E434,0x0802E59A),
        0x08006394:(0x0802E45C,0x0802E5C2),
    }
    for index,app in enumerate((v313,v322)):
        for pc,(before,after) in existing_wrappers.items():
            expected_hook=("bl",f"#{(before,after)[index]:#x}")
            got=next(dec.disasm(app[pc-LINK_BASE:pc-LINK_BASE+4],pc,count=1),None)
            if got is None or (got.mnemonic,got.op_str)!=expected_hook:
                raise ValueError("saved preceding firmware estimate-hook ABI changed")
    for app in (v313,v322):
        for pc,pair in expected.items():
            off=pc-LINK_BASE
            got=next(dec.disasm(app[off:off+4],pc,count=1),None)
            if got is None or (got.mnemonic,got.op_str)!=pair:
                raise ValueError(f"original OEM usage gate opcode mismatch at {pc:#x}")
    return {"original_OEM_precise_instruction_sites":len(expected),
            "two_saved_estimation_hook_targets_pinned":True,
            "one_existing_preload_gate_call_replaced_not_all_secure_gates":True}

def build_candidate(v313:bytes,v322:bytes,asm:str,linker:str,
                    builder_source:str,builder_file:Path)->tuple[bytes,dict,dict[str,int]]:
    audited(v313);audited(v322)
    baseline,bmeta=known_snapshot_candidate(
        v313,v322,asm,linker,builder_source,builder_file
    )
    if not bmeta["new_op"]=="0x15" or len(baseline)!=178176:
        raise ValueError("validated read-only v3.23 predecessor changed")
    verified=verify_oem_gate_source(v313,v322)
    new_asm,new_linker,refs=physically_relocate_source(
        extend_source(asm),linker
    )
    handler,relocs,nm=assemble(new_asm,new_linker)
    syms=symbol_dict(nm)
    if len(handler)!=EXPECTED_HANDLER_BYTES:
        raise ValueError(f"type4 handler unexpected size {len(handler)}")
    if len(refs)!=13:
        raise ValueError("changed original manufacturer symbol inventory")
    end=PHYSICAL_HANDLER+len(handler)
    if end>APP_END_MAX_POLICY_UNAUTHENTICATED:
        raise ValueError("outside conservative, unauthenticated prior image policy")
    decoded=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    reloc=RELOC_LINE.findall(relocs)
    expected_targets=Counter({k-DELTA:v for k,v in EXPECTED_EXTERNAL_TARGET_COUNTS.items()})
    expected_targets[STOCK_GATE_PC]+=1
    decoded_targets=[]
    for off_str,kind,dst_str,_ in reloc:
        off=int(off_str,16);pc=PHYSICAL_HANDLER+off;dst=int(dst_str,16)
        expect_mnemonic="bl" if kind=="R_ARM_THM_CALL" else "b.w"
        ins=next(decoded.disasm(handler[off:off+4],pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=(expect_mnemonic,f"#{dst:#x}"):
            raise ValueError("bad modified handler external call source")
        decoded_targets.append(dst)
    if Counter(decoded_targets)!=expected_targets or len(decoded_targets)!=16:
        raise ValueError("original 15 outward OEM calls not preserved with one gate BL")
    hooks=patches_from_builder(builder_source)
    if len(hooks)!=14 or OEM_PRELOAD_GATE_SITE in [x for x,_ in hooks]:
        raise ValueError("unexpected upstream OEM patch-list change")
    helpers=runpy.run_path(str(builder_file))
    image=bytearray(v313[:APP_PREFIX]+handler)
    hook_sites={}
    for old_nominal,label in hooks:
        pc=old_nominal-DELTA
        addr=syms.get(label)
        if addr is None:raise ValueError("missing legacy wrapper in new physical build")
        hook_sites[pc]=addr
    if NEW_GATE_SYMBOL not in syms:
        raise ValueError("live gate entry missing")
    hook_sites[OEM_PRELOAD_GATE_SITE]=syms[NEW_GATE_SYMBOL]
    for pc,target in hook_sites.items():
        off=pc-LINK_BASE
        patch=helpers["thumb_bl"](pc,target)
        decoded_patch=next(decoded.disasm(patch,pc,count=1),None)
        if decoded_patch is None or (decoded_patch.mnemonic,decoded_patch.op_str)!=("bl",f"#{target:#x}"):
            raise ValueError("OEM inbound source callsite BL relocation mismatch")
        image[off:off+4]=patch
    heap_off=PHYSICAL_HEAP_LITERAL-LINK_BASE
    if struct.unpack_from("<I",image,heap_off)[0]!=0x20006EE8:
        raise ValueError("original sidecar heap literal changed")
    struct.pack_into("<I",image,heap_off,EXPECTED_AFTER_HEAP)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    temporary=bytearray(image)
    temporary[CRC_OFF:META_END]=b"\0"*(META_END-CRC_OFF)
    crc=helpers["crc16_bypass"](temporary)
    struct.pack_into("<H",image,CRC_OFF,crc)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    if len(image)!=EXPECTED_FULL_APP_BYTES or end != LINK_BASE+len(image):
        raise ValueError("candidate length or physical assembly end mismatch")
    allowed=set(range(CRC_OFF,META_END))
    for pc in hook_sites:
        allowed.update(range(pc-LINK_BASE,pc-LINK_BASE+4))
    if any(a!=b and i not in allowed for i,(a,b) in enumerate(zip(image[:APP_PREFIX],baseline[:APP_PREFIX]))):
        raise ValueError("OEM source modified outside 15 hook sites and image metadata")
    if struct.unpack_from("<I",image,heap_off)[0]!=EXPECTED_AFTER_HEAP:
        raise ValueError("known sidecar heap origin not preserved")
    report={
        "physical_APP_base":hex(LINK_BASE),
        "snapshot_v323_parent_bytes":len(baseline),
        "legacy_type4_candidate_APP_bytes":len(image),
        "prototype_readonly_snapshot_op_still_present":True,
        "snapshot_parent_gate_added_bytes":len(image)-len(baseline),
        "legacy_new_OEM_callsite":hex(OEM_PRELOAD_GATE_SITE),
        "old_14_incoming_OEM_hardware_hooks_preserved":True,
        "new_total_incoming_OEM_hook_count":len(hook_sites),
        "15_original_outgoing_OEM_calls_plus_one_stock_gate":len(decoded_targets),
        "new_live_type4_gate_pc":hex(syms[NEW_GATE_SYMBOL]),
        "bootloader_page_last_occupied":(end-1-0x08000000)//2048,
        "image_end_exclusive":hex(end),
        "reserved_last_512KiB_parameter_page":hex(0x0807F800),
        "no_new_secure_element_or_tag_writer_calls":True,
        "no_new_nonstack_SRAM_allocation":True,
        "preserves_original_secure_board_logic":True,
        "only_legacy_Creality_stock_runtime_converted_to_type4":True,
        "secure_board_type7_runtime_retained":True,
        "no_flash_authorization":True,
        "sha256_for_OFFLINE_DO_NOT_FLASH":hashlib.sha256(image).hexdigest(),
        "crc16_for_OFFLINE_DO_NOT_FLASH":hex(crc),
        **verified,
    }
    return bytes(image),report,syms

def emulate_gate(image:bytes,entry:int,hw:int,slot:int,valid:int,mode:int,
                 tag_type:int,total:int,percent:int,dirty:int)->dict:
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    cpu.mem_map(0x08000000,0x40000)
    cpu.mem_write(LINK_BASE,image)
    cpu.mem_map(0x20000000,0x10000)
    cpu.mem_write(HW_FLAG,bytes([hw]))
    cpu.mem_write(SLOT_ROOT+2,bytes([slot]))
    for logical_slot in range(4):
        ptr=REMAIN_RUNTIME+SLOT_STRIDE*logical_slot
        cpu.mem_write(ptr+23,bytes([valid]))
        cpu.mem_write(ptr+22,bytes([mode]))
        cpu.mem_write(ptr+99,bytes([tag_type]))
        cpu.mem_write(ptr+21,bytes([dirty]))
        cpu.mem_write(ptr+20,bytes([percent]))
        cpu.mem_write(ptr+4,struct.pack("<I",total))
    cpu.reg_write(UC_ARM_REG_SP,EMU_STACK)
    cpu.reg_write(UC_ARM_REG_LR,EMU_RETURN|1)
    cpu.reg_write(UC_ARM_REG_R4,0xCAFECAFE)
    wrote=[]
    dispatched=[]
    def oncode(uc,pc,size,user):
        if pc in (STOCK_TASK_PC,0x08015A42,0x0800D83E):
            raise ValueError("guard unexpectedly invoked secure writer / original usage task")
        if pc==STOCK_GATE_PC:
            dispatched.append("OEM_HW_FLAG_READ")
    def onwrite(uc,access,addr,size,value,user):
        if not(0x2000E000 <= addr and addr+size<=0x20010000):
            raise ValueError(f"type4 gate unexpectedly wrote global SRAM {addr:#x}")
        wrote.append(addr)
    cpu.hook_add(UC_HOOK_CODE,oncode)
    cpu.hook_add(UC_HOOK_MEM_WRITE,onwrite)
    cpu.emu_start(entry|1,EMU_RETURN,count=550)
    returned=cpu.reg_read(UC_ARM_REG_R0)
    if cpu.reg_read(UC_ARM_REG_R4)!=0xCAFECAFE:
        raise ValueError("new MCU gate clobbers callee-saved R4")
    expected=hw if hw!=0 else int(
        slot<4 and valid==1 and mode==1 and tag_type==4
        and total>=10000 and 1<=percent<=100
    )
    if returned!=expected:
        raise ValueError(f"unexpected live type4 gate return {returned} != {expected} for {(hw,slot,valid,mode,tag_type,total,percent)}")
    if dispatched!=["OEM_HW_FLAG_READ"]:
        raise ValueError("gate did not honor OEM hardware-read branch")
    return {
        "hw_flag":hw,"selected_slot":slot,"valid":valid,
        "mode":mode,"tag_type":tag_type,"nominal_mm":total,
        "initial_percent":percent,"dirty":dirty,
        "gate_result":returned,"global_SRAM_writes":0,
        "secure_element_calls":0,
    }

def run_matrix(image:bytes,entry:int)->list[dict]:
    inputs=[
        (0,0,1,1,4,EXPECTED_TOTAL,62,0),
        (0,2,1,1,4,EXPECTED_TOTAL,35,1),
        (0,3,1,1,4,EXPECTED_TOTAL,100,1),
        (0,0,0,1,4,EXPECTED_TOTAL,62,1),
        (0,0,1,0,4,EXPECTED_TOTAL,62,1),
        (0,0,1,2,4,EXPECTED_TOTAL,62,1),
        (0,0,1,1,7,EXPECTED_TOTAL,62,1),
        (0,0,1,1,3,EXPECTED_TOTAL,62,1),
        (0,4,1,1,4,EXPECTED_TOTAL,62,1),
        (0,255,1,1,4,EXPECTED_TOTAL,62,1),
        (0,0,1,1,4,0,62,1),
        (0,0,1,1,4,9999,62,1),
        (0,0,1,1,4,EXPECTED_TOTAL,0,1),
        (0,0,1,1,4,EXPECTED_TOTAL,101,1),
        (1,0,0,2,7,0,0,1),
        (1,255,0,0,7,0,0,1),
        (2,0,1,1,4,EXPECTED_TOTAL,60,1),
    ]
    return [emulate_gate(image,entry,*row) for row in inputs]

def emulate_existing_estimation_wrappers(image:bytes,syms:dict[str,int])->list[dict]:
    """Execute old wrapper entry ABIs with a synthetic STOCK_REMAIN_INIT.

    The synthetic STOCK_INIT stands in for the OEM tag's valid total-mm
    extraction: we only test that the wrapper calls it and converts
    the runtime type *after* stock init, and never writes tag/SRAM globals
    other than the slot runtime. No live OEM RFID callback executes.
    """
    gate_cases=[
        # hw, slot, r9 tag-read flag, expected gate
        (0,0,1,1),(0,2,1,1),(0,0,0,0),(0,4,1,0),
        (1,0,0,1),(1,0,1,1),(2,0,1,0),
    ]
    init_cases=[
        # hw, r9, valid, total, pct, expected runtime type
        (0,1,1,270000,78,4), (0,1,1,145000,49,4),
        (0,1,1,0,60,7),(0,1,1,9999,60,7),
        (0,1,0,270000,60,7),(0,1,1,270000,0,7),
        (0,1,1,270000,101,7),(0,0,1,270000,78,7),
        (1,1,1,270000,78,7), (2,1,1,270000,78,7),
    ]
    out=[]
    for typ,cases in (("gate",gate_cases),("stock_creality_init",init_cases)):
        for cfg in cases:
            cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
            cpu.mem_map(0x08000000,0x40000)
            cpu.mem_write(LINK_BASE,image)
            cpu.mem_map(0x20000000,0x10000)
            cpu.mem_write(HW_FLAG,bytes([cfg[0]]))
            cpu.mem_write(SLOT_ROOT+2,bytes([cfg[1] if typ=="gate" else 0]))
            cpu.reg_write(UC_ARM_REG_SP,EMU_STACK)
            cpu.reg_write(UC_ARM_REG_LR,EMU_RETURN|1)
            cpu.reg_write(UC_ARM_REG_R8,cfg[1] if typ=="gate" else 0)
            cpu.reg_write(UC_ARM_REG_R9,cfg[2] if typ=="gate" else cfg[1])
            cpu.reg_write(UC_ARM_REG_R4,0xCAFEBABE)
            source_calls=[]
            def oncode(uc,pc,size,user):
                if pc in (0x08015A42,0x0800D83E,STOCK_TASK_PC):
                    raise ValueError(f"unsafe usage detection/tag path entered {pc:#x}")
                if pc==0x0800DA14:  # sole stub of OEM stock remaining-init
                    source_calls.append("STOCK_INIT")
                    if typ!="stock_creality_init":
                        raise ValueError("stock init unexpectedly called during gate")
                    _,tag_read,valid,total,pct,expect=cfg
                    ptr=REMAIN_RUNTIME
                    uc.mem_write(ptr+23,bytes([valid]))
                    uc.mem_write(ptr+99,b"\x07")
                    uc.mem_write(ptr+4,struct.pack("<I",total))
                    uc.mem_write(ptr+20,bytes([pct]))
                    uc.reg_write(UC_ARM_REG_R0,0)
                    uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            cpu.hook_add(UC_HOOK_CODE,oncode)
            if typ=="gate":
                entry=syms["remaining_gate_wrapper"]
            else:
                entry=syms["remaining_init_wrapper"]
                cpu.reg_write(UC_ARM_REG_R0,0)
                cpu.reg_write(UC_ARM_REG_R1,cfg[4])
            cpu.emu_start(entry|1,EMU_RETURN,count=2300)
            if cpu.reg_read(UC_ARM_REG_R4)!=0xCAFEBABE or cpu.reg_read(UC_ARM_REG_R9)!=(cfg[2] if typ=="gate" else cfg[1]):
                raise ValueError(f"old OEM wrapper ABI: type={typ}, config={cfg}, r4={cpu.reg_read(UC_ARM_REG_R4):#x}, r9={cpu.reg_read(UC_ARM_REG_R9):#x}, pc={cpu.reg_read(UC_ARM_REG_PC):#x}, calls={source_calls}, sp={cpu.reg_read(UC_ARM_REG_SP):#x}")
            if typ=="gate":
                observed=cpu.reg_read(UC_ARM_REG_R0)
                if observed!=cfg[3] or source_calls:
                    raise ValueError(f"Creality/legacy existing gate result changed {cfg} observed {observed}")
                out.append({"case":"estimate_gate","config":cfg,"returned":observed})
            else:
                actual=bytes(cpu.mem_read(REMAIN_RUNTIME+99,1))[0]
                if source_calls!=["STOCK_INIT"] or actual!=cfg[5]:
                    raise ValueError(f"Creality stock init/type4 conversion failure {cfg}, type {actual}")
                out.append({"case":"stock_creality_init","config":cfg,"runtime_type":actual,
                            "OEM_stock_init_called":True,
                            "old_tag_type_not_written":True})
    if len(out)!=17:raise ValueError("existing estimation-wrapper test census changed")
    return out

def negative_tests(v313,v322,source,linker,builder,builder_file)->list[str]:
    bad=[
        ("changed_stock_gate",source.replace("0x080102E2","0x080102E0",1),linker),
        ("bad_physical_linker",source,linker.replace("0x0803AE38","0x0803AE3A",1)),
        ("missing_type4_anchor",source.replace(INSERT_ANCHOR,"missing anchor",1),linker),
    ]
    refused=[]
    for name,asm,ld in bad:
        try:build_candidate(v313,v322,asm,ld,builder,builder_file)
        except (ValueError,AssertionError,subprocess.CalledProcessError):refused.append(name)
        else:raise AssertionError("unsafe modified source accepted "+name)
    corrupt=bytearray(v322);corrupt[0x3500]^=1
    try:build_candidate(v313,bytes(corrupt),source,linker,builder,builder_file)
    except (ValueError,AssertionError,subprocess.CalledProcessError):refused.append("saved_v322_tampered")
    else:raise AssertionError("wrong saved reference accepted")
    assert len(refused)==4
    return refused

def main()->None:
    ap=argparse.ArgumentParser()
    for key in ("v313","v322","asm","linker","builder"):
        ap.add_argument("--"+key,required=True,type=Path)
    ap.add_argument("--self-test",action="store_true")
    ap.add_argument("--json-out",type=Path)
    opts=ap.parse_args()
    v313=pinned(opts.v313,"intermediate_v313")
    v322=pinned(opts.v322,"running_v322")
    asm=opts.asm.read_text()
    linker=opts.linker.read_text()
    builder=opts.builder.read_text()
    image,info,sym=build_candidate(v313,v322,asm,linker,builder,opts.builder)
    tests=run_matrix(image,sym[NEW_GATE_SYMBOL])
    stock_wrapper_tests=emulate_existing_estimation_wrappers(image,sym)
    result={
        "candidate":info,
        "offline_type4_usage_gate_emulator_cases":tests,
        "existing_estimation_wrapper_emulator_cases":stock_wrapper_tests,
        "hardware_release_gates_passed":False,
        "firmware_IMAGE_exported":False,
        "RS485_physical_update_performed":False,
        "production_Kalico_changed":False,
    }
    if opts.self_test:
        result["corrupt_source_mutations_rejected"]=negative_tests(
            v313,v322,asm,linker,builder,opts.builder
        )
    payload=json.dumps(result,indent=2)+"\n"
    if opts.json_out:opts.json_out.write_text(payload)
    print(payload,end="")
if __name__=="__main__":
    main()
