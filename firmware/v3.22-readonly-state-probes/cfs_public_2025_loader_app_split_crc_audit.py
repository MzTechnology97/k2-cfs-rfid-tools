#!/usr/bin/env python3
"""Prove what the PUBLIC 2025 full CFS Flash dump says about boot/app split.

Verifies independently archived 512-KiB original CFS Flash, including
lower boot/startup vector, 0x08003000 APP vector, loader references to
APP_BASE, bootloader handoff instructions, CRC16 0x8005 APP metadata,
and a strict v3.13/v3.22 header comparison.

This is an OLD PUBLIC CFS instance. It does NOT authenticate the
currently deployed CFS loader, its maximum app length, erase coverage,
RDP/option bytes, rollback or a safe v3.23 flashing method.
No device access, no firmware image output, no GPIO/motor/RS485 IO.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from cfs_historical_bootloader_compare import verify_public_blob
from cfs_app_real_link_base_audit import LINK_BASE,audited
from flash_ram_phase2_audit import pinned,crc16_bypass,CRC_OFF,META_END

FLASH_BASE=0x08000000
PAGE_BYTES=2048
APP_BASE=0x08003000
HIST_FLASH_N=524288
HIST_APP_RESET=0x08015B21
HIST_BOOT_RESET=0x080005B9
HIST_APP_MSP=0x20005420
HIST_BOOT_MSP=0x20010000
HIST_APP_LENGTH=150312
HIST_APP_CRC=0x172F
V322_LENGTH=178140
V322_CRC=0xC36F
UNVERIFIED_OLD_POLICY=0x0803B800
CANDIDATE_V323_IMAGE_END=0x0802E800

LITERALS={
    0x08000AA4:APP_BASE,
    0x08001360:APP_BASE,
    0x08001A88:APP_BASE,
    0x08000AA0:0x0800320C,
    0x08001DD8:0x0807F800,
}
OPCODES={
    0x080005B8:("cpsid","i"),
    0x080005BA:("ldr","r3, [pc, #8]"),
    0x080005BC:("ldr","r2, [pc, #8]"),
    0x080005BE:("mov","sp, r3"),
    0x080005C0:("bx","r2"),
    0x08000A08:("push","{r4, r5, lr}"),
    0x08000A0E:("movw","r5, #0x8005"),
    0x08000A3C:("ldr","r3, [pc, #0x60]"),
    0x08000A70:("mov.w","r1, #0x20c"),
    0x08000A74:("ldr","r0, [pc, #0x2c]"),
    0x08000A76:("bl","#0x8000a08"),
    0x08000A84:("movw","r3, #0x211"),
    0x08000A88:("cmp","r4, r3"),
    0x08000A90:("subw","r1, r4, #0x212"),
    0x08000A94:("bl","#0x8000a08"),
    0x08000A98:("cmp","r5, r0"),
    0x08001306:("ldr","r3, [pc, #0x58]"),
    0x08001308:("str","r3, [sp, #4]"),
    0x0800134C:("ldr","r3, [sp, #4]"),
    0x0800134E:("ldr","r3, [r3, #4]"),
    0x08001350:("ldr","r2, [sp, #4]"),
    0x08001352:("ldr","r2, [r2]"),
    0x0800135E:("bx","r3"),
    0x08001A32:("cmp","r3, #7"),
    0x08001A38:("ldr.w","pc, [r2, r3, lsl #2]"),
    0x08001D60:("cpsid","i"),
    0x08001D62:("bl","#0x8000364"),
    0x08001D66:("ldr","r0, [pc, #0x70]"),
    0x08001D68:("bl","#0x80002b8"),
    0x08001D6C:("bl","#0x800033c"),
    0x08001D70:("cpsie","i"),
    0x080002B8:("push","{r3, r4, r5, lr}"),
    0x080002DE:("str","r5, [r3]"),
    0x08001A0A:("ldr","r7, [pc, #0x7c]"),
}
THUMB_MSR_MSP_R2=bytes.fromhex("82f30888")

def rom_word(flash:bytes,at:int)->int:
    pos=at-FLASH_BASE
    if pos<0 or pos+4>len(flash):
        raise ValueError("historical Flash 32-bit address out of bounds")
    return struct.unpack_from("<I",flash,pos)[0]

def disasm_at(flash:bytes,at:int)->tuple[str,str]:
    offset=at-FLASH_BASE
    if offset<0 or offset+4>len(flash):
        raise ValueError("historic PC out of Flash image")
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    ins=next(dec.disasm(flash[offset:offset+4],at,count=1),None)
    if ins is None:
        raise ValueError(f"invalid historical Thumb at {at:#x}")
    return ins.mnemonic,ins.op_str

def loader_layout(flash:bytes)->dict:
    if len(flash)!=HIST_FLASH_N:
        raise ValueError("wrong length of archived physical Flash")
    sp,reset=struct.unpack_from("<II",flash)
    app_sp,app_reset=struct.unpack_from("<II",flash,APP_BASE-FLASH_BASE)
    if (sp,reset,app_sp,app_reset)!=(
        HIST_BOOT_MSP,HIST_BOOT_RESET,HIST_APP_MSP,HIST_APP_RESET
    ):
        raise ValueError("archive contains unexpected boot/application vector tables")
    if not (FLASH_BASE <= (reset&~1)<APP_BASE and APP_BASE <=(app_reset&~1)<FLASH_BASE+len(flash)):
        raise ValueError("vectors do not transfer to two distinct code regions")
    for at,want in LITERALS.items():
        if rom_word(flash,at)!=want:
            raise ValueError(f"historical loader APP vector/metadata reference changed: {at:#x}")
    for at,want in OPCODES.items():
        found=disasm_at(flash,at)
        if found!=want:
            raise ValueError(f"historical loader Thumb changed at {at:#x}: {found} expected {want}")
    # The historical 8-way receive handler has slot 6 entering a
    # caller which passes 0x0807F800 to the FMC erase-page helper.
    # This is a positive *historical* page-erase path, not all app pages.
    if rom_word(flash,0x08001A54)!=0x08001D5D:
        raise ValueError("historical receive dispatch slot6 changed")
    msr_pc=0x08001354
    if flash[msr_pc-FLASH_BASE:msr_pc-FLASH_BASE+4]!=THUMB_MSR_MSP_R2:
        raise ValueError("historical loader does not load application MSP before handoff")
    for at,ptr in ((0x080005BA,0x080005C4),(0x080005BC,0x080005C8),
                   (0x08000A3C,0x08000AA0),(0x08000A74,0x08000AA4),
                   (0x08001306,0x08001360),(0x08001A0A,0x08001A88),
                   (0x08001D66,0x08001DD8)):
        mnemonic,operands=disasm_at(flash,at)
        if mnemonic not in ("ldr","ldr.w"):
            raise ValueError("pinned historic literal load no longer present")
        imm=int(operands.split("#")[1].split("]")[0],0)
        actual=((at+4)&~3)+imm
        if actual!=ptr:
            raise ValueError(f"historic PC relative literal not at pinned address: {at:#x}")
    if rom_word(flash,0x080005C4)!=HIST_BOOT_MSP or rom_word(flash,0x080005C8)!=0x08001F29:
        raise ValueError("historic initial boot reset bootstrap is different")
    if any(flash[0x2400:0x3000]):
        raise ValueError("archived lower-loader tail zero gap differs")
    last_nonzero=max(i for i,x in enumerate(flash[:0x3000]) if x!=0)
    if last_nonzero!=0x2270:
        raise ValueError("historic lower Flash loader extent drift")
    app=flash[APP_BASE-FLASH_BASE:]
    hdr_len=struct.unpack_from("<I",app,0x20E)[0]
    header_crc=struct.unpack_from("<H",app,0x20C)[0]
    if hdr_len!=HIST_APP_LENGTH or header_crc!=HIST_APP_CRC:
        raise ValueError("historical bootloader-image application header mismatch")
    image=bytearray(app[:hdr_len])
    image[CRC_OFF:META_END]=bytes(META_END-CRC_OFF)
    recalculated=crc16_bypass(image)
    if recalculated!=header_crc:
        raise ValueError("historical APP CRC16-0x8005 source check rejected")
    return {
        "historical_2025_public_flash_bytes":len(flash),
        "historic_boot_vector_at":hex(FLASH_BASE),
        "historical_boot_initial_MSP":hex(sp),
        "historical_boot_reset_Thumb":hex(reset),
        "historical_lower_bootstrap_code_last_nonzero":hex(FLASH_BASE+last_nonzero),
        "historical_zero_gap_to_app_base":hex(APP_BASE),
        "second_independent_APP_vector_at":hex(APP_BASE),
        "historical_APP_initial_MSP":hex(app_sp),
        "historical_APP_reset_Thumb":hex(app_reset),
        "three_original_ROM_literal_sources_of_APP_base":[hex(x) for x in sorted(LITERALS) if LITERALS[x]==APP_BASE],
        "source_proven_handoff_reads_APP_vector_and_sets_MSP_before_BX":True,
        "historic_APP_metadata_length":hdr_len,
        "historic_APP_end_exclusive":hex(APP_BASE+hdr_len),
        "historic_APP_metadata_CRC16":hex(header_crc),
        "loader_original_CRC16_polynomial":hex(0x8005),
        "CRC16_saved_header_matches_implemented_algorithm":True,
        "historical_raw_dump_contains_both_loader_and_APP":True,
        "historical_flash_has_loader_0x08000000_and_APP_0x08003000":True,
        "historical_receive_dispatch_slot6_Thumb":hex(0x08001D5D),
        "original_loader_slot6_passes_final_Flash_page_to_FMC_erase":True,
        "loader_FMC_erase_target_last_page":hex(0x0807F800),
        "historic_loader_all_APP_erase_paths_authenticated":False,
    }

def modern_headers(v313:bytes,v322:bytes)->dict:
    a=audited(v313);b=audited(v322)
    if LINK_BASE !=APP_BASE or len(v322)!=V322_LENGTH:
        raise ValueError("modern verified actual APP base / length changed")
    if v313[:8]!=v322[:8]:
        raise ValueError("modern v3.13 and v3.22 reset vectors differ")
    values=[]
    for content in (v313,v322):
        length=struct.unpack_from("<I",content,0x20E)[0]
        crc=struct.unpack_from("<H",content,0x20C)[0]
        copy=bytearray(content)
        copy[CRC_OFF:META_END]=bytes(META_END-CRC_OFF)
        if length!=len(content) or crc16_bypass(copy)!=crc:
            raise ValueError("modern original APP not compatible with old header CRC scheme")
        values.append({"source_APP_bytes":length,"CRC16":hex(crc)})
    if values[1]["CRC16"]!=hex(V322_CRC):
        raise ValueError("known working v3.22 CRC changed")
    end=LINK_BASE+len(v322)
    if end!=0x0802E7DC:
        raise ValueError("modern v3.22 physical end changed")
    if CANDIDATE_V323_IMAGE_END!=0x0802E800:
        raise ValueError("fixed earlier v3.23 prototype size changed")
    return {
        "v313":values[0],
        "v322":values[1],
        "physical_original_APP_base":hex(LINK_BASE),
        "v322_APP_end_exclusive":hex(end),
        "v322_last_2KiB_page":(end-1-FLASH_BASE)//PAGE_BYTES,
        "v323_readonly_candidate_end_exclusive":hex(CANDIDATE_V323_IMAGE_END),
        "v323_readonly_candidate_last_occupied_2KiB_page":(CANDIDATE_V323_IMAGE_END-1-FLASH_BASE)//PAGE_BYTES,
        "arithmetic_headroom_to_arbitrary_historical_POLICY_NOT_loader_guarantee":
            UNVERIFIED_OLD_POLICY-CANDIDATE_V323_IMAGE_END,
        "installed_loader_matches_archived_2025_bytes":False,
        "loader_maximum_APP_length_authenticated":False,
        "loader_actual_ERASE_pages_authenticated":False,
        "interrupted_flash_update_recovery_verified":False,
        "v323_flash_authorized":False,
    }

def synthetic_negative_cases(flash:bytes)->list[str]:
    changes=(
        ("boot_vector_SP",FLASH_BASE),
        ("boot_vector_RESET",FLASH_BASE+4),
        ("APP_vector_SP",APP_BASE),
        ("APP_vector_RESET",APP_BASE+4),
        ("loader_CRC_polynomial_instruction",0x08000A0E),
        ("loader_APP_header_pointer",0x08000AA0),
        ("loader_APP_base_for_crc",0x08000AA4),
        ("loader_APP_base_for_VTOR_handoff",0x08001360),
        ("loader_APP_base_for_dispatch",0x08001A88),
        ("loader_handoff_MSR_MSP",0x08001354),
        ("loader_handoff_BX_reset",0x0800135F),
        ("archived_APP_metadata_crc",APP_BASE+CRC_OFF),
        ("historical_dispatch_slot6",0x08001A54),
        ("historical_last_Flash_page_literal",0x08001DD8),
        ("historical_FMC_page_erase_call",0x08001D68),
        ("historical_FMC_erase_dest_register",0x080002DE),
        ("historical_interrupt_reenable_after_erase",0x08001D70),
        ("archived_APP_metadata_length",APP_BASE+0x20E),
    )
    refused=[]
    for name,at in changes:
        mutate=bytearray(flash)
        mutate[at-FLASH_BASE]^=1
        try:loader_layout(mutate)
        except (ValueError,AssertionError):refused.append(name)
        else:raise AssertionError("accepted tampered historical boot/App source "+name)
    if len(refused)!=len(changes):
        raise AssertionError("historical forensic negative fixture census incomplete")
    return refused

def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--historic-flash",type=Path,required=True)
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    historic=args.historic_flash.read_bytes()
    source=verify_public_blob(historic,"flash")
    old=pinned(args.v313,"intermediate_v313")
    current=pinned(args.v322,"running_v322")
    out={
        "historical_archived_Flash_SHA256":source["sha256"],
        "public_archived_CFS":loader_layout(historic),
        "modern_tested_APP":modern_headers(old,current),
        "emitted_firmware_or_bootloader_bytes":False,
        "active_hardware_access":False,
    }
    if args.self_test:out["mutations_rejected"]=synthetic_negative_cases(historic)
    text=json.dumps(out,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(text)
    print(text,end="")
if __name__=="__main__":main()
