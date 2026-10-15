#!/usr/bin/env python3
"""Prove bounded archived 2025 CFS loader RS485 update/flash geometry.

Reads only SHA-verified PUBLIC historic 512 KiB MCU Flash and SHA-verified
local v3.13/v3.22 APPs. Pins original loader Thumb update routing, 128-byte
serial receive, 256-byte buffering, 2KiB page erase, FMC page-write and
the separate final-parameter-page erase command. Audits synthetic address
boundaries; never emits/uploads/sends firmware or an update command.

IMPORTANT: Public historical loader != authenticated installed loader.
The absence of APP/parameter upper-bound checks *on the source-pinned
write path* does not prove absence of all dynamic checks or loader
compatibility of a new build. No real CFS motor/GPIO/RS485/flash access.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from cfs_historical_bootloader_compare import verify_public_blob
from flash_ram_phase2_audit import pinned

FLASH_BASE=0x08000000
APP_BASE=0x08003000
PARAM_PAGE=0x0807F800
FLASH_END=0x08080000
FLASH_PAGE=0x800
UPDATE_CHUNK=0x80
FLASH_PROGRAM_BUFFER=0x100
KNOWN_V322_BYTES=178140
IN_MEMORY_V323_BYTES=178176
PUBLIC_HISTORIC_FLASH_SHA="58b8b90890c08aae81235dd4625fc75ff955e09e82f6c47ee2d74276498bc125"

# Original Thumb instructions inspected in the old complete ROM image.
# Each address is an original hardware physical PC, not a nominal link address.
PINNED={
    0x08001A32:("cmp","r3, #7"),
    0x08001A38:("ldr.w","pc, [r2, r3, lsl #2]"),
    0x08001E1E:("mov.w","fp, #5"),
    0x08001E26:("movs","r1, #4"),
    0x08001E2A:("bl","#0x800136c"),
    0x08001E66:("ands","r3, r4, #0x7f"),
    0x08001E80:("movs","r1, #0x80"),
    0x08001E84:("bl","#0x800136c"),
    0x08001E94:("bl","#0x80003b0"),
    0x08001E98:("cmp","r0, #1"),
    0x08001EC8:("movs","r5, #3"),
    0x08001ED6:("cmp.w","r3, #0x200"),
    0x08001EF0:("add.w","r0, r7, r4, lsl #7"),
    0x08001EF4:("bl","#0x80003b0"),
    0x080003B0:("ldr","r1, [pc, #0xdc]"),
    0x080003C4:("movs","r4, #0x80"),
    0x080003D2:("adds","r3, #0x80"),
    0x080003D6:("cmp.w","r3, #0x100"),
    0x080003DE:("cpsid","i"),
    0x080003E2:("bl","#0x8000364"),
    0x080003EA:("ubfx","r3, r0, #0, #0xb"),
    0x080003EE:("cbz","r3, #0x8000426"),
    0x08000426:("bl","#0x80002b8"),
    0x0800042E:("bl","#0x800033c"),
    0x08000466:("adds","r4, #4"),
    0x08000468:("cmp.w","r4, #0x100"),
    0x080002C6:("ldr","r3, [pc, #0x60]"),
    0x080002C8:("cmp","r0, r3"),
    0x080002DE:("str","r5, [r3]"),
    0x08001D62:("bl","#0x8000364"),
    0x08001D66:("ldr","r0, [pc, #0x70]"),
    0x08001D68:("bl","#0x80002b8"),
    0x08001D6C:("bl","#0x800033c"),
}
DISPATCH={
    0:0x08001D2D,1:0x08001E0D,2:0x08001DE1,3:0x08001E09,
    4:0x08001A15,5:0x08001A15,6:0x08001D5D,7:0x08001D0D,
}
LITERALS={
    0x08000490:0x20000914, # buffered-byte count
    0x08000494:0x20000B70, # write-base pointer
    0x08000498:0x20000814, # 256B scratch
    0x0800049C:0x20000014, # 128B receive scratch
    0x080004A4:0x0807FFFF, # 512KiB boundary used by density-dependent FMC path
    0x08001DD8:PARAM_PAGE,  # separate subcommand 0x06 erases this page
    0x08001A88:APP_BASE,   # programming reset pointer in command dispatcher
    0x08000AA4:APP_BASE,   # image CRC calculator
}

def word(blob:bytes,absolute:int)->int:
    off=absolute-FLASH_BASE
    if off<0 or off+4>len(blob):raise ValueError("archived flash address outside full source")
    return struct.unpack_from("<I",blob,off)[0]

def checked_thumb(blob:bytes,absolute:int)->tuple[str,str]:
    off=absolute-FLASH_BASE
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    ins=next(decoder.disasm(blob[off:off+4],absolute,count=1),None)
    if not ins:raise ValueError(f"unrecognized original Thumb PC {absolute:#x}")
    return ins.mnemonic,ins.op_str

def inspect_source(blob:bytes)->dict:
    if len(blob)!=512*1024:
        raise ValueError("not the full historical 512KiB archive")
    if hashlib.sha256(blob).hexdigest()!=PUBLIC_HISTORIC_FLASH_SHA:
        raise ValueError("historical source is not the exact published Flash")
    for pc,expected in PINNED.items():
        result=checked_thumb(blob,pc)
        if result!=expected:
            raise ValueError(f"original loader Thumb changed at {pc:#x} {result} != {expected}")
    for i,entry in DISPATCH.items():
        if word(blob,0x08001A3C+i*4)!=entry:
            raise ValueError(f"original loader F0 dispatch slot {i} modified")
    for pc,expected in LITERALS.items():
        if word(blob,pc)!=expected:
            raise ValueError(f"original loader literal at {pc:#x} modified")
    if word(blob,0x08001A54)!=DISPATCH[6]:
        raise ValueError("parameter-page command routing unexpected")
    if word(blob,0x080004A4)!=0x0807FFFF:
        raise ValueError("old loader high/normal-density physical-bank bound changed")
    return {
        "public_historic_full_flash_sha256":hashlib.sha256(blob).hexdigest(),
        "original_Thumb_update_and_FMC_instructions_checked":len(PINNED),
        "original_F0_dispatch_slots_checked":len(DISPATCH),
        "original_Flash_and_SRAM_literals_checked":len(LITERALS),
        "F0_01_update_entry":hex(DISPATCH[1]&~1),
        "F0_06_parameter_erase_entry":hex(DISPATCH[6]&~1),
        "original_update_start_address":hex(APP_BASE),
        "original_serial_chunk_size_bytes":UPDATE_CHUNK,
        "original_buffered_FMC_program_bytes":FLASH_PROGRAM_BUFFER,
        "historical_FMC_page_erase_modulus_bytes":FLASH_PAGE,
        "original_other_command_parameter_page_erase_target":hex(PARAM_PAGE),
        "original_FMC_density_specific_end_comparison":hex(0x0807FFFF),
        "historical_update_writer_is_separate_from_parameter_erase_command":True,
        "original_update_writer_has_pinned_parameter_page_protection":False,
        "loader_main_switch_might_have_additional_checks":True,
        "loaded_CFS_loader_identical_to_archived":False,
        "safe_to_flash_modified_v323":False,
    }

def page_range_for_length(n:int)->dict:
    if not isinstance(n,int) or n<0 or n>0xffffffff:
        raise ValueError("invalid synthetic application length")
    end=APP_BASE+n
    if end<APP_BASE or end>0x100000000:
        raise ValueError("address integer wrap")
    if n==0:
        last=None
    else:
        last=(end-1-FLASH_BASE)//FLASH_PAGE
    return {
        "APP_length_bytes":n,
        "last_byte_exclusive":hex(end),
        "last_touched_page_index":last,
        "last_page_address":None if last is None else hex(FLASH_BASE+last*FLASH_PAGE),
        "overlaps_reserved_parameter_page":end>PARAM_PAGE,
        "overflows_512KiB_physical_flash":end>FLASH_END,
        "is_known_v323_snapshot_image":n==IN_MEMORY_V323_BYTES,
    }

def negative_tests(blob:bytes)->list[str]:
    cases={
        "update_command_slot":0x08001A40,
        "wrong_reserved_parameter_cmd_slot":0x08001A54,
        "update_length_read":0x08001E26,
        "read_128_byte_chunk":0x08001E80,
        "writer_call_from_update":0x08001E94,
        "writer_retry_logic":0x08001EC8,
        "page_modulo_2048":0x080003EA,
        "page_erase_dispatch_branch":0x080003EE,
        "page_erase_call":0x08000426,
        "flash_word_write":0x080002DE,
        "separate_param_page_erase":0x08001D68,
        "parameter_page_target_constant":0x08001DD8,
        "APP_begin_0x08003000":0x08001A88,
        "FMC_physical_density_branch":0x080004A4,
    }
    rejected=[]
    for label,address in cases.items():
        mutation=bytearray(blob)
        mutation[address-FLASH_BASE]^=1
        try:
            # Use unfingerprinted source-path check to prove localized pin
            # verification, not only that the whole-file SHA changed.
            local=bytes(mutation)
            for pc,expected in PINNED.items():
                if checked_thumb(local,pc)!=expected:
                    raise ValueError("original Thumb changed")
            for i,entry in DISPATCH.items():
                if word(local,0x08001A3C+i*4)!=entry:
                    raise ValueError("dispatch changed")
            for pc,value in LITERALS.items():
                if word(local,pc)!=value:raise ValueError("literal changed")
        except ValueError:
            rejected.append(label)
        else:
            raise AssertionError("altered loader source accepted: "+label)
    if len(rejected)!=len(cases):
        raise ValueError("loader critical update geometry negative fixtures incomplete")
    return rejected

def main()->None:
    p=argparse.ArgumentParser()
    p.add_argument("--historic-flash",required=True,type=Path)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    blob=a.historic_flash.read_bytes()
    verify_public_blob(blob,"flash")
    source=inspect_source(blob)
    old=pinned(a.v313,"intermediate_v313")
    current=pinned(a.v322,"running_v322")
    scenarios={
        "known_v313":page_range_for_length(len(old)),
        "known_v322":page_range_for_length(len(current)),
        "experimental_v323_snapshot":page_range_for_length(IN_MEMORY_V323_BYTES),
        "ends_before_param":page_range_for_length(PARAM_PAGE-APP_BASE-1),
        "exactly_ends_at_param":page_range_for_length(PARAM_PAGE-APP_BASE),
        "one_byte_of_param":page_range_for_length(PARAM_PAGE-APP_BASE+1),
        "one_byte_beyond_flash":page_range_for_length(FLASH_END-APP_BASE+1),
    }
    if len(current)!=KNOWN_V322_BYTES:
        raise ValueError("unexpected saved v3.22 APP size")
    if scenarios["experimental_v323_snapshot"]["last_byte_exclusive"]!="0x802e800":
        raise ValueError("trial v3.23 image end changed")
    if scenarios["experimental_v323_snapshot"]["overlaps_reserved_parameter_page"]:
        raise ValueError("trial v3.23 overlaps historical last page")
    if not scenarios["one_byte_of_param"]["overlaps_reserved_parameter_page"]:
        raise ValueError("missing parameter-overlap scenario")
    if scenarios["exactly_ends_at_param"]["overlaps_reserved_parameter_page"]:
        raise ValueError("exclusive page-end semantics wrong")
    result={
        "archive":source,
        "offline_address_boundary_scenarios":scenarios,
        "synthetic_parameter_page_overlap_does_not_imply_real_loader_accepts_that_length":True,
        "real_bootloader_flash_authorization":False,
        "real_CFS_UART_or_FMC_I_O":False,
        "firmware_or_loader_image_emitted":False,
    }
    if a.self_test:result["altered_OEM_code_sites_rejected"]=negative_tests(blob)
    payload=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(payload)
    print(payload,end="")
if __name__=="__main__":
    main()
