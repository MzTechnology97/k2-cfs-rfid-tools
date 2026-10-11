#!/usr/bin/env python3
"""Compare independently archived Creality CFS GD32 bootloader to APP scatter code.

Public 2025 CFS forensic dump: fake-name/cfs-reverse-engineering
  reversing/live_dumps/0x0800_0000.bin
  reversing/live_dumps/0x2000_0000_trunc.bin

Crucial: old public CFS and active custom v3.22 are DIFFERENT firmware
instances. Matching ROM code establishes only historical compatibility,
NOT that the deployed CFS actually uses this same loader byte sequence.
Public bin files are consumed transiently in CI and never committed.

NO device IO, no Flash modification, no motor movement or private data
dumped: only SHA fingerprints, instruction mnemonics and sanitized names.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

from flash_ram_phase2_audit import pinned, APP_BASE
from cfs_scatter_candidate_decompress_audit import verify_image

PIN_PUBLIC_FLASH_BLOB="44e2d48a144356c1ae2b3fe0b4e23175c050e28e"
PIN_PUBLIC_RAM_BLOB="80e1103c16dd5e17ddf5c84af6e976ad14bd0d38"
FLASH_BASE=0x08000000
RAM_BASE=0x20000000
FLASH_N=524288
RAM_N=65535
OLD_LOADER_D=0x0800316C
OLD_LOADER_Z=0x080031C8
CURRENT_APP_D=0x0801016C
CURRENT_APP_Z=0x080101C8
DECOMP_N=0x5C
ZERO_N=0x20
FIVE_NAME_FIELDS=(0x200007B0,0x20000810,0x20000870,
                  0x200008D0,0x20000930)


def verify_public_blob(content: bytes, kind: str):
    want_n=FLASH_N if kind=="flash" else RAM_N
    expected=PIN_PUBLIC_FLASH_BLOB if kind=="flash" else PIN_PUBLIC_RAM_BLOB
    if len(content)!=want_n:
        raise ValueError("public CFS forensic input length changed")
    blob=hashlib.sha1(b"blob "+str(len(content)).encode()+b"\x00"+content).hexdigest()
    if blob!=expected:
        raise ValueError("public source Git blob SHA-1 does not match pinned object")
    return {"length":len(content),"git_blob_sha1":blob,
            "sha256":hashlib.sha256(content).hexdigest()}


def disasm_segment(data: bytes, start:int, end:int):
    decoder=Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    instructions=[]
    for ins in decoder.disasm(data[start-FLASH_BASE:end-FLASH_BASE],start):
        instructions.append({
          "at":hex(ins.address),
          "mnemonic":ins.mnemonic,
          "operands":ins.op_str,
        })
    return instructions


def printable_name(raw: bytes, ptr:int):
    if FLASH_BASE<=ptr<FLASH_BASE+len(raw):
        q=ptr-FLASH_BASE
        chunk=raw[q:q+16]
        if b"\x00" not in chunk:
            return None
        v=chunk.split(b"\x00",1)[0]
        if v in (b"pwm1",b"pwm3",b"pwm4",b"pwm5",b"pwm8"):
            return v.decode("ascii")
    return None


def find_historical_scatter_descriptors(flash:bytes):
    # Search aligned 16-byte records for exactly the archived loader
    # function-pointer words. All candidate fields must describe plausible
    # CFS APP-to-SRAM regions; no live memory is touched.
    result=[]
    for i in range(12,len(flash)-3,4):
        handler=struct.unpack_from("<I",flash,i)[0]
        if handler not in (OLD_LOADER_D,OLD_LOADER_Z,OLD_LOADER_D|1,OLD_LOADER_Z|1):
            continue
        src,dst,size=struct.unpack_from("<III",flash,i-12)
        if not (FLASH_BASE <= src < FLASH_BASE+FLASH_N
                and RAM_BASE <= dst < RAM_BASE+RAM_N
                and 0 < size <= RAM_N and dst-RAM_BASE+size<=RAM_N+1):
            continue
        result.append({
          "descriptor_at":hex(FLASH_BASE+i-12),
          "source":hex(src),
          "destination":hex(dst),
          "output_bytes":size,
          "handler":hex(handler),
          "handler_role":"compressed" if (handler&~1)==OLD_LOADER_D else "zero",
        })
    return result


def analyze(old_flash:bytes, old_ram:bytes, current:bytes):
    old_start=OLD_LOADER_D-FLASH_BASE
    app_start=CURRENT_APP_D-APP_BASE
    old_d=old_flash[old_start:old_start+DECOMP_N]
    cur_d=current[app_start:app_start+DECOMP_N]
    old_zero=old_flash[OLD_LOADER_Z-FLASH_BASE:OLD_LOADER_Z-FLASH_BASE+ZERO_N]
    cur_zero=current[CURRENT_APP_Z-APP_BASE:CURRENT_APP_Z-APP_BASE+ZERO_N]
    old_instr=disasm_segment(old_flash,OLD_LOADER_D,OLD_LOADER_Z)
    current_decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cur_instr=[
        {"at":hex(i.address),"mnemonic":i.mnemonic,"operands":i.op_str}
        for i in current_decoder.disasm(cur_d,CURRENT_APP_D)]
    # Adjust address operands when possible only for side-by-side review,
    # not for an asserted equivalence (branches may have relocations).
    name_fields=[]
    for field in FIVE_NAME_FIELDS:
        off=field-RAM_BASE
        ptr=struct.unpack_from("<I",old_ram,off)[0]
        name_fields.append({
            "name_field":hex(field),
            "historical_snapshot_pointer":hex(ptr),
            "is_candidate_original_ROM_PWM_name":printable_name(old_flash,ptr),
            "valid_flash_pointer":FLASH_BASE<=ptr<FLASH_BASE+len(old_flash),
            "valid_RAM_pointer":RAM_BASE<=ptr<RAM_BASE+len(old_ram),
            "snapshot_matches_v322_data_layout_proven":False,
        })
    vtable=struct.unpack_from("<II",old_flash,0)
    return {
        "historical_scatter_descriptor_candidates":
            find_historical_scatter_descriptors(old_flash),
        "public_historical_Flash":{
            "vector_initial_SP":hex(vtable[0]),
            "vector_reset_PC":hex(vtable[1]),
            "historical_loader_D_at":hex(OLD_LOADER_D),
            "historical_loader_Z_at":hex(OLD_LOADER_Z),
            "decompressor_segment_sha256":hashlib.sha256(old_d).hexdigest(),
            "original_thumb_mnemonics":old_instr,
        },
        "v322_APP_candidates":{
            "decompressor_segment_sha256":hashlib.sha256(cur_d).hexdigest(),
            "original_thumb_mnemonics":cur_instr,
        },
        "historical_bootloader_decompressor_matches_current_APP_bytes":old_d==cur_d,
        "decompressor_matching_byte_count":sum(x==y for x,y in zip(old_d,cur_d)),
        "decompressor_total_bytes_compared":len(old_d),
        "historical_zeroinit_matches_current_APP_bytes":old_zero==cur_zero,
        "zeroinit_matching_byte_count":sum(x==y for x,y in zip(old_zero,cur_zero)),
        "zeroinit_total_bytes_compared":len(old_zero),
        "historical_dump_five_fields_at_v322_offsets_UNVERIFIED":name_fields,
        "historical_CFS_firmware_version_same_as_v322":False,
        "deployed_CFS_bootloader_identity_verified":False,
        "actual_pwm1_runtime_callback_proven":False,
        "independent_motor_feedback_proven":False,
        "firmware_flash_safe":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--public-flash",required=True,type=Path)
    p.add_argument("--public-ram",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old_flash=a.public_flash.read_bytes()
    old_ram=a.public_ram.read_bytes()
    current=pinned(a.v322,"running_v322")
    verify_image(current)
    report={
        "public_flash_integrity":verify_public_blob(old_flash,"flash"),
        "public_RAM_integrity":verify_public_blob(old_ram,"ram"),
        "scope":"offline comparison of pinned 2025 CFS forensic snapshot with exact rebuilt v3.22",
        "analysis":analyze(old_flash,old_ram,current),
        "device_read_commands":False,
        "private_CFS_memory_access":False,
        "any_firmware_flashing":False,
    }
    if a.json_out:a.json_out.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))


if __name__=="__main__":
    main()
