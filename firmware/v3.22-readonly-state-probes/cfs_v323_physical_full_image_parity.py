#!/usr/bin/env python3
"""Build-equivalence rehearsal for modified CFS: physical-address v3.22 parity.

Exact real-Flash (0x08003000) reassembly of unchanged known v3.22
into volatile Python memory, including the original 14 patched BLs,
heap literal, image-length and CRC fields. Require byte-exact match
with SHA-pinned v3.22 hardware-tested reference before any new v3.23
edits. NEVER write output BIN and NEVER touch CFS serial, motor, or flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE, audited
from cfs_v322_full_branch_edge_audit import patches_from_builder
from cfs_v323_physical_relink_baseline import (
    DELTA,PHYSICAL_HANDLER,NOMINAL_HANDLER,assemble,
    physically_relocate_source,verify_physical,symbol_dict,
    EXPECTED_V322_SHA,EXPECTED_V322_BYTES,EXPECTED_HANDLER_BYTES,
)

APP_PREFIX=PHYSICAL_HANDLER-LINK_BASE
CRC_OFF=0x20C
LEN_OFF=0x20E
META_END=0x212
PHYSICAL_HEAP_LITERAL=0x08027960-DELTA
EXPECTED_BEFORE_HEAP=0x20006EE8
EXPECTED_AFTER_HEAP=0x20006F28
EXPECTED_BASE_BYTES=177700

def replay(v313:bytes,v322:bytes,handler_asm:str,linker:str,builder_text:str,
           *,trusted_builder_file:Path)->dict:
    audited(v313)
    audited(v322)
    if len(v313)!=EXPECTED_BASE_BYTES or len(v322)!=EXPECTED_V322_BYTES:
        raise ValueError("saved source image size differs from exact v3.22 reference")
    provenance=verify_physical(v313,v322,handler_asm,linker,builder_text)
    if not provenance["physically_relinked_handler_byte_identical_to_hw_validated_v322"]:
        raise ValueError("physical handler linker baseline missing")
    translated,new_linker,refs=physically_relocate_source(handler_asm,linker)
    new_handler,relocs,new_symbols=assemble(translated,new_linker)
    if len(new_handler)!=EXPECTED_HANDLER_BYTES or len(refs)!=13:
        raise ValueError("unexpected physical rebuilt handler layout")
    if len(v313)<APP_PREFIX:
        raise ValueError("v3.13 source smaller than preserved OEM prefix")
    symbols=symbol_dict(new_symbols)
    hooks=patches_from_builder(builder_text)
    if len(hooks)!=14:
        raise ValueError("unapproved new/removed OEM-to-handler firmware patch")
    # Reuse original known v3.22 CRC and Thumb BL encoding from the
    # already pinned experimental builder. Import only pure helpers:
    # main() is not executed, no builder output path can be supplied.
    helpers=runpy.run_path(str(trusted_builder_file))
    thumb_bl=helpers["thumb_bl"]
    crc16_bypass=helpers["crc16_bypass"]
    # v3.13 has an earlier handler tail; the historical v3.22 builder
    # deliberately truncates/replaces that tail at the same APP offset.
    image=bytearray(v313[:APP_PREFIX]+new_handler)
    if len(image)!=EXPECTED_V322_BYTES:
        raise ValueError("unexpected candidate image length")
    allowed=set(range(APP_PREFIX,len(image)))
    hook_records=[]
    dis=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    for original_nominal_pc,name in hooks:
        pc=original_nominal_pc-DELTA
        dest=symbols.get(name)
        if dest is None or not (PHYSICAL_HANDLER<=dest<LINK_BASE+len(image)):
            raise ValueError("no physical relocated wrapper address for "+name)
        off=pc-LINK_BASE
        if off<0 or off+4>APP_PREFIX:
            raise ValueError("source hook outside original OEM code")
        encoded=thumb_bl(pc,dest)
        instruction=list(dis.disasm(encoded,pc,count=1))
        if (len(encoded)!=4 or len(instruction)!=1
                or instruction[0].mnemonic!="bl"
                or instruction[0].op_str!=f"#{dest:#x}"):
            raise ValueError("physical patch BL did not decode to registered wrapper")
        previous=bytes(image[off:off+4])
        image[off:off+4]=encoded
        allowed.update(range(off,off+4))
        hook_records.append({
            "physical_pc":hex(pc),"name":name,
            "physical_target":hex(dest),
            "original_OEM_instruction":previous.hex(),
            "physically_encoded_BL":encoded.hex()
        })
    heap_off=PHYSICAL_HEAP_LITERAL-LINK_BASE
    if struct.unpack_from("<I",image,heap_off)[0]!=EXPECTED_BEFORE_HEAP:
        raise ValueError("known v3.13 heap origin no longer at pinned literal")
    struct.pack_into("<I",image,heap_off,EXPECTED_AFTER_HEAP)
    allowed.update(range(heap_off,heap_off+4))
    # Legacy v3.22 metadata scheme is preserved exactly. This does NOT
    # qualify any new loader/app image-length or erase boundary.
    struct.pack_into("<I",image,LEN_OFF,len(image))
    masked=bytearray(image)
    masked[CRC_OFF:META_END]=b"\x00"*(META_END-CRC_OFF)
    check=crc16_bypass(masked)
    struct.pack_into("<H",image,CRC_OFF,check)
    struct.pack_into("<I",image,LEN_OFF,len(image))
    allowed.update(range(CRC_OFF,META_END))
    diff=[i for i in range(APP_PREFIX) if image[i]!=v313[i]]
    unforeseen=[i for i in diff if i not in allowed]
    if unforeseen:
        raise ValueError("unapproved bytes changed in original APP: "+repr(unforeseen[:8]))
    image_sha=hashlib.sha256(image).hexdigest()
    if image_sha!=EXPECTED_V322_SHA or image!=v322:
        differences=[hex(LINK_BASE+i) for i,(a,b) in enumerate(zip(image,v322)) if a!=b]
        raise ValueError("physical-source whole-APP replay differs from tested v3.22: "+
                         repr(differences[:16]))
    return {
        "APP_physical_base":hex(LINK_BASE),
        "physical_handler_origin":hex(PHYSICAL_HANDLER),
        "physical_handler_bytes":len(new_handler),
        "v313_source_bytes":len(v313),
        "reconstructed_APP_bytes":len(image),
        "full_image_SHA256":image_sha,
        "physical_relinked_full_v322_matches_reference_byte_for_byte":True,
        "original_OEM_physical_hook_count":len(hooks),
        "new_HANDLER_to_OEM_verified_branches":provenance["complete_external_Thumb_branch_target_checks"],
        "reconstructed_hook_manifest":hook_records,
        "initial_heap_literal_physical_PC":hex(PHYSICAL_HEAP_LITERAL),
        "initial_heap_value_after_known_v322_patch":hex(EXPECTED_AFTER_HEAP),
        "saved_metadata_crc16":hex(check),
        "original_unexpected_changed_bytes":len(unforeseen),
        "fresh_v323_feature_or_binary_created":False,
        "verified_loader_flash_page_and_recovery":False,
        "physical_motor_idle_interlock_qualified":False,
        "release_for_flash":False,
        "MCU_or_production_Kalico_access":False,
    }

def negatives(v313,v322,asm,linker,builder,builder_file)->list[str]:
    checks=[
        ("handler_source_unrecognized_symbol",asm.replace("0x0803393C","0x0803393E",1),linker,builder),
        ("linker_changed",asm,linker.replace("0x0803AE38","0x0803AE3A"),builder),
        ("builder_hook_unreviewed",asm,linker,builder.replace(
            "[(0x0802A5F2,'heap_init_sidecar_wrapper')]",
            "[(0x0802A5F2,'heap_init_sidecar_wrapper'),(0x08011116,'test')]")),
    ]
    refused=[]
    for label,source,ld,build in checks:
        try:replay(v313,v322,source,ld,build,trusted_builder_file=builder_file)
        except (ValueError,AssertionError):refused.append(label)
        else:raise AssertionError("modified v3.22 offline source accepted: "+label)
    corrupted=bytearray(v322)
    corrupted[-1]^=1
    try:replay(v313,bytes(corrupted),asm,linker,builder,trusted_builder_file=builder_file)
    except (ValueError,AssertionError):refused.append("corrupt_saved_v322_append")
    else:raise AssertionError("corrupted whole reference accepted")
    corrupt_base=bytearray(v313)
    corrupt_base[0x5000]^=1
    try:replay(bytes(corrupt_base),v322,asm,linker,builder,trusted_builder_file=builder_file)
    except (ValueError,AssertionError):refused.append("corrupt_saved_v313_source")
    else:raise AssertionError("mutated v3.13 base accepted")
    if len(refused)!=5:
        raise ValueError("five physical complete-image negative tests did not fail")
    return refused

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--asm",type=Path,required=True)
    p.add_argument("--linker",type=Path,required=True)
    p.add_argument("--builder",type=Path,required=True)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    before=pinned(a.v313,"intermediate_v313")
    after=pinned(a.v322,"running_v322")
    result=replay(before,after,a.asm.read_text(),a.linker.read_text(),
                  a.builder.read_text(),trusted_builder_file=a.builder)
    if a.self_test:
        result["negative_fixtures_rejected"]=negatives(
            before,after,a.asm.read_text(),a.linker.read_text(),
            a.builder.read_text(),a.builder)
    data=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(data)
    print(data,end="")
if __name__=="__main__":
    main()
