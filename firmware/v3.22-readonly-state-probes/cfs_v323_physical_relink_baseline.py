#!/usr/bin/env python3
"""Source-only physical-address toolchain baseline for future CFS v3.23.

The shipping-tested saved v3.22 was assembled with a nominal
0x08010000 APP base, but actually runs from 0x08003000. The old
assembler and physical linker can be translated uniformly by -0xD000
for the 13 exact OEM external branch references.

This test physically reassembles the existing UNMODIFIED v3.22 handler
in disposable directories, checks all object relocation kinds,
all 15 outgoing/14 incoming branch edges, and proves byte-for-byte
identity of the newly linked handler against saved v3.22.

There is NO firmware output, no serial/GPIO/MCU access, and absolutely
NO v3.23 write/flash approval. Do not use as a loader/partition check.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE, audited
from cfs_v322_full_branch_edge_audit import (
    compiled_unchanged, flash_word_literals, inspect as inspect_old_edges,
    patches_from_builder, EXPECTED_EXTERNAL_RELOCS,
    EXPECTED_EXTERNAL_TARGET_COUNTS, EXPECTED_PATCHES,
    RELOC_LINE,
)

NOMINAL_BASE = 0x08010000
NOMINAL_HANDLER = 0x0803AE38
DELTA = NOMINAL_BASE - LINK_BASE
PHYSICAL_HANDLER = NOMINAL_HANDLER - DELTA
EXPECTED_V322_SHA = "40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7"
EXPECTED_V322_BYTES = 178140
EXPECTED_HANDLER_BYTES = 2468
ROM_EQ = re.compile(r"(?m)^(\.equ\s+([A-Z][A-Z_0-9]*),\s*)(0x08[0-9A-Fa-f]{6})([^\n]*)$")
LINKER_EXPECTED = "0x0803AE38"
EXPECTED_EQU_NAMES = {
    "SEND_RESPONSE", "LEGACY_AUTH_READ", "ALT_AUTH_READ", "STOCK_MEMCMP",
    "STOCK_MSG_VALIDATE", "STOCK_REMAIN_INIT", "STOCK_REMAIN_VALID",
    "STOCK_REMAIN_GATE", "REMAIN_SET", "STOCK_51", "STOCK_INVALID",
    "STOCK_DONE", "STOCK_HEAP_INIT",
}
# This pins *all* old absolute Flash EQu source data, not just count.
EXPECTED_ROM_EQU_ADDRESSES = {
    "SEND_RESPONSE": 0x0801BAF2, "LEGACY_AUTH_READ": 0x0801A39E,
    "ALT_AUTH_READ": 0x08022082, "STOCK_MEMCMP": 0x0803393C,
    "STOCK_MSG_VALIDATE": 0x0801A670, "STOCK_REMAIN_INIT": 0x0801AA14,
    "STOCK_REMAIN_VALID": 0x0801245C, "STOCK_REMAIN_GATE": 0x080102E2,
    "REMAIN_SET": 0x080123E4, "STOCK_51": 0x0801C704,
    "STOCK_INVALID": 0x0801C7F8, "STOCK_DONE": 0x0801C808,
    "STOCK_HEAP_INIT": 0x080278D4,
}
SYMBOL_ENTRY = re.compile(r"^([0-9a-fA-F]{8})\s+[a-zA-Z]\s+(\w+)$")

def call(*args: str) -> str:
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout

def physically_relocate_source(source: str, linker: str) -> tuple[str, str, dict[str, int]]:
    if DELTA != 0xD000 or PHYSICAL_HANDLER != 0x0802DE38:
        raise ValueError("physical APP/base mismatch; do not infer v3.23 linker")
    if flash_word_literals(source):
        raise ValueError("unreviewed absolute Flash word embedded in handler")
    if linker.count(LINKER_EXPECTED) != 1:
        raise ValueError("historical handler linker does not match v3.22")
    seen: dict[str, int] = {}
    def rewrite(match: re.Match[str]) -> str:
        name = match.group(2)
        address = int(match.group(3), 16)
        if name in seen:
            raise ValueError("duplicate old OEM Flash symbol")
        seen[name] = address
        if not (NOMINAL_BASE <= address < 0x08040000):
            raise ValueError(f"unexpected old manufacturer branch address: {name} {address:#x}")
        return f"{match.group(1)}0x{address-DELTA:08X}{match.group(4)}"
    transformed = ROM_EQ.sub(rewrite, source)
    if seen != EXPECTED_ROM_EQU_ADDRESSES:
        raise ValueError("unreviewed/additional/missing original Flash .equ branch definition")
    new_linker = linker.replace(LINKER_EXPECTED, f"0x{PHYSICAL_HANDLER:08X}", 1)
    if LINKER_EXPECTED in new_linker:
        raise ValueError("nominal handler address still in physical linker")
    if ROM_EQ.findall(transformed) and any(
        int(raw,16) >= NOMINAL_HANDLER for _,_,raw,_ in ROM_EQ.findall(transformed)
    ):
        raise ValueError("unexpected physical ROM equ remains in obsolete area")
    return transformed,new_linker,seen

def assemble(source: str, linker: str) -> tuple[bytes,str,str]:
    with tempfile.TemporaryDirectory(prefix="cfs-v323-physical-link-") as tmp:
        t=Path(tmp)
        asm=t/"handler.S"; ld=t/"link.ld"
        obj=t/"handler.o"; elf=t/"handler.elf"; raw=t/"handler.bin"
        asm.write_text(source); ld.write_text(linker)
        call("arm-none-eabi-gcc","-c","-mcpu=cortex-m3","-mthumb",
             "-ffreestanding","-nostdlib","-o",str(obj),str(asm))
        relocs=call("arm-none-eabi-readelf","-r",str(obj))
        call("arm-none-eabi-ld","-T",str(ld),"-o",str(elf),str(obj))
        call("arm-none-eabi-objcopy","-O","binary",str(elf),str(raw))
        return raw.read_bytes(),relocs,call("arm-none-eabi-nm","-n",str(elf))

def symbol_dict(nm: str) -> dict[str,int]:
    d={}
    for row in nm.splitlines():
        m=SYMBOL_ENTRY.fullmatch(row.strip())
        if m:
            d[m.group(2)]=int(m.group(1),16)
    return d

def verify_physical(v313:bytes,v322:bytes,asm:str,linker:str,builder:str)->dict:
    audited(v313); audited(v322)
    if len(v322)!=EXPECTED_V322_BYTES or hashlib.sha256(v322).hexdigest()!=EXPECTED_V322_SHA:
        raise ValueError("saved v3.22 APP differs from validated experiment")
    # The existing 29-edge audit provides independent source callsite checks.
    unchanged, old_reloc, old_nm, _ = compiled_unchanged_source(asm,linker)
    original=inspect_old_edges(v313,v322,unchanged,old_reloc,old_nm,asm,builder)
    if (original["external_Thumb_branch_relocations_verified"]!=15 or
            original["modified_original_APP_branch_sites_verified"]!=14):
        raise ValueError("29 previously proven v3.22 edges not recovered")
    transformed,ld,refs=physically_relocate_source(asm,linker)
    physical, new_reloc,new_nm=assemble(transformed,ld)
    prefix=PHYSICAL_HANDLER-LINK_BASE
    if (len(physical)!=EXPECTED_HANDLER_BYTES or v322[prefix:]!=physical or
            unchanged!=physical):
        raise ValueError("new physical linker changed bytes of existing tested v3.22 handler")
    old_syms=symbol_dict(old_nm)
    new_syms=symbol_dict(new_nm)
    if set(old_syms)!=set(new_syms):
        raise ValueError("symbol table changed between nominal and physically linked build")
    for name,old in old_syms.items():
        new=new_syms[name]
        if 0x08000000 <= old <0x08100000 and new!=old-DELTA:
            raise ValueError(f"physical symbol drift: {name}: {old:#x} -> {new:#x}")
        if 0x08000000 <= new <0x08100000 and old<0x08000000:
            raise ValueError("new Flash symbol lacks old equivalent")
    old_rl=RELOC_LINE.findall(old_reloc)
    new_rl=RELOC_LINE.findall(new_reloc)
    if len(new_rl)!=EXPECTED_EXTERNAL_RELOCS or len(new_rl)!=len(old_rl):
        raise ValueError("handler OEM external reloc inventory incomplete")
    def decode_reloc(arr):
        return [(int(off,16),kind,int(target,16)) for off,kind,target,_ in arr]
    old_edges=decode_reloc(old_rl);new_edges=decode_reloc(new_rl)
    if [(off,kind,target-DELTA) for off,kind,target in old_edges]!=new_edges:
        raise ValueError("external callsite locations/relocations differ after physical shift")
    if Counter(target for _,_,target in new_edges)!=Counter({
        address-DELTA:num for address,num in EXPECTED_EXTERNAL_TARGET_COUNTS.items()
    }):
        raise ValueError("physical OEM target multiplicity unexpected")
    dis=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    outgoing=[]
    for off,kind,target in new_edges:
        pc=PHYSICAL_HANDLER+off
        instruction=list(dis.disasm(physical[off:off+4],pc,count=1))
        mnemonic="bl" if kind=="R_ARM_THM_CALL" else "b.w"
        if (len(instruction)!=1 or instruction[0].mnemonic!=mnemonic or
                instruction[0].op_str!=f"#{target:#x}"):
            raise ValueError(f"physical branch target failed Thumb decode at {pc:#x}")
        outgoing.append([hex(pc),hex(target)])
    patches=patches_from_builder(builder)
    if patches!=EXPECTED_PATCHES or len(patches)!=14:
        raise ValueError("changed v3.22 patch inventory")
    incoming=[]
    for nominal,name in patches:
        pc=nominal-DELTA;dst=new_syms.get(name)
        if dst is None:
            raise ValueError("missing physical wrapper symbol: "+name)
        off=pc-LINK_BASE
        instruction=list(dis.disasm(v322[off:off+4],pc,count=1))
        if (len(instruction)!=1 or instruction[0].mnemonic!="bl" or
                instruction[0].op_str!=f"#{dst:#x}"):
            raise ValueError(f"saved app OEM patched-callsite drift: {pc:#x}")
        incoming.append([hex(pc),hex(dst),name])
    return {
        "verified_saved_original_32_APP_SHA256":hashlib.sha256(v322).hexdigest(),
        "nominal_builder_base":hex(NOMINAL_BASE),
        "actual_APP_base":hex(LINK_BASE),
        "physical_handler_start":hex(PHYSICAL_HANDLER),
        "physical_handler_bytes":len(physical),
        "physically_relinked_handler_byte_identical_to_hw_validated_v322":True,
        "physically_relinked_handler_SHA256":hashlib.sha256(physical).hexdigest(),
        "rewritten_source_flash_branch_symbols":len(refs),
        "all_13_source_flash_symbols_shifted_by_minus_D000":True,
        "complete_external_Thumb_branch_target_checks":len(outgoing),
        "original_patched_OEM_BL_callsite_checks":len(incoming),
        "physical_external_call_targets":outgoing,
        "physical_OEM_hook_targets":incoming,
        "image_source_original_v322_unchanged":True,
        "fresh_v323_firmware_created":False,
        "bootloader_partition_and_erase_page_owner_authenticated":False,
        "motor_busy_interlock_physically_verified":False,
        "firmware_flash_authorized":False,
        "MCU_hardware_io_performed":False,
    }

def compiled_unchanged_source(source: str,linker:str):
    old,reloc,nm,_=compile_in_temporary(source,linker)
    return old,reloc,nm,None

def compile_in_temporary(source:str,linker:str):
    with tempfile.TemporaryDirectory(prefix="cfs-original-v322-baseline-") as root:
        path=Path(root);asm=path/"handler.S";ld=path/"link.ld"
        asm.write_text(source);ld.write_text(linker)
        return compiled_unchanged(asm,ld)

def negative_tests(v313,v322,src,linker,builder)->list[str]:
    # The negative fixtures test safety fences, not a CPU-side mutation attempt.
    fails=[]
    cases=[
        ("changed_source_ROM_equ",src.replace("0x0803393C","0x0803393E",1),linker),
        ("untracked_new_ROM_equ",src+"\n.equ ROGUE_FLASH, 0x0803393C\n",linker),
        ("lost_expected_ROM_equ",src.replace(".equ STOCK_DONE,", ".equ REMOVED_DONE,",1),linker),
        ("inserted_absolute_ROM_word",src+"\nrogue_pointer: .word 0x0803393C\n",linker),
        ("physical_linker_not_exact_nominal",src,linker.replace(LINKER_EXPECTED,"0x0803AE3A")),
        ("nominal_linker_duplicated",src,linker+"/* 0x0803AE38 */"),
    ]
    for name,s,l in cases:
        try:physically_relocate_source(s,l)
        except ValueError:fails.append(name)
        else:raise AssertionError("unsafe physical relink fixture accepted: "+name)
    mut=bytearray(v322);mut[PHYSICAL_HANDLER-LINK_BASE]^=1
    try:verify_physical(v313,bytes(mut),src,linker,builder)
    except ValueError:fails.append("tampered_saved_handler_image")
    else:raise AssertionError("mutated saved handler approved")
    if len(fails)!=7:raise ValueError("physical toolchain negative tests incomplete")
    return fails

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--asm",required=True,type=Path)
    p.add_argument("--linker",required=True,type=Path)
    p.add_argument("--builder",required=True,type=Path)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    x=p.parse_args()
    a=pinned(x.v313,"intermediate_v313")
    b=pinned(x.v322,"running_v322")
    src=x.asm.read_text();ld=x.linker.read_text();build=x.builder.read_text()
    result=verify_physical(a,b,src,ld,build)
    if x.self_test:result["negative_fixtures_rejected"]=negative_tests(a,b,src,ld,build)
    payload=json.dumps(result,indent=2)+"\n"
    if x.json_out:x.json_out.write_text(payload)
    print(payload,end="")
if __name__=="__main__":main()
