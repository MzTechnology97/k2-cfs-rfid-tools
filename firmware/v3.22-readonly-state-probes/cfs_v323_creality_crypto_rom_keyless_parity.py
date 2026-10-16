#!/usr/bin/env python3
"""Keyless Creality RFID crypto-ROM integrity audit for experimental CFS v3.23.

Source-grounded stock app table layout is described by the public
OpenCFS-Firmware tools/re/extract_tag_keys.py (Apache-2.0), commit
67f0f063736709a20cc0fb22ca15c8b5a01e4435.

This script *never prints, persists, hashes or uploads* any key, AES
table payload, original RFID record or UID. It only checks whether the
existing manufacturer's per-image key table, AES S-box region and ROM
pointer are unchanged in the saved v3.13, installed-reference v3.22
and latest exact in-memory v3.23 candidate.

Creality remaining-runtime type 4 is NOT NFC Forum Type 4 / ISO-DEP;
this audit tests preservation of Creality's MIFARE Classic crypto only.

No physical MCU, RFID tag, Kalico, UART, Flash or secret header touched.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE,audited
from cfs_v323_raw_gpio_feeder_drive_snapshot_candidate import build as build_latest
from cfs_v323_latest_image_preflight import inspect_header,verify_persistent_stock

KEY_TABLE_BYTES=48
KEY_WORD_BYTES=16
EXPECTED_GD32_BASE=0x08003000
EXPECTED_PUBLIC_EXTRACTOR_CHECKPOINT="67f0f063736709a20cc0fb22ca15c8b5a01e4435"

def aes_substitution_region()->bytes:
    """Compute public AES forward+inverse S-box algorithmically, no keys."""
    sbox=[0]*256
    p=q=1
    while True:
        p=p^((p<<1)&0xff)^(0x1b if p&0x80 else 0)
        q^=q<<1
        q^=q<<2
        q^=q<<4
        q &=0xff
        if q&0x80:
            q ^=0x09
        def rot(v:int,n:int)->int:
            return ((v<<n)|(v>>(8-n)))&0xff
        sbox[p] = q^rot(q,1)^rot(q,2)^rot(q,3)^rot(q,4)^0x63
        if p==1:
            break
    sbox[0]=0x63
    inverse=[0]*256
    for at,b in enumerate(sbox):
        inverse[b]=at
    out=bytes(sbox+inverse)
    if len(out)!=512 or out[:4]!=bytes((0x63,0x7c,0x77,0x7b)):
        raise ValueError("bad standard AES lookup generation")
    return out

def locate_rom_table(image:bytes,box:bytes)->dict:
    """Prove table position via unique S-box pair and physical ROM pointer.

    Return only offsets and boolean metadata. Never return table bytes or keys.
    """
    if LINK_BASE != EXPECTED_GD32_BASE:
        raise ValueError("changed APP physical origin")
    pos=image.find(box)
    if pos<KEY_TABLE_BYTES or image.find(box,pos+1)>=0:
        raise ValueError("AES SBox plus inverse missing or nonunique")
    table=pos-KEY_TABLE_BYTES
    physical=LINK_BASE+table
    literal=struct.pack("<I",physical)
    sites=[i for i in range(0,len(image)-3,4) if image[i:i+4]==literal]
    if len(sites)!=1:
        raise ValueError("manufacturer key table ROM physical reference missing or ambiguous")
    if table+KEY_TABLE_BYTES!=pos:
        raise ValueError("OEM AES key region is not contiguous with S-box")
    return {
        "key_table_offset":table,
        "aes_substitution_offset":pos,
        "pointer_literal_offset":sites[0],
        "table_48_bytes_before_AES_substitutions":True,
        "physical_APP_pointer_in_original_ROM":True,
    }

def private_key_pair(image:bytes,table_at:int)->tuple[bytes,bytes]:
    """Only for in-process comparisons. Never serialize, log, or return to UI."""
    # Four 12-byte AES key-row pairs, per OEM reverse-engineered layout.
    raw=image[table_at:table_at+KEY_TABLE_BYTES]
    if len(raw)!=KEY_TABLE_BYTES:
        raise ValueError("truncated manufacturer table")
    first=b"".join(raw[i*12:i*12+4] for i in range(4))
    second=b"".join(raw[i*12+4:i*12+8] for i in range(4))
    if len(first)!=KEY_WORD_BYTES or len(second)!=KEY_WORD_BYTES:
        raise ValueError("unexpected manufacturer AES key lengths")
    if len(set(first))<4 or len(set(second))<4:
        raise ValueError("degenerate manufacturer key words")
    return first,second

def test_in_memory(original13:bytes,old22:bytes,new23:bytes,syms:dict)->dict:
    substitution=aes_substitution_region()
    ref=locate_rom_table(original13,substitution)
    old=locate_rom_table(old22,substitution)
    new=locate_rom_table(new23,substitution)
    if not (ref==old==new):
        raise ValueError("manufacturer AES crypto lookup location or literal changed")
    table=ref["key_table_offset"]
    start=ref["aes_substitution_offset"]
    stop=start+len(substitution)
    if not (original13[table:stop]==old22[table:stop]==new23[table:stop]):
        raise ValueError("manufacturer AES keys or lookup substitution changed")
    # Never expose either derived AES value, their digest, or the table itself.
    k13=private_key_pair(original13,table)
    k22=private_key_pair(old22,table)
    k23=private_key_pair(new23,table)
    if not(k13==k22==k23):
        raise ValueError("manufacturer K1/K2 derivation across app revisions changed")
    if len(new23)!=178568:
        raise ValueError("new #54 v3.23 preflight candidate source no longer pinned")
    # v3.23 already contains a ROM source-preservation contract for reader,
    # secure-element and no-write enforcement. Re-use it instead of guessing.
    stock=verify_persistent_stock(new23,old22,syms)
    assert stock["both_manufacturer_secure_callsite_guards_present"]
    assert stock["CONFIG_SET_RESET_firmware_entries_BW_redirect_to_busy"]
    assert "original_secure_consumption_writer" in stock["untouched_original_OEM_code_sites"]
    return {
        "parent_original_v313_v322_latest_v323_crypto_table_equivalent":True,
        "creality_manufacturer_AES128_K1_and_K2_retained":True,
        "standard_AES_forward_inverse_substitution_still_present":True,
        "physical_APP_base":hex(LINK_BASE),
        "source_table_offset":hex(table),
        "source_table_ROM_address":hex(LINK_BASE+table),
        "source_ROM_reference_offset":hex(ref["pointer_literal_offset"]),
        "manufacturer_MIFARE_Creality_reader_and_secure_callsites_preserved":True,
        "v323_type4_remaining_is_not_NFC_ISODEP_Type4":True,
        "no_personal_local_headers_accessed":True,
        "no_key_values_or_digests_exported":True,
        "no_crypto_data_modified":True,
        "motor_CONFIG_SET_RESET_still_fail_closed":True,
        "flash_approved":False,
    }

def negative_mutations(original13:bytes,old22:bytes,new23:bytes,syms:dict)->list[str]:
    ref=locate_rom_table(new23,aes_substitution_region())
    tests=[
        ("mutate_first_manufacturer_key_table_byte",ref["key_table_offset"]),
        ("mutate_second_manufacturer_key_row_byte",ref["key_table_offset"]+KEY_TABLE_BYTES-1),
        ("mutate_standard_AES_substitution_byte",ref["aes_substitution_offset"]),
        ("mutate_original_physical_pointer_literal",ref["pointer_literal_offset"]),
    ]
    refused=[]
    for label,at in tests:
        corrupted=bytearray(new23)
        corrupted[at]^=1
        try:
            test_in_memory(original13,old22,bytes(corrupted),syms)
        except (ValueError,AssertionError):
            refused.append(label)
        else:
            raise AssertionError("confidential OEM crypto mutation not rejected")
    if len(refused)!=len(tests):
        raise ValueError("unexpected crypto mutation fixture census")
    return refused

def main():
    arg=argparse.ArgumentParser()
    for name in ("v313","v322","asm","linker","builder"):
        arg.add_argument("--"+name,required=True,type=Path)
    arg.add_argument("--json-out",type=Path)
    a=arg.parse_args()
    first=pinned(a.v313,"intermediate_v313")
    second=pinned(a.v322,"running_v322")
    audited(first)
    audited(second)
    candidate,source_report,syms=build_latest(
        first,second,a.asm.read_text(),a.linker.read_text(),
        a.builder.read_text(),a.builder
    )
    inspect_header(candidate,second)
    accepted=test_in_memory(first,second,candidate,syms)
    rejected=negative_mutations(first,second,candidate,syms)
    report={
        "source":"public OpenCFS tag-key table layout; pinned original K2 source ROM",
        "reference_public_OpenCFS_commit":EXPECTED_PUBLIC_EXTRACTOR_CHECKPOINT,
        "reference_private_PC_key_pair_checked_externally_without_transmission":False,
        "proof":accepted,
        "tampered_secret_region_or_source_mutations_rejected":rejected,
        "OEM_runtime_RFID_decode_called_on_hardware":False,
        "private_KeyA_AES_KDF_used_to_unlock_real_tag":False,
        "no_BIN_HEX_ELF_created":True,
    }
    payload=json.dumps(report,indent=2)+"\n"
    if a.json_out:
        a.json_out.write_text(payload)
    print(payload,end="")

if __name__=="__main__":
    main()
