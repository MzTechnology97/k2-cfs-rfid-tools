#!/usr/bin/env python3
"""Find original PWM name-to-SRAM pointer relationships in archived 2025 CFS.

The 2025 raw Flash and RAM snapshot are public and independently captured.
The old scatter stream decompresses 2,844 bytes under the byte-identical
CFS old-loader/current-APP Thumb decoder. Scan ONLY that decoded, original
initialized image for explicit pointers to five ROM strings and compare
observed runtime SRAM (snapshot); don't assume v3.22 layout is identical.

Does not publish old Flash/RAM contents or execute live CFS commands.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from cfs_historical_bootloader_compare import (
  FLASH_BASE, RAM_BASE, verify_public_blob, find_historical_scatter_descriptors,
)
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar

NAMES = ("pwm1","pwm3","pwm4","pwm5","pwm8")
RAM_START = 0x20000000
DECODED_RAM_BYTES = 2844


def analyze(flash:bytes, ram:bytes):
    verify_public_blob(flash,"flash")
    verify_public_blob(ram,"ram")
    ds=find_historical_scatter_descriptors(flash)
    pair=[d for d in ds if d["handler_role"]=="compressed"]
    if len(pair)!=1:
        raise ValueError("historical bootloader does not have the expected one compressed descriptor")
    desc=pair[0]
    if (desc["source"],desc["destination"],desc["output_bytes"])!=(
        "0x80278d0","0x20000000",DECODED_RAM_BYTES
    ):
        raise ValueError("historical RAM descriptor changed")
    lo=0x080278D0-FLASH_BASE
    hi=0x08027B28-FLASH_BASE
    status,recovered=bounded_thumb_grammar(flash[lo:hi],DECODED_RAM_BYTES)
    if (not status["valid"] or len(recovered)!=DECODED_RAM_BYTES
        or status["source_consumed"]!=599):
        raise ValueError("historical scratch RAM reconstruction incomplete")
    names=[]
    for n in NAMES:
        needle=n.encode("ascii")+b"\x00"
        locations=[]
        p=0
        while True:
            p=flash.find(needle,p)
            if p<0:break
            address=FLASH_BASE+p
            # Scan every aligned 32-bit word in fully decoded historical
            # data region for exact pointer to this *specific* string.
            refs=[]
            for off in range(0,len(recovered)-3,4):
                value=struct.unpack_from("<I",recovered,off)[0]
                if value==address:
                    runtime=struct.unpack_from("<I",ram,off)[0]
                    refs.append({
                        "decoded_RAM_reference_field":hex(RAM_START+off),
                        "historical_later_snapshot_same_pointer":runtime==address,
                    })
            locations.append({"ROM_string":hex(address),
                              "decoded_RAM_pointer_refs":refs,
                              "pointer_reference_count":len(refs)})
            p+=1
        names.append({"name":n,"ROM_occurrences":locations,
                      "initialized_RAM_refs_found":sum(x["pointer_reference_count"]
                           for x in locations)})
    refs_per_name=[n["initialized_RAM_refs_found"] for n in names]
    ram_hits=[]
    for off in range(0,len(recovered)-3,4):
        val=struct.unpack_from("<I",recovered,off)[0]
        if not (FLASH_BASE<=val<FLASH_BASE+len(flash)):
            continue
        body=flash[val-FLASH_BASE:val-FLASH_BASE+9]
        prefix=body.split(b"\x00",1)[0]
        if prefix.decode("ascii","ignore") in NAMES:
            ram_hits.append({"initialized_field":hex(RAM_START+off),
                             "pwm_name":prefix.decode("ascii"),
                             "ROM_pointer":hex(val),
                             "matched_in_snapshot":struct.unpack_from("<I",ram,off)[0]==val})
    result={
      "historic_compressed_stream_decoded":True,
      "legacy_source_consumed":status["source_consumed"],
      "legacy_synthetic_data_size":len(recovered),
      "five_ROM_names":names,
      "initialized_RAM_pointer_fields_to_five_pwm_names":ram_hits[:100],
      "total_RAM_pointer_fields":len(ram_hits),
      "some_named_objects_inferred_by_string_pointer_ONLY":bool(ram_hits),
      "layout_safely_transferable_to_v322":False,
      "real_v322_PWM1_callback_known":False,
      "live_CFS_hardware_access":False,
      "motor_stop_feedback_proven":False,
    }
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--public-flash",required=True,type=Path)
    p.add_argument("--public-ram",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    data=analyze(a.public_flash.read_bytes(),a.public_ram.read_bytes())
    body=json.dumps(data,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":
    main()
