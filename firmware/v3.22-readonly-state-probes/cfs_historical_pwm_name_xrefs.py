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
    # The earlier CFS constructor uses object+0x54 for name and
    # object+0x38 for a generic device callback. Inspect these fields
    # in the ARCHIVED old SRAM only; v3.22 pointer identity unproven.
    old_named_devices=[]
    for entry in ram_hits:
        field=int(entry["initialized_field"],16)
        obj=field-0x54
        pos=obj-RAM_START
        selectors=(0x08,0x14,0x30,0x34,0x38,0x40,0x54)
        if pos<0 or pos+max(selectors)+4>len(recovered):
            raise ValueError("historical named device field outside reconstructed SRAM")
        fields={}
        for of in selectors:
            val=struct.unpack_from("<I",recovered,pos+of)[0]
            older_live=struct.unpack_from("<I",ram,pos+of)[0]
            fields[hex(of)]={
                "initial":hex(val),
                "same_in_historical_snapshot":val==older_live,
                "in_historical_Flash_or_zero":val==0 or
                    FLASH_BASE<=val<FLASH_BASE+len(flash),
            }
        old_named_devices.append({
            "name":entry["pwm_name"],
            "reconstructed_object":hex(obj),
            "fields":fields,
            "has_expected_name_pointer_at_plus_0x54":(
                fields["0x54"]["initial"]==entry["ROM_pointer"]
            ),
        })
    callback_words={x["fields"]["0x38"]["initial"] for x in old_named_devices}
    result={
      "historic_compressed_stream_decoded":True,
      "legacy_source_consumed":status["source_consumed"],
      "legacy_synthetic_data_size":len(recovered),
      "five_ROM_names":names,
      "initialized_RAM_pointer_fields_to_five_pwm_names":ram_hits[:100],
      "historical_named_objects_and_device_operation_fields":old_named_devices,
      "old_five_objects_share_callback_plus_0x38":len(callback_words)==1,
      "old_callback_value_at_plus_0x38_if_shared":(
          next(iter(callback_words)) if len(callback_words)==1 else None),

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
