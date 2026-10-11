#!/usr/bin/env python3
"""Compare v3.13 and v3.22 scatter inputs, and probe bounded source offset hypotheses.

No CFS/CM5 IO, no new flashable firmware, no vendor data bytes emitted.
This script separates:
  * the original 0x0803AA10 scatter descriptor *facts*;
  * whether the exact compressed source changed in the v3.22 builder;
  * a very small exploratory scan around the referenced source.
No scan hit implies a valid loader, a valid type-9 PWM mapping or motor idle.
"""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path
from flash_ram_phase2_audit import APP_BASE, pinned
from cfs_scatter_candidate_decompress_audit import (
    EXPECTED_SCATTER_FIRST, EXPECTED_SCATTER_SECOND, verify_image
)
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar, RejectedStream

NAME_FIELDS = (0x200007B0, 0x20000810, 0x20000870,
               0x200008D0, 0x20000930)
MAX_SHIFT=128

def analyze(v313:bytes, v322:bytes):
    src, dst, n, handler = EXPECTED_SCATTER_FIRST
    stop=EXPECTED_SCATTER_SECOND[0]
    assert tuple(struct.unpack_from("<IIII",v322,
               0x0803AA10-APP_BASE))==EXPECTED_SCATTER_FIRST
    assert tuple(struct.unpack_from("<IIII",v313,
               0x0803AA10-APP_BASE))==EXPECTED_SCATTER_FIRST
    lo=src-APP_BASE; hi=stop-APP_BASE
    a=v313[lo:hi]; b=v322[lo:hi]
    changes=[src+i for i,(x,y) in enumerate(zip(a,b)) if x!=y]
    a_descriptor=v313[0x0803AA10-APP_BASE:0x0803AA30-APP_BASE]
    b_descriptor=v322[0x0803AA10-APP_BASE:0x0803AA30-APP_BASE]
    reports={
        "v313_image_SHA256":hashlib.sha256(v313).hexdigest(),
        "v322_image_SHA256":hashlib.sha256(v322).hexdigest(),
        "same_original_first_scatter_descriptor": a_descriptor==b_descriptor,
        "input_length":len(b),
        "v313_input_SHA256":hashlib.sha256(a).hexdigest(),
        "v322_input_SHA256":hashlib.sha256(b).hexdigest(),
        "input_changed_byte_count":len(changes),
        "first_changed_compressed_byte_addresses":[hex(x) for x in changes[:12]],
        "original_loader_callback":hex(handler),
        "candidate_full_decodes":[],
        "searched_relative_offset_range":[-MAX_SHIFT,MAX_SHIFT],
        "differential_decode_mismatch_at_original_source":None,
        "no_assumed_runtime_name_mapping":True,
        "safe_to_write_while_motor_active":False,
        "safe_to_flash_v323":False,
    }
    for name, image in (("v313",v313),("v322",v322)):
        try:
            status, data=bounded_thumb_grammar(image[lo:hi],n)
        except RejectedStream as e:
            reports[name+"_candidate_decode"]={
                "valid":False, "reason":e.reason, "state":e.state
            }
        else:
            reports[name+"_candidate_decode"]={
                "valid":True, "summary":status,
                "all_five_name_fields_valid_ROM_pointers":all(
                  APP_BASE<=struct.unpack_from("<I",data,field-dst)[0]
                       < APP_BASE+len(image) for field in NAME_FIELDS)
            }
    # Source alignment shift search is exploratory: never use a shifted
    # source to make firmware modifications or infer loader behavior.
    # Include only ranges wholly inside the pinned APP, with length bound
    # by the actual next scatter section.
    end=hi
    for shift in range(-MAX_SHIFT,MAX_SHIFT+1):
        if shift==0: continue
        off=lo+shift
        if off<0 or off>=end:
            continue
        candidate=v322[off:end]
        try: 
            d,scratch=bounded_thumb_grammar(candidate,n)
        except RejectedStream:
            continue
        pointers=[struct.unpack_from("<I",scratch,f-dst)[0] for f in NAME_FIELDS]
        reports["candidate_full_decodes"].append({
            "source_delta_bytes":shift,
            "stream_consumed":d["source_consumed"],
            "source_available":len(candidate),
            "five_possible_rom_pointers":sum(APP_BASE<=x<APP_BASE+len(v322) for x in pointers),
            "all_five_pointers_are_plausible":all(APP_BASE<=x<APP_BASE+len(v322) for x in pointers),
            "this_does_not_validate_bootloader_source_or_PWM_identity":True,
        })
    return reports

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    options=p.parse_args()
    old=pinned(options.v313,"intermediate_v313")
    new=pinned(options.v322,"running_v322")
    verify_image(new)
    evidence=analyze(old,new)
    print(json.dumps(evidence,indent=2))
    if options.json_out:options.json_out.write_text(json.dumps(evidence,indent=2)+"\n")

if __name__=="__main__": main()
