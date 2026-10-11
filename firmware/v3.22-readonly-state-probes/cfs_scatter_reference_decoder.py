#!/usr/bin/env python3
"""Conservative *reference* decoder for a CFS scatter data candidate.

This Python transcription models the observed Thumb token state machine
at 0x0801016C. It does NOT execute the real bootloader implementation
at 0x0800316C, which has not been dumped. Sanitized values ONLY.

The source region is 0x0802DB6C..0x0802DE38 in SHA-pinned v3.22.
The output is capped at 0xBC4 bytes in a *private, simulated* RAM copy.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from flash_ram_phase2_audit import APP_BASE, pinned
from cfs_scatter_candidate_decompress_audit import (
    verify_image, EXPECTED_SCATTER_FIRST, EXPECTED_SCATTER_SECOND,
    OBJ_BASE, OBJ_STRIDE, NUM_OBJECTS,
)

NAME_ROM_STRINGS = {
    0x080399E4:"pwm1",
    0x080399EC:"pwm3",
    0x080399F4:"pwm4",
    0x080399FC:"pwm5",
    0x08039A04:"pwm8",
}


def candidate_decode(image: bytes) -> dict:
    source, destination, output_limit, handler = EXPECTED_SCATTER_FIRST
    pointer=source-APP_BASE
    source_limit=EXPECTED_SCATTER_SECOND[0]-APP_BASE
    out=bytearray()
    first_tokens=[]
    count=0

    def take_byte() -> int:
        nonlocal pointer
        if pointer >= source_limit:
            raise ValueError("input advanced past next original scatter descriptor")
        byte=image[pointer]
        pointer+=1
        return byte

    while len(out)<output_limit:
        count+=1
        if count>output_limit:
            raise ValueError("scatter decoder no forward progress")
        tag=take_byte()
        lit_n=tag & 7
        if lit_n==0:
            lit_n=take_byte()
        rep_n=tag>>4
        if rep_n==0:
            rep_n=take_byte()
        if lit_n<1 or lit_n-1>output_limit-len(out):
            raise ValueError("invalid codeword literal count")
        for _ in range(lit_n-1):
            out.append(take_byte())
        if tag & 8:
            off=take_byte()
            if off==0 or off>len(out):
                raise ValueError("invalid scatter history distance")
            rep_n+=2
            if rep_n>output_limit-len(out):
                raise ValueError("backref exceeds declared destination")
            for _ in range(rep_n):
                out.append(out[-off])
            action="history-copy"
        else:
            if rep_n>output_limit-len(out):
                raise ValueError("zero run exceeds declared destination")
            out.extend(bytes(rep_n))
            action="zero-fill"
        if len(first_tokens)<6:
            first_tokens.append({
                "src_consumed":pointer-(source-APP_BASE),
                "dst_produced":len(out),
                "action":action,
                "literal_count":lit_n-1,
                "repeat_count":rep_n,
            })
    if len(out)!=output_limit:
        raise ValueError("decoder output length differs from RAM descriptor")
    obj=[]
    for i in range(NUM_OBJECTS):
        ram_obj=OBJ_BASE+i*OBJ_STRIDE
        off=ram_obj+0x54-destination
        pointer_value=struct.unpack_from("<I",out,off)[0]
        if pointer_value in NAME_ROM_STRINGS:
            name=NAME_ROM_STRINGS[pointer_value]
        elif destination<=pointer_value<destination+len(out):
            q=pointer_value-destination
            raw=bytes(out[q:q+20]).split(b"\x00",1)[0]
            name=(raw.decode("ascii","replace")
                  if raw and all(32<=x<127 for x in raw) and len(raw)<=8
                  else None)
        else:
            name=None
        obj.append({
            "index":i,
            "object_RAM":hex(ram_obj),
            "name_field_RAM":hex(ram_obj+0x54),
            "decoded_pointer_if_algorithm_matches":hex(pointer_value),
            "sanitized_name_if_resolvable":name,
            "actual_live_memory_observed":False,
        })
    return {
        "candidate_decoder_method":"manual Python translation of APP Thumb token machine",
        "tokens":count,
        "source_bytes_consumed":pointer-(source-APP_BASE),
        "source_capacity_bytes":source_limit-(source-APP_BASE),
        "output_bytes":len(out),
        "initial_token_trace":first_tokens,
        "five_candidate_objects":obj,
        "real_bootloader_decompressor_executed":False,
        "actual_CFS_PWM1_callback_identified":False,
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--v322",required=True,type=Path)
    ap.add_argument("--json-out",type=Path)
    args=ap.parse_args()
    image=pinned(args.v322,"running_v322")
    original=verify_image(image)
    decoded=candidate_decode(image)
    evidence={
      "source":original,
      "counterfactual_reference_decoder":decoded,
      "physical_CFS_accessed":False,
      "installed_bootloader_ownership_proven":False,
      "actual_runtime_pwm1_name_pointer_proven":False,
      "independent_motor_stop_proven":False,
      "expanded_v323_firmware_safe_to_flash":False,
    }
    body=json.dumps(evidence,indent=2)+"\n"
    if args.json_out:
        args.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":
    main()
