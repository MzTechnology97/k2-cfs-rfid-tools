#!/usr/bin/env python3
"""Cross-check ONE pinned manufacturer Thumb token grammar on two CFS inputs.

Old public 2025 CFS: 600-byte packed stream expands into 2844 SRAM bytes.
Exact v3.22 saved APP: 716-byte packed stream targets 3012 SRAM bytes.

The historical bootloader decompressor @0x0800316C is byte-identical
to the v3.22 APP's bundled @0x0801016C for all 92 bytes, but the
physical bootloader on the user's installed CFS is NOT authenticated.

Emits only summary lengths, failure reason and hash; no proprietary
compressed stream, raw RAM, serial commands, motor calls or firmware.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from flash_ram_phase2_audit import pinned, APP_BASE
from cfs_historical_bootloader_compare import (
    verify_public_blob, find_historical_scatter_descriptors, FLASH_BASE,
)
from cfs_scatter_candidate_decompress_audit import (
    EXPECTED_SCATTER_FIRST, EXPECTED_SCATTER_SECOND, verify_image,
)


class RejectedStream(Exception):
    def __init__(self, reason:str, state:dict):
        super().__init__(reason)
        self.reason=reason
        self.state=state


def bounded_thumb_grammar(src:bytes, out_len:int):
    # Faithful control grammar of pinned APP/old-loader Thumb:
    # low3 = literal count+1, zero extended from next source byte;
    # upper nibble = repeat count, zero extended from next byte;
    # bit3: copy from output history (repeat+2) or zero-fill (repeat).
    out=bytearray()
    cur=0
    tokens=0
    def get():
        nonlocal cur
        if cur>=len(src):
            raise RejectedStream("source_exhausted",{"source_consumed":cur,
                     "output_written":len(out),"tokens":tokens})
        value=src[cur]
        cur+=1
        return value
    while len(out)<out_len:
        tokens+=1
        if tokens>out_len:
            raise RejectedStream("no_forward_progress",
                 {"tokens":tokens,"source_consumed":cur,"output_written":len(out)})
        initial=len(out)
        tag=get()
        literal=tag&7
        if literal==0:
            literal=get()
        repeat=tag>>4
        if repeat==0:
            repeat=get()
        if literal==0:
            raise RejectedStream("zero_literal_underflow",{
                "tokens":tokens,"source_consumed":cur,"output_written":len(out)})
        for _ in range(literal-1):
            if len(out)>=out_len:
                raise RejectedStream("literal_exceeds_output",{
                    "tokens":tokens,"source_consumed":cur,"output_written":len(out)})
            out.append(get())
        if tag&8:
            distance=get()
            if not (0<distance<=len(out)):
                raise RejectedStream("uninitialized_backreference",{
                   "tokens":tokens,"source_consumed":cur,
                   "output_written":len(out),"distance":distance})
            for _ in range(repeat+2):
                if len(out)>=out_len:
                    raise RejectedStream("history_exceeds_output",{
                        "tokens":tokens,"source_consumed":cur,"output_written":len(out)})
                out.append(out[-distance])
        else:
            if repeat>out_len-len(out):
                raise RejectedStream("zero_exceeds_output",{
                    "tokens":tokens,"source_consumed":cur,"output_written":len(out)})
            out.extend(bytes(repeat))
        if len(out)<=initial:
            raise RejectedStream("no_forward_progress",{
                "tokens":tokens,"source_consumed":cur,"output_written":len(out)})
    return {"valid":True,"source_consumed":cur,"source_capacity":len(src),
            "output_bytes":len(out),"tokens":tokens,
            "decoded_SHA256":hashlib.sha256(out).hexdigest()},bytes(out)


def try_stream(source:bytes,n:int,snapshot:bytes|None=None):
    try:
        report,data=bounded_thumb_grammar(source,n)
    except RejectedStream as e:
        return {"valid":False,"reason":e.reason,
                "state":e.state,"expected_output":n,
                "source_capacity":len(source),
                "any_device_names_authenticated":False}
    if snapshot is not None and len(snapshot)>=n:
        report["historical_snapshot_matching_output_byte_count"] = sum(
            a==b for a,b in zip(data,snapshot[:n]))
        report["historical_snapshot_contains_runtime_mutations_possible"]=True
    report["any_device_names_authenticated"]=False
    return report


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--public-flash",required=True,type=Path)
    ap.add_argument("--public-ram",required=True,type=Path)
    ap.add_argument("--v322",required=True,type=Path)
    ap.add_argument("--json-out",type=Path)
    args=ap.parse_args()
    flash=args.public_flash.read_bytes()
    ram=args.public_ram.read_bytes()
    current=pinned(args.v322,"running_v322")
    verify_public_blob(flash,"flash")
    verify_public_blob(ram,"ram")
    verify_image(current)
    descriptors=find_historical_scatter_descriptors(flash)
    comp=[r for r in descriptors if r["handler_role"]=="compressed"]
    zero=[r for r in descriptors if r["handler_role"]=="zero"]
    if len(comp)!=1 or len(zero)!=1:
        raise ValueError("expected exactly one public original CFS compressed and zero region")
    old=comp[0]
    lo=int(old["source"],16)-FLASH_BASE
    hi=int(zero[0]["source"],16)-FLASH_BASE
    if (lo,hi,old["output_bytes"]) != (0x278d0,0x27b28,2844):
        raise ValueError("historical CFS packed source bounds changed")
    source,_,amount,_=EXPECTED_SCATTER_FIRST
    new_src=current[source-APP_BASE:
        EXPECTED_SCATTER_SECOND[0]-APP_BASE]
    old_result=try_stream(flash[lo:hi],old["output_bytes"],ram)
    new_result=try_stream(new_src,amount)
    result={
      "public_original_2025":old_result,
      "current_saved_APP_v322":new_result,
      "old_scatter_source_bytes":hi-lo,
      "old_scatter_output_bytes":old["output_bytes"],
      "new_scatter_source_bytes":len(new_src),
      "new_scatter_output_bytes":amount,
      "same_bytes_at_historical_bootloader_vs_APP_candidate":(
          flash[0x316c:0x31c8] ==
          current[0x1016c-APP_BASE:0x101c8-APP_BASE]),
      "actual_deployed_bootloader_verified":False,
      "physical_CFS_access":False,
      "motor_safety_release_authorized":False,
    }
    if not result["same_bytes_at_historical_bootloader_vs_APP_candidate"]:
        raise ValueError("public original decoder and current APP differ")
    body=json.dumps(result,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":
    main()
