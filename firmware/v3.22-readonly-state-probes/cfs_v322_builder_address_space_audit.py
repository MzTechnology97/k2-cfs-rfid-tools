#!/usr/bin/env python3
"""Address-space consistency audit of the CURRENT v3.22 builder (offline).

Important: the saved vendor CFS APP's real link origin is 0x08003000,
while the 2026 custom build tools still use a 0x08010000 nominal
offset coordinate system. This audit CANNOT certify their runtime
absolute stock-call addresses. It enumerates ambiguous references
without changing builder assembly or creating firmware.

No embedded credentials, serial commands, hardware, or flash.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
from flash_ram_phase2_audit import pinned

TRUE_BASE=0x08003000
OLD_OFFSET_BASE=0x08010000
SHIFT=OLD_OFFSET_BASE-TRUE_BASE
EXPECTED_V322_BYTES=178140
EXPECTED_BUILDER_CODE_POSITION=0x0803AE38
EXPECTED_VENDOR_HANDLER_REAL_POSITION=0x0802DE38
SYMBOL_PATTERN=re.compile(
    r"(?m)^\s*\.equ\s+([A-Za-z][A-Za-z0-9_]*),\s*(0x080[0-9A-Fa-f]{5})\b"
)

def audit(builder: str, asm:str, linker:str, image:bytes):
    if len(image)!=EXPECTED_V322_BYTES or SHIFT!=0xD000:
        raise ValueError("unexpected saved image size or APP base discrepancy")
    for line in (
        "APP_BASE=0x08010000",
        "HANDLER_ADDR=0x0803AE38",
        "UNVERIFIED_BUILD_LIMIT=0x0803B800",
    ):
        if line not in builder:
            raise ValueError(f"v3.22 historical builder changed: {line}")
    if "0x0803AE38" not in linker:
        raise ValueError("historical linker location differs from nominal builder")
    offset=EXPECTED_BUILDER_CODE_POSITION-OLD_OFFSET_BASE
    phys=TRUE_BASE+offset
    if phys!=EXPECTED_VENDOR_HANDLER_REAL_POSITION:
        raise AssertionError("handler append location conversion differs")
    end=TRUE_BASE+len(image)
    references=[]
    for name,raw in SYMBOL_PATTERN.findall(asm):
        numeric=int(raw,16)
        if not (TRUE_BASE<=numeric<0x08080000):
            raise ValueError("unexpected absolute stock-code constant")
        references.append({
            "symbol":name,"raw_assembler_literal":hex(numeric),
            "literal_within_saved_vendor_APP_at_correct_origin":
                TRUE_BASE<=numeric<end,
            "literal_within_legacy_nominal_APP_coordinates":
                OLD_OFFSET_BASE<=numeric<OLD_OFFSET_BASE+len(image),
            "alternative_if_legacy_offset_was_used":hex(numeric-SHIFT),
            "absolute_pointer_relocation_verified":False
        })
    if len(references)<10:
        raise ValueError("incomplete stock function address catalogue")
    unsupported=[x for x in references
                 if not x["literal_within_saved_vendor_APP_at_correct_origin"]]
    if not any(x["symbol"]=="STOCK_MEMCMP" and
               x["raw_assembler_literal"]=="0x803393c"
               for x in unsupported):
        raise ValueError("known unverified STOCK_MEMCMP address no longer tracked")
    return {
        "validated_vendor_APP_link_origin":hex(TRUE_BASE),
        "nominal_offset_base_in_old_build_tools":hex(OLD_OFFSET_BASE),
        "nominal_minus_physical_bytes":SHIFT,
        "image_bytes":len(image),
        "verified_physical_saved_APP_end_exclusive":hex(end),
        "historical_builder_nominal_handler_address":hex(EXPECTED_BUILDER_CODE_POSITION),
        "actual_saved_handler_offset_in_file":hex(offset),
        "actual_physical_handler_location_if_APP_starts_at_verified_base":hex(phys),
        "historical_builder_nominal_image_end":hex(OLD_OFFSET_BASE+len(image)),
        "historical_policy_limit_0x0803b800_certified_by_bootloader":False,
        "source_assembly_absolute_flash_function_literals":references,
        "literal_count":len(references),
        "outside_saved_vendor_APP_reference_count":len(unsupported),
        "out_of_image_references":unsupported,
        "BL_relative_displacements_survive_uniform_base_correction":True,
        "external_absolute_references_AUTOMATICALLY_relocated":False,
        "may_flash_or_change_runtime_motor_guard":False,
        "no_production_CFS_or_Kalico_access":True
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--builder",type=Path,required=True)
    p.add_argument("--handler",type=Path,required=True)
    p.add_argument("--linker",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    o=p.parse_args()
    result=audit(o.builder.read_text(),o.handler.read_text(),
                 o.linker.read_text(),pinned(o.v322,"running_v322"))
    s=json.dumps(result,indent=2)+"\n"
    if o.json_out:o.json_out.write_text(s)
    print(s,end="")

if __name__=="__main__":
    main()
