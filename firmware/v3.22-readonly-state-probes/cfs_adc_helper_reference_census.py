#!/usr/bin/env python3
"""Classify manufacturer ADC0 helper direct call/pointer evidence (OFFLINE).

Four source-pinned original ADC register-operation helper entries:
  0x08022926  CTL1 bit-set routine (source local semantics)
  0x08022932  CTL1 bit-clear routine
  0x08022988  CTL0 bit-mask routine
  0x08022BBC  RDATA read routine (potential EOC-clearing)

Halfword disassembly BL counts are *candidates* over mixed code/data,
not reachable motor callers. Aligned little-endian ROM pointer words
may be data and omit computed indirect pointers. No routine is
asserted to be dead solely because both candidate kinds are absent.

Do not access a running MCU or install ADC telemetry; RDATA reads can
modify EOC and can race ordinary conversions.
"""
from __future__ import annotations

import argparse,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE,audited
from cfs_adc0_rdata_source_provenance import CODE,RESULT_HELPER_PC

HELPERS={
    0x08022926:"ADC0_CTL1_MASK_SET",
    0x08022932:"ADC0_CTL1_MASK_CLEAR",
    0x08022988:"ADC0_CTL0_MASK_CHANGE",
    RESULT_HELPER_PC:"ADC0_RDATA_READ",
}
MAX_BL_CANDIDATES=150
MAX_ROM_PTRS=80


def inspect(image:bytes):
    audited(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    refs={pc:{"function":label,"PC":hex(pc),"direct_BL_candidates":[],
              "aligned_ROM_word_refs":[]}
          for pc,label in HELPERS.items()}
    for off in range(0,len(image)-3,2):
        pc=LINK_BASE+off
        ins=next(cs.disasm(image[off:off+4],pc,count=1),None)
        if not ins or ins.mnemonic!="bl" or ins.size!=4:
            continue
        for target in HELPERS:
            if ins.op_str==f"#0x{target:x}":
                refs[target]["direct_BL_candidates"].append(hex(pc))
    for off in range(0,len(image)-3,4):
        word=struct.unpack_from("<I",image,off)[0]
        if (word & ~1) in HELPERS:
            refs[word&~1]["aligned_ROM_word_refs"].append({
               "ROM_slot":hex(LINK_BASE+off),
               "stored_thumb_entry":hex(word),
            })
    for pc,row in refs.items():
        if (len(row["direct_BL_candidates"])>MAX_BL_CANDIDATES or
            len(row["aligned_ROM_word_refs"])>MAX_ROM_PTRS):
            raise ValueError("unexpected ADC source reference growth")
    known=refs[RESULT_HELPER_PC]
    if known["direct_BL_candidates"] or known["aligned_ROM_word_refs"]:
        raise ValueError("previously pinned isolated ADC0_RDATA helper has changed")
    for pc in HELPERS:
        if not any(at==pc for at,_,_ in CODE):
            raise ValueError("expected pinned original source helper absent")
    return {
        "physical_link_base":hex(LINK_BASE),
        "function_entries":list(refs.values()),
        "direct_BL_candidate_total":sum(len(x["direct_BL_candidates"]) for x in refs.values()),
        "aligned_ROM_word_reference_total":sum(len(x["aligned_ROM_word_refs"]) for x in refs.values()),
        "original_ADC0_RDATA_direct_BL_candidates":0,
        "original_ADC0_RDATA_aligned_ROM_pointer_words":0,
        "ADC_helper_reachable_from_actual_motor_control_proven":False,
        "ADC_conversion_rank_and_channel_current_measurement_proven":False,
        "GPIO_motor_hardware_stop_proven":False,
        "safe_to_read_ADC_RDATA_on_live_CFS":False,
        "safe_to_flash_or_SET_RESET_v323":False,
        "real_hardware_access":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=inspect(pinned(a.v313,"intermediate_v313"))
    new=inspect(pinned(a.v322,"running_v322"))
    if old!=new:
        raise ValueError("original ADC helper source references differ between saved v3.13 and v3.22")
    result={"original_v313_v322_reference_census_identical":True,
            "audit":new,
            "ROM_census_does_not_prove_dead_code":True,
            "no_real_CFS_CM5_Kalico_access":True}
    out=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(out)
    print(out,end="")


if __name__=="__main__":
    main()
