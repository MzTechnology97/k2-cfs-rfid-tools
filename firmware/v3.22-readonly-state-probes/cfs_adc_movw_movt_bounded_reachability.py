#!/usr/bin/env python3
"""Bounded non-adjacent MOVW/MOVT ADC address formation (offline only).

Complement the original strict adjacent MOVW/MOVT census by looking for
a MOVT writing the SAME register within at most 12 straight-line Thumb
instructions after MOVW, with no intervening write to that register,
branch, function call, stack-pop, IT conditional or decode gap.

Important epistemic boundary:
- Arbitrary halfword starts include ROM data and unreachable code.
- A pair constructing ADC MMIO is *not* evidence of ADC conversion.
- Zero matches is not proof of no indirect, arithmetic, table, DMA,
  runtime/ISR or other motor-current conversion path.
- Nothing on the CFS / CM5 / Kalico is read or changed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_REG
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_adc_gpio_literal_xref_discovery import PERIPHERALS

MAX_GAP_INSTRUCTIONS = 12
MAX_DIAGNOSTIC_MATCHES = 80
FLOW = {"bl", "blx", "bx", "cbz", "cbnz", "pop", "tbb", "tbh",
        "svc", "udf", "bkpt"}


def one(cs, image: bytes, offset: int):
    if offset < 0 or offset+2 > len(image):
        return None
    at=LINK_BASE+offset
    return next(cs.disasm(image[offset:min(len(image),offset+4)],at,count=1),None)


def is_flow_barrier(ins) -> bool:
    # Fail closed rather than tracking values across conditional flows.
    m=ins.mnemonic
    return (m in FLOW or m.startswith("b.") or m in ("b","b.w","it",
            "itt","ite","ittt","itttt","itet","ittee") or m.startswith("it"))


def tracked_writes(ins, reg: int) -> bool:
    try:
        _, writes=ins.regs_access()
    except Exception:
        return True
    return reg in writes


def inspect(image:bytes):
    audited(image)
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    discovered=[]
    starts=0
    terminating={"flow":0,"overwrite":0,"decode":0,"limit":0}
    for offset in range(0,len(image)-3,2):
        first=one(cs,image,offset)
        if (first is None or first.mnemonic!="movw"
                or len(first.operands)!=2
                or first.operands[0].type!=ARM_OP_REG
                or first.operands[1].type!=ARM_OP_IMM):
            continue
        starts+=1
        reg=first.operands[0].reg
        low=first.operands[1].imm & 0xffff
        loc=offset+first.size
        steps=0
        while steps<MAX_GAP_INSTRUCTIONS:
            next_ins=one(cs,image,loc)
            if next_ins is None or next_ins.address!=LINK_BASE+loc:
                terminating["decode"]+=1
                break
            if is_flow_barrier(next_ins):
                terminating["flow"]+=1
                break
            if (next_ins.mnemonic=="movt"
                    and len(next_ins.operands)==2
                    and next_ins.operands[0].type==ARM_OP_REG
                    and next_ins.operands[1].type==ARM_OP_IMM
                    and next_ins.operands[0].reg==reg):
                address=low | ((next_ins.operands[1].imm&0xffff)<<16)
                for name,(lo,hi) in PERIPHERALS.items():
                    if name.startswith("ADC") and lo<=address<hi:
                        discovered.append({
                            "MOVW_pc":hex(LINK_BASE+offset),
                            "MOVT_pc":hex(LINK_BASE+loc),
                            "intervening_instructions":steps,
                            "result":hex(address),
                            "ADC_peripheral":name,
                            "offset_in_peripheral":hex(address-lo),
                            "original_ROM_byte_evidence_only":True,
                            "reachability_or_motor_sampling_proven":False,
                        })
                break
            if tracked_writes(next_ins,reg):
                terminating["overwrite"]+=1
                break
            loc+=next_ins.size
            steps+=1
        else:
            terminating["limit"]+=1
    if len(discovered)>MAX_DIAGNOSTIC_MATCHES:
        raise ValueError("too many possible ADC MOVW/MOVT pairs: manual review required")
    return {
        "correct_saved_APP_origin":hex(LINK_BASE),
        "halfword_scan_MOVW_candidates":starts,
        "bounded_window_max_following_instructions":MAX_GAP_INSTRUCTIONS,
        "stop_statistics":terminating,
        "ADC_MOVW_MOVT_bounded_candidates":discovered,
        "matched_ADC_candidate_count":len(discovered),
        "actual_original_motor_ADC_channel_owner_authenticated":False,
        "complete_address_construction_coverage_proven":False,
        "physical_motor_idle_proven":False,
        "safe_to_read_live_ADC_RDATA":False,
        "motor_active_SET_RESET_write_or_v323_flash_allowed":False,
        "real_device_interaction":False
    }


def synthetic_contract():
    # Fake bytes are a *decoder contract*, not reconstructed CFS RAM.
    # movw r2,#0x244c; nop; movt r2,#0x4001 -> 0x4001244c.
    asm = bytes.fromhex("42f64c42 00bf c4f20102".replace(" ",""))
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    seq=list(cs.disasm(asm,LINK_BASE))
    if len(seq)!=3:
        raise AssertionError("unexpected Thumb reference fixture decode")
    # Verify fixture syntactically, not by hard-coding a claimed CFS result.
    if (seq[0].mnemonic,seq[1].mnemonic,seq[2].mnemonic)!=("movw","nop","movt"):
        raise AssertionError("reference MOVW/NOP/MOVT pair invalid")
    constructed=(seq[0].operands[1].imm&0xffff)|((seq[2].operands[1].imm&0xffff)<<16)
    if constructed!=0x4001244c:
        raise AssertionError(f"fixture ADC register addr changed: {constructed:#x}")
    return {"synthetic_bounded_pair_validated":True,
            "synthetic_address":hex(constructed),
            "no_original_CFS_execution_derived_from_fixture":True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    old=inspect(pinned(args.v313,"intermediate_v313"))
    new=inspect(pinned(args.v322,"running_v322"))
    report={
        "original_v313_v322_bounded_candidates_identical":old==new,
        "original_v313":old,
        "original_v322":new,
        "reference_synthetic_fixture":synthetic_contract(),
        "no_actual_CFS_or_CM5_read":True,
        "no_ADC_EOC_side_effect_and_no_firmware_flash":True,
    }
    payload=json.dumps(report,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(payload)
    print(payload,end="")


if __name__=="__main__":
    main()
