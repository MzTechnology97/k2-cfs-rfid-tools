#!/usr/bin/env python3
"""Correct the original 102 motor command BL addresses, offline only.

Historical motor_command_callgraph_audit.py used 0x08010000 as a
SYNTHETIC origin while the saved CFS APP was linked at 0x08003000.
Rebase its known SHA-pinned 102 call sites and their Thumb relative
branch targets by exactly -0xD000, then *re-decode source bytes* at
the physical PC to verify that the relationship truly holds.

This preserves only source-accurate command-flow facts, not physical
motor/encoder feedback or a safe MCU motor-busy guard.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from flash_ram_phase2_audit import APP_BASE, pinned
from cfs_app_real_link_base_audit import LINK_BASE, audited
from motor_command_callgraph_audit import CALLS, TAILS, VERIFIED_INSTRUCTIONS

DELTA = APP_BASE - LINK_BASE


def single(image:bytes, legacy_pc:int, cs):
    pc=legacy_pc-DELTA
    off=pc-LINK_BASE
    if not 0<=off<=len(image)-4:
        raise ValueError("physical source address not within binary")
    instruction=next(cs.disasm(image[off:off+4],pc,count=1),None)
    if instruction is None or instruction.address!=pc:
        raise ValueError("no valid original Thumb instruction at real PC")
    return instruction


def analyze(image:bytes):
    audited(image)  # Ensure vector, original scatter and PWM identities.
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    checks=[]
    for old_target, sites in CALLS.items():
        real_target=old_target-DELTA
        for old_site in sites:
            ins=single(image,old_site,cs)
            if (ins.mnemonic!="bl" or ins.size!=4
                    or ins.op_str!=f"#0x{real_target:x}"):
                raise ValueError(
                    f"original motor BL site fails physical rebasing:"
                    f" {old_site:#x} {ins.mnemonic} {ins.op_str}")
            checks.append({"from":hex(old_site-DELTA),"to":hex(real_target)})
    if len(checks)!=102 or len(set(x["from"] for x in checks))!=102:
        raise ValueError("102 original BL source sites not unique")
    tails=[]
    for old_site,old_target in TAILS.items():
        ins=single(image,old_site,cs)
        dest=old_target-DELTA
        if not ins.mnemonic.startswith("b") or ins.op_str!=f"#0x{dest:x}":
            raise ValueError("rebased motor wrapper tail no longer targets shared routine")
        tails.append({"from":hex(old_site-DELTA),"to":hex(dest)})
    pinned_context=[]
    for old_at,(mnemonic,operands) in VERIFIED_INSTRUCTIONS.items():
        ins=single(image,old_at,cs)
        if (ins.mnemonic,ins.op_str)!=(mnemonic,operands):
            raise ValueError(f"motor command Thumb opcode changed under physical base at {old_at:#x}")
        pinned_context.append(hex(old_at-DELTA))
    return {
      "real_APP_link_base":hex(LINK_BASE),
      "legacy_artificial_link_base":hex(APP_BASE),
      "corrected_PC_delta":-DELTA,
      "physical_rebased_BL_count":len(checks),
      "physical_forward_BL":len(CALLS[next(k for k in CALLS if k==0x0801E164)]),
      "physical_reverse_BL":len(CALLS[0x0801E17E]),
      "physical_zero_command_BL":len(CALLS[0x0801E198]),
      "physical_direct_controller_BL":len(CALLS[0x0801E0CC]),
      "corrected_common_controller_PC":hex(0x0801E0CC-DELTA),
      "corrected_forward_PC":hex(0x0801E164-DELTA),
      "corrected_reverse_PC":hex(0x0801E17E-DELTA),
      "corrected_zero_command_PC":hex(0x0801E198-DELTA),
      "rebased_calls":checks,
      "rebased_tail_branches":tails,
      "rebased_pin_addresses":pinned_context,
      "physical_encoder_idle_feedback_proven":False,
      "covers_other_indirect_or_async_motion_paths":False,
      "source_code_proves_motor_STOP":False,
      "safe_to_add_MCU_trace_hook":False,
      "safe_to_authorize_MCU_writes":False
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    earlier=analyze(pinned(args.v313,"intermediate_v313"))
    latest=analyze(pinned(args.v322,"running_v322"))
    if earlier!=latest:
        raise ValueError("v3.13 and v3.22 physical motor command callgraphs differ")
    report={"versions_same_physically_rebased_callgraph":True,
            "v322":latest,
            "actual_installed_CFS_read":False,
            "v323_flash_release_authorized":False}
    body=json.dumps(report,indent=2)+"\n"
    if args.json_out:
        args.json_out.write_text(body)
    print(body,end="")

if __name__=="__main__":
    main()
