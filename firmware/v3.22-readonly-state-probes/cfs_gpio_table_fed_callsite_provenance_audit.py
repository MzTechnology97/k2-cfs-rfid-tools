#!/usr/bin/env python3
"""Offline source-level classification of formerly ambiguous OEM GPIO write calls.

The CFS firmware uses table-fed GPIO pin IDs, not only MOVS immediates.
Recover the original Keil-initialized RAM 0x20000594/598 pin pair and
ROM 0x0802B4CC pin pair, then audit reviewed CALLSITE->LDR->TABLE edges
at the *physical* APP PC 0x08003000.

Does not prove live SRAM retains those values, motor start-path coverage,
real GPIO/driver state, physical motor stop, or flash safety.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB

from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar
from cfs_m1_m2_gpio_helper_callsites import inspect as existing_census
from cfs_gpio_bounded_argument_provenance import inspect as immediate_census

GPIO_WRITE = 0x08018EEC
ROM_INPUT_START = 0x0802DB6C
ROM_INPUT_END = 0x0802DE38
RAM_OUT = 3012
RAM_PIN_PAIR = 0x20000594
PIN_DATA_ROOT = 0x080147CC
PIN_DATA_ROOT_2 = 0x08015DAC
ROM_PIN_PAIR = 0x0802B4CC
ROM_PIN_PAIR_PTR_LITERAL = 0x0801B894
ROM_PINS = (0x2B, 0x2C)
RAM_PINS = (0x1A, 0x1B)
M1_M2_IDS = (0x30, 0x31, 0x32, 0x33)
EXPECTED_ALL_BL_CANDIDATES = 122

# Each independently reviewed entry records original physical PC of
# BL, source "LDR r0,[r4,#N]" and which RAM word it addresses.
# LDR r4,ROM literal -> r4=RAM_PIN_PAIR is independently pinned below.
TABLE_RAM_CALLS = {
    0x08014438: (0x08014436, 0), 0x08014440: (0x0801443E, 4),
    0x08014480: (0x0801447E, 4), 0x08014488: (0x08014486, 0),
    0x08014496: (0x08014494, 4), 0x080144B6: (0x080144B4, 0),
    0x080144C0: (0x080144BE, 0), 0x080144D6: (0x080144CC, 4),
    0x080144E2: (0x080144E0, 0), 0x080144F6: (0x080144F4, 0),
    0x08014508: (0x08014506, 0), 0x0801452E: (0x0801452C, 0),
    0x08014552: (0x08014550, 4), 0x0801455A: (0x08014558, 0),
    0x08014568: (0x08014566, 4), 0x080145E4: (0x080145E2, 0),
    0x080145F2: (0x080145F0, 0), 0x08014600: (0x080145FE, 0),
    0x08014622: (0x08014620, 0), 0x0801462E: (0x0801462C, 4),
    0x0801463C: (0x0801463A, 0), 0x0801464A: (0x08014648, 0),
    0x08015BD8: (0x08015BD6, 0), 0x08015BE6: (0x08015BE4, 0),
    0x08015BF4: (0x08015BF2, 0), 0x08015C16: (0x08015C14, 0),
    0x08015C22: (0x08015C20, 0), 0x08015C30: (0x08015C2E, 0),
    0x08015C3E: (0x08015C3C, 0),
}

# The ROM pair contains two BYTE pin IDs, not 32-bit words; the
# manufacturer copies each 8-byte descriptor then uses LDRB r0.
TABLE_ROM_CALLS = {
    0x0801B826: (0x0801B822, 0), 0x0801B82E: (0x0801B82A, 1),
    0x0801B85A: (0x0801B856, 0), 0x0801B868: (0x0801B864, 0),
}

RAM_ROOT_LOADS = {
    0x08014422: (0x080147CC, "ldr", "r4, [pc, #0x3a8]"),
    0x0801447A: (0x080147CC, "ldr", "r4, [pc, #0x350]"),
    0x080144B0: (0x080147CC, "ldr", "r4, [pc, #0x318]"),
    0x0801454C: (0x080147CC, "ldr", "r4, [pc, #0x27c]"),
    0x080145DA: (0x080147CC, "ldr", "r4, [pc, #0x1f0]"),
    0x08015BD0: (0x08015DAC, "ldr", "r4, [pc, #0x1d8]"),
}

ROM_TABLE_SOURCE = {
    0x0801B7E4: ("push.w", "{r4, r5, r6, r7, r8, sb, sl, lr}"),
    0x0801B7E8: ("movs", "r7, #1"),
    0x0801B7EE: ("ldr.w", "r8, [pc, #0xa4]"),
    0x0801B7F2: ("movs", "r6, #0"),
    0x0801B808: ("add.w", "r4, r8, r6, lsl #3"),
    0x0801B822: ("ldrb", "r0, [r4]"),
    0x0801B82A: ("ldrb", "r0, [r4, #1]"),
    0x0801B856: ("ldrb", "r0, [r4]"),
    0x0801B864: ("ldrb", "r0, [r4]"),
    0x0801B880: ("adds", "r6, r6, #1"),
    0x0801B882: ("cmp", "r6, r7"),
    0x0801B884: ("blo", "#0x801b7f4"),
}

def u32(b: bytes, a: int, base: int = LINK_BASE) -> int:
    return struct.unpack_from("<I", b, a - base)[0]

def op_at(b: bytes, pc: int, expected: tuple[str,str]) -> None:
    off = pc - LINK_BASE
    c = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    ins = next(c.disasm(b[off:off+4], pc, count=1), None)
    if ins is None or (ins.mnemonic, ins.op_str) != expected:
        raise ValueError(f"OEM opcode different at {pc:#x}: "
                         f"{(ins.mnemonic, ins.op_str) if ins else None} expected={expected}")

def pin_data(b: bytes) -> tuple[bytes, dict]:
    stream = b[ROM_INPUT_START-LINK_BASE:ROM_INPUT_END-LINK_BASE]
    status, ram = bounded_thumb_grammar(stream, RAM_OUT)
    if (not status["valid"] or len(ram)!=RAM_OUT or
            status["source_consumed"] != ROM_INPUT_END-ROM_INPUT_START or
            status["tokens"] != 251 or
            status["decoded_SHA256"] != "553c4915151144282cc2fb33e52e1cd6f5b5d1c372881e91237d3245cdc1930a"):
        raise ValueError("manufacturer initialized RAM scatter input changed")
    return ram,status

def inspect(b: bytes, *, altered_ram: bytes | None = None) -> dict:
    c = existing_census(b)
    if c["BL_candidates_found"] != EXPECTED_ALL_BL_CANDIDATES:
        raise ValueError("OEM GPIO write BL census changed")
    true_sites = {
        int(x["possible_original_helper_call_pc"],16) for x in c["callsites"]
    }
    if len(true_sites) != EXPECTED_ALL_BL_CANDIDATES:
        raise ValueError("OEM GPIO write callsite census has duplicate PCs")
    ram, info = pin_data(b)
    if altered_ram is not None:
        ram = altered_ram
    if len(ram)!=RAM_OUT:
        raise ValueError("simulated initialized RAM changed length")
    actual_ram = (u32(ram, RAM_PIN_PAIR, 0x20000000),
                  u32(ram, RAM_PIN_PAIR+4, 0x20000000))
    if actual_ram != RAM_PINS:
        raise ValueError("the OEM initial two-pin RAM identifiers changed")
    for source,(literal,ins,ops) in RAM_ROOT_LOADS.items():
        op_at(b,source,(ins,ops))
        marker = int(ops.split("#")[1].rstrip("]"),0)
        if ((source+4)&~3)+marker != literal:
            raise ValueError("OEM LDR literal address arithmetic mismatch")
        if u32(b,literal)!=RAM_PIN_PAIR:
            raise ValueError("RAM pin root literal no longer points to original initialized RAM")
    if u32(b,ROM_PIN_PAIR_PTR_LITERAL)!=ROM_PIN_PAIR:
        raise ValueError("ROM pin descriptor pointer changed")
    for pc,s in ROM_TABLE_SOURCE.items():
        op_at(b,pc,s)
    if ((0x0801B7EE+4)&~3)+0xa4!=ROM_PIN_PAIR_PTR_LITERAL:
        raise ValueError("LDR.W r8 PC literal slot mismatch")
    # The ROM GPIO pin-pair bytes are the first two bytes of a single
    # eight-byte record; r7=1 means only record index r6=0 is used.
    actual_rom = tuple(b[ROM_PIN_PAIR-LINK_BASE:ROM_PIN_PAIR-LINK_BASE+2])
    if actual_rom != ROM_PINS:
        raise ValueError("first OEM ROM pin-descriptor values changed")
    if any(p in M1_M2_IDS for p in actual_ram+actual_rom):
        raise ValueError("these data groups must not be attributed to M1/M2")

    out_ram = []
    for call,(load,delta) in TABLE_RAM_CALLS.items():
        if call not in true_sites:
            raise ValueError(f"expected OEM direct BL not in original census: {call:#x}")
        op_at(b,call,("bl",f"#{GPIO_WRITE:#x}"))
        op_at(b,load,("ldr", "r0, [r4]" if delta==0 else "r0, [r4, #4]"))
        if not 0<call-load<=16:
            raise ValueError("original table-fed GPIO load separated from call")
        # This is a source-derived initial pin value; runtime RAM can
        # subsequently change and all intervening control-flow is NOT
        # comprehensively modeled by this static argument check.
        out_ram.append({"callsite":hex(call),"pin_load_pc":hex(load),
                        "initially_loaded_pin":hex(actual_ram[delta//4]),
                        "runtime_r4_liveness_or_full_CFG_proven":False})
    out_rom = []
    for call,(load,delta) in TABLE_ROM_CALLS.items():
        if call not in true_sites:
            raise ValueError("ROM table GPIO BL missing")
        op_at(b,call,("bl",f"#{GPIO_WRITE:#x}"))
        op_at(b,load,("ldrb", "r0, [r4]" if delta==0 else "r0, [r4, #1]"))
        if not 0<call-load<=8:
            raise ValueError("original ROM byte load separated from call")
        out_rom.append({"callsite":hex(call),"pin_load_pc":hex(load),
                        "ROM_descriptor_pin":hex(actual_rom[delta]),
                        "every_indirect_function_owner_proven":False})
    # This is a non-overlapping split of independently validated, bounded
    # immediate R0/R1 pairs versus the newly reconstructed table-fed sites.
    # It leaves the remaining 31 UNCLASSIFIED, never labelled safe or unused.
    adjacent = immediate_census(b)
    immediate_sites={int(x["call_pc"],16) for x in adjacent["candidate_BLs"]
                     if x["candidate_pin_and_value"] is not None}
    table_sites=set(TABLE_RAM_CALLS)|set(TABLE_ROM_CALLS)
    if (len(immediate_sites)!=58 or len(table_sites)!=33 or
            immediate_sites&table_sites or len(true_sites-immediate_sites-table_sites)!=31):
        raise ValueError("unclassified manufacturer GPIO candidate inventory changed")
    for x in adjacent["candidate_BLs"]:
        pair=x["candidate_pin_and_value"]
        if pair and int(pair["pin_id"],16) in M1_M2_IDS:
            raise ValueError("previous direct immediate result acquired unknown motor pin")

    if len(out_ram)!=29 or len(out_rom)!=4 or len(true_sites)!=122:
        raise ValueError("pinned inventory of vetted read sites changed")
    return {
        "real_APP_base":hex(LINK_BASE),
        "GPIO_helper":hex(GPIO_WRITE),
        "original_direct_BL_candidate_count":len(true_sites),
        "reviewed_RAM_loaded_BL_sites":out_ram,
        "reviewed_ROM_loaded_BL_sites":out_rom,
        "original_keil_decompressed_RAM": {
            "source_consumed":info["source_consumed"],
            "tokens":info["tokens"],
            "RAM_pin_pair":hex(RAM_PIN_PAIR),
            "initialized_pair_hex":list(map(hex,actual_ram)),
            "ROM_pin_pair":hex(ROM_PIN_PAIR),
            "ROM_pair_hex":list(map(hex,actual_rom)),
        },
        "original_motor_pin_ids":list(map(hex,M1_M2_IDS)),
        "these_33_callsites_are_not_source_evidence_of_M1_M2":True,
        "reviewed_bounded_immediate_pin_and_value_sites":len(immediate_sites),
        "immediate_and_table_classification_overlap":False,
        "total_source_classified_direct_BL_sites":len(immediate_sites|table_sites),
        "still_unclassified_direct_BL_candidates":len(true_sites-immediate_sites-table_sites),
        "remaining_direct_BL_candidates_not_classified_by_this_audit":122-33,
        "all_GPIO_callsites_are_reachable_proven":False,
        "remaining_sites_are_M1_M2_excluded":False,
        "real_motor_start_stop_callgraph_recovered":False,
        "runtime_RAM_initial_equals_live_value_proven":False,
        "GPIO_driver_or_motor_electrical_response_measured":False,
        "safe_to_approve_v323_MCU_SET_RESET_or_flash":False,
    }

def negative_scenarios(b: bytes) -> list[str]:
    done = []
    def corrupt_rom(label: str, a: int) -> None:
        x=bytearray(b)
        x[a-LINK_BASE]^=1
        try:inspect(bytes(x))
        except ValueError:done.append(label)
        else:raise AssertionError("mutated source accepted: "+label)
    for label,a in (
        ("RAM_pair_root_literal",PIN_DATA_ROOT),
        ("ROM_descriptor_pin_0",ROM_PIN_PAIR),
        ("ROM_descriptor_pin_1",ROM_PIN_PAIR+1),
        ("ROM_descriptor_root_literal",ROM_PIN_PAIR_PTR_LITERAL),
        ("ROM_descriptor_call_opcode",0x0801B826),
        ("ROM_descriptor_r8_pointer_load",0x0801B7EE),
        ("RAM_table_driven_call_opcode",0x08014438),
        ("RAM_table_driven_pin_load",0x08014436),
        ("ROM_descriptor_loop_limit",0x0801B7E8),
    ):
        corrupt_rom(label,a)
    ram,_=pin_data(b)
    modified=bytearray(ram)
    modified[RAM_PIN_PAIR-0x20000000]^=1
    try:inspect(b,altered_ram=bytes(modified))
    except ValueError:done.append("reconstructed_initial_RAM_pin_changed")
    else:raise AssertionError("mutated reconstructed RAM pin accepted")
    if len(done)!=10:
        raise ValueError("negative test coverage incomplete")
    return done

def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=pinned(a.v313,"intermediate_v313")
    new=pinned(a.v322,"running_v322")
    audited(old);audited(new)
    legacy=inspect(old)
    active=inspect(new)
    if legacy!=active:
        raise ValueError("ROM/RAM source pointer provenance changed v3.13 to v3.22")
    report={"two_saved_versions_agree":True,
            "source_only":active,
            "real_CFS_peripheral_reads_or_writes":False,
            "motor_interlock_verified":False,
            "safe_to_flash_v323":False}
    if a.self_test:
        report["negative_scenarios_rejected"]=negative_scenarios(new)
    output=json.dumps(report,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(output)
    print(output,end="")

if __name__=="__main__":
    main()
