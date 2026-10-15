#!/usr/bin/env python3
"""Offline OEM GPIO multi-table / dynamic argument provenance census.

Examines *source* code for 24 of the 28 direct BL encodings still
unclassified after four-motor record audit. All claims are bounded:
- 15 producer LDRH loads reference initial 0x200001D0 halfword pairs
- 1 loop-source LDR.W references 10-word initialized 0x20000218
- 2 loop-source loads reference four 8-byte pairs at 0x20000528
- 1 command-source LDR references the latter array via +6 pointer bias
- 4 immediate IDs 0x21..0x24 use software register r5 as value.
- 1 conditional compare pins the first GPIO ID to 0x10.
The four remaining BLs take call-argument/dynamic runtime pin IDs.

A static initialized pin ID is not a live GPIO/motor-state reading,
and none of the audit paths grant firmware flash, motor motion, or
MCU SET/RESET authorization.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar
from cfs_oem_four_brushed_motor_pin_provenance_audit import inspect as motor_audit
from cfs_m1_m2_gpio_helper_callsites import inspect as all_calls

CALL=0x08018EEC
RAM_BASE=0x20000000
HALFWORD_RAM=0x200001D0
TEN_PIN_RAM=0x20000218
PAIR_RAM=0x20000528
TEN_PINS=(0x37,0x36,0x35,0x34,0x4A,0x49,0x48,0x47,0x38,0x39)
FOUR_PAIRS=((0x17,0x26),(0x14,0x27),(0x15,0x28),(0x16,0x29))
HALFWORD_PINS=(0x18,0x19,0x1A,0x1B)
MOTOR_PINS=set(range(0x30,0x34))
RAM_SHA="553c4915151144282cc2fb33e52e1cd6f5b5d1c372881e91237d3245cdc1930a"

# Expected immediate predecessor of each original literal/halfword
# pin load (the original preceding MOV/CMP/branch is not assumed to
# certify task ownership or runtime reachability).
HALFWORD_CALLS={
  0x0800BBFE:(0x0800BBF8,"ldrh.w","r0, [r5, r4, lsl #2]"),
  0x0800BC54:(0x0800BC52,"ldrh","r0, [r0, #2]"),
  0x0800BC64:(0x0800BC5E,"ldrh.w","r0, [r5, r4, lsl #2]"),
  0x0800BC86:(0x0800BC84,"ldrh","r0, [r5, #2]"),
  0x0800BC96:(0x0800BC90,"ldrh.w","r0, [r6, r4, lsl #2]"),
  0x0800BCD2:(0x0800BCC8,"ldrh","r0, [r4, #2]"),
  0x0800BCDC:(0x0800BCD6,"ldrh.w","r0, [r8, r5, lsl #2]"),
  0x0800BCEC:(0x0800BCE6,"ldrh.w","r0, [r8, r5, lsl #2]"),
  0x0800BCF4:(0x0800BCF0,"ldrh","r0, [r4, #2]"),
  0x0800BD18:(0x0800BD12,"ldrh.w","r0, [r8, r5, lsl #2]"),
  0x0800BD32:(0x0800BD2C,"ldrh.w","r0, [r6, r5, lsl #2]"),
  0x0800BD68:(0x0800BD62,"ldrh.w","r0, [r4, r5, lsl #2]"),
  0x0800BD84:(0x0800BD7E,"ldrh.w","r0, [r4, r5, lsl #2]"),
  0x0800BDA8:(0x0800BD9A,"ldrh.w","r0, [r4, r5, lsl #2]"),
  0x0800BDB8:(0x0800BDB2,"ldrh.w","r0, [r4, r5, lsl #2]"),
}
HALFWORD_ROOT_LOADS={
  0x0800BBE0:("ldr","r5, [pc, #0x3e0]"),
  0x0800BC4A:("ldr","r5, [pc, #0x378]"),
  0x0800BC7C:("ldr","r6, [pc, #0x344]"),
  0x0800BCBC:("ldr.w","r8, [pc, #0x304]"),
  0x0800BD58:("ldr","r4, [pc, #0x268]"),
}
TEN_LOADS={
  0x0800E766:("ldr","r5, [pc, #0x26c]"),
  0x0800E76E:("ldr.w","r0, [r5, r4, lsl #2]"),
  0x0800E772:("bl",f"#{CALL:#x}"),
  0x0800E76A:("movs","r4, #0"),
  0x0800E776:("adds","r4, r4, #1"),
  0x0800E77A:("cmp","r4, #0xa"),
  0x0800E77C:("blo","#0x800e76c"),
}
PAIR_LOADS={
  0x08010642:("ldr","r5, [pc, #0x3f8]"),
  0x08010644:("movs","r4, #0"),
  0x0801065E:("ldr.w","r0, [r5, r4, lsl #3]"),
  0x08010662:("movs","r1, #0"),
  0x08010664:("bl",f"#{CALL:#x}"),
  0x08010652:("add.w","r6, r5, r4, lsl #3"),
  0x08010668:("movs","r1, #0"),
  0x0801066A:("ldr","r0, [r6, #4]"),
  0x0801066C:("bl",f"#{CALL:#x}"),
  0x08010670:("adds","r4, r4, #1"),
  0x08010674:("cmp","r4, #4"),
  0x08010676:("blo","#0x8010648"),
}
COMMAND_LOADS={
  0x08010D72:("ldr","r0, [pc, #0xa4]"),
  0x08010D74:("adds","r0, r0, #6"),
  0x08010D88:("add.w","r0, r0, r4, lsl #3"),
  0x08010D8C:("ldr","r0, [r0, #4]"),
  0x08010D92:("ldr.w","r0, [r0, r4, lsl #3]"),
  0x08010D9A:("add.w","r0, r0, r4, lsl #3"),
  0x08010D9E:("ldr","r0, [r0, #4]"),
  0x08010DA2:("bl",f"#{CALL:#x}"),
  0x08010DA8:("ldr.w","r0, [r0, r4, lsl #3]"),
}
CONST_HIGH_WRITES={
  0x0800A5B0:("movs","r5, #1"),
  0x0800A5CC:("mov","r1, r5"),
  0x0800A5CE:("movs","r0, #0x21"),
  0x0800A5D0:("bl",f"#{CALL:#x}"),
  0x0800A5D4:("mov","r1, r5"),
  0x0800A5D6:("movs","r0, #0x22"),
  0x0800A5D8:("bl",f"#{CALL:#x}"),
  0x0800A5DC:("mov","r1, r5"),
  0x0800A5DE:("movs","r0, #0x23"),
  0x0800A5E0:("bl",f"#{CALL:#x}"),
  0x0800A5E4:("mov","r1, r5"),
  0x0800A5E6:("movs","r0, #0x24"),
  0x0800A5E8:("bl",f"#{CALL:#x}"),
}
DYNAMIC_REMAIN={
  0x0800727C,0x08007298,0x080072E8,0x08007302,
}
PIN_COMPARE_EQ_TEN={
  0x0800A5C0:("ldrb","r0, [r4, #7]"),
  0x0800A5C2:("cmp","r0, #0x10"),
  0x0800A5C4:("bne","#0x800a5b6"),
  0x0800A5C6:("mov","r1, r5"),
  0x0800A5C8:("bl",f"#{CALL:#x}"),
}

def rom_word(b:bytes,a:int)->int:
    return struct.unpack_from("<I",b,a-LINK_BASE)[0]
def ram_word(b:bytes,a:int)->int:
    return struct.unpack_from("<I",b,a-RAM_BASE)[0]
def inst(b:bytes,pc:int,expected:tuple[str,str]) -> None:
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    x=next(decoder.disasm(b[pc-LINK_BASE:pc-LINK_BASE+4],pc,count=1),None)
    if x is None or (x.mnemonic,x.op_str)!=expected:
        raise ValueError(f"OEM 0x{pc:08X} opcode differs expected={expected} "
                         f"found={(x.mnemonic,x.op_str) if x else None}")
def pc_literal(pc:int,operand:str)->int:
    if "[pc, #" not in operand:raise ValueError("not literal LDR")
    imm=int(operand.split("#")[1].split("]")[0],0)
    return ((pc+4)&~3)+imm
def ram_init(b:bytes)->bytes:
    s=b[0x0802DB6C-LINK_BASE:0x0802DE38-LINK_BASE]
    meta,ram=bounded_thumb_grammar(s,3012)
    if (not meta["valid"] or len(ram)!=3012 or
        meta["source_consumed"]!=716 or meta["tokens"]!=251 or
        hashlib.sha256(ram).hexdigest()!=RAM_SHA):
        raise ValueError("OEM decompressed initialization drift")
    return ram

def inspect(b:bytes,*,ram_override:bytes|None=None) -> dict:
    prev=motor_audit(b)
    if prev["total_categorized_direct_GPIO_BLs"]!=94 or prev["unresolved_direct_GPIO_BL_candidate_count"]!=28:
        raise ValueError("previous GPIO source classification base changed")
    allsites={int(x["possible_original_helper_call_pc"],16)
              for x in all_calls(b)["callsites"]}
    if len(allsites)!=122:raise ValueError("GPIO direct BL candidate count changed")
    now=set(HALFWORD_CALLS)|{0x0800E772,0x08010664,0x0801066C,0x08010DA2,0x0800A5C8}|{0x0800A5D0,0x0800A5D8,0x0800A5E0,0x0800A5E8}
    if (len(now)!=24 or not now<=allsites or
        (allsites-set(now))!=set(allsites-now) or
        not DYNAMIC_REMAIN<=allsites-now):
        raise ValueError("new dynamic/table callsite set unexpected")
    # Independent claim: 94 pre-classified calls and 23 new do not overlap.
    # Count remaining and pin exact five source-inspected dynamic call PC.
    previously={int(x,16) for x in prev["OEM_motor_GPIO_direct_calls"]}
    from cfs_gpio_table_fed_callsite_provenance_audit import inspect as tables
    from cfs_gpio_bounded_argument_provenance import inspect as immediate
    t=tables(b)
    previously|={int(x["callsite"],16) for x in t["reviewed_RAM_loaded_BL_sites"]+t["reviewed_ROM_loaded_BL_sites"]}
    previously|={int(x["call_pc"],16) for x in immediate(b)["candidate_BLs"] if x["candidate_pin_and_value"] is not None}
    if len(previously)!=94 or now&previously or allsites-previously-now!=DYNAMIC_REMAIN:
        raise ValueError("previously classified vs new vs unknown GPIO candidates mismatched")
    ram=ram_override if ram_override is not None else ram_init(b)
    if len(ram)!=3012:raise ValueError("source RAM image size changed")

    if tuple(struct.unpack_from("<4H",ram,HALFWORD_RAM-RAM_BASE))!=HALFWORD_PINS:
        raise ValueError("OEM two halfword pin pairs modified")
    for pc,expected in HALFWORD_ROOT_LOADS.items():
        inst(b,pc,expected)
        loc=pc_literal(pc,expected[1])
        if loc!=0x0800BFC4 or rom_word(b,loc)!=HALFWORD_RAM:
            raise ValueError("halfword GPIO table literal has changed")
    half=[]
    for call,(load,mnemonic,operand) in HALFWORD_CALLS.items():
        inst(b,load,(mnemonic,operand))
        inst(b,call,("bl",f"#{CALL:#x}"))
        if not 0<call-load<=14:raise ValueError("GPIO halfword producer distance drift")
        half.append({"BL_PC":hex(call),"halfword_load_PC":hex(load),
                     "OEM_initialized_halfword_candidates":list(map(hex,HALFWORD_PINS)),
                     "runtime_array_index_and_liveness_fully_proven":False})

    ten=tuple(ram_word(ram,TEN_PIN_RAM+i*4) for i in range(10))
    if ten!=TEN_PINS:raise ValueError("ten-pin setup list changed")
    for pc,e in TEN_LOADS.items():inst(b,pc,e)
    if pc_literal(0x0800E766,TEN_LOADS[0x0800E766][1])!=0x0800E9D4 or rom_word(b,0x0800E9D4)!=TEN_PIN_RAM:
        raise ValueError("ten-pin ROM root changed")

    pair=tuple((ram_word(ram,PAIR_RAM+8*i),
                ram_word(ram,PAIR_RAM+8*i+4)) for i in range(4))
    if pair!=FOUR_PAIRS:raise ValueError("four loop pair GPIO records changed")
    for pc,e in PAIR_LOADS.items():inst(b,pc,e)
    if pc_literal(0x08010642,PAIR_LOADS[0x08010642][1])!=0x08010A3C or rom_word(b,0x08010A3C)!=PAIR_RAM:
        raise ValueError("four-pair pointer literal mismatch")

    for pc,e in COMMAND_LOADS.items():inst(b,pc,e)
    if (pc_literal(0x08010D72,COMMAND_LOADS[0x08010D72][1])!=0x08010E18 or
        rom_word(b,0x08010E18)!=PAIR_RAM-6):
        raise ValueError("OEM dynamic command pointer bias changed")

    for pc,e in CONST_HIGH_WRITES.items():inst(b,pc,e)
    high=(0x21,0x22,0x23,0x24)
    source_ids=set(HALFWORD_PINS)|set(TEN_PINS)|{p for duo in FOUR_PAIRS for p in duo}|set(high)
    if source_ids&MOTOR_PINS:
        raise ValueError("OEM nonmotor table unexpectedly overlaps four brushed motor pins")

    for pc,e in PIN_COMPARE_EQ_TEN.items():inst(b,pc,e)
    for pc in (0x0800727C,0x08007298,0x080072E8,0x08007302):
        inst(b,pc,("bl",f"#{CALL:#x}"))
    return {
        "physical_APP_base":hex(LINK_BASE),
        "OEM_direct_GPIO_BL_count":122,
        "previously_source_classified":94,
        "new_direct_GPIO_source_classified":len(now),
        "total_static_source_classified":len(previously|now),
        "still_dynamic_parameter_pin_direct_GPIO_BLs":[hex(x) for x in sorted(DYNAMIC_REMAIN)],
        "remaining_direct_GPIO_BLs_unclassified":len(allsites-previously-now),
        "halfword_table_RAM":hex(HALFWORD_RAM),
        "halfword_initial_pin_pairs":[list(map(hex,HALFWORD_PINS[i:i+2])) for i in (0,2)],
        "halfword_load_sites":half,
        "ten_pin_init_RAM":hex(TEN_PIN_RAM),
        "ten_pin_initial_values":list(map(hex,TEN_PINS)),
        "four_pair_RAM":hex(PAIR_RAM),
        "four_pair_initial_values":[list(map(hex,x)) for x in FOUR_PAIRS],
        "command_dynamic_index_PC":hex(0x08010DA2),
        "command_dynamic_index_bounds_proven":False,
        "additional_four_immediate_source_pin_IDs":list(map(hex,high)),
        "conditional_verified_pin_0x10_GPIO_call":hex(0x0800A5C8),
        "conditional_pin_is_source_value_0x10":True,
        "previous_GPIO_disjoint_inventory_unchanged":True,
        "source_pin_tables_differ_from_all_brushed_motor_pins":True,
        "all_external_dynamic_pin_arguments_are_nonmotor":False,
        "runtime_RAM_equals_initial_values":False,
        "GPIO_PIN_WRITE_source_implies_motor_stopped":False,
        "indirect_or_tail_callpaths_completely_covered":False,
        "physical_motor_idle_signal_verified":False,
        "MCU_SET_RESET_or_v323_flash_authorized":False,
    }

def negative_fixtures(b:bytes)->list[str]:
    errors=[]
    def badrom(label:str,address:int):
        altered=bytearray(b)
        altered[address-LINK_BASE]^=1
        try:inspect(bytes(altered))
        except ValueError:errors.append(label)
        else:raise AssertionError("bad ROM accepted: "+label)
    for name,pc in (
        ("halfword_source_root",0x0800BFC4),
        ("halfword_load_instruction",0x0800BBF8),
        ("halfword_direct_BL",0x0800BBFE),
        ("halfword_extra_direct_BL",0x0800BDB8),
        ("ten_pin_root",0x0800E9D4),
        ("ten_pin_index_source",0x0800E76E),
        ("ten_pin_loop_bound",0x0800E77A),
        ("four_pair_root",0x08010A3C),
        ("four_pair_load",0x0801065E),
        ("four_pair_other_BL",0x0801066C),
        ("command_biased_root",0x08010E18),
        ("command_added_bias",0x08010D74),
        ("command_dynamic_BL",0x08010DA2),
        ("static_0x24_held_r5_pin",0x0800A5E6),
        ("static_0x21_direct_BL",0x0800A5D0),
        ("conditional_pin_0x10_comparison",0x0800A5C2),
        ("other_unknown_argument_direct_BL",0x0800727C),
    ):badrom(name,pc)
    src=ram_init(b)
    for label,offset in (
        ("mutate_halfword_RAM",HALFWORD_RAM-RAM_BASE),
        ("mutate_ten_pin_RAM",TEN_PIN_RAM-RAM_BASE),
        ("mutate_pair_RAM",PAIR_RAM-RAM_BASE),
    ):
        altered=bytearray(src)
        altered[offset]^=1
        try:inspect(b,ram_override=bytes(altered))
        except ValueError:errors.append(label)
        else:raise AssertionError("mutated RAM accepted: "+label)
    if len(errors)!=20:raise ValueError("20 negative fixtures were not rejected")
    return errors

def main()->None:
    p=argparse.ArgumentParser()
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    a,b=pinned(args.v313,"intermediate_v313"),pinned(args.v322,"running_v322")
    audited(a);audited(b)
    old,new=inspect(a),inspect(b)
    if old!=new:raise ValueError("manufacturer GPIO indirect source differed v3.13 vs v3.22")
    data={"two_OEM_saved_generations_identical":True,"source":new,
          "no_live_device_IO":True,"firmware_release_authorized":False}
    if args.self_test:data["negative_scenarios_rejected"]=negative_fixtures(b)
    out=json.dumps(data,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(out)
    print(out,end="")
if __name__=="__main__":main()
