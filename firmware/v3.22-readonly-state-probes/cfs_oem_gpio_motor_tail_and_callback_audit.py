#!/usr/bin/env python3
"""Audit OEM GPIO / motor tail branches and source-visible indirect callback.

Source-only: original saved v3.13 and v3.22 APP binaries; no physical CFS
actions, no firmware release or motor commands. A Thumb branch census is
NOT an exhaustive callgraph or proof of runtime execution/physical STOP.
"""
from __future__ import annotations
import argparse, json, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar
from cfs_gpio_pin_ops_registration_and_m1m2_gpiod_audit import source_audit as ops_audit
from cfs_oem_gpio_deeper_indirect_tables_audit import inspect as bl_audit

GPIO_DISPATCH=0x08018EEC
MOTOR_CONTROL=0x08010054
PIN_WRITE=0x0801AB90
PIN_OPS_SLOT=0x0802B4A0
GPIO_DISPATCH_LOAD=0x08018F0A
GPIO_DISPATCH_BX=0x08018F12
GPIO_BSS_DEVICE_FIELD=0x20004C84
GPIO_BRANCHES=(
    0x0800A1B6, 0x0800A264, 0x0800A2AA, 0x0800A2D2,
    0x0800A362, 0x0800ADBA, 0x0800ADF4, 0x0800AEBE,
    0x0800B5A6, 0x0800B5D8, 0x0800BC0A, 0x0800BCA8,
    0x0800BD44, 0x0800BDCC, 0x080106C2, 0x08019156,
    0x0801B7AE, 0x0801B7B8,
)
MOTOR_BRANCHES=(0x0800D24A,0x080102C0)
# Only the contiguous, source-checked MOVS immediate return-stubs are
# here. Every other branch retains a dynamic/table-fed source label.
GPIO_IMMEDIATE={
    0x0800A1B6:(0x0800A1B4,0x10,0x0800A1AE,0),
    0x0800A264:(0x0800A262,0x21,0x0800A260,1),
    0x0800A2AA:(0x0800A2A8,0x21,0x0800A2A6,1),
    0x0800A2D2:(0x0800A2D0,0x21,0x0800A2CA,1),
    0x0800A362:(0x0800A360,0x10,0x0800A35E,0),
    0x0800ADBA:(0x0800ADB8,0x45,0x0800ADB2,0),
    0x0800ADF4:(0x0800ADF2,0x45,0x0800ADEC,0),
    0x0800AEBE:(0x0800AEBC,0x45,0x0800AEB6,0),
    0x0800B5D8:(0x0800B5D6,0x1C,0x0800B5D0,1),
}
# Each listed instruction is a physical PC in the OEM executable.
PARSER_GPIO={
    0x080190F0:("push","{r4, r5, r6, lr}"),
    0x08019104:("bl","#0x80268b8"),
    0x08019108:("mov","r5, r0"),
    0x08019134:("bl","#0x80190a0"),
    0x08019138:("movs","r5, r0"),
    0x0801914A:("movs","r1, #1"),
    0x0801914E:("movs","r1, #0"),
    0x08019150:("mov","r0, r5"),
    0x08019152:("pop.w","{r4, r5, r6, lr}"),
    0x08019156:("b",f"#{GPIO_DISPATCH:#x}"),
}
MOTOR_TAIL_SOURCE={
    0x0800D226:("push","{r4, r5, r6, lr}"),
    0x0800D228:("mov","r4, r0"),
    0x0800D22A:("mov","r5, r1"),
    0x0800D242:("sxtb","r0, r4"),
    0x0800D244:("pop.w","{r4, r5, r6, lr}"),
    0x0800D248:("movs","r1, #0"),
    0x0800D24A:("b.w",f"#{MOTOR_CONTROL:#x}"),
    0x080102AC:("movs","r2, #0x2b"),
    0x080102AE:("smulbb","r3, r0, r2"),
    0x080102B2:("ldr","r2, [pc, #0x2a8]"),
    0x080102B4:("add.w","r2, r2, r3, lsl #2"),
    0x080102B8:("strh.w","r1, [r2, #0xaa]"),
    0x080102BC:("ldrb.w","r1, [r2, #0xa8]"),
    0x080102C0:("b",f"#{MOTOR_CONTROL:#x}"),
}
DYNAMIC_TAIL_SOURCE={
    0x0800B5A2:("ldr","r2, [pc, #0x310]"),
    0x0800B5A4:("ldrb","r0, [r2, r0]"),
    0x0800B5A6:("b.w",f"#{GPIO_DISPATCH:#x}"),
    0x0800BC02:("ldrh","r0, [r6, #2]"),
    0x0800BC0A:("b.w",f"#{GPIO_DISPATCH:#x}"),
    0x0800BCA0:("ldrh","r0, [r5, #2]"),
    0x0800BCA8:("b.w",f"#{GPIO_DISPATCH:#x}"),
    0x0800BD3C:("ldrh","r0, [r4, #2]"),
    0x0800BD44:("b.w",f"#{GPIO_DISPATCH:#x}"),
    0x0800BDC2:("ldrh.w","r0, [r4, r5, lsl #2]"),
    0x0800BDCC:("b.w",f"#{GPIO_DISPATCH:#x}"),
    0x080106BC:("ldr","r0, [r3, #4]"),
    0x080106C2:("b.w",f"#{GPIO_DISPATCH:#x}"),
    0x0801B7A8:("ldrb","r0, [r0, #1]"),
    0x0801B7AE:("b.w",f"#{GPIO_DISPATCH:#x}"),
    0x0801B7B2:("ldrb","r0, [r0]"),
    0x0801B7B8:("b.w",f"#{GPIO_DISPATCH:#x}"),
}
BRANCH_DESTS={GPIO_DISPATCH:set(GPIO_BRANCHES),MOTOR_CONTROL:set(MOTOR_BRANCHES)}

def word(raw:bytes,offset:int,base:int=LINK_BASE)->int:
    if not base<=offset<=base+len(raw)-4:raise ValueError("unmapped ROM/RAM word")
    return struct.unpack_from("<I",raw,offset-base)[0]
def dis(raw:bytes,pc:int):
    off=pc-LINK_BASE
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    return next(decoder.disasm(raw[off:off+4],pc,count=1),None)
def must(raw:bytes,pc:int,expected:tuple[str,str])->None:
    result=dis(raw,pc)
    if result is None or (result.mnemonic,result.op_str)!=expected:
        raise ValueError(f"original Thumb opcode mismatch at {pc:#x}: "
                         f"got {(result.mnemonic,result.op_str) if result else None}, expected {expected}")
def branch_census(raw:bytes)->dict[int,list[int]]:
    result={p:[] for p in BRANCH_DESTS}
    options={f"#{v:#x}":v for v in result}
    for off in range(0,len(raw)-3,2):
        inst=dis(raw,LINK_BASE+off)
        if inst and inst.mnemonic in {"b","b.w"} and inst.op_str in options:
            result[options[inst.op_str]].append(inst.address)
    return result

def spot_checks(raw:bytes)->dict:
    for pc in GPIO_BRANCHES:
        got=dis(raw,pc)
        if got is None or got.mnemonic not in ("b","b.w") or got.op_str!=f"#{GPIO_DISPATCH:#x}":
            raise ValueError(f"GPIO tail branch opcode target corrupted @{pc:#x}")
        if got.size not in (2,4):
            raise ValueError("GPIO tail branch unexpected opcode width")
    for pc in MOTOR_BRANCHES:
        got=dis(raw,pc)
        if got is None or got.mnemonic not in ("b","b.w") or got.op_str!=f"#{MOTOR_CONTROL:#x}":
            raise ValueError(f"Motor controller tail branch invalid at {pc:#x}")
    for pc,(pinpc,pin,valpc,val) in GPIO_IMMEDIATE.items():
        must(raw,pinpc,("movs",f"r0, #{pin:#x}" if pin>=10 else f"r0, #{pin}"))
        must(raw,valpc,("movs",f"r1, #{val}"))
        if not (pinpc+2<=pc and valpc<pc):
            raise ValueError("GPIO static source immediate position drift")
    for table in (PARSER_GPIO,MOTOR_TAIL_SOURCE,DYNAMIC_TAIL_SOURCE):
        for pc,op in table.items():must(raw,pc,op)
    if word(raw,PIN_OPS_SLOT)!=(PIN_WRITE|1):
        raise ValueError("RT-Thread pin write callback Thumb pointer changed")
    must(raw,GPIO_DISPATCH_LOAD,("ldr","r3, [r0, #4]"))
    must(raw,GPIO_DISPATCH_BX,("bx","r3"))
    # Decode the real Keil scatter source, not a live SRAM snapshot.
    mem=raw[0x0802DB6C-LINK_BASE:0x0802DE38-LINK_BASE]
    info,ram=bounded_thumb_grammar(mem,3012)
    if not info["valid"] or info["source_consumed"]!=716 or info["tokens"]!=251:
        raise ValueError("OEM initialized SRAM source changed")
    targets=(GPIO_DISPATCH,MOTOR_CONTROL,0x08007264,0x080072D0,PIN_WRITE)
    ptrs={}
    for target in targets:
        flash=[LINK_BASE+off for off in range(0,len(raw)-3,4)
               if struct.unpack_from("<I",raw,off)[0] in (target,target|1)]
        ram_hits=[0x20000000+off for off in range(0,len(ram)-3,4)
                  if struct.unpack_from("<I",ram,off)[0] in (target,target|1)]
        expected_flash=[PIN_OPS_SLOT] if target==PIN_WRITE else []
        if flash!=expected_flash or ram_hits:
            raise ValueError(f"unexpected ROM/RAM initialized function pointer {target:#x}")
        ptrs[hex(target)]={"ROM_aligned_pointer_words":[hex(x) for x in flash],
                           "decompressed_initial_RAM_pointer_words":[hex(x) for x in ram_hits]}
    return {"source_emitted_GPIO_tail_call_sites":len(GPIO_BRANCHES),
            "source_emitted_motor_tail_call_sites":len(MOTOR_BRANCHES),
            "known_static_GPIO_pin_tail_sites":len(GPIO_IMMEDIATE),
            "other_gpio_tail_sites_with_table_or_runtime_pin_source":
                len(GPIO_BRANCHES)-len(GPIO_IMMEDIATE),
            "unbounded_parameter_parser_gpio_tail":hex(0x08019156),
            "motor_control_tail_targets":[hex(p) for p in MOTOR_BRANCHES],
            "pin_ops_ROM_Thumb_write_callback":hex(word(raw,PIN_OPS_SLOT)),
            "manufacturer_initial_ROM_and_RAM_function_pointer_hits":ptrs,
            "indirect_RT_Thread_registered_pin_ops_dispatch_proven_in_ROM":True,
            "production_BSS_current_callback_measured":False,
            "all_indirect_BLX_callbacks_source_enumerated":False,
            "parameter_parser_is_nonmotor_and_safe":False,
            "motor_STOP_or_idle_is_physically_confirmed":False,
            "motor_critical_section_and_ISR_atomicity_proven":False,
            "MCU_SET_RESET_or_v323_flash_allowed":False}

def inspect(raw:bytes)->dict:
    old=bl_audit(raw)
    if old["OEM_direct_GPIO_BL_count"]!=122 or old["total_static_source_classified"]!=118:
        raise ValueError("previous GPIO direct BL audit changed")
    registry=ops_audit(raw)
    if (registry["GPIO_write_callback"]!=hex(PIN_WRITE) or
            registry["registered_global_BSS_field"]!=hex(GPIO_BSS_DEVICE_FIELD)):
        raise ValueError("OEM registered GPIO callback chain not source proven")
    r=spot_checks(raw)
    census=branch_census(raw)
    if set(census[GPIO_DISPATCH])!=set(GPIO_BRANCHES):
        raise ValueError(f"GPIO B/B.W scan differs from pinned source: {census[GPIO_DISPATCH]}")
    if set(census[MOTOR_CONTROL])!=set(MOTOR_BRANCHES):
        raise ValueError("motor B/B.W scan differs")
    r.update({"census_original_GPIO_B_or_BW_physical_PCs":[hex(p) for p in GPIO_BRANCHES],
              "census_original_MOTOR_B_or_BW_physical_PCs":[hex(p) for p in MOTOR_BRANCHES],
              "existing_source_classified_direct_GPIO_BL":118,
              "BLX_or_runtime_non_LITERAL_function_pointers_are_excluded_by_static_pointer_search":False})
    return r

def negatives(raw:bytes)->list[str]:
    cases=(
        ("GPIO_constant_tail_target",0x0800A264),
        ("GPIO_r1_value_pre_tail",0x0800A260),
        ("dynamic_ROM_lookup_source",0x0800B5A4),
        ("dynamic_RAM_halfword_tail",0x0800BDCC),
        ("dynamic_parser_r5_argument",0x08019108),
        ("dynamic_parser_tail",0x08019156),
        ("dynamic_GPIO_lookup_tail",0x0801B7B8),
        ("motor_indirect_call_source",0x0800D244),
        ("motor_first_tail",0x0800D24A),
        ("motor_secondary_tail",0x080102C0),
        ("motor_selected_object_store",0x080102B8),
        ("registered_pin_write_ROM_pointer",PIN_OPS_SLOT),
        ("RT_Thread_dynamic_dispatch_load",GPIO_DISPATCH_LOAD),
        ("RT_Thread_dynamic_dispatch_BX",GPIO_DISPATCH_BX),
    )
    rejected=[]
    for label,pc in cases:
        corrupted=bytearray(raw);corrupted[pc-LINK_BASE+(1 if label=="RT_Thread_dynamic_dispatch_BX" else 0)]^=1
        try:spot_checks(bytes(corrupted))
        except ValueError:rejected.append(label)
        else:raise AssertionError("source mutation was accepted: "+label)
    if len(rejected)!=14:raise ValueError("not all expected GPIO negative cases rejected")
    return rejected

def main()->None:
    p=argparse.ArgumentParser()
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    before=pinned(args.v313,"intermediate_v313")
    after=pinned(args.v322,"running_v322")
    audited(before);audited(after)
    a,b=inspect(before),inspect(after)
    if a!=b:raise ValueError("OEM GPIO tail and callback source changed v3.13 to v3.22")
    out={"source_only_original_app_agrees_between_generations":True,
         "OEM_tail_and_callback_evidence":b,
         "no_physical_motor_gpio_or_flash_IO":True,
         "v323_release_approved":False}
    if args.self_test:out["negative_fixtures_rejected"]=negatives(after)
    payload=json.dumps(out,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(payload)
    print(payload,end="")
if __name__=="__main__":main()
