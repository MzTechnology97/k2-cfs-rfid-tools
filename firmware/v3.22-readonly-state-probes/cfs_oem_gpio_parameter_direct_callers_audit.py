#!/usr/bin/env python3
"""Source-only census of all visible *direct* OEM callers of parameterized GPIO routines.

The four outstanding BLs in the previous 118/122 source-only census
receive the GPIO logical pin from their caller argument. This pins
the fourteen ROM direct callers that supply literal pin ID pairs,
plus the two direct calls from the intermediate two-stage helper.

This is a bounded direct-BL inventory. Indirect function pointers,
task/IRQ call paths and active motor states are NOT authenticated.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE
from cfs_oem_gpio_deeper_indirect_tables_audit import inspect as previous

HELPER_TWO_PASS=0x080072B0
HELPER_GPIO=0x08007264
HELPER_GPIO2=0x080072D0
OEM_GPIO_WRITE=0x08018EEC
TARGETS=(HELPER_TWO_PASS,HELPER_GPIO,HELPER_GPIO2)

# Keyed by saved physical APP callsite PC. Reg values represent
# immediate r0/r1 passed into the named helper, NOT electrical signals.
DIRECT_CALLERS={
    0x080075A4:(HELPER_TWO_PASS,0x38,0x39),
    0x080075D4:(HELPER_TWO_PASS,0x21,0x22),
    0x08007606:(HELPER_TWO_PASS,0x23,0x24),
    0x08007662:(HELPER_TWO_PASS,0x0C,0x06),
    0x08007692:(HELPER_TWO_PASS,0x07,0x04),
    0x0800733A:(HELPER_GPIO2,0x37,0x26),
    0x0800746A:(HELPER_GPIO2,0x36,0x27),
    0x08007496:(HELPER_GPIO2,0x35,0x28),
    0x080074C2:(HELPER_GPIO2,0x34,0x29),
    0x080074EE:(HELPER_GPIO2,0x47,0x17),
    0x0800751A:(HELPER_GPIO2,0x48,0x14),
    0x08007546:(HELPER_GPIO2,0x49,0x15),
    0x08007578:(HELPER_GPIO2,0x4A,0x16),
    0x08007632:(HELPER_GPIO2,0x0B,0x10),
}
# Immediate sites use MOVS r1 at pc-4 and MOVS r0 at pc-2,
# except 0x08007578, whose MOVS are followed by a branch into BL.
TWO_PASS_TO_PIN_FUNC=(0x080072B6,0x080072C2)
PARAMETER_GPIO_BL_SITES=(0x0800727C,0x08007298,0x080072E8,0x08007302)

PIN_COMMAND_PROVENANCE={
  0x08007264:("push","{r4, r5, r6, lr}"),
  0x08007266:("mov","r4, r1"),
  0x08007268:("mov","r5, r0"),
  0x08007278:("movs","r1, #1"),
  0x0800727A:("mov","r0, r4"),
  0x0800727C:("bl",f"#{OEM_GPIO_WRITE:#x}"),
  0x08007294:("movs","r1, #0"),
  0x08007296:("mov","r0, r4"),
  0x08007298:("bl",f"#{OEM_GPIO_WRITE:#x}"),
  0x080072B0:("push","{r4, r5, r6, lr}"),
  0x080072B2:("mov","r4, r1"),
  0x080072B4:("mov","r5, r0"),
  0x080072B6:("bl",f"#{HELPER_GPIO:#x}"),
  0x080072BE:("mov","r1, r5"),
  0x080072C0:("mov","r0, r4"),
  0x080072C2:("bl",f"#{HELPER_GPIO:#x}"),
  0x080072D0:("push","{r4, r5, r6, lr}"),
  0x080072D2:("mov","r4, r1"),
  0x080072D4:("mov","r5, r0"),
  0x080072E4:("movs","r1, #1"),
  0x080072E6:("mov","r0, r4"),
  0x080072E8:("bl",f"#{OEM_GPIO_WRITE:#x}"),
  0x080072FE:("movs","r1, #0"),
  0x08007300:("mov","r0, r4"),
  0x08007302:("bl",f"#{OEM_GPIO_WRITE:#x}"),
}
JUMP_BRIDGED_CALL=0x08007578
JUMP_BRIDGE={
  0x0800756E:("movs","r1, #0x16"),
  0x08007570:("movs","r0, #0x4a"),
  0x08007572:("b",f"#{JUMP_BRIDGED_CALL:#x}"),
}

def decode(b:bytes,pc:int):
    d=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    return next(d.disasm(b[pc-LINK_BASE:pc-LINK_BASE+4],pc,count=1),None)
def require(b:bytes,pc:int,op:tuple[str,str])->None:
    i=decode(b,pc)
    if i is None or (i.mnemonic,i.op_str)!=op:
        raise ValueError(f"changed original Thumb opcode @{pc:#x}; got "
                         f"{(i.mnemonic,i.op_str) if i else None}, expected {op}")
def scan_direct_bl(b:bytes)->dict[int,list[int]]:
    counts={k:[] for k in TARGETS}
    strings={f"#{v:#x}":v for v in TARGETS}
    for delta in range(0,len(b)-3,2):
        ins=decode(b,LINK_BASE+delta)
        if ins and ins.mnemonic=="bl" and ins.op_str in strings:
            counts[strings[ins.op_str]].append(ins.address)
    return counts

def inspect(b:bytes,*,strict_earlier:bool=True)->dict:
    if strict_earlier:
        x=previous(b)
        if x["total_static_source_classified"]!=118 or x["remaining_direct_GPIO_BLs_unclassified"]!=4:
            raise ValueError("previous direct GPIO census moved")
        if {int(t,16) for t in x["still_dynamic_parameter_pin_direct_GPIO_BLs"]}!=set(PARAMETER_GPIO_BL_SITES):
            raise ValueError("unknown dynamic callsite targets moved")
    for pc,op in PIN_COMMAND_PROVENANCE.items():require(b,pc,op)
    for pc,op in JUMP_BRIDGE.items():require(b,pc,op)
    for pc,(callee,r0,r1) in DIRECT_CALLERS.items():
        require(b,pc,("bl",f"#{callee:#x}"))
        if pc==JUMP_BRIDGED_CALL:
            require(b,pc-10,("movs",f"r1, #{r1:#x}"))
            require(b,pc-8,("movs",f"r0, #{r0:#x}"))
        else:
            require(b,pc-4,("movs",f"r1, #{r1:#x}" if r1>=10 else f"r1, #{r1}"))
            require(b,pc-2,("movs",f"r0, #{r0:#x}" if r0>=10 else f"r0, #{r0}"))
    calls=scan_direct_bl(b)
    expected={
      HELPER_TWO_PASS:{p for p,x in DIRECT_CALLERS.items() if x[0]==HELPER_TWO_PASS},
      HELPER_GPIO:set(TWO_PASS_TO_PIN_FUNC),
      HELPER_GPIO2:{p for p,x in DIRECT_CALLERS.items() if x[0]==HELPER_GPIO2},
    }
    for target in TARGETS:
        if set(calls[target])!=expected[target]:
            raise ValueError(f"new/unreviewed direct manufacturer BL into {target:#x}")
    if (len(calls[HELPER_TWO_PASS])!=5 or len(calls[HELPER_GPIO2])!=9 or
            len(calls[HELPER_GPIO])!=2):
        raise ValueError("OEM direct call counts changed")
    motor_pins={0x30,0x31,0x32,0x33,0x3C,0x3D,0x3E,0x3F}
    if any(p in motor_pins for _,a,b in DIRECT_CALLERS.values() for p in (a,b)):
        raise ValueError("OEM reviewed upstream direct caller now passes a brushed motor pin")
    return {
      "linked_APP_base":hex(LINK_BASE),
      "upstream_source_only_BL_into_two_pass":len(calls[HELPER_TWO_PASS]),
      "upstream_source_only_BL_into_GPIO_helper_2":len(calls[HELPER_GPIO2]),
      "internal_two_pass_BL_into_GPIO_helper_1":len(calls[HELPER_GPIO]),
      "all_14_reviewed_external_direct_callers": [
        {"physical_BL_PC":hex(pc),"OEM_target":hex(callee),
         "source_r0_PIN":hex(r0),"source_r1_PIN":hex(r1)}
        for pc,(callee,r0,r1) in sorted(DIRECT_CALLERS.items())
      ],
      "all_upstream_direct_arg_pairs_outside_brushed_motor_pins":True,
      "these_14_source_proven_direct_calls_exhaust_ALL_indirect_entries":False,
      "direct_or_indirect_external_task_callers_fully_proven":False,
      "runtime_dynamic_argument_is_necessarily_nonmotor":False,
      "physical_motor_idle_or_driver_deenergized":False,
      "v323_flash_or_motor_active_MCU_writes_permitted":False,
    }

def negatives(b:bytes)->list[str]:
    rejected=[]
    for name,pc in (
      ("literal_M1_like_argument_changed",0x08007336),
      ("second_caller_pin_changed",0x08007466),
      ("bridged_caller_first_pin_changed",0x08007570),
      ("bridge_jump_changed",0x08007572),
      ("nested_GPIO_function_reg_preserve",0x080072B2),
      ("nested_two_stage_first_BL",0x080072B6),
      ("nested_two_stage_second_BL",0x080072C2),
      ("parameter_pin_argument_MOV",0x080072D2),
      ("dynamic_unknown_GPIO_call",0x08007302),
    ):
        m=bytearray(b);m[pc-LINK_BASE]^=1
        try:inspect(bytes(m),strict_earlier=False)
        except ValueError:rejected.append(name)
        else:raise AssertionError("unexpected accepted mutated OEM caller "+name)
    if len(rejected)!=9:raise ValueError("fail-closed caller mutation tests incomplete")
    return rejected

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old,new=pinned(a.v313,"intermediate_v313"),pinned(a.v322,"running_v322")
    audited(old);audited(new)
    x,y=inspect(old),inspect(new)
    if x!=y:raise ValueError("direct OEM helper callers differ across saved generations")
    result={"both_SHA_pinned_generations_identical":True,"direct_source_only":y,
            "no_live_device_reads_or_writes":True,
            "v323_release_allowed":False}
    if a.self_test:result["rejected_mutation_cases"]=negatives(new)
    data=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(data)
    print(data,end="")
if __name__=="__main__":main()
