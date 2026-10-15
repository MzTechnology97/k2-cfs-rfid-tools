#!/usr/bin/env python3
"""Pin the OEM four-brushed-motor GPIO control path (SOURCE ONLY).

Original GD32 CFS application at physical Flash 0x08003000. Recover
four 0xAC-stride motor objects from the saved compressed init SRAM;
map their two pin bytes via the ROM board table; trace the motor
command dispatcher at 0x08010054 to its four direct GPIO BLs.

No live MCU, printer, RS485, GPIO, flash, motor command or
SET/RESET. Static source connectivity ≠ full callgraph, motor STOP
feedback or safety release.
"""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_REG_R4
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited, LINK_BASE
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar
from cfs_gpio_table_fed_callsite_provenance_audit import inspect as first_table_audit
from cfs_gpio_bounded_argument_provenance import inspect as first_immediate_audit

SRC0,SRCEND=0x0802DB6C,0x0802DE38
RAM_ORIGIN=0x20000000
RAM_EXPECTED_SHA="553c4915151144282cc2fb33e52e1cd6f5b5d1c372881e91237d3245cdc1930a"
MOTOR_BASE=0x20000270
MOTOR_STRIDE=0xAC
MOTOR_RECORDS=(
    ("M1",0x32,0x33,2,3),
    ("M2",0x30,0x31,0,1),
    ("M3",0x3E,0x3F,14,15),
    ("M4",0x3C,0x3D,12,13),
)
PIN_LOOKUP=0x0802AD5C
GPIO_HELPER=0x08018EEC

ANCHORS={
  0x08010054:("push.w","{r4, r5, r6, r7, r8, lr}"),
  0x08010058:("mov","r6, r0"),
  0x0801005A:("mov","r5, r1"),
  0x08010072:("movs","r0, #0x2b"),
  0x08010074:("smulbb","r0, r6, r0"),
  0x08010078:("ldr","r1, [pc, #0x10]"),
  0x0801007A:("ldr","r2, [pc, #0x10]"),
  0x0801007C:("add.w","r4, r1, r0, lsl #2"),
  0x08010088:("b","#0x801019c"),
  0x0801019C:("cbz","r1, #0x80101ca"),
  0x0801019E:("cbz","r0, #0x80101fe"),
  0x080101CA:("cbz","r0, #0x80101ea"),
  0x080101EA:("ldrb","r0, [r4, #4]"),
  0x080101EC:("movs","r1, #1"),
  0x080101EE:("bl",f"#{GPIO_HELPER:#x}"),
  0x080101F6:("ldrb","r0, [r4, #5]"),
  0x080101F8:("b","#0x801020e"),
  0x08010200:("cbz","r5, #0x8010266"),
  0x08010204:("ldrb","r0, [r4, #4]"),
  0x08010206:("bl",f"#{GPIO_HELPER:#x}"),
  0x0801020A:("ldrb","r0, [r4, #5]"),
  0x0801020C:("movs","r1, #1"),
  0x0801020E:("bl",f"#{GPIO_HELPER:#x}"),
}
# Four direct CALL encodings are source-pinned. 0x080101F8 branches
# directly into the BL at 0x0801020E (another possible path).
GPIO_BL_SITES=(0x080101EE,0x08010206,0x0801020E)
INIT_ROOT_LITERALS=(0x0801008C,0x0801055C)
ROM_PORT_GPIOD=0x40011400

def ins_at(b:bytes,pc:int,expected:tuple[str,str]) -> None:
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    found=next(decoder.disasm(b[pc-LINK_BASE:pc-LINK_BASE+4],pc,count=1),None)
    # Keep the byte window anchored directly at the physical PC; do
    # not perform a linear disassembly through adjacent embedded ROM data.
    if found is None or (found.mnemonic,found.op_str)!=expected:
        raise ValueError(f"OEM motor opcode changed at {pc:#x}: "
                         f"{(found.mnemonic,found.op_str) if found else None}")
def word(b:bytes,addr:int,base:int=LINK_BASE) -> int:
    return struct.unpack_from("<I",b,addr-base)[0]
def decode_ram(b:bytes) -> bytes:
    stream=b[SRC0-LINK_BASE:SRCEND-LINK_BASE]
    meta,ram=bounded_thumb_grammar(stream,3012)
    if (not meta["valid"] or meta["tokens"]!=251 or
        meta["source_consumed"]!=716 or len(ram)!=3012 or
        hashlib.sha256(ram).hexdigest()!=RAM_EXPECTED_SHA):
        raise ValueError("OEM four-motor initialized RAM scatter drift")
    return ram

def inspect(b:bytes,*,ram_override:bytes|None=None) -> dict:
    for addr,x in ANCHORS.items():
        ins_at(b,addr,x)
    if word(b,INIT_ROOT_LITERALS[0])!=MOTOR_BASE or word(b,INIT_ROOT_LITERALS[1])!=MOTOR_BASE:
        raise ValueError("source motor object root ROM literals differ")
    # Real PC-relative LDR targets. First pointer must resolve
    # to the hardware-linked original initialized memory address.
    if (((0x08010078+4)&~3)+0x10)!=INIT_ROOT_LITERALS[0]:
        raise ValueError("Thumb LDR source root PC offset wrong")
    if (((0x0801007A+4)&~3)+0x10)!=INIT_ROOT_LITERALS[0]:
        raise ValueError("Thumb LDR secondary PC offset wrong")
    if 0x2b*4 != MOTOR_STRIDE:
        raise ValueError("OEM shifted stride arithmetic mismatch")
    ram=ram_override if ram_override is not None else decode_ram(b)
    if len(ram)!=3012:raise ValueError("decoded RAM length changed")
    motor_entries=[]
    all_pin_ids=set()
    for index,(name,first,second,pa,pb) in enumerate(MOTOR_RECORDS):
        base=MOTOR_BASE+index*MOTOR_STRIDE
        if base+8>RAM_ORIGIN+len(ram):
            raise ValueError("motor record exceeds initialized memory")
        got=tuple(ram[base-RAM_ORIGIN+4:base-RAM_ORIGIN+6])
        if got!=(first,second):
            raise ValueError(f"{name} OEM initialized pin pair changed: {got}")
        table=[]
        for pin,physical_index in ((first,pa),(second,pb)):
            loc=PIN_LOOKUP+16*pin
            port,mask=word(b,loc+4),word(b,loc+8)
            if port!=ROM_PORT_GPIOD or mask!=1<<physical_index:
                raise ValueError(f"{name} OEM board pin-to-port mapping drift")
            table.append({"OEM_pin":hex(pin),"physical_GPIO":f"PD{physical_index}",
                          "bitmask":hex(mask),"OEM_pin_ROM_entry":hex(loc)})
            all_pin_ids.add(pin)
        motor_entries.append({
            "OEM_motor_record_number":index,
            "label_from_operator_wiring_not_stock_symbol":name,
            "initial_motor_object_RAM":hex(base),
            "original_initialized_pin_pair":list(map(hex,got)),
            "GPIO_board_mapping":table,
            "preinit_decompressed_RAM_matches_live_motor_state":False,
        })
    if len(all_pin_ids)!=8:
        raise ValueError("brushed motor GPIO pins overlap")
    # Within the pinned source selection block, r4 is the record
    # chosen by the original index. There are calls/branches but no
    # direct instruction clobber of r4 in the contiguous 0x1019C-020E
    # code. Do NOT claim that every path is reachable or atomic.
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    decoder.detail=True
    lo,hi=0x0801019C,0x08010212
    body=list(decoder.disasm(b[lo-LINK_BASE:hi-LINK_BASE],lo))
    if not body or body[0].address!=lo or body[-1].address+body[-1].size!=hi:
        raise ValueError("brushed motor control block disassembly gap")
    for x,y in zip(body,body[1:]):
        if x.address+x.size!=y.address:
            raise ValueError("brushed motor block not contiguous")
    for x in body:
        try:_,wr=x.regs_access()
        except Exception as exc:raise ValueError("unmodelled register write") from exc
        if ARM_REG_R4 in wr:
            raise ValueError(f"motor object register r4 overwritten @{x.address:#x}")
    for pc in GPIO_BL_SITES:
        ins_at(b,pc,("bl",f"#{GPIO_HELPER:#x}"))
    previous=first_table_audit(b)
    immediate=first_immediate_audit(b)
    first_sets=(set(int(x["callsite"],16) for x in (
        previous["reviewed_RAM_loaded_BL_sites"]+previous["reviewed_ROM_loaded_BL_sites"])) |
        set(int(x["call_pc"],16) for x in immediate["candidate_BLs"]
            if x["candidate_pin_and_value"] is not None))
    if (len(first_sets)!=91 or set(GPIO_BL_SITES)&first_sets or
            previous["original_direct_BL_candidate_count"]!=122):
        raise ValueError("brushed motor calls unexpectedly overlap previously classified GPIO BLs")
    assert len(GPIO_BL_SITES)==3
    return {
        "new_motor_record_sourced_direct_GPIO_BLs":len(GPIO_BL_SITES),
        "total_categorized_direct_GPIO_BLs":len(first_sets|set(GPIO_BL_SITES)),
        "unresolved_direct_GPIO_BL_candidate_count":122-len(first_sets|set(GPIO_BL_SITES)),
        "actual_APP_link_base":hex(LINK_BASE),
        "initial_motor_object_base":hex(MOTOR_BASE),
        "original_motor_object_stride":MOTOR_STRIDE,
        "motor_selection_producer":hex(0x08010054),
        "selector_multiplied_by_0x2B_then_shifted_2":True,
        "motor_record_selection_index_range_verified_live":False,
        "OEM_motor_GPIO_direct_calls":[hex(x) for x in GPIO_BL_SITES],
        "conditional_branch_to_same_GPIO_call":hex(0x080101F8),
        "original_brushed_motor_records":motor_entries,
        "pin_pairs_identical_v313_and_v322":True,
        "motor_electrical_state_measured":False,
        "all_callers_and_task_IRQ_ownership_recovered":False,
        "physically_stopped_and_race_free_MCU_write_proven":False,
        "v323_flash_or_SET_RESET_authorized":False,
    }

def negatives(b:bytes) -> list[str]:
    rejected=[]
    def corrupt(label:str,addr:int):
        v=bytearray(b);v[addr-LINK_BASE]^=1
        try:inspect(bytes(v))
        except ValueError:rejected.append(label)
        else:raise AssertionError("mutation not rejected: "+label)
    for label,addr in (
       ("motor_root_pointer",0x0801008C),
       ("motor_secondary_root_pointer",0x0801055C),
       ("motor_stride_shift_instruction",0x0801007C),
       ("motor_dispatch_branch",0x08010088),
       ("motor_first_GPIO_BL",0x080101EE),
       ("motor_second_GPIO_BL",0x08010206),
       ("motor_third_GPIO_BL",0x0801020E),
       ("motor_index_source",0x08010074),
       ("M1_PD2_pinmap",PIN_LOOKUP+0x32*16+8),
       ("M2_PD0_pinmap",PIN_LOOKUP+0x30*16+8),
    ):corrupt(label,addr)
    ram=decode_ram(b)
    for i,name in enumerate(["M1_pin0","M2_pin1","M3_pin0","M4_pin1"]):
        v=bytearray(ram)
        v[MOTOR_BASE-RAM_ORIGIN+i*MOTOR_STRIDE+4+(i%2)]^=1
        try:inspect(b,ram_override=bytes(v))
        except ValueError:rejected.append(name)
        else:raise AssertionError("tampered RAM motor pin accepted")
    if len(rejected)!=14:raise ValueError("incomplete mutation test count")
    return rejected

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    old,new=pinned(a.v313,"intermediate_v313"),pinned(a.v322,"running_v322")
    audited(old);audited(new)
    x,y=inspect(old),inspect(new)
    if x!=y:raise ValueError("four brushed motor source maps differ across OEM generations")
    out={"two_generations_source_identical":True,"source":y,
         "live_MCU_or_motor_access":False,"real_M1_M2_motor_stop_proven":False,
         "firmware_flash_permitted":False}
    if a.self_test:out["negative_mutation_cases_rejected"]=negatives(new)
    result=json.dumps(out,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(result)
    print(result,end="")

if __name__=="__main__":main()
