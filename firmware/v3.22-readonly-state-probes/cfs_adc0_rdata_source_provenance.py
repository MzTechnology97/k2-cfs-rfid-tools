#!/usr/bin/env python3
"""Source-pin GD32F303 ADC0_RDATA read helper in saved original CFS ROM.

The manufacturer Thumb code at physical 0x08022BBC:
   LDR R0, [PC,#0xC8]  (ROM[0x08022C88] = ADC0_CTL1 0x40012408)
   ADDS R0,#0x44     (ADC0_RDATA = 0x4001244C)
   LDR R0,[R0]       (read the routine conversion-data register)
   BX LR

This proves existence of a *generic* ADC0 result-read helper in both
original SHA-pinned v3.13 and v3.22 APP saved files, NOT actual execution
on the live unit, channel rank, ADC source pin or motor-current consumer.
The vendor manual states RDATA reads can clear EOC; do NOT propose
sampling that register from a separate debug agent on a running MCU.

Direct BL callsite search is discovery-only: code may call indirectly
and disassembly of data can produce false positives. Fail closed.
"""
from __future__ import annotations
import argparse,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import audited,LINK_BASE

ADC0_CTL1 = 0x40012408
ADC0_RDATA = 0x4001244C
BASE_LITERAL_PC = 0x08022C88
RESULT_HELPER_PC = 0x08022BBC
CODE = (
    (0x08022926,"ldr","r0, [pc, #0x360]"),
    (0x08022928,"ldr","r1, [r0]"),
    (0x0802292A,"orr","r1, r1, #0x800000"),
    (0x0802292E,"str","r1, [r0]"),
    (0x08022932,"ldr","r0, [pc, #0x354]"),
    (0x08022934,"ldr","r1, [r0]"),
    (0x08022936,"bic","r1, r1, #0x800000"),
    (0x0802293A,"str","r1, [r0]"),
    (0x08022988,"ldr","r1, [pc, #0x2fc]"),
    (0x0802298A,"subs","r1, r1, #4"),
    (0x0802298C,"ldr","r2, [r1]"),
    (0x0802298E,"bic","r2, r2, #0xf0000"),
    (0x08022992,"str","r2, [r1]"),
    (0x08022BBC,"ldr","r0, [pc, #0xc8]"),
    (0x08022BBE,"adds","r0, #0x44"),
    (0x08022BC0,"ldr","r0, [r0]"),
    (0x08022BC2,"bx","lr"),
)

def analyze(image:bytes):
    audited(image)
    ofs=BASE_LITERAL_PC-LINK_BASE
    if struct.unpack_from("<I",image,ofs)[0]!=ADC0_CTL1:
        raise ValueError("original ADC0_CTL1 literal changed")
    c=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    for pc,mnemonic,args in CODE:
        pos=pc-LINK_BASE
        ins=next(c.disasm(image[pos:pos+4],pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=(mnemonic,args):
            raise ValueError(f"original ADC instruction differs at {pc:#x}")
    if ((RESULT_HELPER_PC+4)&~3)+0xC8!=BASE_LITERAL_PC:
        raise AssertionError("original ADC0_RDATA source pointer not PC-relative")
    if ADC0_CTL1+0x44!=ADC0_RDATA:
        raise AssertionError("original ADC result address arithmetic changed")
    # Search independent Thumb BL encoding, without assuming generic
    # RDATA helper is reachable, executed, or used by current monitors.
    calls=[]
    for i in range(0,len(image)-4,2):
        pc=LINK_BASE+i
        ins=next(c.disasm(image[i:i+4],pc,count=1),None)
        if ins is not None and ins.mnemonic=="bl" and ins.size==4 \
           and ins.op_str==f"#0x{RESULT_HELPER_PC:x}":
            calls.append(hex(pc))
    if len(calls)>80:
        raise ValueError("unexpected ADC result helper callsite count")
    pointer_refs=[]
    for pos in range(0,len(image)-3,4):
        word=struct.unpack_from("<I",image,pos)[0]
        if word in (RESULT_HELPER_PC,RESULT_HELPER_PC|1):
            pointer_refs.append({
                "ROM_word_slot":hex(LINK_BASE+pos),
                "stored_pointer_value":hex(word),
                "indirect_call_or_reachable_code_proven":False,
            })
    return {
        "original_Thumb_instruction_sites_checked":len(CODE),
        "original_ADC0_CTL1_register":hex(ADC0_CTL1),
        "original_ADC0_RDATA_register":hex(ADC0_RDATA),
        "ADC0_RDATA_helper_physical_PC":hex(RESULT_HELPER_PC),
        "original_method_reads_32bit_ADC0_RDATA":True,
        "BL_encoded_direct_callsite_candidates":calls,
        "number_of_direct_BL_candidates":len(calls),
        "ROM_word_references_to_helper":pointer_refs,
        "number_of_ROM_word_pointer_references":len(pointer_refs),
        "any_call_to_RDATA_helper_from_actual_motor_current_logic_proven":False,
        "possible_EOC_clear_side_effect_on_RDATA_read":True,
        "safe_to_poll_ADC_RDATA_concurrently_on_live_CFS":False,
        "OEM_ADC_channels_15_10_1_0_actually_configured_proven":False,
        "actual_brushed_motor_current_read_consumers_recovered":False,
        "ADC_result_RAM_locations_or_motor_gain_calibration_proven":False,
        "physical_motor_idle_or_all_driver_disabled_proven":False,
        "MCU_flash_or_SET_RESET_authorized":False,
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--v313",type=Path,required=True)
    parser.add_argument("--v322",type=Path,required=True)
    parser.add_argument("--json-out",type=Path)
    a=parser.parse_args()
    old=analyze(pinned(a.v313,"intermediate_v313"))
    latest=analyze(pinned(a.v322,"running_v322"))
    if old!=latest:
        raise ValueError("ADC0_RDATA helper or BL candidates differ in saved versions")
    report={"both_saved_original_versions_identical":True,
            "v322":latest,
            "no_real_CFS_ADC_or_GPIO_reads":True,
            "safe_to_flash_v323":False}
    body=json.dumps(report,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(body)
    print(body,end="")

if __name__=="__main__":main()
