#!/usr/bin/env python3
"""Stop emulation at original indirect CFS PWM backing driver entry.

Actual source: saved v3.13/v3.22 APP linked at 0x08003000.
The 3012B Keil initialized SRAM contains:
    [0x20000758] = 0x0801B395 (original Thumb backing driver).
RT-Thread PWM constructor receives &0x20000758 as its +0x40
callback context. Its +0x38 control callback at 0x0801939C
for non-constant operation 0x1E02 loads that pointer and calls it.

Unicorn stops BEFORE executing backing driver bytes or hardware MMIO.
This reveals a valid next reverse-engineering target, NOT motor-idle
state, TIMER feedback, safe writes, or a flashable v3.23.
"""
from __future__ import annotations
import argparse,json,struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_LR,UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_SP
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE,audited
from cfs_scatter_two_generation_input_audit import bounded_thumb_grammar

ROOT=0x20000758
DRIVER_PTR=0x0801B395
DRIVER_PC=DRIVER_PTR&~1
CTRL_PC=0x0801939C
OBJECT=0x20002000
BUFFER=0x20002500
ROM_BASE=0x08000000
RAM_BASE=0x20000000
SPECIAL_COMMAND=0x1E02

PINS={
  0x0801B3FC:("ldr","r2, [pc, #0x110]"),
  0x0801B404:("subs","r2, r2, #4"),
  0x0801B408:("bl","#0x801944a"),
  0x08019476:("strd","r5, r6, [r4, #0x3c]"),
  0x080193AC:("ldr","r4, [r0, #0x40]"),
  0x080193AE:("ldr","r4, [r4]"),
  0x080193B0:("cbz","r4, #0x80193b6"),
  0x080193B2:("blx","r4"),
  0x0801B3B8:("b","#0x801b28e"),
  0x0801B28E:("push.w","{r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}"),
  0x0801B296:("ldrd","r0, r3, [r6, #4]"),
  0x0801B29C:("movs","r1, #0x18"),
  0x0801B29E:("bl","#0x8023770"),
  0x0801B2B8:("bl","#0x802384c"),
}

def trial(image:bytes):
    audited(image)
    source=image[0x0802DB6C-LINK_BASE:0x0802DE38-LINK_BASE]
    info,data=bounded_thumb_grammar(source,3012)
    if not info["valid"] or len(data)!=3012:
        raise ValueError("original initialized SRAM reconstruction missing")
    name_driver=struct.unpack_from("<I",data,ROOT-RAM_BASE)[0]
    if name_driver!=DRIVER_PTR:
        raise ValueError("authentic manufacturer PWM backing pointer changed")
    c=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    for pc,(mn,ops) in PINS.items():
        inst=next(c.disasm(image[pc-LINK_BASE:pc-LINK_BASE+4],pc,count=1),None)
        if inst is None or (inst.mnemonic,inst.op_str)!=(mn,ops):
            raise ValueError(f"original RT-Thread PWM backing path changed {pc:#x}")
    if struct.unpack_from("<I",image,0x0801B510-LINK_BASE)[0]!=0x2000075C:
        raise ValueError("object array root literal changed")
    # Show a bounded ORIGINAL backing-function disassembly, no dynamic
    # execution of its body and no guest MMIO mapped or emulated.
    listing=[f"{ins.mnemonic} {ins.op_str}" for ins in
             c.disasm(image[DRIVER_PC-LINK_BASE:DRIVER_PC-LINK_BASE+24],
                      DRIVER_PC)]
    if not listing:
        raise ValueError("original backing driver Thumb address not decodable")
    downstream={}
    for role,start,n in (
        ("request_1e00_or_1e01",0x0801B20C,96),
        ("request_1e02_initializes_GPIO_and_configures_driver",0x0801B28E,96),
        ("other_unclassified_code",0x0801B5E0,64),
    ):
        downstream[role]=[
            {"at":hex(i.address),"opcode":i.mnemonic+" "+i.op_str}
            for i in c.disasm(
                image[start-LINK_BASE:start-LINK_BASE+n],start
            )
        ]
        if not downstream[role]:
            raise ValueError("undecodable saved CFS driver branch "+role)


    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    u.mem_map(ROM_BASE,0x80000)
    u.mem_map(RAM_BASE,0x10000)
    u.mem_write(LINK_BASE,image)
    u.mem_write(OBJECT+0x40,struct.pack("<I",ROOT))
    u.mem_write(ROOT,struct.pack("<I",DRIVER_PTR))
    u.reg_write(UC_ARM_REG_SP,0x2000E000)
    u.reg_write(UC_ARM_REG_LR,0x08050001)
    u.reg_write(UC_ARM_REG_R0,OBJECT)
    u.reg_write(UC_ARM_REG_R1,SPECIAL_COMMAND)
    u.reg_write(UC_ARM_REG_R2,BUFFER)
    hits=[]
    def hook(uc,pc,size,user):
        if pc==DRIVER_PC:
            hits.append((uc.reg_read(UC_ARM_REG_R0),
                         uc.reg_read(UC_ARM_REG_R1),
                         uc.reg_read(UC_ARM_REG_R2)))
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(CTRL_PC|1,0,count=100)
    if hits!=[(OBJECT,SPECIAL_COMMAND,BUFFER)]:
        raise ValueError("failed to reach saved real manufacturer driver callback")
    return {
      "original_initialized_RAM_root":hex(ROOT),
      "original_initialized_RAM_driver_Thumb_pointer":hex(DRIVER_PTR),
      "original_real_driver_PC":hex(DRIVER_PC),
      "RTThread_control_opcode":hex(SPECIAL_COMMAND),
      "synthetic_original_Thumb_reaches_driver_entry":True,
      "backing_driver_body_was_executed":False,
      "first_decoded_original_driver_instructions":listing,
      "bounded_downstream_original_Thumb_branch_disassembly":downstream,
      "downstream_gpio_get_is_rotor_feedback_PROVEN":False,
      "driver_register_or_GPIO_feedback_semantics_proven":False,
      "driver_MCU_running_motion_STOPPED_proven":False,
      "safe_to_hook_or_flash_v323":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=trial(pinned(a.v313,"intermediate_v313"))
    new=trial(pinned(a.v322,"running_v322"))
    if old!=new:
        raise ValueError("v3.13/v3.22 saved manufacturer device backend differ")
    result={"v322":new,"v313_equal":True,
      "physical_motor_active_feedback_proven":False,
      "no_hardware_MMIO_executed":True,
      "no_real_CFS_or_Kalico_modified":True,
      "no_firmware_flash_approved":True}
    if a.json_out:
        a.json_out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))

if __name__=="__main__":main()
