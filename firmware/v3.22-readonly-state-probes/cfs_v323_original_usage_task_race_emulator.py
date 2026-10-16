#!/usr/bin/env python3
"""CFS v3.23: execute ORIGINAL OEM RFID usage task with injected state races.

The original Creality ARM/Thumb + VFP usage task 0x0800DC94 runs inside
Unicorn with only synthetic MCU RAM and stubbed (never executed) external
odometer/log/RTC/secure-chip/transport calls.

Compares unchanged task in two in-memory experimental APPs:
  - PR #39: type4 live gate and Creality initialization only
  - PR #40: that plus two chipless secure sink guards
Tests print percentage math, unload/no-record/tag type changes, and
post-entry state mutations that invalidate the earlier gate approval.

No physical UART, CFS, SWD, sensor, GPIO, Kalico or firmware images.
This proves only bounded OEM task machine-code behavior under stubs,
not fully atomic preemption, a real MCU hardware test or flash safety.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_C1_C0_2,UC_ARM_REG_FPEXC,UC_ARM_REG_S0,
    UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_R0,UC_ARM_REG_R1,
    UC_ARM_REG_SP,
)
from flash_ram_phase2_audit import pinned
from cfs_v323_legacy_type4_live_usage_candidate import (
    build_candidate as compile_initial_type4,
    emulate_gate as test_entry_gate,
)
from cfs_v323_type4_secure_sink_guards_candidate import (
    compile_defended,OEM_USAGE_DETECT_SITE,OEM_USAGE_DETECT_TARGET,
    OEM_USAGE_SECURE_WRITE_SITE,OEM_USAGE_SECURE_WRITE_TARGET,
    OEM_USAGE_REREAD_SITE,OEM_USAGE_REREAD_TARGET,
)
from cfs_app_real_link_base_audit import LINK_BASE

MAIN_OEM_TASK=0x0800DC94
RETURN_PC=0x0802F000
RAM_BASE=0x20000000
RAM_END=0x20010000
RUNTIME=0x20004590
BOX=0x200001F0
READ_RECORD=0x20004460
HARDWARE=0x20000000
STACK=0x2000F000
OEM_ODOMETER=0x0800E730
OEM_CLOCK=0x0801D4D2
OEM_PERCENT=0x080053E4
OEM_LOG=0x08020074
OEM_LOG2=0x080265D0
OEM_COMPARE=0x0802693C
OEM_DUMP=0x0800F814

SCENARIOS=(
  dict(name="idle_clean",mode=0,dirty=0,kind=4,odo=25000),
  dict(name="type4_print_5000mm",mode=1,dirty=0,kind=4,odo=5000),
  dict(name="type4_print_25000mm",mode=1,dirty=0,kind=4,odo=25000),
  dict(name="type4_print_55000mm",mode=1,dirty=0,kind=4,odo=55000),
  dict(name="type4_print_dirty_update",mode=1,dirty=1,kind=4,odo=25000),
  dict(name="type4_unload_dirty",mode=2,dirty=1,kind=4,odo=22),
  dict(name="invalid_record_dirty",mode=1,dirty=1,kind=4,valid=0,odo=22),
  dict(name="type7_record_dirty",mode=1,dirty=1,kind=7,odo=22),
  dict(name="type7_secure_board",mode=1,dirty=1,kind=7,hw=1,odo=22),
  dict(name="type7_secure_unload",mode=2,dirty=1,kind=7,hw=1,odo=22),
  dict(name="race_print_to_unload",mode=1,dirty=0,kind=4,odo=5000,inject="unload"),
  dict(name="race_record_removed",mode=1,dirty=0,kind=4,odo=5000,inject="removed"),
  dict(name="race_type4_to_type7",mode=1,dirty=0,kind=4,odo=5000,inject="type7"),
  dict(name="race_bad_type_and_dirty",mode=1,dirty=0,kind=4,odo=5000,inject="bad_type"),
  dict(name="race_bad_type_after_detect",mode=2,dirty=1,kind=7,odo=22,inject="force_detection_success"),
)

def f32(value:float)->int:
    return struct.unpack("<I",struct.pack("<f",value))[0]

def u32(cpu:Uc,address:int,value:int)->None:
    cpu.mem_write(address,struct.pack("<I",value))

def read_u32(cpu:Uc,address:int)->int:
    return struct.unpack("<I",bytes(cpu.mem_read(address,4)))[0]

def execute_task(image:bytes,scenario:dict)->dict:
    s=dict(scenario)
    name=s["name"]
    mode=s.get("mode",1)
    dirty=s.get("dirty",0)
    kind=s.get("kind",4)
    valid=s.get("valid",1)
    odo=s.get("odo",22)
    chip=s.get("hw",0)
    mutation=s.get("inject")
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    cpu.mem_map(0x08000000,0x40000)
    cpu.mem_write(LINK_BASE,image)
    cpu.mem_map(RAM_BASE,0x10000)
    cpu.reg_write(UC_ARM_REG_C1_C0_2,0x00F00000)
    cpu.reg_write(UC_ARM_REG_FPEXC,0x40000000)
    cpu.reg_write(UC_ARM_REG_SP,STACK)
    cpu.reg_write(UC_ARM_REG_LR,RETURN_PC|1)
    cpu.mem_write(BOX+2,b"\x00")
    cpu.mem_write(BOX+3,b"\x50")
    cpu.mem_write(HARDWARE,bytes([chip]))
    cpu.mem_write(READ_RECORD+0x4B,bytes([kind]))
    u32(cpu,RUNTIME+0,0)
    u32(cpu,RUNTIME+4,250000)
    u32(cpu,RUNTIME+8,1000)
    u32(cpu,RUNTIME+0xC,f32(0.))
    cpu.mem_write(RUNTIME+0x14,b"\x50")
    cpu.mem_write(RUNTIME+0x15,bytes([dirty]))
    cpu.mem_write(RUNTIME+0x16,bytes([mode]))
    cpu.mem_write(RUNTIME+0x17,bytes([valid]))
    cpu.mem_write(RUNTIME+0x63,bytes([kind]))
    events=[]
    touched=[]
    modified=False
    calls=0

    def oncode(m:Uc,pc:int,size:int,_user)->None:
        nonlocal modified,calls
        calls+=1
        if calls>5000:
            raise ValueError("original OEM task emulator exceeded bounded steps")
        # Inject a *state transition after an earlier successful entry
        # gate*, just as this unchanged OEM task reaches the save path.
        if mutation in ("unload","removed","type7","bad_type") and not modified and pc==0x0800DE58:
            modified=True
            if mutation=="unload":
                m.mem_write(RUNTIME+0x16,b"\x02")
                m.mem_write(RUNTIME+0x15,b"\x01")
            elif mutation=="removed":
                m.mem_write(RUNTIME+0x17,b"\x00")
                m.mem_write(RUNTIME+0x15,b"\x01")
            elif mutation=="type7":
                m.mem_write(RUNTIME+0x63,b"\x07")
                m.mem_write(READ_RECORD+0x4B,b"\x07")
                m.mem_write(RUNTIME+0x15,b"\x01")
            else:
                m.mem_write(RUNTIME+0x16,b"\x02")
                m.mem_write(RUNTIME+0x17,b"\x00")
                m.mem_write(RUNTIME+0x63,b"\x07")
                m.mem_write(READ_RECORD+0x4B,b"\x07")
                m.mem_write(RUNTIME+0x15,b"\x01")
            events.append("injected_record_change")
        if mutation=="force_detection_success" and pc==0x0800DE6C:
            m.reg_write(UC_ARM_REG_R0,0)
            modified=True
            events.append("forced_postguard_success")
        if pc in (OEM_USAGE_DETECT_SITE,OEM_USAGE_SECURE_WRITE_SITE):
            touched.append(hex(pc))
        if pc==OEM_ODOMETER:
            m.reg_write(UC_ARM_REG_S0,f32(odo))
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_CLOCK:
            m.reg_write(UC_ARM_REG_R0,1050)
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif pc in (OEM_LOG,OEM_LOG2):
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_PERCENT:
            events.append(f"percent_published:{m.reg_read(UC_ARM_REG_R1)}")
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_COMPARE:
            # Synthetic manufacturer RFID IDs match, to exercise
            # the branch that would attempt an FM15L013 update.
            events.append("synthetic_id_compare_equal")
            m.reg_write(UC_ARM_REG_R0,0)
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif pc in (OEM_USAGE_DETECT_TARGET,OEM_USAGE_SECURE_WRITE_TARGET):
            # Do not run physical hardware-dependent OEM routines.
            events.append(f"ORIGINAL_SECURE_SINK:{pc:#x}")
            m.reg_write(UC_ARM_REG_R0,0)
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_USAGE_REREAD_TARGET:
            events.append("ORIGINAL_TAG_REREAD")
            m.reg_write(UC_ARM_REG_R0,1)
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_DUMP:
            m.reg_write(UC_ARM_REG_R0,0)
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif pc==0x0800D940:
            # Avoid long module state machine in timeout subpath.
            events.append("OEM_unload_timeout")
            m.reg_write(UC_ARM_REG_R0,0)
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
    def onwrite(m:Uc,access,address:int,size:int,value:int,_user)->None:
        if not (RAM_BASE <= address and address+size <= RAM_END):
            raise ValueError("OEM task wrote outside synthetic SRAM")
    cpu.hook_add(UC_HOOK_CODE,oncode)
    cpu.hook_add(UC_HOOK_MEM_WRITE,onwrite)
    cpu.emu_start(MAIN_OEM_TASK|1,RETURN_PC,count=5100)
    if cpu.reg_read(UC_ARM_REG_PC)!=RETURN_PC:
        raise ValueError("original task did not return")
    return {
        "scenario":name,
        "hw":chip,
        "original_task_instructions":calls,
        "used_mm":read_u32(cpu,RUNTIME),
        "display_percent":bytes(cpu.mem_read(BOX+3,1))[0],
        "runtime_dirty":bytes(cpu.mem_read(RUNTIME+0x15,1))[0],
        "runtime_mode":bytes(cpu.mem_read(RUNTIME+0x16,1))[0],
        "mutation_occurred":modified,
        "events":events,
        "original_secure_entry_count":sum(e.startswith("ORIGINAL_SECURE_SINK:") for e in events),
        "manager_sensitive_callsite_PCs":touched,
    }

def test_cases(v39:bytes,v40:bytes)->list[dict]:
    out=[]
    cases={s["name"]:s for s in SCENARIOS}
    for name,scenario in cases.items():
        old=execute_task(v39,scenario)
        defended=execute_task(v40,scenario)
        # Source wrappers change only branches into secure-chip sinks,
        # not the OEM type4 odometer/percentage calculations.
        if name in ("type4_print_5000mm","type4_print_25000mm","type4_print_55000mm"):
            expected={
                "type4_print_5000mm":(5000,78),
                "type4_print_25000mm":(25000,70),
                "type4_print_55000mm":(55000,58)
            }[name]
            for result in (old,defended):
                if (result["used_mm"],result["display_percent"])!=expected:
                    raise ValueError(f"OEM consumption math drift: {name} {result}")
                if result["original_secure_entry_count"]!=0:
                    raise ValueError("type4 consumption unexpectedly reached secure sink")
        if name=="idle_clean":
            if any(r["used_mm"] for r in (old,defended)):
                raise ValueError("IDLE unexpectedly consumed filament")
        if scenario.get("inject") in ("unload","removed","type7","bad_type","force_detection_success"):
            if not old["mutation_occurred"] or not defended["mutation_occurred"]:
                raise ValueError("requested mid-task fault injection did not occur")
        if scenario.get("hw",0)==0:
            if defended["original_secure_entry_count"]!=0:
                raise ValueError(f"chipless secure OEM path still reachable: {name}")
        else:
            if name.startswith("type7_secure") and not defended["original_secure_entry_count"]:
                raise ValueError("secure-element board lost its stock OEM branch")
        if name in ("type4_unload_dirty","invalid_record_dirty","type7_record_dirty",
                    "race_print_to_unload","race_record_removed","race_type4_to_type7",
                    "race_bad_type_and_dirty","race_bad_type_after_detect"):
            if old["original_secure_entry_count"]==0:
                raise ValueError(f"unprotected predecessor does not demonstrate risk: {name}")
            if defended["original_secure_entry_count"]!=0:
                raise ValueError(f"second guard did not block secure call: {name}")
        if name=="race_bad_type_after_detect":
            if old["original_secure_entry_count"]<2:
                raise ValueError("baseline synthetic detection success did not reach write sink")
            if defended["original_secure_entry_count"]!=0:
                raise ValueError("secure write guard bypassed after synthetic detection override")
        out.append({
            "case":name,
            "earlier_gate_only_secure_calls":old["original_secure_entry_count"],
            "with_two_secure_sink_guards_secure_calls":defended["original_secure_entry_count"],
            "old_percent":old["display_percent"],
            "guarded_percent":defended["display_percent"],
            "old_used_mm":old["used_mm"],
            "guarded_used_mm":defended["used_mm"],
            "synthetic_mutation_applied":defended["mutation_occurred"],
            "runtime_sensitive_callsites_visited":defended["manager_sensitive_callsite_PCs"],
        })
    if len(out)!=len(SCENARIOS):
        raise ValueError("original usage-task dual-build test-case census changed")
    return out

def negative_hook_removal(initial:bytes,guarded:bytes)->list[dict]:
    """Revert each of the only two second-stage hook bytes separately.

    With the original OEM BL reinstated, an actually executed original
    secure path MUST reappear under the already tested synthetic race.
    """
    fixtures=(
        ("remove_secure_detect_guard",OEM_USAGE_DETECT_SITE,
         dict(name="type4_unload_dirty",mode=2,dirty=1,kind=4,odo=22)),
        ("remove_secure_write_guard",OEM_USAGE_SECURE_WRITE_SITE,
         dict(name="race_bad_type_after_detect",mode=2,dirty=1,kind=7,odo=22,
              inject="force_detection_success")),
    )
    found=[]
    for name,pc,scenario in fixtures:
        off=pc-LINK_BASE
        if initial[off:off+4]==guarded[off:off+4]:
            raise ValueError("second-stage secure sink hook unexpectedly missing")
        tampered=bytearray(guarded)
        tampered[off:off+4]=initial[off:off+4]
        vulnerable=execute_task(bytes(tampered),scenario)
        intact=execute_task(guarded,scenario)
        if vulnerable["original_secure_entry_count"]<1:
            raise ValueError("mutant missing risk; CI would not detect a removed guard")
        if intact["original_secure_entry_count"]!=0:
            raise ValueError("defended OEM task still reached secure sink")
        found.append({
            "fault":name,
            "original_callsite_PC":hex(pc),
            "removed_original_BL_restored_from_pinned_parent":True,
            "OEM_secure_accesses_after_one_hook_removed":
                vulnerable["original_secure_entry_count"],
            "OEM_secure_accesses_with_both_hooks":0,
        })
    return found

def main():
    p=argparse.ArgumentParser()
    for arg in ("v313","v322","asm","linker","builder"):
        p.add_argument("--"+arg,type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=pinned(a.v313,"intermediate_v313")
    saved=pinned(a.v322,"running_v322")
    src=a.asm.read_text()
    linker=a.linker.read_text()
    builder=a.builder.read_text()
    initial,meta,_=compile_initial_type4(old,saved,src,linker,builder,a.builder)
    defended,guard_meta,syms=compile_defended(old,saved,src,linker,builder,a.builder)
    if len(initial)!=178320 or len(defended)!=178352:
        raise ValueError("earlier compiled v3.23 candidate references changed")
    # Exercise the actual newly assembled type4 MCU approval gate
    # BEFORE the synthetic record is mutated inside the stock task.
    # These are two independent emulation instances sharing a pinned
    # candidate image, to model a real RTOS rescheduling window.
    preflight=test_entry_gate(
        defended,syms["live_type4_usage_gate"],
        0,0,1,1,4,250000,80,0,
    )
    if preflight["gate_result"]!=1 or preflight["global_SRAM_writes"]!=0:
        raise ValueError("earlier valid type4 entry gate not demonstrated")
    cases=test_cases(initial,defended)
    mutants=negative_hook_removal(initial,defended)
    report={
        "OEM_original_ARM_VFP_usage_task":hex(MAIN_OEM_TASK),
        "earlier_gate_only_candidate_APP_bytes":len(initial),
        "with_two_secure_sinks_candidate_APP_bytes":len(defended),
        "only_original_OEM_task_code_emulated":True,
        "stubs_are_synthetic_and_no_OEM_RFID_hardware_code_executed":True,
        "two_original_secure_sink_branch_PCs":[hex(OEM_USAGE_DETECT_SITE),hex(OEM_USAGE_SECURE_WRITE_SITE)],
        "original_tag_reread_branch_source_only":[hex(OEM_USAGE_REREAD_SITE)],
        "earlier_valid_original_MCU_entry_gate_emulated":preflight,
        "case_results":cases,
        "two_single_hook_removal_mutations_rejected":mutants,
        "real_RTOS_preemption_or_IRQ_qualified":False,
        "flash_approved":False,
        "hardware_IO":False,
        "firmware_BIN_emitted":False
    }
    text=json.dumps(report,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(text)
    print(text,end="")
if __name__=="__main__":
    main()
