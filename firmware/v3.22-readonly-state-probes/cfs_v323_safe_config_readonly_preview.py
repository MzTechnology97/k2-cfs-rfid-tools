#!/usr/bin/env python3
"""CFS v3.23 first-hardware-test profile: fail-closed volatile config writes.

Stacked on the exact, SHA-pinned in-memory v3.23 type4 lifecycle candidate
from PR #44. It does NOT enable motor SET, RESET, or boot custom profiles.
It overlays exactly two existing handler ENTRY instructions with unconditional
Thumb B.W to the existing status_busy response. No other app bytes except
CRC/length can change. No persistent compiled firmware output.

Original CFG GET/INFO remain supported, including stock read-only speeds.
OEM heap init still clears the volatile 64B sidecar magic/mask on each
MCU boot; any custom persisted profile therefore requires a future host
handshake and a verified atomic motor-start interlock, NOT ready now.

Uses Unicorn original ARM instructions for host command, heap init, and
failure injections. No CFS UART, Kalico, motors, GPIO, flash, actual MCU.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_SP,
)
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE
from cfs_v323_type4_spool_lifecycle_candidate import compiled
from cfs_v323_physical_full_image_parity import CRC_OFF,LEN_OFF,META_END
def crc16_bypass(data:bytes)->int:
    crc=0
    for value in data:
        crc ^= value<<8
        for _ in range(8):
            crc=(((crc<<1)^0x8005)&0xffff) if crc&0x8000 else ((crc<<1)&0xffff)
    return crc


SIDECAR=0x20006EE8
MSG=0x20000200
HEAP_ADDR=0x20006F28
SENTINEL=0x0802F000
OEM_SEND=0x0800EAF2
OEM_DONE=0x0800F808
OEM_HEAP_INIT=0x0801A8D4
GUARDED_COMMANDS=(0x12,0x13)
OLD_READONLY_SPEED_IDS=tuple(range(6))
EFFECTIVE_TIMING_IDS=(7,8)
STORED_ONLY_IDS=tuple(range(9,28))
NO_ATOMIC_MOTOR_INTERLOCK=True
CFG_WRITE_SAFETY_NOT_PROVEN=True

def thumb_b_w(pc:int,dest:int)->bytes:
    """Assemble and source-PC-verify one Thumb unconditional long branch."""
    with tempfile.TemporaryDirectory(prefix="cfs-v323-ro-") as folder:
        base=Path(folder)
        (base/"x.S").write_text(
            ".syntax unified\n.thumb\n.cpu cortex-m3\n"
            '.section .text,"ax",%progbits\n'
            ".global x\n.thumb_func\nx:\n"
            f"    b.w 0x{dest:08X}\n"
        )
        (base/"x.ld").write_text(
            f"SECTIONS {{ . = 0x{pc:08X}; .text : {{ *(.text) }} }}\n"
        )
        subprocess.run(["arm-none-eabi-gcc","-c","-mcpu=cortex-m3","-mthumb",
                        "-ffreestanding","-nostdlib","-o",str(base/"x.o"),
                        str(base/"x.S")],check=True,capture_output=True)
        subprocess.run(["arm-none-eabi-ld","-T",str(base/"x.ld"),
                        "-o",str(base/"x.elf"),str(base/"x.o")],
                       check=True,capture_output=True)
        subprocess.run(["arm-none-eabi-objcopy","-O","binary",
                        str(base/"x.elf"),str(base/"x.bin")],
                       check=True,capture_output=True)
        out=(base/"x.bin").read_bytes()
    ins=next(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
             .disasm(out,pc,count=1),None)
    if len(out)!=4 or ins is None or (ins.mnemonic,ins.op_str)!=(
        "b.w",f"#{dest:#x}"):
        raise ValueError("MCU fail-closed unconditional B.W not correctly encoded")
    return out

def release_preview(old:bytes,symbols:dict[str,int])->tuple[bytes,dict]:
    """Immutable original OEM file prefix; overlay in-memory only."""
    if len(old)!=178416:
        raise ValueError("stacked v3.23 type4/slot lifecycle base changed")
    patched=bytearray(old)
    reject=symbols["status_busy"]
    changes=[]
    decode=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    for entry,opcode in (("op_config_v2_set",0x12),("op_config_v2_reset",0x13)):
        pc=symbols[entry]
        off=pc-LINK_BASE
        original=bytes(old[off:off+4])
        ins=next(decode.disasm(original,pc,count=1),None)
        if ins is None or (ins.mnemonic,ins.op_str)!=("ldrb","r0, [r4, #1]"):
            raise ValueError(f"unverified v3.23 original command start {pc:#x}")
        guard=thumb_b_w(pc,reject)
        patched[off:off+4]=guard
        changes.append({"opcode":hex(opcode),"entry_PC":hex(pc),
                        "original_first_instruction":original.hex(),
                        "protected_first_instruction":guard.hex(),
                        "existing_busy_status_target":hex(reject)})
    blob=bytearray(patched)
    blob[CRC_OFF:META_END]=bytes(META_END-CRC_OFF)
    c=crc16_bypass(blob)
    struct.pack_into("<H",patched,CRC_OFF,c)
    struct.pack_into("<I",patched,LEN_OFF,len(patched))
    allowed=set(range(CRC_OFF,META_END))
    for item in changes:
        off=int(item["entry_PC"],16)-LINK_BASE
        allowed.update(range(off,off+4))
    changed={i for i,(before,after) in enumerate(zip(old,patched)) if before!=after}
    if not changed.issubset(allowed) or not all(
        any(i in range(int(v["entry_PC"],16)-LINK_BASE,
                       int(v["entry_PC"],16)-LINK_BASE+4)
            for i in changed) for v in changes
    ):
        raise ValueError("read-only overlay modified unexpected OEM/handler bytes")
    if patched[0x20E:0x212]!=old[0x20E:0x212]:
        raise ValueError("unexpected APP length update")
    result={
        "previous_full_v323_APP_length":len(old),
        "read_only_config_preview_APP_length":len(patched),
        "size_and_last_Flash_page_unchanged":True,
        "end_exclusive":hex(LINK_BASE+len(patched)),
        "last_Flash_page":(LINK_BASE+len(patched)-1-0x08000000)//0x800,
        "fail_closed_original_command_entries":changes,
        "preexisting_0x57_CONFIG_INFO_GET_persists":True,
        "preexisting_0x57_CONFIG_SET_RESET_never_write":True,
        "old_stock_speed_ids_read_only":list(OLD_READONLY_SPEED_IDS),
        "effective_advanced_timing_ids_only_if_host_enable_later":list(EFFECTIVE_TIMING_IDS),
        "storage_only_tuning_ids_not_effective":list(STORED_ONLY_IDS),
        "MCU_boot_clears_volatile_override_magic_and_mask":True,
        "automatic_custom_Kalico_RAM_profile_on_MCU_boot":False,
        "independent_motor_stop_signal_fully_proven":False,
        "motion_task_ISR_atomic_interlock_implemented":False,
        "firmware_ready_to_flash":False,
        "no_permanent_firmware_image_generated":True,
        "experimental_in_memory_sha256":hashlib.sha256(patched).hexdigest(),
        "experimental_in_memory_crc16":hex(c),
    }
    return bytes(patched),result

def machine(blob:bytes)->Uc:
    c=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    c.mem_map(0x08000000,0x40000)
    c.mem_write(LINK_BASE,blob)
    c.mem_map(0x20000000,0x10000)
    c.reg_write(UC_ARM_REG_SP,0x2000F000)
    c.reg_write(UC_ARM_REG_LR,SENTINEL|1)
    return c

def invoke_host_config(blob:bytes,sym:dict[str,int],cmd:int,state:int,magic:int,mask:int,*,require_fail_closed:bool=True)->dict:
    c=machine(blob)
    req=bytearray(16)
    req[1]=7 if cmd==0x12 else 5 if cmd in (0x11,0x13) else 4
    req[4]=cmd
    req[5]=7
    req[6:8]=(3200).to_bytes(2,"little")
    c.mem_write(MSG,bytes(req))
    c.mem_write(0x200037D2,bytes([state]))
    sidecar=bytearray([0xA5]*64)
    struct.pack_into("<I",sidecar,0,magic)
    struct.pack_into("<I",sidecar,4,mask)
    c.mem_write(SIDECAR,bytes(sidecar))
    original_sidecar=bytes(c.mem_read(SIDECAR,64))
    c.reg_write(UC_ARM_REG_R0,0x57)
    c.reg_write(UC_ARM_REG_R4,MSG)
    calls=[]
    global_writes=[]
    def hook_code(uc,pc,size,_):
        if pc==OEM_SEND:
            status=uc.reg_read(UC_ARM_REG_R1)
            length=uc.reg_read(UC_ARM_REG_R3)
            buf=uc.reg_read(UC_ARM_REG_R2)
            if length>16:raise ValueError("unexpected OEM response size")
            pay=bytes(uc.mem_read(buf,length)) if length else b""
            calls.append({"status":status,"payload_hex":pay.hex()})
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_DONE:
            uc.reg_write(UC_ARM_REG_PC,SENTINEL)
        elif pc==0x0800F27C:
            raise ValueError("original firmware main dispatcher unexpectedly entered")
    def hook_write(uc,access,address,size,value,_):
        if not 0x2000E000<=address and address+size<=0x20010000:
            global_writes.append((address,size))
    c.hook_add(UC_HOOK_CODE,hook_code)
    c.hook_add(UC_HOOK_MEM_WRITE,hook_write)
    c.emu_start(sym["handler_start"]|1,SENTINEL,count=2200)
    if len(calls)!=1:
        raise ValueError("0x57 did not produce one response")
    after=bytes(c.mem_read(SIDECAR,64))
    data={"command":hex(cmd),"BOX_STATE":state,
          "status":calls[0]["status"],
          "payload_hex":calls[0]["payload_hex"],
          "sidecar_changed":original_sidecar!=after,
          "nonstack_writes":len(global_writes)}
    if cmd in GUARDED_COMMANDS and require_fail_closed:
        if (data["status"],data["sidecar_changed"],data["nonstack_writes"])!=(7,False,0):
            raise ValueError("unsafe v3.23 CONFIG SET/RESET was not denied")
    if cmd==0x10 and (data["status"]!=0 or len(calls[0]["payload_hex"])!=8):
        raise ValueError("CONFIG INFO must remain functional")
    if cmd==0x11:
        if data["status"]!=0 or calls[0]["payload_hex"]!="07800c":
            raise ValueError("CONFIG GET ID7 should keep OEM default value 3200")
    return data

def invoke_heap_boot_reset(blob:bytes,sym:dict[str,int])->dict:
    c=machine(blob)
    before=bytes([0x5A]*64)
    c.mem_write(SIDECAR,before)
    visits=[]
    writes=[]
    def hook_code(uc,pc,size,_):
        if pc==OEM_HEAP_INIT:
            visits.append("STOCK_HEAP_INIT_STUB")
            uc.reg_write(UC_ARM_REG_R0,HEAP_ADDR)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    def onwrite(uc,access,addr,size,val,_):
        if not 0x2000E000<=addr and addr+size<=0x20010000:
            writes.append((addr,size))
    c.hook_add(UC_HOOK_CODE,hook_code)
    c.hook_add(UC_HOOK_MEM_WRITE,onwrite)
    c.emu_start(sym["heap_init_sidecar_wrapper"]|1,SENTINEL,count=350)
    new=bytes(c.mem_read(SIDECAR,64))
    if visits!=["STOCK_HEAP_INIT_STUB"] or new[:8]!=bytes(8) or new[8:]!=before[8:]:
        raise ValueError("boot reset must invalidate volatile config magic and flags, leave values")
    if writes!=[(SIDECAR,4),(SIDECAR+4,4)]:
        raise ValueError("boot reset wrote beyond volatile sidecar magic + mask")
    return {
        "OEM_heap_hook_invoked":True,
        "magic_and_enabled_mask_cleared":True,
        "old_sidecar_stored_values_ignored_after_boot":True,
        "no_custom_override_profile_reloaded":True,
        "changed_global_SRAM_only_two_words":True,
    }

def main():
    a=argparse.ArgumentParser()
    for arg in ("v313","v322","asm","linker","builder"):
        a.add_argument("--"+arg,required=True,type=Path)
    a.add_argument("--json-out",type=Path)
    opts=a.parse_args()
    v313=pinned(opts.v313,"intermediate_v313")
    v322=pinned(opts.v322,"running_v322")
    _,prior,meta,sym=compiled(v313,v322,opts.asm.read_text(),
                              opts.linker.read_text(),opts.builder.read_text(),
                              opts.builder)
    candidate,summary=release_preview(prior,sym)
    cases=[]
    for state in (0,1,2,3,4,5):
        for opcode in GUARDED_COMMANDS:
            cases.append(invoke_host_config(candidate,sym,opcode,state,0x35564643,1))
    # Distinct valid and invalid sidecars: writes must still be rejected.
    for mask in (0,1,0xFFFFFFFF):
        for opcode in GUARDED_COMMANDS:
            cases.append(invoke_host_config(candidate,sym,opcode,0,0xDEADBEEF,mask))
    for opcode in (0x10,0x11):
        cases.append(invoke_host_config(candidate,sym,opcode,0,0,0))
    if len(cases)!=20:raise ValueError("MCU command-case census unexpectedly changed")
    boot=invoke_heap_boot_reset(candidate,sym)
    old_unsafe=invoke_host_config(prior,sym,0x12,0,0x35564643,1,require_fail_closed=False)
    if not old_unsafe["sidecar_changed"] or old_unsafe["nonstack_writes"]==0:
        raise ValueError("unpatched prior v3.23 does not reproduce the BOX_STATE-only write risk")
    report={
        "candidate":summary,
        "original_staging_v323_SET_before_guard":old_unsafe,
        "fail_closed_CONFIG_SET_RESET_motor_state_matrix":cases,
        "original_OEM_heap_boot_sidecar_reset":boot,
        "Kalico_changes_performed":False,
        "CFS_hardware_io":False,
        "flash_approved":False,
        "firmware_BIN_exported":False,
    }
    output=json.dumps(report,indent=2)+"\n"
    if opts.json_out:opts.json_out.write_text(output)
    print(output,end="")
if __name__=="__main__":main()
