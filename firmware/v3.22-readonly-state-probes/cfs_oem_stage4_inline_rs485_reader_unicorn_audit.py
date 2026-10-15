#!/usr/bin/env python3
"""Offline OEM CFS stage-4 embedded RS485 path audit (no hardware).

The stock feed command stage4 (0x10) invokes a private serial reader and
CRC/stage validator INSTEAD of the main RS485 dispatcher. Validate the
actual OEM Cortex-M code in exact SHA-pinned v3.13 and v3.22, then execute
the original routines under Unicorn with a synthetic serial-read stub.

This is bounded differential behavior research, NOT a new firmware patch
and NOT proof that malformed requests can reach the physical UART parser.
No firmware BIN, CFS serial, motor, RFID, GPIO, flash or Kalico I/O.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_R0,UC_ARM_REG_R2,
    UC_ARM_REG_R3,UC_ARM_REG_SP,
)
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE,audited

STAGE4_LOAD_ENTRY=0x080045C6
STAGE4_LOOP=0x08025C4E
STAGE4_UART_READER=0x08025EB2
STAGE4_SPECIAL_VALIDATOR=0x08025C18
UART_RT_READ=0x080169CE
RT_SLEEP=0x08021E28
OEM_CRC8=0x0800E9EC
OEM_MAIN_RS485_DISPATCH=0x0800F27C
V322_PATCHED_ROUTER=0x0800F3A0
EMU_RETURN=0x0802E700
EMU_STACK=0x2000F000
EMU_PACKET_HOST=0x20000200
EMU_OWN_ADDRESS_ROOT=0x20000BB0
EMU_OWN_ADDRESS=0x20000800
EMU_SERIAL_DEVICE_ROOT=0x20000254
EMU_SERIAL_DEVICE=0x20000B00

# All these ORIGINAL manufacturer instructions are directly checked in
# both exact firmware generations; each PC and operand is canonical.
OEM_EXPECTED={
    0x08004658:("bl","#0x8025c4e"),
    0x08025C84:("bl","#0x8025eb2"),
    0x08025C88:("cmp","r0, #5"),
    0x08025C8C:("cmp","r0, #6"),
    0x08025C90:("cmp","r0, #0xff"),
    0x08025CBA:("bl","#0x800eaf2"),
    0x08025EB2:("push","{r4, r5, lr}"),
    0x08025EC0:("bl","#0x80169ce"),
    0x08025ECE:("cmp","r0, #0xf7"),
    0x08025ED8:("movs","r3, #8"),
    0x08025EE2:("bl","#0x80169ce"),
    0x08025EF0:("bl","#0x8025c18"),
    0x08025EF4:("cmp","r0, #5"),
    0x08025EF8:("cmp","r0, #6"),
    0x08025F06:("bl","#0x80169ce"),
    0x08025C18:("push","{r4, lr}"),
    0x08025C1E:("ldrb","r1, [r4, #1]"),
    0x08025C22:("ldrb","r0, [r0]"),
    0x08025C24:("cmp","r1, r0"),
    0x08025C28:("ldrb","r0, [r4, #4]"),
    0x08025C2A:("cmp","r0, #0x10"),
    0x08025C2E:("movs","r1, #6"),
    0x08025C30:("adds","r0, r4, #2"),
    0x08025C32:("bl","#0x800e9ec"),
    0x08025C36:("ldrb","r1, [r4, #8]"),
    0x08025C38:("cmp","r0, r1"),
    0x08025C3C:("movs","r0, #0xff"),
    0x08025C40:("ldrb","r0, [r4, #6]"),
    0x08025C42:("cmp","r0, #5"),
    0x08025C46:("cmp","r0, #6"),
    # Manufacturer stage-4 feed physically drives the hub and has
    # several explicit stop sites; these are source-level pins only.
    0x08025C60:("bl","#0x8011164"),
    0x08025CD0:("bl","#0x8011198"),
    0x08025D04:("bl","#0x8011198"),
    0x08025D2E:("bl","#0x8011198"),
    0x08025D52:("bl","#0x8011198"),
    0x08011164:("push","{r4, lr}"),
    0x08011168:("movs","r1, #0"),
    0x0801116A:("movs","r0, #0x44"),
    0x0801116C:("bl","#0x8018eec"),
    0x08011172:("bl","#0x80110b2"),
    0x0801117C:("b","#0x80110cc"),
    0x08011198:("push","{r4, lr}"),
    0x0801119A:("movs","r1, #1"),
    0x0801119C:("movs","r0, #0x44"),
    0x0801119E:("bl","#0x8018eec"),
    0x080111A6:("movs","r0, #0"),
    0x080111A8:("b","#0x80110cc"),
}

def instruction_at(app:bytes,pc:int)->tuple[str,str]:
    off=pc-LINK_BASE
    if off<0 or off+4>len(app):
        raise ValueError(f"OEM instruction outside pinned source {pc:#x}")
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    ins=next(md.disasm(app[off:off+4],pc,count=1),None)
    if ins is None:
        raise ValueError(f"bad OEM Thumb at {pc:#x}")
    return (ins.mnemonic,ins.op_str)

def verify_instruction_sites(app:bytes)->None:
    for pc,expected in OEM_EXPECTED.items():
        actual=instruction_at(app,pc)
        if actual!=expected:
            raise ValueError(
                f"manufacturer stage4/RS485 source differs {pc:#x}: "
                f"{actual} != {expected}"
            )
    if STAGE4_LOOP==OEM_MAIN_RS485_DISPATCH or STAGE4_SPECIAL_VALIDATOR==OEM_MAIN_RS485_DISPATCH:
        raise AssertionError("internal reader should be distinct from main dispatcher")

def crc8(data:bytes)->int:
    state=0
    for x in data:
        state^=x
        for _ in range(8):
            state=((state<<1)^(7 if state&0x80 else 0))&0xff
    return state

def synthetic_frame(*,address:int=1,declared_length:int=6,
                    qualifier:int=0xff,command:int=0x10,
                    stage:int=5,sync:int=0xf7,break_crc:bool=False)->bytes:
    frame=bytearray([sync,address,declared_length,qualifier,command,1,stage,0,0])
    frame[8]=crc8(frame[2:8])
    if break_crc:frame[8]^=1
    return bytes(frame)

def emulate_embedded_reader(app:bytes,frame:bytes)->dict:
    # Map only original OEM ROM and synthetic SRAM. Externally called UART
    # read and delay are intercepted before executing their OEM bodies.
    assert len(frame)==9
    machine=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    machine.mem_map(0x08000000,0x40000)
    machine.mem_write(LINK_BASE,app)
    machine.mem_map(0x20000000,0x10000)
    machine.mem_write(EMU_OWN_ADDRESS_ROOT,EMU_OWN_ADDRESS.to_bytes(4,"little"))
    machine.mem_write(EMU_OWN_ADDRESS,b"\x01")
    machine.mem_write(EMU_SERIAL_DEVICE_ROOT,EMU_SERIAL_DEVICE.to_bytes(4,"little"))
    machine.reg_write(UC_ARM_REG_SP,EMU_STACK)
    machine.reg_write(UC_ARM_REG_LR,EMU_RETURN|1)
    machine.reg_write(UC_ARM_REG_R0,0)
    to_receive=bytearray(frame)
    serial_reads:list[list[int]]=[]
    sleep_calls:list[int]=[]
    real_writes=[]
    def emulated_memory_write(uc,access,addr,size,value,user):
        if not (0x2000E000<=addr and addr+size<=0x20010000):
            raise ValueError(f"OEM stage4 reader wrote outside synthetic stack {addr:#x}")
        real_writes.append((addr,size))
    def replace_hardware_call(uc,pc,size,user):
        if pc==UART_RT_READ:
            requested=uc.reg_read(UC_ARM_REG_R3)
            target=uc.reg_read(UC_ARM_REG_R2)
            if not 0<=requested<=0x80:
                raise ValueError("OEM UART read requested unexpectedly large buffer")
            if not (0x2000E000<=target and target+requested<=0x20010000):
                raise ValueError("unexpected OEM UART destination outside stack")
            portion=bytes(to_receive[:requested])
            del to_receive[:requested]
            if portion:
                uc.mem_write(target,portion)
            uc.reg_write(UC_ARM_REG_R0,len(portion))
            serial_reads.append([requested,len(portion)])
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif pc==RT_SLEEP:
            sleep_calls.append(uc.reg_read(UC_ARM_REG_R0))
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif pc==OEM_MAIN_RS485_DISPATCH or pc==V322_PATCHED_ROUTER:
            raise ValueError("embedded reader unexpectedly executed the main RS485 dispatcher")
    machine.hook_add(UC_HOOK_CODE,replace_hardware_call)
    machine.hook_add(UC_HOOK_MEM_WRITE,emulated_memory_write)
    machine.emu_start(STAGE4_UART_READER|1,EMU_RETURN,count=5000)
    outcome=machine.reg_read(UC_ARM_REG_R0)
    # First sync byte, 2-ms sleep then fixed eight-byte read.
    # Corrupt sync takes a distinct drain/discard path.
    return {
        "input_frame_hex":frame.hex(),
        "returned_stage_or_error":outcome,
        "emulated_serial_reads_requested_returned":serial_reads,
        "emulated_sleep_calls_ms":sleep_calls,
        "OEM_Flash_or_nonstack_SRAM_write_detected":False,
        "main_dispatch_invoked":False,
        "synthetic_serial_stub_only":True,
    }

CASES={
    "valid_stage5":dict(stage=5),
    "valid_stage6":dict(stage=6),
    "length_7_with_matching_crc":dict(declared_length=7),
    "length_2_with_matching_crc":dict(declared_length=2),
    "header_00_with_matching_crc":dict(qualifier=0),
    "header_99_with_matching_crc":dict(qualifier=0x99),
    "bad_address":dict(address=2),
    "bad_command_57":dict(command=0x57),
    "bad_stage":dict(stage=4),
    "bad_crc":dict(break_crc=True),
    "bad_sync":dict(sync=0),
}
EXPECTED_RETURNS={
    "valid_stage5":5,
    "valid_stage6":6,
    "length_7_with_matching_crc":5,
    "length_2_with_matching_crc":5,
    "header_00_with_matching_crc":5,
    "header_99_with_matching_crc":5,
    "bad_address":0,
    "bad_command_57":0,
    "bad_stage":0,
    "bad_crc":0,
    "bad_sync":0,
}

def emulate_validator_direct(app:bytes,frame:bytes)->int:
    """Directly invoke only the OEM fixed-layout validator, no UART calls."""
    machine=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    machine.mem_map(0x08000000,0x40000)
    machine.mem_write(LINK_BASE,app)
    machine.mem_map(0x20000000,0x10000)
    machine.mem_write(EMU_OWN_ADDRESS_ROOT,EMU_OWN_ADDRESS.to_bytes(4,"little"))
    machine.mem_write(EMU_OWN_ADDRESS,b"\x01")
    machine.mem_write(EMU_PACKET_HOST,frame)
    machine.reg_write(UC_ARM_REG_SP,EMU_STACK)
    machine.reg_write(UC_ARM_REG_LR,EMU_RETURN|1)
    machine.reg_write(UC_ARM_REG_R0,EMU_PACKET_HOST)
    machine.emu_start(STAGE4_SPECIAL_VALIDATOR|1,EMU_RETURN,count=800)
    return machine.reg_read(UC_ARM_REG_R0)


def test_generation(app:bytes)->dict:
    verify_instruction_sites(app)
    actual={}
    for name,kwargs in CASES.items():
        frame=synthetic_frame(**kwargs)
        outcome=emulate_embedded_reader(app,frame)
        if outcome["returned_stage_or_error"]!=EXPECTED_RETURNS[name]:
            raise ValueError(f"unexpected OEM stage4 reader behavior: {name}, {outcome}")
        reads=outcome["emulated_serial_reads_requested_returned"]
        if name=="bad_sync":
            if not reads or reads[0]!=[1,1] or len(reads)<2 or reads[1][0]!=128:
                raise ValueError("invalid sync not routed to OEM drain")
        else:
            if reads[:2]!=[[1,1],[8,8]] or outcome["emulated_sleep_calls_ms"]!=[2]:
                raise ValueError("OEM embedded reader does not use one plus fixed eight UART bytes")
        direct=emulate_validator_direct(app,frame)
        if name=="bad_crc":
            if direct!=0xff or outcome["returned_stage_or_error"]!=0:
                raise ValueError("CRC error should be 0xff at validator but 0 at reader")
        elif name=="bad_sync":
            # This validator is called only AFTER the reader sync gate.
            if direct!=5 or outcome["returned_stage_or_error"]!=0:
                raise ValueError("sync validation is owned by the UART reader, not validator")
        elif direct!=outcome["returned_stage_or_error"]:
            raise ValueError("unexpected conversion of direct validator return: "+name)
        outcome["direct_OEM_validator_return"]=direct
        actual[name]=outcome
    return actual

def negative_source_tests(app:bytes)->list[str]:
    names={
        "redirected_stage4_inline_entry":0x08004658,
        "redirected_embedded_UART_read":0x08025C84,
        "modified_sync_compare":0x08025ECE,
        "modified_second_read_fixed_length":0x08025ED8,
        "skipped_embedded_validator":0x08025EF0,
        "modified_frame_address_match":0x08025C24,
        "modified_cmd_10_guard":0x08025C2A,
        "modified_constant_six_crc_size":0x08025C2E,
        "modified_oem_crc_call":0x08025C32,
        "modified_crc_compare":0x08025C38,
        "modified_stage5_compare":0x08025C42,
        "modified_stage6_compare":0x08025C46,
        "modified_stage4_response_route":0x08025CBA,
        "changed_motor_hub_start_call":0x08025C60,
        "changed_motor_hub_stop_on_timeout":0x08025CD0,
        "changed_motor_hub_stop_on_loop_failure":0x08025D04,
        "changed_motor_brake_deassertion":0x08011168,
        "changed_motor_brake_assertion":0x0801119A,
    }
    failures=[]
    for name,pc in names.items():
        modified=bytearray(app)
        modified[pc-LINK_BASE]^=1
        try:verify_instruction_sites(bytes(modified))
        except ValueError:failures.append(name)
        else:raise AssertionError("modified original motor-stage source accepted: "+name)
    if len(failures)!=18:
        raise AssertionError("exact source mutations not rejected")
    return failures

def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    old=pinned(args.v313,"intermediate_v313")
    current=pinned(args.v322,"running_v322")
    audited(old);audited(current)
    before=test_generation(old)
    after=test_generation(current)
    if before!=after:
        raise ValueError("old/new OEM embedded RS485 behavior differs")
    out={
        "original_APP_physical_base":hex(LINK_BASE),
        "original_stage4_load_function":hex(STAGE4_LOAD_ENTRY),
        "original_stage4_motor_loop":hex(STAGE4_LOOP),
        "original_stage4_UART_reader":hex(STAGE4_UART_READER),
        "original_stage4_frame_validator":hex(STAGE4_SPECIAL_VALIDATOR),
        "original_main_RS485_dispatcher_distinct":hex(OEM_MAIN_RS485_DISPATCH),
        "original_0x57_hooked_main_router":hex(V322_PATCHED_ROUTER),
        "OEM_instruction_sites_verified_across_two_pinned_APPs":len(OEM_EXPECTED),
        "OEM_stage4_calls_hub_start_before_receive":True,
        "OEM_stage4_has_four_source_verified_hub_stop_calls":True,
        "OEM_hub_brake_pin_original_0x44":True,
        "physical_motor_energized_status_from_brake_signal_verified":False,
        "v313_v322_embedded_receive_behavior_identical":True,
        "embedded_reader_requires_one_plus_eight_serial_bytes_for_sync":True,
        "embedded_reader_returns_stages_5_6_or_0_and_drops_CRC_failure":True,
        "OEM_validator_raw_crc_error_is_0xFF_but_reader_returns_0":True,
        "OEM_validator_checks_no_sync_byte_but_reader_does":True,
        "OEM_validator_accepts_noncanonical_declared_length_if_crc_matches":True,
        "OEM_validator_accepts_noncanonical_qualifier_if_crc_matches":True,
        "OEM_stage4_does_not_dispatch_0x57":True,
        "external_full_UART_receiver_acceptance_proven":False,
        "physical_motor_quiescence_verified":False,
        "installed_firmware_flashing_authorized":False,
        "emulated_synthetic_cases":after,
        "hardware_access":False,
    }
    if args.self_test:
        out["OEM_source_mutations_rejected"]=negative_source_tests(current)
    serialized=json.dumps(out,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(serialized)
    print(serialized,end="")
if __name__=="__main__":
    main()
