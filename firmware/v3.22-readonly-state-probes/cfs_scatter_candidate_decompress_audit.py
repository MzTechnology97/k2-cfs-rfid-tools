#!/usr/bin/env python3
"""Safely execute the COPY/DECOMPRESS-LIKE ARM routine in a saved CFS APP.

This executes ORIGINAL (not reimplemented) original-application Thumb
at 0x0801016C, on SHA-256 pinned rebuilt v3.22 bytes in Unicorn with
separate emulated SRAM. The source, destination and length come from
the ORIGINAL application's 4-word scatter table at 0x0803AA10.

Very important: the actual descriptor invokes code at 0x0800316C,
which is in UNDUMPED loader flash. A copy of a similar decompression
algorithm exists at 0x0801016C, exactly 0xD000 higher, but without
the loader dump we cannot assert the two implementations match.
This is a COUNTERFACTUAL reconstruction, not verified live RAM.

Never performs actual MCU/serial/motor operations, firmware patch or flash.
Never emits reconstructed vendor binary, only sanitized diagnostic JSON.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from flash_ram_phase2_audit import (
    APP_BASE, CRC_OFF, META_END, crc16_bypass, pinned, report_image,
)
from unicorn import (
    Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE,
    UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
)
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_SP,
)

ROM_BASE = 0x08000000
ROM_SIZE = 0x80000
RAM_BASE = 0x20000000
RAM_SIZE = 0x10000
SCATTER_FIRST = 0x0803AA10
SCATTER_SECOND = 0x0803AA20
ORIGINAL_LOAD_HANDLER = 0x0800316C
APP_DECOMPRESS_CANDIDATE = 0x0801016C
APP_ZERO_INIT_CANDIDATE = 0x080101C8
EXPECTED_SCATTER_FIRST = (
    0x0802DB6C, 0x20000000, 0x0BC4, ORIGINAL_LOAD_HANDLER,
)
EXPECTED_SCATTER_SECOND = (
    0x0802DE38, 0x20000BC4, 0x6324, 0x080031C8,
)
SENTINEL = 0x0803B700
OBJ_BASE = 0x2000075C
OBJ_STRIDE = 96
NUM_OBJECTS = 5
ROM_STRINGS = ("pwm1", "pwm3", "pwm4", "pwm5", "pwm8")
PINS = {
    0x0801016C: "add",
    0x0801016E: "mov.w",
    0x08010172: "ldrb",
    0x08010176: "ands",
    0x08010180: "asrs",
    0x08010188: "subs",
    0x0801018C: "ldrb",
    0x08010192: "strb",
    0x08010198: "tst.w",
    0x080101B4: "ldrb",
    0x080101B8: "strb",
    0x080101C0: "cmp",
    0x080101C4: "bx",
}


def word(image: bytes, address: int):
    return struct.unpack_from("<I", image, address - APP_BASE)[0]


def verify_image(image: bytes):
    header = report_image(image, "running_v322")
    first = tuple(word(image, SCATTER_FIRST + i * 4) for i in range(4))
    second = tuple(word(image, SCATTER_SECOND + i * 4) for i in range(4))
    if (first, second) != (EXPECTED_SCATTER_FIRST, EXPECTED_SCATTER_SECOND):
        raise ValueError("original CFS loader descriptor mismatch")
    if (APP_DECOMPRESS_CANDIDATE - ORIGINAL_LOAD_HANDLER) != 0xD000:
        raise AssertionError("candidate routine relative offset unexpected")
    dis = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    instructions = []
    for address, expected_mnemonic in PINS.items():
        off = address - APP_BASE
        decoded = next(dis.disasm(image[off:off+4], address, count=1), None)
        if decoded is None or decoded.mnemonic != expected_mnemonic:
            raise ValueError(f"candidate original Thumb mismatch at {address:#x}")
        instructions.append({
            "address":hex(address), "mnemonic":decoded.mnemonic,
            "bytes":decoded.bytes.hex(),
        })
    return {
        "sha256":hashlib.sha256(image).hexdigest(),
        "original_scatter_descriptor": [hex(x) for x in first],
        "next_scatter_descriptor": [hex(x) for x in second],
        "candidate_ROM_routine":hex(APP_DECOMPRESS_CANDIDATE),
        "undumped_actual_handler":hex(ORIGINAL_LOAD_HANDLER),
        "candidate_minus_handler":hex(APP_DECOMPRESS_CANDIDATE-ORIGINAL_LOAD_HANDLER),
        "verified_instruction_pins":instructions,
        "actual_bootloader_implementation_verified":False,
    }


def readable_string(u, ptr):
    if ROM_BASE <= ptr < ROM_BASE+ROM_SIZE:
        end = ROM_BASE+ROM_SIZE
    elif RAM_BASE <= ptr < RAM_BASE+RAM_SIZE:
        end = RAM_BASE+RAM_SIZE
    else:
        return None
    raw=bytes(u.mem_read(ptr, min(32, end-ptr)))
    if b"\x00" not in raw:
        return None
    value=raw.split(b"\x00",1)[0]
    if len(value)>15 or any(x<32 or x>126 for x in value):
        return None
    return value.decode("ascii")


def emulate_candidate(image: bytes):
    src, dest, n, handler = EXPECTED_SCATTER_FIRST
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    u.mem_map(ROM_BASE, ROM_SIZE)
    u.mem_map(RAM_BASE, RAM_SIZE)
    u.mem_write(APP_BASE,image)
    # Deterministic nonzero initial RAM prevents falsely assuming ZI.
    u.mem_write(dest,bytes([0xA5])*n)
    u.reg_write(UC_ARM_REG_SP,0x2000F000)
    u.reg_write(UC_ARM_REG_R0,src)
    u.reg_write(UC_ARM_REG_R1,dest)
    u.reg_write(UC_ARM_REG_R2,n)
    u.reg_write(UC_ARM_REG_LR,SENTINEL|1)
    trace={"returned":False,"steps":0,"read_min":None,"read_max":None,
           "write_min":None,"write_max":None,"written_count":0}
    written=set()
    def code(uc,pc,size,_):
        trace["steps"]+=1
        if pc==SENTINEL:
            trace["returned"]=True
            uc.emu_stop()
    def mmio_read(uc,access,address,size,value,_):
        if dest <= address and address + size <= dest + n:
            # The original decompressor uses overlapping LZ-style
            # look-back copying. Read only bytes already initialized.
            if not all(x in written for x in range(address,address+size)):
                raise ValueError(f"uninitialized decompressor lookback at {address:#x}")
            return
        if not (src <= address and address + size <= EXPECTED_SCATTER_SECOND[0]):
            raise ValueError(f"candidate read outside encoded source at {address:#x}")
        trace["read_min"] = min(trace["read_min"] or address, address)
        trace["read_max"] = max(trace["read_max"] or address+size,address+size)
    def ram_write(uc,access,address,size,value,_):
        if not (dest<=address and address+size<=dest+n):
            raise ValueError(f"candidate wrote outside destination at {address:#x}")
        trace["write_min"]=min(trace["write_min"] or address,address)
        trace["write_max"]=max(trace["write_max"] or address+size,address+size)
        written.update(range(address,address+size))
    u.hook_add(UC_HOOK_CODE,code)
    u.hook_add(UC_HOOK_MEM_READ,mmio_read)
    u.hook_add(UC_HOOK_MEM_WRITE,ram_write)
    u.emu_start(APP_DECOMPRESS_CANDIDATE|1,0,count=400000)
    if not trace["returned"]:
        raise ValueError("candidate decompressor failed to return")
    final_source=u.reg_read(UC_ARM_REG_R0)
    final_output=u.reg_read(UC_ARM_REG_R1)
    expected_end=dest+n
    if final_output!=expected_end:
        raise ValueError(f"candidate output incorrect {final_output:#x} vs {expected_end:#x}")
    if len(written)!=n:
        raise ValueError(f"candidate did not initialize entire RAM region: {len(written)}")
    trace["written_count"]=len(written)
    out=[]
    for i in range(NUM_OBJECTS):
        obj=OBJ_BASE+i*OBJ_STRIDE
        field=obj+0x54
        ptr=struct.unpack("<I",u.mem_read(field,4))[0]
        name=readable_string(u,ptr)
        out.append({
            "index":i,"object":hex(obj),"field":hex(field),
            "candidate_decoded_pointer":hex(ptr),
            "candidate_resolved_name":name,
            "candidate_name_is_one_of_five_stock_PWM_strings":name in ROM_STRINGS,
            "actual_loader_and_real_RAM_not_observed":True,
        })
    return {
        "emulator":trace,
        "source_first":hex(src),
        "source_next_descriptor_boundary":hex(EXPECTED_SCATTER_SECOND[0]),
        "final_source_register":hex(final_source),
        "final_destination_register":hex(final_output),
        "candidate_5_objects":out,
        "all_names_resolved_under_candidate":all(x["candidate_resolved_name"] is not None for x in out),
        "real_CFS_RAM_recovered":False,
        "actual_bootloader_handler_executed":False,
        "actual_motor_driver_callback_proven":False,
    }


def mutation_checks(image: bytes):
    where = {
        "source_destination_length":SCATTER_FIRST,
        "actual_loader_entry":SCATTER_FIRST+12,
        "candidate_start":APP_DECOMPRESS_CANDIDATE,
        "decoder_byte":0x08010172,
        "literal_copy":0x08010192,
        "backref_copy":0x080101B8,
        "loop_end":0x080101C0,
    }
    rejected=[]
    for name, addr in where.items():
        modified=bytearray(image)
        modified[addr-APP_BASE]^=1
        copy=bytearray(modified)
        copy[CRC_OFF:META_END]=bytes(META_END-CRC_OFF)
        struct.pack_into("<H",modified,CRC_OFF,crc16_bypass(copy))
        if not report_image(bytes(modified),"running_v322")["header_crc_valid"]:
            raise AssertionError("mutation must be checksum correct")
        try:
            verify_image(bytes(modified))
        except ValueError:
            rejected.append(name)
        else:
            raise AssertionError("accepted altered original ROM pin: "+name)
    return {"recomputed_CRC_corruptions_rejected":rejected,"count":len(rejected)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    args=p.parse_args()
    image=pinned(args.v322,"running_v322")
    info={
        "scope":"offline original APP candidate decompressor, actual 0x0800316C bootloader unavailable",
        "original_ROM":verify_image(image),
        "counterfactual_decompression":emulate_candidate(image),
        "physical_MCU_access":False,
        "actual_loader_behavior_proven":False,
        "actual_pwm1_registry_object_proven":False,
        "motor_stop_feedback_proven":False,
        "safe_to_flash_extended_v323":False,
    }
    if args.self_test:
        info["tamper"]=mutation_checks(image)
    body=json.dumps(info,indent=2)+"\n"
    if args.json_out:
        args.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":
    main()
