#!/usr/bin/env python3
"""Source-only OEM CFS RS485 envelope/CRC verification at physical 0x08003000.

Pins original v3.13 and reconstructed v3.22 manufacturer Thumb callsites
for CRC8/poly07, F7 byte output, declared length = payload + 3, and
receive first-byte / length checks. This is *not* proof of the complete
RS485 command set, loader protocol access, timing, or driver availability.

Do not use this audit to flash an MCU or drive a motor.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from flash_ram_phase2_audit import pinned
from cfs_app_real_link_base_audit import LINK_BASE, audited

CRC_ENTRY = 0x0800E9EC
CRC_HELPER = 0x0800A8CA
TX_ENTRY = 0x0800AA44
RX_STATE_SYNC = 0x0800F8E8
FRAME_VALIDATOR = 0x0800A92C

# These opcodes derive from original bytes in two exact SHA-pinned APP
# generations, not from a copied/distributed original source file.
SOURCE_OPS = {
    CRC_ENTRY: ("push", "{r4, r5, r6, lr}"),
    0x0800E9F0: ("movs", "r0, #0"),
    0x0800E9F4: ("movs", "r4, #7"),
    0x0800E9F8: ("ldrb", "r3, [r5, r2]"),
    0x0800E9FA: ("eors", "r0, r3"),
    0x0800E9FE: ("lsls", "r6, r0, #0x18"),
    0x0800EA00: ("bpl", "#0x800ea08"),
    0x0800EA02: ("eor.w", "r0, r4, r0, lsl #1"),
    0x0800EA08: ("lsls", "r0, r0, #1"),
    0x0800EA0C: ("uxtb", "r0, r0"),
    0x0800EA0E: ("cmp", "r3, #8"),
    0x0800EA10: ("blo", "#0x800e9fe"),
    0x0800EA14: ("cmp", "r2, r1"),
    0x0800EA16: ("blo", "#0x800e9f8"),
    CRC_HELPER: ("push", "{r4, lr}"),
    0x0800A8D0: ("ldrb", "r0, [r0, #2]"),
    0x0800A8D6: ("ldrb", "r0, [r4, #3]"),
    0x0800A8DC: ("ldrb", "r0, [r4, #4]"),
    0x0800A8E4: ("adds", "r1, r4, #5"),
    0x0800A8EA: ("subs", "r2, r2, #3"),
    0x0800A8EC: ("bl", "#0x8026ac8"),
    0x0800A8F0: ("ldrb", "r1, [r4, #2]"),
    0x0800A8F4: ("bl", f"#{CRC_ENTRY:#x}"),
    TX_ENTRY: ("push", "{r4, r5, r6, lr}"),
    0x0800AA4A: ("movs", "r0, #0xf7"),
    0x0800AA4E: ("strb", "r0, [r4]"),
    0x0800AA50: ("strb", "r1, [r4, #1]"),
    0x0800AA52: ("adds", "r0, r2, #3"),
    0x0800AA54: ("strb", "r0, [r4, #2]"),
    0x0800AA56: ("movs", "r0, #0"),
    0x0800AA58: ("strb", "r0, [r4, #3]"),
    0x0800AA5A: ("strb", "r5, [r4, #4]"),
    0x0800AA5C: ("mov", "r1, r3"),
    0x0800AA5E: ("adds", "r0, r4, #5"),
    0x0800AA60: ("bl", "#0x8026ac8"),
    0x0800AA66: ("bl", f"#{CRC_HELPER:#x}"),
    FRAME_VALIDATOR: ("push", "{r4, lr}"),
    0x0800A930: ("ldrb", "r0, [r0]"),
    0x0800A932: ("cmp", "r0, #0xf7"),
    0x0800A934: ("beq", "#0x800a94c"),
    0x0800A95A: ("ldrb", "r0, [r4, #2]"),
    0x0800A95C: ("subs", "r0, r0, #3"),
    0x0800A95E: ("cmp", "r0, #0x62"),
    0x0800A960: ("blo", "#0x800a966"),
    RX_STATE_SYNC: ("cmp", "r0, #0xf7"),
    0x0800F8EA: ("bne", "#0x800f986"),
    0x0800F926: ("cmp", "r0, #3"),
    0x0800F928: ("blo", "#0x800f934"),
    0x0800F92C: ("subs", "r0, r0, #3"),
    0x0800F998: ("strb.w", "r0, [r4, #0x6a]"),
    0x0800F99E: ("bl", "#0x800eaa4"),
}

def get_inst(data: bytes, pc: int) -> tuple[str, str] | None:
    offset = pc - LINK_BASE
    if not 0 <= offset <= len(data)-4:
        raise ValueError(f"OEM PC out of APP image: {pc:#x}")
    disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    i = next(disassembler.disasm(data[offset:offset+4], pc, count=1), None)
    return (i.mnemonic, i.op_str) if i else None

def check_opcodes(data: bytes) -> None:
    for addr, expected in SOURCE_OPS.items():
        if get_inst(data, addr) != expected:
            raise ValueError(
                f"OEM RS485 instruction drift at {addr:#x}: "
                f"{get_inst(data, addr)} expected {expected}"
            )

def crc8_reference(data: bytes) -> int:
    # Independent mathematical check of source algorithm:
    # CRC init=0, XOR each byte then MSB-first 8 rounds with 0x07.
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (((crc << 1) ^ (0x07 if crc & 0x80 else 0)) & 0xFF)
    return crc

def inspect(data: bytes) -> dict:
    audited(data)
    check_opcodes(data)
    if crc8_reference(bytes.fromhex("04 00 f0 00")) != 0x4C:
        raise ValueError("documented read-only F0/00 frame does not match OEM CRC model")
    if crc8_reference(bytes.fromhex("03 ff 14")) != 0x06:
        raise ValueError("documented 0x14 read-only frame does not match OEM CRC model")
    return {
        "OEM_image_physical_APP_base":hex(LINK_BASE),
        "CRC8_function_PC":hex(CRC_ENTRY),
        "CRC8_initial_value":0,
        "CRC8_polynomial":hex(7),
        "CRC8_reflected":False,
        "CRC8_octets_per_byte":8,
        "source_checksum_input_starts_at_declared_length_not_sync":True,
        "manufacturer_TX_sync":hex(0xF7),
        "OEM_transmit_entry":hex(TX_ENTRY),
        "OEM_transmit_declared_length_equals_payload_plus_three":True,
        "OEM_TX_zero_qualifier_instruction_is_present":True,
        "OEM_receive_sync_comparison_PC":hex(RX_STATE_SYNC),
        "OEM_receive_minimum_declared_length_three_check_PC":hex(0x0800F926),
        "OEM_validator_compares_payload_length_to_strict_less_than_0x62":True,
        "OEM_validator_max_payload_on_that_path":0x62-1,
        "all_application_and_loader_receive_paths_have_same_limit":False,
        "complete_runtime_command_protocol_recovered":False,
        "MSH_or_other_dynamic_motor_source_is_safely_interlocked":False,
        "hardware_motor_STOP_verified":False,
        "firmware_flashable":False,
    }

def negatives(data:bytes)->list[str]:
    rejected=[]
    sites=(
        ("CRC_initial",0x0800E9F0),
        ("CRC_polynomial",0x0800E9F4),
        ("CRC_branch",0x0800EA02),
        ("CRC_iterations",0x0800EA0E),
        ("TX_sync_value",0x0800AA4A),
        ("TX_declared_length",0x0800AA52),
        ("TX_crc_call",0x0800AA66),
        ("RX_header_check",RX_STATE_SYNC),
        ("RX_length_min_check",0x0800F926),
        ("RX_crc_validation",0x0800F99E),
        ("RX_path_length_0x62",0x0800A95E),
        ("RX_path_0x62_branch",0x0800A960),
    )
    for name, pc in sites:
        m=bytearray(data)
        m[pc-LINK_BASE] ^= 1
        try:check_opcodes(bytes(m))
        except ValueError:rejected.append(name)
        else:raise AssertionError(f"mutated {name} accepted")
    if len(rejected)!=len(sites):
        raise ValueError("source negative tests incomplete")
    return rejected

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v313",required=True,type=Path)
    p.add_argument("--v322",required=True,type=Path)
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=pinned(a.v313,"intermediate_v313")
    current=pinned(a.v322,"running_v322")
    before,after=inspect(old),inspect(current)
    if before!=after:raise ValueError("OEM CRC/RS485 source changed between pinned generations")
    out={"saved_v313_and_v322_source_identical":True,
         "OEM_RS485_Thumb_source_only":after,
         "live_serial_or_GPIO_access":False,
         "flash_authorization":False}
    if a.self_test:out["negative_fixtures_rejected"]=negatives(current)
    serialized=json.dumps(out,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(serialized)
    print(serialized,end="")
if __name__=="__main__":main()
