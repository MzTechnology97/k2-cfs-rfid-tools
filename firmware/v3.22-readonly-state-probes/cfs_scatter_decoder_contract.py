#!/usr/bin/env python3
"""APP scatter token decoder contract: original Thumb + independent fixtures.

VERIFICATION SCOPE:
  1) Verify the COMPLETE original v3.22 APP Thumb instruction sequence,
     including IT-condition groups and branch directions, at 0x0801016C.
  2) Run an independently specified byte-stream model against artificial
     compression examples, including valid overlap and invalid history.
  3) Re-test the ORIGINAL CFS saved APP source, and REQUIRE its rejection
     on the reproducible second-token invalid lookback.

This is NOT evidence of loader code at 0x0800316C. The APP Thumb bytes
and loader bytes have not been shown identical. The physical CFS remains
untouched; no proprietary firmware bytes or decoded RAM are published.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

from flash_ram_phase2_audit import APP_BASE, pinned
from cfs_scatter_reference_decoder import candidate_decode

LO = 0x0801016C
HI = 0x080101C6
# Full code/IT instruction coverage, reviewed from actual v3.22 Capstone
# output in CI on 2026-10-11. Not an automatically guessed opcode list.
THUMB = (
    (0x0801016C, "add", "r2, r1"),
    (0x0801016E, "mov.w", "ip, #0"),
    (0x08010172, "ldrb", "r3, [r0], #1"),
    (0x08010176, "ands", "r4, r3, #7"),
    (0x0801017A, "it", "eq"),
    (0x0801017C, "ldrbeq", "r4, [r0], #1"),
    (0x08010180, "asrs", "r5, r3, #4"),
    (0x08010182, "it", "eq"),
    (0x08010184, "ldrbeq", "r5, [r0], #1"),
    (0x08010188, "subs", "r4, r4, #1"),
    (0x0801018A, "beq", "#0x8010198"),
    (0x0801018C, "ldrb", "r6, [r0], #1"),
    (0x08010190, "subs", "r4, r4, #1"),
    (0x08010192, "strb", "r6, [r1], #1"),
    (0x08010196, "bne", "#0x801018c"),
    (0x08010198, "tst.w", "r3, #8"),
    (0x0801019C, "ittt", "ne"),
    (0x0801019E, "ldrbne", "r4, [r0], #1"),
    (0x080101A2, "addne", "r5, r5, #2"),
    (0x080101A4, "subne", "r4, r1, r4"),
    (0x080101A6, "bne", "#0x80101bc"),
    (0x080101A8, "subs", "r5, r5, #1"),
    (0x080101AA, "it", "pl"),
    (0x080101AC, "strbpl", "ip, [r1], #1"),
    (0x080101B0, "bpl", "#0x80101a8"),
    (0x080101B2, "b", "#0x80101c0"),
    (0x080101B4, "ldrb", "r6, [r4], #1"),
    (0x080101B8, "strb", "r6, [r1], #1"),
    (0x080101BC, "subs", "r5, r5, #1"),
    (0x080101BE, "bpl", "#0x80101b4"),
    (0x080101C0, "cmp", "r1, r2"),
    (0x080101C2, "blo", "#0x8010172"),
    (0x080101C4, "bx", "lr"),
)


def verify_full_rom(image: bytes) -> dict:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    rows = [(ins.address, ins.mnemonic, ins.op_str, ins.bytes.hex())
            for ins in decoder.disasm(image[LO - APP_BASE:HI - APP_BASE], LO)]
    actual = [(a, m, op) for a, m, op, _ in rows]
    if actual != list(THUMB):
        for got, expected in zip(actual, THUMB):
            if got != expected:
                raise ValueError(f"original Thumb disassembly differs: {got!r} vs {expected!r}")
        raise ValueError("original Thumb decoder length/layout differs")
    if rows[-1][0] + len(bytes.fromhex(rows[-1][3])) != HI:
        raise ValueError("decoder did not end at expected Thumb boundary")
    return {"full_instruction_count":len(rows),
            "instruction_addresses":[hex(x[0]) for x in rows],
            "all_IT_and_branch_instructions_verified":True,
            "actual_loader_bytes_verified":False}


class InvalidHistory(ValueError):
    def __init__(self, offset: int, output: int):
        super().__init__(f"invalid backref distance={offset},initialized={output}")
        self.offset = offset
        self.output = output


def decode_synthetic(stream: bytes, out_length: int) -> bytes:
    """Reference to *this* APP's token syntax, not the missing loader.

    Original ARM 0x08010176: literals = (tag & 7)-1,
    except tag&7==0 reads a count byte.
    Original ARM 0x08010180: repeat=(tag>>4), with zero extended.
    Original ARM 0x08010198: tag&8 distinguishes zero fill from
    lookback; lookback reads one byte and copies repeat+2 bytes.
    """
    ip=0
    out=bytearray()
    def get():
        nonlocal ip
        if ip >= len(stream):
            raise ValueError("truncated candidate compressed source")
        val=stream[ip]
        ip += 1
        return val
    while len(out)<out_length:
        before=len(out)
        flag=get()
        lit=(flag&7)
        if lit==0:
            lit=get()
        repeat=flag>>4
        if repeat==0:
            repeat=get()
        if lit==0:
            raise ValueError("zero literal count would underflow Thumb copy loop")
        for _ in range(lit-1):
            if len(out)>=out_length:
                raise ValueError("synthetic literals exceed destination")
            out.append(get())
        if flag&8:
            offset=get()
            if not 0<offset<=len(out):
                raise InvalidHistory(offset,len(out))
            for _ in range(repeat+2):
                if len(out)>=out_length:
                    raise ValueError("synthetic history exceeds destination")
                out.append(out[-offset])
        else:
            if len(out)+repeat>out_length:
                raise ValueError("synthetic zero fill exceeds destination")
            out.extend(bytes(repeat))
        if len(out)<=before:
            raise ValueError("synthetic token produced no progress")
    if ip!=len(stream):
        raise ValueError("synthetic stream has unused trailing bytes")
    return bytes(out)


def synthetic_contract():
    vectors={
        "four_zeros":(b"\x41", b"\x00"*4),
        "literal_then_zero":(b"\x23AB", b"AB\x00\x00"),
        "extended_literal":(b"\x20\x03AB", b"AB\x00\x00"),
        "extended_repeat":(b"\x03\x04AB", b"AB\x00\x00\x00\x00"),
        "literal_only":(b"\x05\x00ABCD", b"ABCD"),
        "lookback_exact":(b"\x05\x00ABCD\x29\x04", b"ABCDABCD"),
        "lookback_overlap":(b"\x05\x00ABCD\x39\x01", b"ABCDDDDDD"),
    }
    observed=[]
    for label, (src, expected) in vectors.items():
        actual=decode_synthetic(src,len(expected))
        if actual!=expected:
            raise AssertionError(f"APP candidate token model fails fixture {label}")
        observed.append({"scenario":label,"output_length":len(expected),
                         "expected_behaviour_observed":True})
    invalid=[]
    for label,data,n,offset,outsize in (
        ("uninitialized_history",b"\x05\x00ABCD\x29\xA0",8,160,4),
        ("zero_history_offset",b"\x05\x00ABCD\x29\x00",8,0,4)
    ):
        try:
            decode_synthetic(data,n)
        except InvalidHistory as e:
            if (e.offset,e.output)!=(offset,outsize):
                raise AssertionError("invalid-offset guard changed") from e
            invalid.append(label)
        else:
            raise AssertionError("uninitialized history unexpectedly accepted")
    return {"valid":observed,"invalid_rejected":invalid,
            "synthetic_tests_total":len(observed)+len(invalid)}


def original_rejection(image: bytes):
    try:
        candidate_decode(image)
    except ValueError as exc:
        prefix="invalid scatter history distance: "
        if not str(exc).startswith(prefix):
            raise ValueError("unexpected APP-v3.22 decode failure") from exc
        details=json.loads(str(exc)[len(prefix):])
        if (details["token"],details["src_bytes"],details["decoded_len"],
                details["offset"],details["tag"]) != (2,14,10,160,"0x4f"):
            raise ValueError("APP-v3.22 decode mismatch differs") from exc
        return {"candidate_decode_rejected":True,
                "reason":"invalid backwards reference to uninitialized output",
                "token":2,"consumed_bytes":14,"initialized_output_bytes":10,
                "backref_offset":160,
                "validated_PWM_names_from_real_loader":False}
    raise AssertionError("unverified APP decoder unexpectedly accepted real saved input")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v322",required=True,type=Path)
    parser.add_argument("--json-out",type=Path)
    opt=parser.parse_args()
    image=pinned(opt.v322,"running_v322")
    result={
        "source":"SHA-pinned CFS v3.22",
        "manufacturer_Thumb":verify_full_rom(image),
        "controlled_synthetic_codec_tests":synthetic_contract(),
        "actual_saved_stream":original_rejection(image),
        "actual_vendor_bootloader_0x0800316C_authenticated":False,
        "CFS_PWM_names_recovered":False,
        "independent_motor_idle_proven":False,
        "firmware_release_allowed":False,
        "real_CFS_hardware_access":False,
    }
    body=json.dumps(result,indent=2)+"\n"
    if opt.json_out:
        opt.json_out.write_text(body)
    print(body,end="")


if __name__=="__main__":
    main()
