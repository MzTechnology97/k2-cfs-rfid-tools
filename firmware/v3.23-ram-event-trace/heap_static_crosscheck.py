#!/usr/bin/env python3
"""Offline-only v3.23 heap-window cross-check against byte-pinned CFS images.

This confirms a known initialization pattern and checks for literal-address
collisions. It cannot measure live heap, DMA, task stacks or bootloader limits.
It never connects to a device, modifies firmware, or creates a flash image.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROM_BASE = 0x08010000
INIT_SITE = 0x080278F2
INIT_ENCODING = bytes.fromhex("1a491a4805f073be")
ALLOCATOR_SITE = 0x0802D5E0
ALLOCATOR_PREFIX = bytes.fromhex("70b50446c01d20f00705")
HEAP_TOP_SITE = 0x0802795C
HEAP_START_SITE = 0x08027960
TOP = 0x20010000
OLD_START = 0x20006EE8
V322_START = 0x20006F28
RING_BYTES = 512
RING_END = V322_START + RING_BYTES
APP_EMPIRICAL_END = 0x0803B800  # Hypothesis, NOT certified by bootloader.
PINNED = {
    "previous_v313": ("9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff", 177700, OLD_START),
    "working_v322": ("40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7", 178140, V322_START),
    "unflashed_sizeopt": ("06f36ef5c088ee2bb3497c89e30695ab1a3ca3b786b563b6f3d2c368ccf28d19", 178120, V322_START),
}

def region(data: bytes, address: int, size: int) -> bytes:
    offset = address - ROM_BASE
    if offset < 0 or offset + size > len(data):
        raise ValueError("ROM region outside image: " + hex(address))
    return data[offset:offset + size]

def word(data: bytes, addr: int) -> int:
    return struct.unpack("<I", region(data, addr, 4))[0]

def inspect(data: bytes, variant: str) -> dict:
    sha, expected_len, start = PINNED[variant]
    if len(data) != expected_len or hashlib.sha256(data).hexdigest() != sha:
        raise ValueError(variant + ": pinned image SHA/length mismatch; aborting")
    if region(data, INIT_SITE, len(INIT_ENCODING)) != INIT_ENCODING:
        raise ValueError(variant + ": heap initialization call changed")
    if region(data, ALLOCATOR_SITE, len(ALLOCATOR_PREFIX)) != ALLOCATOR_PREFIX:
        raise ValueError(variant + ": candidate allocator entry changed")
    if word(data, HEAP_TOP_SITE) != TOP or word(data, HEAP_START_SITE) != start:
        raise ValueError(variant + ": unexpected heap-bound literals")
    # The image scan recognizes only aligned, *immediate* little-endian words.
    # Computed addresses or RAM mutations can escape this screen entirely.
    # Four 32-bit words in this range are FALSE POSITIVES from sequential
    # Thumb instructions: they are NOT address literals. Pin their exact
    # encodings, including the unaligned half of the 32-bit STRH.W at 19EF6.
    thumb_false_positives = {
        0x08011628: (0x08011628, bytes.fromhex("a0700020"), "STRB R0,[R4,#2]; MOVS R0,#0"),
        0x08017A54: (0x08017A54, bytes.fromhex("a0700020"), "STRB R0,[R4,#2]; MOVS R0,#0"),
        0x08018138: (0x08018138, bytes.fromhex("05700020"), "STRB R5,[R0]; MOVS R0,#0"),
        0x08019EF8: (0x08019EF6, bytes.fromhex("adf808700020"),
                     "second halfword of STRH.W R7,[SP,#8]; MOVS R0,#0"),
    }
    for at, (start_addr, encoding, meaning) in thumb_false_positives.items():
        if region(data, start_addr, len(encoding)) != encoding:
            raise ValueError(variant + ": Thumb instruction fingerprint changed: " + hex(at))
    candidate_words = []
    for offset in range(0, len(data) - 3, 4):
        val = struct.unpack_from("<I", data, offset)[0]
        if not V322_START <= val < RING_END:
            continue
        address = ROM_BASE + offset
        if address in thumb_false_positives:
            category = "instruction_encoding_false_positive"
        elif address == HEAP_START_SITE and variant != "previous_v313" and val == V322_START:
            category = "known_heap_base_literal"
        else:
            raise ValueError(variant + ": UNEXPLAINED aligned word in ring address range at "
                             + hex(address) + "=" + hex(val))
        candidate_words.append({"rom": hex(address), "value": hex(val),
                                "classification": category})
    expected_sites = set(thumb_false_positives)
    if variant != "previous_v313":
        expected_sites.add(HEAP_START_SITE)
    if {int(item["rom"], 16) for item in candidate_words} != expected_sites:
        raise ValueError(variant + ": missing expected Thumb words / heap base literal")
    return {
        "sha256": sha,
        "size_bytes": len(data),
        "heap_init_load_r1_at": hex(INIT_SITE),
        "heap_init_load_r0_at": hex(INIT_SITE + 2),
        "heap_init_call_at": hex(INIT_SITE + 4),
        "allocator_entry": hex(ALLOCATOR_SITE),
        "upper_literal": hex(TOP),
        "lower_literal": hex(start),
        "nominal_allocator_window_bytes": TOP - start,
        "address_looking_aligned_words": candidate_words,
        "thumb_instruction_false_positives": 4,
        "unexplained_aligned_immediate_words_in_ring_span": 0,
        "static_literal_screen_passed_NOT_A_RUNTIME_PROOF": True,
    }

def build_report(previous: bytes, working: bytes, optimized: bytes | None = None) -> dict:
    images = {
        "previous_v313": inspect(previous, "previous_v313"),
        "working_v322": inspect(working, "working_v322"),
    }
    if optimized is not None:
        images["unflashed_sizeopt"] = inspect(optimized, "unflashed_sizeopt")
    result = {
        "scope": "offline byte-pinned static ROM evidence only",
        "source_images": images,
        "heap_top": hex(TOP),
        "v322_alloc_start": hex(V322_START),
        "proposed_ring_half_open_range": [hex(V322_START), hex(RING_END)],
        "proposed_new_allocator_start_NOT_PATCHED": hex(RING_END),
        "current_nominal_heap_span_bytes": TOP - V322_START,
        "proposed_nominal_heap_span_bytes": TOP - RING_END,
        "nominal_heap_reduction_bytes": RING_BYTES,
        "nominal_heap_reduction_percent": round(100 * RING_BYTES / (TOP - V322_START), 3),
        "heap_alignment_8_ok": (RING_END % 8 == 0),
        "conservative_unverified_app_end": hex(APP_EMPIRICAL_END),
        "headroom_v322_bytes": APP_EMPIRICAL_END - (ROM_BASE + len(working)),
        "headroom_sizeopt_bytes": None if optimized is None else APP_EMPIRICAL_END - (ROM_BASE + len(optimized)),
        "direct_literal_scan_is_runtime_nonoverlap_proof": False,
        "rtos_heap_peak_and_fragmentation_verified": False,
        "task_stack_highwater_verified": False,
        "dma_and_isr_ownership_verified": False,
        "bootloader_app_partition_verified": False,
        "no_patch_no_flash_no_device_io": True,
        "safe_to_flash": False,
    }
    return result

def self_test(previous: bytes, working: bytes, optimized: bytes | None) -> int:
    count = 0
    build_report(previous, working, optimized)
    count += 1
    # Fail-closed invariants: known image, heap-site, call-site, allocator body.
    for address in (INIT_SITE, ALLOCATOR_SITE, HEAP_TOP_SITE, HEAP_START_SITE):
        test = bytearray(working)
        test[address - ROM_BASE] ^= 0x01
        try:
            inspect(bytes(test), "working_v322")
        except ValueError:
            count += 1
        else:
            raise AssertionError("Mutation unexpectedly accepted at " + hex(address))
    try:
        inspect(previous, "working_v322")
    except ValueError:
        count += 1
    else:
        raise AssertionError("Wrong variant was accepted")
    return count

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--optimized", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    previous = args.previous.read_bytes()
    current = args.current.read_bytes()
    optimized = None if args.optimized is None else args.optimized.read_bytes()
    result = build_report(previous, current, optimized)
    if args.self_test:
        result["fail_closed_cases_passed"] = self_test(previous, current, optimized)
    output = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(output)
    print(output, end="")

if __name__ == "__main__":
    main()