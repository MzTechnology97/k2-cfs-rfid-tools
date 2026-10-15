#!/usr/bin/env python3
"""Read-only evidence gate for CFS G32/app153 Flash and SRAM.

Uses exact SHA256-pinned vendor and test application images. Never accesses
RS485, /dev devices, running Klipper, MCU flash or runtime memory. It neither
patches nor emits a flashable binary. Only an optional JSON audit is written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

# WARNING 2026-10-12: APP_BASE is a LEGACY ARTIFICIAL ANALYSIS ORIGIN.
# The SAVED CFS APP is truly linked at 0x08003000. This module's old
# address/end/page report numbers are not physical measurements and must
# never be used to justify firmware placement or flashing. Retained only
# to reproduce old SHA-pinned studies; migrate dependents separately.
# See cfs_app_real_link_base_audit.py and cfs_v323_corrected_release_gate.py.
APP_BASE = 0x08010000
FLASH_START = 0x08000000
# GD32F303VE: first 256KiB has fast instruction fetch; remaining 256KiB
# is still readable / potentially executable with higher fetch latency.
# Neither boundary is the Creality application's certified allocation limit.
FAST_FETCH_END = 0x08040000
MAIN_FLASH_END = 0x08080000
SRAM_START = 0x20000000
SRAM_END = 0x20010000
CONSERVATIVE_APP_END = 0x0803B800  # UNVERIFIED hypothetical loader limit
CRC_OFF, LENGTH_OFF, META_END = 0x20C, 0x20E, 0x212
HEAP_TOP_LITERAL = 0x0802795C
HEAP_START_LITERAL = 0x08027960
INITIAL_HEAP_START = 0x20006EE8
TESTED_HEAP_START = 0x20006F28
SIDE_CAR_BYTES = 64
PROPOSED_RING_BYTES = 512
PINS = {
    "creality_stock_153": (
        175672, "5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea"),
    "intermediate_v313": (
        177700, "9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff"),
    "running_v322": (
        178140, "40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7"),
    "experimental_sizeopt_unflashed": (
        178120, "06f36ef5c088ee2bb3497c89e30695ab1a3ca3b786b563b6f3d2c368ccf28d19"),
}


def pinned(path: Path, which: str) -> bytes:
    data = path.read_bytes()
    want_size, want_sha = PINS[which]
    if len(data) != want_size or hashlib.sha256(data).hexdigest() != want_sha:
        raise ValueError(which + ": size/SHA mismatch; abort, unknown firmware")
    return data


def word(image: bytes, at: int) -> int:
    i = at - APP_BASE
    if i < 0 or i + 4 > len(image):
        raise ValueError("address outside image: " + hex(at))
    return struct.unpack_from("<I", image, i)[0]


def crc16_bypass(data: bytes) -> int:
    crc = 0
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = (((crc << 1) ^ 0x8005) & 0xFFFF
                   if crc & 0x8000 else (crc << 1) & 0xFFFF)
    return crc


def report_image(data: bytes, variant: str) -> dict:
    sp, reset = struct.unpack_from("<II", data)
    header_length = struct.unpack_from("<I", data, LENGTH_OFF)[0]
    expected_crc = struct.unpack_from("<H", data, CRC_OFF)[0]
    unsigned = bytearray(data)
    unsigned[CRC_OFF:META_END] = b"\x00" * (META_END - CRC_OFF)
    actual_crc = crc16_bypass(unsigned)
    if header_length != len(data) or expected_crc != actual_crc:
        raise ValueError(variant + ": corrupt application header length / CRC")
    if not SRAM_START <= sp < SRAM_END:
        raise ValueError(variant + ": initial stack pointer outside 64KiB SRAM")
    if not (reset & 1 and APP_BASE <= (reset & ~1) < APP_BASE + len(data)):
        raise ValueError(variant + ": reset vector outside linked application/Thumb")
    heap_start = word(data, HEAP_START_LITERAL)
    heap_top = word(data, HEAP_TOP_LITERAL)
    expected_heap_start = (
        TESTED_HEAP_START
        if variant in ("running_v322", "experimental_sizeopt_unflashed")
        else INITIAL_HEAP_START
    )
    if heap_start != expected_heap_start or heap_top != SRAM_END:
        raise ValueError(variant + ": unexpected allocator bounds; stop audit")
    if sp != INITIAL_HEAP_START:
        raise ValueError(variant + ": initial MSP changed unexpectedly")
    end = APP_BASE + len(data)
    if end > MAIN_FLASH_END:
        raise ValueError(variant + ": image exceeds reported physical main Flash capacity")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "linked_base": hex(APP_BASE),
        "linked_end_exclusive": hex(end),
        "header_crc_valid": True,
        "header_size_matches": True,
        "initial_stack_pointer": hex(sp),
        "reset_vector_thumb": hex(reset),
        "sram_end": hex(SRAM_END),
        "heap_start_literal": hex(heap_start),
        "heap_end_literal": hex(heap_top),
        "nominal_heap_window_bytes": heap_top - heap_start,
        "bytes_to_unverified_0x0803b800": CONSERVATIVE_APP_END - end,
        "bytes_to_fast_fetch_end_NOT_AUTHORISED": FAST_FETCH_END - end,
        "bytes_to_total_flash_end_NOT_AUTHORISED": MAIN_FLASH_END - end,
    }


def literal_observations(data: bytes) -> dict:
    # Scan 4-byte-aligned words only; instructions may look like addresses.
    # Count observations but NEVER interpret them as verified live pointers.
    classes = {
        "pre_256k_end_0x0803b800_to_0x0803ffff": (0x0803B800, FAST_FETCH_END),
        "slower_flash_0x08040000_to_0x0807ffff": (FAST_FETCH_END, MAIN_FLASH_END),
        "within_64k_sram": (SRAM_START, SRAM_END),
        "above_64k_sram_lookalikes": (SRAM_END, SRAM_END + 0x8000),
        "candidate_ring_span_0x20006f28_to_0x20007127": (
            TESTED_HEAP_START, TESTED_HEAP_START + PROPOSED_RING_BYTES),
    }
    result = {}
    for name, (lo, hi) in classes.items():
        candidates = []
        for offset in range(0, len(data) - 3, 4):
            value = struct.unpack_from("<I", data, offset)[0]
            if lo <= value < hi:
                candidates.append({"rom": hex(APP_BASE + offset),
                                   "unclassified_value": hex(value)})
        result[name] = {"count": len(candidates),
                        "examples": candidates[:12],
                        "literal_and_instruction_bytes_NOT_disambiguated": True}
    return result


def unused_source_candidates(source: str) -> dict:
    # Only an evidence pointer. A count of one is NOT dead-code proof:
    # a computed address, vector, register-indirect or script reference
    # can reach otherwise unreferenced ARM labels.
    symbols = ("config_v2_ensure", "config_defaults", "SIDECAR_SIZE")
    result = {
        name: {
            "source_occurrences": len(re.findall(r"\b" + re.escape(name) + r"\b", source)),
            "candidate_only_no_relocation_removal_authorised": True,
        }
        for name in symbols
    }
    # 2026-10-11 correction: two assembler labels share the *same* address.
    # config_ptr is called by GET; its config_v2_ensure alias is NOT dead.
    # Merely counting the spelling "config_v2_ensure" was misleading.
    aliases_identical = "config_v2_ensure:\nconfig_ptr:\n" in source
    real_alias_caller = len(re.findall(r"\bbl\s+config_ptr\b", source))
    result["config_v2_ensure"].update({
        "same_entrypoint_as_called_config_ptr": aliases_identical,
        "bl_config_ptr_source_calls": real_alias_caller,
        "confirmed_live_via_alias": aliases_identical and real_alias_caller > 0,
        "safe_to_remove": False,
    })
    result["config_defaults"].update({
        "direct_symbol_references_excluding_label": max(
            0, len(re.findall(r"\bconfig_defaults\b", source)) - 1),
        "independent_offline_build_test_only_saved_bytes": 4,
        "safe_to_remove_in_installed_firmware": False,
    })
    result["SIDECAR_SIZE"]["source_constant_only_binary_bytes"] = 0
    return result


def collect(stock: bytes, old: bytes, current: bytes,
            optimized: bytes | None = None, source: str | None = None) -> dict:
    images = {
        "creality_stock_153": report_image(stock, "creality_stock_153"),
        "intermediate_v313": report_image(old, "intermediate_v313"),
        "running_v322": report_image(current, "running_v322"),
    }
    if optimized is not None:
        images["experimental_sizeopt_unflashed"] = report_image(
            optimized, "experimental_sizeopt_unflashed")
    initial_sp = struct.unpack_from("<I", current)[0]
    nominal_heap = SRAM_END - TESTED_HEAP_START
    proposed_start = TESTED_HEAP_START + PROPOSED_RING_BYTES
    if initial_sp != INITIAL_HEAP_START or proposed_start % 8:
        raise ValueError("RAM geometry mismatch / proposed heap misalignment")
    return {
        "scope": "offline static evidence; not dynamic MCU measurements",
        "soc": {
            "part": "GD32F303VET6 (CFS G32 hypothesis; re-confirm actual silicon)",
            "core": "Cortex-M4 (older test assembly targets M3 ISA subset)",
            "total_flash_bytes": 512 * 1024,
            "fast_instruction_fetch_flash_bytes": 256 * 1024,
            "slower_instruction_fetch_flash_bytes": 256 * 1024,
            "slower_flash_instruction_fetch_possible": True,
            "sram_bytes": 64 * 1024,
            "reference": "https://www.gigadevice.com.cn/product/mcu/mcus-product-selector/gd32f303vet6",
        },
        "images": images,
        "flash": {
            "total_main_flash_half_open": [hex(FLASH_START), hex(MAIN_FLASH_END)],
            "fast_fetch_flash_half_open": [hex(FLASH_START), hex(FAST_FETCH_END)],
            "instruction_fetch_after_256k_has_higher_latency": True,
            "application_base": hex(APP_BASE),
            "lower_64k_separate_area_content_UNDUMPED": True,
            "prior_conservative_application_boundary_UNVERIFIED": hex(CONSERVATIVE_APP_END),
            "physical_flash_and_256k_latency_split_ARE_NOT_loader_app_limits": True,
            "original_v322_spot_crc_and_vectors_match": (
                stock[:8] == current[:8]),
            "possible_last_reserved_flash_pages_unknown": True,
            "candidate_20B_smaller_image_unflashed": optimized is not None,
            "max_proven_additional_code_bytes": 0,
        },
        "sram": {
            "initial_sp": hex(initial_sp),
            "sidecar_half_open": [hex(INITIAL_HEAP_START), hex(TESTED_HEAP_START)],
            "sidecar_bytes": SIDE_CAR_BYTES,
            "current_heap_half_open": [hex(TESTED_HEAP_START), hex(SRAM_END)],
            "current_nominal_heap_bytes": nominal_heap,
            "UNCOMMITTED_ring_half_open": [hex(TESTED_HEAP_START),
                                           hex(proposed_start)],
            "UNCOMMITTED_new_heap_start": hex(proposed_start),
            "UNCOMMITTED_new_nominal_heap_bytes": SRAM_END - proposed_start,
            "heap_window_reduction_bytes": PROPOSED_RING_BYTES,
            "heap_window_reduction_percent": round(
                PROPOSED_RING_BYTES * 100 / nominal_heap, 3),
            "heap_peak_fragmentation_verified": False,
            "task_stack_highwater_verified": False,
            "dma_buffers_and_irq_writers_verified": False,
        },
        "aligned_word_heuristics": literal_observations(current),
        "source_unused_SYMBOL_CANDIDATES": (
            unused_source_candidates(source) if source is not None else {}),
        "release_gates": {
            "bootloader_full_dump_or_authenticated_layout_verified": False,
            "application_update_max_length_verified": False,
            "last_page_reservations_verified": False,
            "heap_and_stack_dynamic_safety_verified": False,
            "v323_event_ring_flash_ramsafe": False,
            "approve_flash": False,
            "approve_motion_writes": False,
        },
        "read_only": True,
        "new_bin_or_elf_created": False,
    }


def self_test(stock, old, cur, opt=None, source=None):
    collect(stock, old, cur, opt, source)
    checks = 0
    for target in ("header", "heap_lower", "heap_upper", "reset_vector"):
        changed = bytearray(cur)
        at = {
            "header": LENGTH_OFF, "heap_lower": HEAP_START_LITERAL - APP_BASE,
            "heap_upper": HEAP_TOP_LITERAL - APP_BASE, "reset_vector": 4,
        }[target]
        changed[at] ^= 1
        try:
            report_image(bytes(changed), "running_v322")
        except ValueError:
            checks += 1
        else:
            raise AssertionError(target + " mutation was wrongly accepted")
    return checks


def main() -> None:
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--stock", type=Path, required=True)
    a.add_argument("--v313", type=Path, required=True)
    a.add_argument("--v322", type=Path, required=True)
    a.add_argument("--unflashed-sizeopt", type=Path)
    a.add_argument("--asm", type=Path)
    a.add_argument("--self-test", action="store_true")
    a.add_argument("--json-out", type=Path)
    args = a.parse_args()
    stock = pinned(args.stock, "creality_stock_153")
    old = pinned(args.v313, "intermediate_v313")
    cur = pinned(args.v322, "running_v322")
    opt = (pinned(args.unflashed_sizeopt, "experimental_sizeopt_unflashed")
           if args.unflashed_sizeopt else None)
    source = args.asm.read_text() if args.asm else None
    result = collect(stock, old, cur, opt, source)
    if args.self_test:
        result["tamper_cases_rejected"] = self_test(stock, old, cur, opt, source)
    rendered = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
