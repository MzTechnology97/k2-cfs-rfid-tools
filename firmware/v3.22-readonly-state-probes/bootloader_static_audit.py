#!/usr/bin/env python3
"""Evidence-only Creality CFS loader/app flash-map audit.

No /dev opening, no RS485, no bootloader entry, no erase, no flash output.
Never extrapolate application capacity from silicon capacity or host packet
size. Optional external bootloader dump is ONLY read from a supplied file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from flash_ram_phase2_audit import (
    APP_BASE, CONSERVATIVE_APP_END, PINS, report_image, pinned
)

FLASH_START = 0x08000000
FLASH_END = 0x08080000
FAST_FETCH_END = 0x08040000
PAGE_BYTES = 2048
LAST_PAGE_ADDR = FLASH_END - PAGE_BYTES
APP_PTR_TABLE_ADDR = 0x08036D10
APP_PTR_TABLE_END = 0x08036D48
FLASH_ADDR_WORD_AT = 0x08036D2C
PAGE_SIZE_WORD_AT = 0x08036D38
RAM_ADDR_WORD_AT = 0x08036D3C
HOST_UPDATER_SHA = "dcf3a63136d5ef5766812c22ac243640e26b5600400ef951091ff72fcc0784d8"
HOST_SEEK_END_OPCODE_AT = 0x135F0
HOST_STORED_SIZE_OPCODE_AT = 0x135FC
HOST_ELF_CODE_TO_FILE_OFFSET = 0x10000  # verified only for this exact ELF


def word_in_image(image: bytes, address: int) -> int:
    pos = address - APP_BASE
    if pos < 0 or pos + 4 > len(image):
        raise ValueError("word address outside supplied application")
    return struct.unpack_from("<I", image, pos)[0]


def page_index(address: int) -> int:
    if not FLASH_START <= address < FLASH_END:
        raise ValueError("not within 512 KiB main flash")
    return (address - FLASH_START) // PAGE_BYTES


def analyze_application(image: bytes, label: str) -> dict:
    meta = report_image(image, label)
    if image.count(struct.pack("<I", CONSERVATIVE_APP_END)) != 0:
        raise ValueError("unexpected historical policy boundary literal in app")
    if word_in_image(image, FLASH_ADDR_WORD_AT) != LAST_PAGE_ADDR:
        raise ValueError("missing pinned last-Flash-page address in app table")
    if word_in_image(image, PAGE_SIZE_WORD_AT) != PAGE_BYTES:
        raise ValueError("missing pinned 2 KiB word adjacent to last-page address")
    if word_in_image(image, RAM_ADDR_WORD_AT) != 0x20004A20:
        raise ValueError("associated RAM address changed; inspect table")
    t0 = APP_PTR_TABLE_ADDR - APP_BASE
    t1 = APP_PTR_TABLE_END - APP_BASE
    table = image[t0:t1]
    meta.update({
        "last_flash_page_address_occurrences": image.count(
            struct.pack("<I", LAST_PAGE_ADDR)),
        "page_aligned_flash_word_at": hex(FLASH_ADDR_WORD_AT),
        "adjacent_flash_word": hex(LAST_PAGE_ADDR),
        "adjacent_size_word_at": hex(PAGE_SIZE_WORD_AT),
        "adjacent_size_word": PAGE_BYTES,
        "associated_ram_word_at": hex(RAM_ADDR_WORD_AT),
        "associated_ram_word": "0x20004a20",
        "table_sha256": hashlib.sha256(table).hexdigest(),
        "table_routine_references_not_semantically_proven": True,
        "0x0803B800_literal_occurrences": 0,
        "last_written_page_index_if_normal_2k_paging": page_index(
            APP_BASE + len(image) - 1),
    })
    return meta


def analyze_updater(path: Path | None) -> dict:
    if path is None:
        return {"stock_updater_elf_supplied": False,
                "loader_internal_size_check_proven": False}
    data = path.read_bytes()
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != HOST_UPDATER_SHA:
        raise ValueError("unexpected stock updater ELF SHA; refuse interpretation")
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF binary")
    if data[4] != 1 or data[5] != 1 or struct.unpack_from("<H", data, 18)[0] != 40:
        raise ValueError("expected 32-bit little-endian ARM host utility")
    # Stock utility: mov r2,#2 (SEEK_END), lseek(), str returned length
    # at offset +36; these are host-side facts ONLY, not loader constraints.
    seek = HOST_SEEK_END_OPCODE_AT - HOST_ELF_CODE_TO_FILE_OFFSET
    stored = HOST_STORED_SIZE_OPCODE_AT - HOST_ELF_CODE_TO_FILE_OFFSET
    if data[seek:seek + 4] != bytes.fromhex("0200a0e3"):
        raise ValueError("host SEEK_END fingerprint not present")
    if data[stored:stored + 4] != bytes.fromhex("240084e5"):
        raise ValueError("host size-store fingerprint not present")
    return {
        "stock_updater_elf_supplied": True,
        "sha256": actual_sha,
        "host_file_length_read_elf_va": hex(HOST_SEEK_END_OPCODE_AT),
        "host_file_length_store_elf_va": hex(HOST_STORED_SIZE_OPCODE_AT),
        "host_file_length_taken_from_SEEK_END": True,
        "host_transmits_app_length_as_u32": True,
        "f0_03_token_e0_is_128_byte_TRANSPORT_chunk": True,
        "token_equals_physical_erase_page": False,
        "host_selects_target_flash_destination": False,
        "loader_internal_size_check_proven": False,
        "host_has_no_possible_size_guard_PROVEN": False,
        "full_control_flow_validated": False,
    }


def analyze_loader_dump(path: Path | None) -> dict:
    """Optional acquisition supplied by authorised operator, no hardware IO."""
    if path is None:
        return {
            "bootloader_raw_dump_available": False,
            "bootloader_actual_size_boundary_proven": False,
        }
    data = path.read_bytes()
    if len(data) != 65536:
        raise ValueError("loader dump must be exact lower 64KiB, not app contents")
    if len(set(data)) < 8:
        raise ValueError("suspicious blank/protected-region dump")
    candidates = (APP_BASE, CONSERVATIVE_APP_END, FAST_FETCH_END,
                  LAST_PAGE_ADDR, FLASH_END)
    return {
        "bootloader_raw_dump_available": True,
        "raw_dump_sha256": hashlib.sha256(data).hexdigest(),
        "possible_address_literals": {
            hex(v): data.count(struct.pack("<I", v)) for v in candidates
        },
        "bootloader_actual_size_boundary_proven": False,
        "bootloader_erase_page_ownership_proven": False,
        "requires_disassembly_pointer_validation": True,
    }


def report(v322: bytes, stock: bytes | None = None,
           updater: Path | None = None,
           loader: Path | None = None) -> dict:
    v = analyze_application(v322, "running_v322")
    original = None
    if stock is not None:
        original = analyze_application(stock, "creality_stock_153")
        if v["table_sha256"] != original["table_sha256"]:
            raise ValueError("original vs patched flash address table differs")
    return {
        "scope": "offline bootloader/host boundary evidence, not a loader dump",
        "verified_original_preserves_table": (
            None if original is None else True),
        "tested_v322": v,
        "vendor_stock": original,
        "physical_flash": {
            "assumed_mcu": "GD32F303VET6 (physical marking not independently confirmed)",
            "main_flash": [hex(FLASH_START), hex(FLASH_END)],
            "first_256KiB_fast_instruction_fetch_end": hex(FAST_FETCH_END),
            "second_256KiB_may_execute_with_extra_latency": True,
            "physical_2k_erase_pages_total": 256,
            "app_link_start_page": page_index(APP_BASE),
            "app_last_image_page": page_index(APP_BASE + len(v322) - 1),
            "historical_build_boundary_first_excluded_page": page_index(
                CONSERVATIVE_APP_END),
            "historical_build_boundary_ends_on_2k_page": (
                CONSERVATIVE_APP_END % PAGE_BYTES == 0),
            "undocumented_2k_pages_between_policy_and_fast_fetch_end": (
                (FAST_FETCH_END - CONSERVATIVE_APP_END) // PAGE_BYTES),
            "undocumented_pages_are_proven_unallocated": False,
            "stock_application_last_flash_page_pointer": hex(LAST_PAGE_ADDR),
            "stock_pointer_in_table_plus_matching_0x800_word": True,
            "last_page_usage_semantics_confirmed": False,
        },
        "updater": analyze_updater(updater),
        "loader": analyze_loader_dump(loader),
        "conclusions": {
            "0x0803B800_from_loader_determined": False,
            "last_page_0x0807F800_live_read_write_proven": False,
            "interrupted_update_recovery_proven": False,
            "max_accepted_application_size": None,
            "all_physical_flash_outside_app_is_free": False,
            "new_code_in_slower_flash_approved": False,
            "safe_to_expand_CFS_binary": False,
            "authorises_flash": False,
            "no_mcu_or_rs485_io": True,
        },
    }


def self_test(v322: bytes, stock: bytes | None) -> int:
    report(v322, stock)
    mutations_rejected = 0
    for site in (FLASH_ADDR_WORD_AT, PAGE_SIZE_WORD_AT, RAM_ADDR_WORD_AT):
        wrong = bytearray(v322)
        wrong[site - APP_BASE] ^= 1
        try:
            analyze_application(bytes(wrong), "running_v322")
        except ValueError:
            mutations_rejected += 1
        else:
            raise AssertionError("corrupted pointer table accepted: " + hex(site))
    try:
        page_index(FLASH_END)
    except ValueError:
        mutations_rejected += 1
    else:
        raise AssertionError("end-exclusive address accepted")
    return mutations_rejected


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--v322", type=Path, required=True)
    ap.add_argument("--stock", type=Path)
    ap.add_argument("--stock-updater-elf", type=Path)
    ap.add_argument("--bootloader-dump", type=Path)
    ap.add_argument("--json-out", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    v322 = pinned(args.v322, "running_v322")
    stock = pinned(args.stock, "creality_stock_153") if args.stock else None
    result = report(v322, stock, args.stock_updater_elf, args.bootloader_dump)
    if args.self_test:
        result["four_mutations_rejected"] = self_test(v322, stock)
    rendered = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
