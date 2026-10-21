#!/usr/bin/env python3
"""Rebuild/check v3.22 with conservative source-only size optimization.

Creates modified v3.22 binaries ONLY inside a disposable temporary directory.
Does not touch the installed CFS, existing firmware repository inputs, or
installer files. No serial/USB/SWD access, flashing, Klipper or hardware calls.

This is a regression experiment, NOT a production firmware release.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from heap_static_crosscheck import build_report as audit_heap, self_test as test_heap_gate

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
FIRMWARE = REPO / "firmware"
SRC = FIRMWARE / "v3.22-readonly-state-probes"
PREVIOUS = FIRMWARE / "v3.19-volatile-ram"
BASE_NAME = "cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin"
OLD_SHA = "40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7"
NEW_SHA = "06f36ef5c088ee2bb3497c89e30695ab1a3ca3b786b563b6f3d2c368ccf28d19"
ORIGINAL_SIZE = 178140
OPTIMIZED_SIZE = 178120
EMPIRICAL_LIMIT = 0x0803B800
APP_BASE = 0x08010000
OLD_REPLY = """    strb    r6, [sp]
    strb    r7, [sp, #1]
    lsrs    r7, r7, #8
    strb    r7, [sp, #2]
    mov     r2, sp
    movs    r3, #3
    movs    r1, #0
    b       send
"""
NEW_REPLY = """    @ Offline size experiment: reuse the proven GET 3-byte serializer.
    mov     r0, r7
    b.w     v322_get_result
"""
BRANCH_PATTERN = r"\b(b|beq|bne|bhs|blo|bhi|bls|bpl|bmi|bge|blt|bgt|ble)\.w\b"
PRECHECK_LINE = "s.count('bne.w   status_busy') == 2"
PRECHECK_REPLACEMENT = (
    "len(re.findall(r'\\bbne(?:\\.w)?\\s+status_busy\\b',s)) == 2"
)

def call(*args: str, cwd: Path):
    subprocess.run(args, cwd=cwd, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   text=True)

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def stage(target: Path):
    # Preserve relative layout expected by original builder and Unicorn tests.
    stage_fw = target / "firmware"
    stage_src = stage_fw / "v3.22-readonly-state-probes"
    stage_base = stage_fw / "v3.19-volatile-ram"
    stage_src.mkdir(parents=True)
    stage_base.mkdir(parents=True)
    for name in (
        "handler-v3_22.S", "link.ld", "build-v3_22.py",
        "bench_preflight_v3_22.py", "emulate_v3_22.py",
    ):
        shutil.copyfile(SRC / name, stage_src / name)
    for name in (
        BASE_NAME,
        "cfs0_050_G32-cfs0_000_153-runtime-config-v3_19-VOLATILE-RAM-BENCH.bin",
    ):
        shutil.copyfile(PREVIOUS / name, stage_base / name)
    return stage_src, stage_base

def build(target: Path):
    img = target / "test-only-unflashed.bin"
    call(
        "python3", "build-v3_22.py",
        "--base", str(target.parent / "v3.19-volatile-ram" / BASE_NAME),
        "--out", str(img), cwd=target
    )
    return img.read_bytes()

def emulate(target: Path, data: bytes):
    name = "CFS-v3_22-PROBE-EXPERIMENTAL-UNFLASHED.bin"
    (target / name).write_bytes(data)
    call("python3", "emulate_v3_22.py", cwd=target)
    result = json.loads((target / "arm-emulation.json").read_text())
    (target / name).unlink()  # Remove redundant input after tests
    return result

def optimize_source(target: Path):
    asm = target / "handler-v3_22.S"
    data = asm.read_text()
    assert data.count(OLD_REPLY) == 1, "SET reply fragment changed upstream"
    assert data.count("v322_get_result:") == 1
    data = data.replace(OLD_REPLY, NEW_REPLY)
    data, replacements = re.subn(BRANCH_PATTERN, r"\1", data)
    assert replacements == 18, ("Unexpected wide-branch count", replacements)
    assert len(re.findall(r"\bbne(?:\.w)?\s+status_busy\b", data)) == 2
    assert data.count("ldr     r0, box_operating_state_ptr") == 2
    assert "movs    r0, #0xD7" in data
    asm.write_text(data)
    check_file = target / "bench_preflight_v3_22.py"
    check = check_file.read_text()
    assert check.count(PRECHECK_LINE) == 1
    check = check.replace(PRECHECK_LINE, PRECHECK_REPLACEMENT)
    check_file.write_text(check)
    return replacements

def equivalent_functionality(baseline, optimized):
    # The emulator runs GET 0..31, 21 advanced SET/GET/RESET,
    # 42 out-of-range checks, 7 CFS BUSY classes and original ID7/8 hooks.
    keys = (
        "info", "default_get_count", "readonly_internal_probe_get_ids",
        "readonly_probe_values_verified", "probe_ids_reject_set_and_reset",
        "GET32_rejected", "set_get_reset_individual_count",
        "stock_parameter_writes_rejected", "invalid_bounds_rejected",
        "corrupt_runtime_value_guarded", "get_does_not_modify_storage",
        "retained_rfid_slot_still_allows_idle_set_reset",
        "busy_state_rejects_set", "busy_state_rejects_reset",
        "moving_and_unknown_states_rejected", "physical_movw_hooks_emulated",
    )
    for name in keys:
        assert name in baseline and name in optimized, name
        assert baseline[name] == optimized[name], (
            "behavioral regression", name, baseline[name], optimized[name]
        )
    return len(keys)

def main():
    with tempfile.TemporaryDirectory(prefix="cfs-v323-sizeopt-offline-") as td:
        root = Path(td)
        original, _ = stage(root / "original")
        optimized, _ = stage(root / "optimized")
        old = build(original)
        assert len(old) == ORIGINAL_SIZE and sha256(old) == OLD_SHA, (
            "Baseline image mismatch", len(old), sha256(old)
        )
        before = emulate(original, old)
        num_relaxed = optimize_source(optimized)
        new = build(optimized)
        assert len(new) == OPTIMIZED_SIZE and sha256(new) == NEW_SHA, (
            "Optimized image mismatch", len(new), sha256(new)
        )
        assert APP_BASE + len(new) <= EMPIRICAL_LIMIT
        after = emulate(optimized, new)
        fields_checked = equivalent_functionality(before, after)
        # Byte-pinned, source-only memory gate; images remain disposable.
        v313 = (root / "original" / "firmware" /
                "v3.19-volatile-ram" / BASE_NAME).read_bytes()
        heap_evidence = audit_heap(v313, old, new)
        assert heap_evidence["safe_to_flash"] is False
        for item in heap_evidence["source_images"].values():
            assert item["unexplained_aligned_immediate_words_in_ring_span"] == 0
            assert item["thumb_instruction_false_positives"] == 4
        heap_fail_closed = test_heap_gate(v313, old, new)
        assert heap_fail_closed == 6
        # The temporary scratch directory and experimental BINs are removed
        # on exit; this script cannot install any firmware.
        result = {
            "status": "PASS — test-only optimized CFS v3.22 (NOT FLASHABLE)",
            "baseline_sha256": OLD_SHA, "optimized_sha256": NEW_SHA,
            "baseline_bytes": len(old), "optimized_bytes": len(new),
            "space_saved_bytes": len(old) - len(new),
            "empirical_unproven_limit": hex(EMPIRICAL_LIMIT),
            "remaining_bytes_to_empirical_limit": EMPIRICAL_LIMIT - APP_BASE - len(new),
            "wide_branch_qualifiers_relaxed": num_relaxed,
            "behavioral_comparison_fields_checked": fields_checked,
            "heap_static_crosscheck_images": 3,
            "heap_static_false_positive_thumb_words_each": 4,
            "heap_static_mutation_fail_closed_tests": heap_fail_closed,
            "heap_static_check_is_runtime_proof": False,
            "same_28_get_values_and_21_set_reset": True,
            "physical_motor_hooks_added": False,
            "hardware_or_installer_touched": False,
            "bootloader_capacity_verified": False,
            "safe_to_flash": False,
        }
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
