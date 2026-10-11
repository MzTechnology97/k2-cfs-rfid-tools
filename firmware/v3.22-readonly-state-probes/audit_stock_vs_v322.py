#!/usr/bin/env python3
"""Byte-pinned offline audit: original Creality CFS 153 -> v3.13 -> v3.22.

No device IO, writes to MCU, firmware alterations, or implicit flash output.
The proprietary stock BIN is intentionally NOT committed to this repository.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROM = 0x08010000
STOCK_SHA = "5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea"
STOCK_LENGTH = 175672
V313_SHA = "9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff"
V313_LENGTH = 177700
V322_SHA = "40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7"
V322_LENGTH = 178140
HANDLER_START = 0x0803AE38


def pinned(path, sha, length):
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != length or digest != sha:
        raise ValueError("unexpected firmware image fingerprint: " + str(path))
    return data


def differences(a, b):
    """Common-prefix byte deltas, excluding appended content."""
    return [i for i, (x, y) in enumerate(zip(a, b)) if x != y]


def ranges(items):
    """Human-readable nearby byte-delta clusters (max 16-byte gaps)."""
    if not items:
        return []
    start = prev = items[0]
    out = []
    for idx in items[1:]:
        if idx - prev > 16:
            out.append({"rom_start": hex(ROM + start),
                        "rom_end_exclusive": hex(ROM + prev + 1)})
            start = idx
        prev = idx
    out.append({"rom_start": hex(ROM + start),
                "rom_end_exclusive": hex(ROM + prev + 1)})
    return out


def inspect(stock, v313, v322, manifest, rebuilt=None):
    stock_delta = differences(stock, v322)
    delta = differences(v313, v322)
    # v3.13 already includes RFID API7 and six-speed runtime work. The delta
    # to v3.22 should touch only header CRC, declared 4-byte BL/MOV callsites,
    # heap-start literal and the appended handler region.
    sites = {int(item["callsite"], 16) for item in manifest["patches"]}
    allowed = set(range(0x0801020C, 0x08010210))
    allowed.update(range(0x08027960, 0x08027964))
    for site in sites:
        allowed.update(range(site, site + 4))
    unexplained = [ROM + i for i in delta
                   if ROM + i < HANDLER_START and ROM + i not in allowed]
    if unexplained:
        raise ValueError("unexplained v3.13->v3.22 changes outside handler: "
                         + ",".join(map(hex, unexplained[:24])))
    if manifest["sha256"] != V322_SHA or manifest["unexpected_changed_bytes"] != 0:
        raise ValueError("unexpected static builder manifest")
    actual_patches = []
    for p in manifest["patches"]:
        location = int(p["callsite"], 16) - ROM
        replacement = bytes.fromhex(p["after"])
        if v322[location:location + len(replacement)] != replacement:
            raise ValueError("patched callsite mismatch: " + p["symbol"])
        actual_patches.append(p["symbol"])
    if rebuilt is not None and rebuilt != v322:
        raise ValueError("offline builder no longer reproduces the running v3.22 image")
    return {
        "stock": {"sha256": STOCK_SHA, "size_bytes": len(stock)},
        "v313": {"sha256": V313_SHA, "size_bytes": len(v313)},
        "v322": {"sha256": V322_SHA, "size_bytes": len(v322)},
        "stock_to_v322": {
            "different_bytes_within_original_length": len(stock_delta),
            "new_suffix_bytes": len(v322) - len(stock),
            "diff_clusters_in_original_length": ranges(stock_delta),
        },
        "v313_to_v322": {
            "different_bytes_within_base_length": len(delta),
            "appended_bytes": len(v322) - len(v313),
            "clusters": ranges(delta),
            "expected_patched_original_callsites": actual_patches,
            "unexplained_changes_before_handler": 0,
        },
        "explicit_nonclaims": {
            "safe_to_flash_new_image": False,
            "independent_mcu_motor_busy_guard_verified": False,
            "heap_stack_dma_runtime_proven": False,
            "bootloader_flash_partition_proven": False,
            "all_28_parameters_affect_physical_behavior": False,
            "rfid_secure_backend_capture_hardware_validated": False,
        },
        "offline_read_only": True,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stock", required=True)
    ap.add_argument("--base", required=True, help="v3.13 exact patched CFS base")
    ap.add_argument("--modified", required=True, help="v3.22 exact BIN")
    ap.add_argument("--manifest", default=str(Path(__file__).with_name("static-validation.json")))
    ap.add_argument("--rebuilt", help="optional rebuilt v3.22 image for byte equality")
    ap.add_argument("--output", help="optional JSON report path, not a flash image")
    args = ap.parse_args()
    stock = pinned(args.stock, STOCK_SHA, STOCK_LENGTH)
    base = pinned(args.base, V313_SHA, V313_LENGTH)
    modified = pinned(args.modified, V322_SHA, V322_LENGTH)
    rebuilt = pinned(args.rebuilt, V322_SHA, V322_LENGTH) if args.rebuilt else None
    report = inspect(stock, base, modified, json.loads(Path(args.manifest).read_text()), rebuilt)
    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
