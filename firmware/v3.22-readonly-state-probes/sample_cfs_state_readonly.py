#!/usr/bin/env python3
"""Observe a v3.22 CFS at low rate, without motion, flash, or write commands.

The operator controls physical load/unload independently. Moonraker may queue
GCODE during an active move: delayed samples are explicitly NOT motor-time
measurements. Outputs contain raw, uninterpreted candidate diagnostic bytes.
"""
import argparse
import json
import re
import time
import urllib.request
from pathlib import Path

ROOT = "http://127.0.0.1:7125"
PATTERN = re.compile(
    r"motor_candidate=([0-9A-F]{4}):([0-9A-F]{4}) "
    r"task_candidate=([0-9A-F]{4}):([0-9A-F]{4})"
)


def get(path, timeout=6):
    with urllib.request.urlopen(ROOT + path, timeout=timeout) as response:
        return json.load(response)["result"]


def snapshot():
    s = get(
        "/printer/objects/query?"
        "webhooks&print_stats&box&box_cfs_runtime&"
        "filament_switch_sensor%20filament_sensor"
    )["status"]
    c = s["box_cfs_runtime"]
    if c.get("firmware_features") != 0xD7 or c.get("parameter_count") != 28:
        raise RuntimeError("Requires CFS experimental v3.22 marker 0xD7/28")
    box = s["box"]
    return {
        "klipper": s["webhooks"]["state"],
        "print": s["print_stats"]["state"],
        "box": box["state"],
        "operation": box["operation"],
        "loaded_slot": box["loaded_slot"],
        "head_sensor": s["filament_switch_sensor filament_sensor"][
            "filament_detected"
        ],
    }


def diagnostic_gcode():
    request = urllib.request.Request(
        ROOT + "/printer/gcode/script",
        data=json.dumps({"script": "BOX_CFS_CONFIG_SNAPSHOT"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        json.load(response)


def recent_diag(after_timestamp):
    entries = get("/server/gcode_store?count=45")["gcode_store"]
    found = [
        item
        for item in entries
        if item.get("time", 0) >= after_timestamp - 0.2
        and PATTERN.search(item.get("message", ""))
    ]
    if not found:
        return None
    match = PATTERN.search(found[-1]["message"])
    return {
        "words_hex": list(match.groups()),
        "gcode_reply_time": found[-1]["time"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=float, default=1.5)
    parser.add_argument("--samples", type=int, default=50)
    parser.add_argument(
        "--output",
        default=str(
            Path.home()
            / "cfs-rfid-v322-readonly-probe-lab"
            / "V322_OBSERVATIONS.jsonl"
        ),
    )
    args = parser.parse_args()
    if args.interval < 1.0 or args.samples < 1 or args.samples > 1000:
        parser.error("Use interval >= 1.0 seconds and 1..1000 samples")
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    snapshot()
    print("READ-ONLY v3.22: no load/unload, motion, SET, RESET, or flash issued")
    print("Do not equate an opaque word or delayed G-code reply with motor idle")

    with path.open("w", encoding="utf-8") as output:
        for i in range(args.samples):
            started = time.time()
            row = {"index": i, "request_time": started}
            try:
                row["before"] = snapshot()
                diagnostic_gcode()
                row["after"] = snapshot()
                row["reply"] = recent_diag(started)
                row["duration_sec"] = round(time.time() - started, 3)
                row["delayed"] = row["duration_sec"] > args.interval
                row["correlation_valid"] = bool(
                    row["reply"]
                    and not row["delayed"]
                    and row["before"]["operation"]
                    == row["after"]["operation"]
                )
            except Exception as exc:
                row["error"] = str(exc)[:300]
                row["correlation_valid"] = False
                print("SAMPLE_ERROR", i, row["error"])
            output.write(json.dumps(row, ensure_ascii=False) + "\n")
            output.flush()
            print(
                "SAMPLE",
                i,
                "BOX",
                row.get("before", {}).get("box"),
                "VALID",
                row.get("correlation_valid", False),
            )
            time.sleep(max(0.0, args.interval - (time.time() - started)))
    print("CAPTURE_SAVED", path)


if __name__ == "__main__":
    main()
