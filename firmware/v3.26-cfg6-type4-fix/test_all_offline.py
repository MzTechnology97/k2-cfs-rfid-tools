#!/usr/bin/env python3
"""Reproducible firmware-only CFG6 regression suite, no printer access.

First rebuild the ELF and candidate from the exact stock base image, then run
all regressions. Removes only tool outputs created by this invocation.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent
name = "CFG6-TYPE4-RESCAN-FIX-NOT-FOR-FLASH.bin"
expected = "7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb"
reference = root / name
base = root.parent / "v3.19-volatile-ram" / "cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin"
tests = [
    "bench_preflight_v3_23.py",
    "test_type4_rescan_preserves_print.py",
    "test_stock_odometer_sign.py",
    "emulate_v3_23.py",
    "test_type4_gate.py",
    "test_type4_accounting_fullpath.py",
    "test_type4_print_start_end.py",
    "test_cfg5_abi.py",
    "test_cfg6_abi.py",
    "test_transport_contract.py",
]

def run(args, name_of_test):
    r = subprocess.run(args, cwd=root, text=True, capture_output=True, check=False)
    if r.returncode:
        print(r.stdout[-3500:])
        print(r.stderr[-3500:])
        raise SystemExit(f"FAILED: {name_of_test} (rc={r.returncode})")
    print("PASS:", name_of_test)

assert hashlib.sha256(reference.read_bytes()).hexdigest() == expected
generated = [root / ("handler-v3_23" + suffix) for suffix in (".o", ".elf", ".bin")]
existing = {p for p in generated if p.exists()}
try:
    with tempfile.TemporaryDirectory(prefix="cfg6-rebuild-") as tmp:
        rebuilt = Path(tmp) / "candidate.bin"
        run([
            sys.executable, str(root / "build-v3_23.py"),
            "--base", str(base), "--out", str(rebuilt)
        ], "build-from-clean-source")
        assert hashlib.sha256(rebuilt.read_bytes()).hexdigest() == expected
        assert rebuilt.read_bytes() == reference.read_bytes()
        for test in tests:
            args = [sys.executable, str(root / test)]
            if test == "emulate_v3_23.py":
                args.append(str(reference))
            run(args, test)
finally:
    for output in generated:
        if output not in existing:
            output.unlink(missing_ok=True)
print(json.dumps({"pass":True,"sha256":expected,"regression_tests":len(tests),"rebuilt":True},indent=2))
