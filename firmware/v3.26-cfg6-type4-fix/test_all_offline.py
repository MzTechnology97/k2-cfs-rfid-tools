#!/usr/bin/env python3
"""Run CFG6 type-4 rescan offline tests: never talks to a printer."""
from pathlib import Path
import hashlib
import subprocess
import sys
import json

root = Path(__file__).resolve().parent
name = "CFG6-TYPE4-RESCAN-FIX-NOT-FOR-FLASH.bin"
expected = "7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb"
assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected
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
]
for test in tests:
    result = subprocess.run(
        ([sys.executable, str(root / test), str(root / name)]
         if test == "emulate_v3_23.py" else [sys.executable, str(root / test)]),
        cwd=root, text=True, capture_output=True, check=False
    )
    if result.returncode:
        print(result.stdout[-2500:])
        print(result.stderr[-2500:])
        raise SystemExit("FAILED: " + test)
    print("PASS:", test)
print(json.dumps({"pass": True, "sha256": expected, "count": len(tests)}, indent=2))
