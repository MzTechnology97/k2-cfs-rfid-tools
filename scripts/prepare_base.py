#!/usr/bin/env python3
"""Recover the pinned intermediate input from Git history, never flash a device."""
from pathlib import Path
import argparse
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '0ad22669248cc845a3c8d22dd613500c4b95feb3'
PATH = 'firmware/v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin'
SHA256 = '9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff'

def prepare(source=None):
    target = ROOT / 'work/base-pinned.bin'
    if source is not None:
        data = Path(source).read_bytes()
    elif target.exists():
        data = target.read_bytes()
    else:
        result = subprocess.run(['git', '-C', str(ROOT), 'show', COMMIT + ':' + PATH],
                                capture_output=True)
        if result.returncode:
            raise SystemExit('Pinned base is missing. Fetch commit ' + COMMIT
                             + ' (or use --from-file), then retry. No download or device operation was attempted.')
        data = result.stdout
    if len(data) != 177700 or hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit('Pinned intermediate base size/SHA-256 mismatch')
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists() or target.read_bytes() != data:
        target.write_bytes(data)
    return target

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--from-file')
    args = ap.parse_args()
    print(prepare(args.from_file))
