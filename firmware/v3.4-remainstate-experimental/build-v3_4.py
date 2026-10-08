#!/usr/bin/env python3
"""Rebuild the experimental v3.4 read-only CFS remaining-state candidate.

The input must be the hardware-validated v3.3 image. This script compiles the
replacement handler, repoints only the six stock RFID read callsites whose
wrapper addresses moved, extends the image tail, and recomputes the Creality
container length/CRC16. It never patches any stock tag-write callsite.
"""
import argparse
import hashlib
import pathlib
import struct
import subprocess
import tempfile

APP_BASE = 0x08010000
HANDLER_ADDR = 0x0803AE38
CRC_OFF = 0x20C
LEN_OFF = 0x20E
META_END = 0x212
EXPECTED_V33_SHA256 = (
    "5bab3acff49253a54089e779ea473d2cf587db09ab0d9c07c4d6c2e31b810388"
)
EXPECTED_V33_HANDLER_SIZE = 1072

LEGACY_CALLS = (
    (0x0801A4CC, "legacy_read0_wrapper"),
    (0x0801A52C, "legacy_read1_wrapper"),
    (0x0801A590, "legacy_read2_wrapper"),
)
ALT_CALLS = (
    (0x080225D0, "alt_read_wrapper"),
    (0x08022604, "alt_read_wrapper"),
    (0x08022638, "alt_read_wrapper"),
)


def run(*args):
    subprocess.check_call(list(map(str, args)))


def output(*args):
    return subprocess.check_output(list(map(str, args)), text=True)


def crc16_bypass(data):
    crc = 0
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = (((crc << 1) ^ 0x8005) & 0xFFFF
                   if crc & 0x8000 else (crc << 1) & 0xFFFF)
    return crc


def symbols(elf):
    result = {}
    for line in output("arm-none-eabi-nm", "-n", elf).splitlines():
        parts = line.split()
        if len(parts) == 3:
            try:
                result[parts[2]] = int(parts[0], 16)
            except ValueError:
                pass
    return result


def thumb_bl(src, dst):
    # Let the ARM toolchain encode the branch rather than duplicating the
    # Thumb-2 BL immediate encoding in the builder.
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        asm = td / "bl.S"
        ld = td / "bl.ld"
        obj = td / "bl.o"
        elf = td / "bl.elf"
        raw = td / "bl.bin"
        asm.write_text(
            ".syntax unified\n.thumb\n.cpu cortex-m3\n"
            ".section .text,\"ax\",%%progbits\n.global x\n.thumb_func\n"
            "x:\n    bl 0x%08x\n" % dst
        )
        ld.write_text(
            "SECTIONS { . = 0x%08x; .text : { *(.text) } }\n" % src)
        run("arm-none-eabi-gcc", "-c", "-mcpu=cortex-m3", "-mthumb",
            "-ffreestanding", "-nostdlib", "-o", obj, asm)
        run("arm-none-eabi-ld", "-T", ld, "-o", elf, obj)
        run("arm-none-eabi-objcopy", "-O", "binary", elf, raw)
        data = raw.read_bytes()
        if len(data) != 4:
            raise RuntimeError("unexpected Thumb BL size %d" % len(data))
        return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True,
                    help="hardware-validated v3.3 candidate")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    here = pathlib.Path(__file__).resolve().parent
    base_path = pathlib.Path(args.base)
    out_path = pathlib.Path(args.out)
    base = base_path.read_bytes()
    digest = hashlib.sha256(base).hexdigest()
    if digest != EXPECTED_V33_SHA256:
        raise SystemExit(
            "refusing unexpected base image: %s (wanted %s)"
            % (digest, EXPECTED_V33_SHA256))

    obj = here / "handler-v3_4.build.o"
    elf = here / "handler-v3_4.build.elf"
    raw = here / "handler-v3_4.build.bin"
    run("arm-none-eabi-gcc", "-c", "-mcpu=cortex-m3", "-mthumb",
        "-ffreestanding", "-nostdlib", "-o", obj,
        here / "handler-v3_4.S")
    run("arm-none-eabi-ld", "-T", here / "link.ld", "-o", elf, obj)
    run("arm-none-eabi-objcopy", "-O", "binary", elf, raw)
    handler = raw.read_bytes()
    syms = symbols(elf)

    handler_off = HANDLER_ADDR - APP_BASE
    if len(base) != handler_off + EXPECTED_V33_HANDLER_SIZE:
        raise SystemExit("v3.3 handler/tail layout is not the validated shape")
    image = bytearray(base[:handler_off] + handler)

    for callsite, name in LEGACY_CALLS + ALT_CALLS:
        target = syms[name]
        patch = thumb_bl(callsite, target)
        off = callsite - APP_BASE
        image[off:off + 4] = patch

    struct.pack_into("<I", image, LEN_OFF, len(image))
    check = bytearray(image)
    check[CRC_OFF:META_END] = b"\0" * (META_END - CRC_OFF)
    crc = crc16_bypass(check)
    struct.pack_into("<H", image, CRC_OFF, crc)
    struct.pack_into("<I", image, LEN_OFF, len(image))

    out_path.write_bytes(image)
    print("size=%d" % len(image))
    print("handler_size=%d" % len(handler))
    print("crc16=0x%04X" % crc)
    print("sha256=%s" % hashlib.sha256(image).hexdigest())
    for callsite, name in LEGACY_CALLS + ALT_CALLS:
        print("0x%08X -> %s @ 0x%08X"
              % (callsite, name, syms[name]))


if __name__ == "__main__":
    main()