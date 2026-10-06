#!/usr/bin/env python3
"""Inspect and repack Creality CFS application images offline.

The container metadata layout and CRC algorithm are taken from Creality's
tool/host_crc16.c and were cross-checked against stock CFS 113, 122, 150 and
153 images.

This module performs no serial, RS485, update or hardware operations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

APP_BASE = 0x08010000
APP_ID_OFFSET = 0x200
APP_ID_SIZE = 12
CRC_OFFSET = 0x20C
LENGTH_OFFSET = 0x20E
METADATA_END = 0x212


class CFSImageError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def creality_crc16(data: bytes | bytearray) -> int:
    """Creality CONFIG_USE_NEW_CRC16: poly 0x8005, init 0, non-reflected."""
    crc = 0
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def _decode_app_id(data: bytes | bytearray) -> str:
    if len(data) < METADATA_END:
        raise CFSImageError("image is too short for CFS metadata")
    raw = bytes(data[APP_ID_OFFSET:APP_ID_OFFSET + APP_ID_SIZE])
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CFSImageError("application identifier is not ASCII") from exc


def calculate_container_crc(data: bytes | bytearray) -> int:
    work = bytearray(data)
    if len(work) < METADATA_END:
        raise CFSImageError("image is too short for CFS metadata")
    work[CRC_OFFSET:METADATA_END] = b"\x00" * (METADATA_END - CRC_OFFSET)
    return creality_crc16(work)


def inspect_image(data: bytes | bytearray) -> dict:
    if len(data) < METADATA_END:
        raise CFSImageError("image is too short for CFS metadata")
    stored_crc = struct.unpack_from("<H", data, CRC_OFFSET)[0]
    declared_size = struct.unpack_from("<I", data, LENGTH_OFFSET)[0]
    initial_msp, reset_vector = struct.unpack_from("<II", data, 0)
    calculated_crc = calculate_container_crc(data)
    reset_addr = reset_vector & ~1
    return {
        "sha256": sha256(bytes(data)),
        "size": len(data),
        "application": _decode_app_id(data),
        "stored_crc16": stored_crc,
        "calculated_crc16": calculated_crc,
        "crc16_valid": stored_crc == calculated_crc,
        "declared_size": declared_size,
        "size_valid": declared_size == len(data),
        "initial_msp": initial_msp,
        "reset_vector": reset_vector,
        "msp_plausible": 0x20000000 <= initial_msp < 0x20080000 and not (initial_msp & 0x7),
        "reset_vector_plausible": bool(reset_vector & 1)
        and APP_BASE <= reset_addr < APP_BASE + len(data),
    }


def validate_image(data: bytes | bytearray, expected_application: str | None = None) -> dict:
    info = inspect_image(data)
    errors = []
    if expected_application is not None and info["application"] != expected_application:
        errors.append(
            "application identifier %r does not match expected %r"
            % (info["application"], expected_application)
        )
    if not info["size_valid"]:
        errors.append(
            "declared size 0x%x does not match actual size 0x%x"
            % (info["declared_size"], info["size"])
        )
    if not info["crc16_valid"]:
        errors.append(
            "CRC16 mismatch: stored 0x%04x, calculated 0x%04x"
            % (info["stored_crc16"], info["calculated_crc16"])
        )
    if not info["msp_plausible"]:
        errors.append("initial MSP is outside the expected aligned SRAM range")
    if not info["reset_vector_plausible"]:
        errors.append("reset vector is not a Thumb address inside the application")
    if errors:
        raise CFSImageError("; ".join(errors))
    return info


def repack_image(data: bytes | bytearray) -> bytes:
    """Regenerate CFS CRC16 and total-length metadata exactly like Creality."""
    out = bytearray(data)
    if len(out) < METADATA_END:
        raise CFSImageError("image is too short for CFS metadata")
    out[CRC_OFFSET:METADATA_END] = b"\x00" * (METADATA_END - CRC_OFFSET)
    crc = creality_crc16(out)
    struct.pack_into("<H", out, CRC_OFFSET, crc)
    struct.pack_into("<I", out, LENGTH_OFFSET, len(out))
    return bytes(out)


def _hexify(info: dict) -> dict:
    out = dict(info)
    for key in ("stored_crc16", "calculated_crc16", "initial_msp", "reset_vector"):
        out[key] = "0x%x" % out[key]
    out["declared_size_hex"] = "0x%x" % info["declared_size"]
    out["size_hex"] = "0x%x" % info["size"]
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)

    ip = sub.add_parser("inspect")
    ip.add_argument("image")

    vp = sub.add_parser("validate")
    vp.add_argument("image")
    vp.add_argument("--application")

    rp = sub.add_parser("repack")
    rp.add_argument("input")
    rp.add_argument("output")
    rp.add_argument("--expected-source-sha256")

    args = ap.parse_args()
    if args.command in ("inspect", "validate"):
        data = Path(args.image).read_bytes()
        if args.command == "inspect":
            info = inspect_image(data)
        else:
            info = validate_image(data, args.application)
        print(json.dumps(_hexify(info), indent=2))
        return

    src = Path(args.input).read_bytes()
    if args.expected_source_sha256:
        actual = sha256(src)
        if actual.lower() != args.expected_source_sha256.lower():
            raise SystemExit(
                "source SHA-256 mismatch: expected %s, got %s"
                % (args.expected_source_sha256, actual)
            )
    out = repack_image(src)
    Path(args.output).write_bytes(out)
    print(json.dumps(_hexify(validate_image(out)), indent=2))


if __name__ == "__main__":
    main()
