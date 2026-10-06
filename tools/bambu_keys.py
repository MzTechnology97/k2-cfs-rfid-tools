#!/usr/bin/env python3
"""
Derive Bambu Lab MIFARE Classic sector keys from a 4-byte tag UID.

This host-side helper implements the public derivation documented by the
Bambu RFID reverse-engineering community. It is intentionally separate from
the CFS firmware so the firmware remains vendor-neutral.
"""
import argparse
import hashlib
import hmac
import json


SALT = bytes.fromhex("9a759cf2c4f7caff222cb9769b41bc96")
SECTORS = 16
KEY_LEN = 6


def hkdf_sha256(master, key_len, salt, context, num_keys):
    prk = hmac.new(salt, master, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    wanted = key_len * num_keys

    while len(output) < wanted:
        previous = hmac.new(
            prk,
            previous + context + bytes((counter,)),
            hashlib.sha256,
        ).digest()
        output.extend(previous)
        counter += 1

    raw = bytes(output[:wanted])
    return [raw[i * key_len : (i + 1) * key_len] for i in range(num_keys)]


def derive(uid):
    uid = bytes(uid)
    if len(uid) != 4:
        raise ValueError("Bambu reference derivation currently expects a 4-byte UID")
    return {
        "A": hkdf_sha256(uid, KEY_LEN, SALT, b"RFID-A\0", SECTORS),
        "B": hkdf_sha256(uid, KEY_LEN, SALT, b"RFID-B\0", SECTORS),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Derive Bambu Lab MIFARE Classic sector keys from tag UID"
    )
    ap.add_argument("uid", help="4-byte UID as 8 hexadecimal characters")
    ap.add_argument("--sector", type=int, choices=range(16))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    try:
        uid = bytes.fromhex(a.uid)
    except ValueError as exc:
        raise SystemExit("UID must be hexadecimal") from exc

    try:
        keys = derive(uid)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    sectors = [a.sector] if a.sector is not None else list(range(SECTORS))
    rows = [
        {
            "sector": sector,
            "key_a": keys["A"][sector].hex().upper(),
            "key_b": keys["B"][sector].hex().upper(),
        }
        for sector in sectors
    ]

    if a.json:
        print(json.dumps({"uid": uid.hex().upper(), "sectors": rows}, indent=2))
        return

    print(f"UID {uid.hex().upper()}")
    for row in rows:
        print(
            f"sector {row['sector']:02d}: "
            f"A={row['key_a']} B={row['key_b']}"
        )


if __name__ == "__main__":
    main()