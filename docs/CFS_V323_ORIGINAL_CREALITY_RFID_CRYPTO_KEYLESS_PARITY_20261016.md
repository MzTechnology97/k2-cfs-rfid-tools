# Creality CFS v3.23 — original RFID crypto parity with complete OpenCFS reverse engineering

*16 October 2026. Source-only offline audit stacked on draft #54, no firmware flash or private key transfer.*

## Verified recent reverse engineering

Review of the user's Windows source working directory
`Documents/cfs-firmware-re` and the new public
[OpenCFS draft PR #5](https://github.com/MzTechnology97/OpenCFS-Firmware/pull/5)
at commit `67f0f063736709a20cc0fb22ca15c8b5a01e4435`
confirms a significant step from the earlier specification:

- Source-backed stock CFS 1.5.3 protocol and hardware map (Ghidra
  export recorded **1,135 functions**), original vendor RFID read,
  motion/feed/runout behavior and recovery design.
- Clean/spec-first C++ implementation of firmware behavior with
  cooperative core, read-only FM17622 drivers, feeder/hub controls,
  display/sensors, NDEF Type-2 and ISO-DEP Type-4 tag parsing, 4/7/10
  byte UIDs and multiple manufacturer decoders.
- New Runtime Config API v2 with a **design-level cooperative
  motor interlock**, stock parameter units and Kalico host-contract
  tests. The isolated source project runs **269 deterministic
  host checks with zero failures** on the Windows PC. Its
  documentation reports **101 host-code compatibility checks**.
- **Still not a physically qualified CFS binary:** no deployable
  OEM-compatible bootloader/ELF/BIN update, and no live hardware
  verification of motor direction, RF timings, 24C16 EEPROM
  or recovery. Compile/simulator success must not override
  production motor/Flash safety.

**Do not transplant OpenCFS's cooperative-task interlock into the
Creality OEM RT-Thread firmware by assumption.** The stock firmware
still has concurrently running motor threads, hub PID callbacks and
interrupts. Our modified v3.23 explicitly keeps SET/RESET denied
until a separate atomic OEM-side guard can be source-proved.

## Locally checked keys — never exported

The user's PC has these locally held private headers:

- `Documents/cfs-firmware-re/src/board/k2cfs/local/creality_keys.hpp`
- `Documents/cfs-firmware-re/src/board/k2cfs/local/vendor_keys.hpp`

Their values are **not** reproduced here. The Creality header
contains two **128-bit** arrays (tag Key-A derivation and
Creality block-decryption key). A **local-only** consistency
check on the user's PC recovered the two original arrays from
their **own** 1.5.3 stock firmware using OpenCFS's
`tools/re/extract_tag_keys.py` procedure and compared them
with the privately generated header: **both match**. The
vendor header was confirmed present but its secrets were
**not read or verified**.

The public OpenCFS checkout does **not** include either
private generated header. The public repository does not
track `cpp/board/k2cfs/local/`, and the private research
workspace's `.gitignore` excludes
`src/board/k2cfs/local/`. Never copy, upload, commit, log,
publish screenshots of, or serialize these headers in
`k2-cfs-rfid-tools`, OpenCFS, CI artifacts or release builds.

## What the OEM v3.23 actually needs

**For Creality tags, no new key loader is needed.** The stock
Creality K1/K2 and the original RFID reader/decryptor are already
compiled into the original OEM APP; our additive type-4 live
usage and read-only MCU diagnostics should not change them.

New [keyless parity audit](../firmware/v3.22-readonly-state-probes/cfs_v323_creality_crypto_rom_keyless_parity.py)
rebuilds the exact **178,568-byte** v3.23 experimental APP
from saved SHA-pinned OEM v3.13/v3.22 sources (as in #54),
then verifies:

1. A unique 512-byte standard AES S-box/inverse S-box region,
   preceded by the OEM 48-byte private key-table structure;
2. A single in-ROM original physical pointer to that table;
3. **Exact unchanged key-table and substitution bytes** across
   saved v3.13, v3.22 and new v3.23 images;
4. Identical derived K1/K2 **in memory only**, without
   reporting their bytes, digests, hash fingerprints, UIDs
   or plaintext RFID data;
5. The existing OEM reader and FM15L013 secure function
   references remain unchanged; v3.23 CONFIG SET/RESET
   still fail closed;
6. Four negative mutations (table beginning, table end,
   AES S-box and physical ROM literal) are rejected.

The original manufacturer table is source-located at
physical **`0x0802BD59`** with its pointer literal at
APP offset **`0x231BC`**. These are nonsecret
ROM *locations* only — the audit never exports the table.

**Do not confuse** manufacturer's **runtime usage record
`type=4`** (our v3.23 live accounting path, an internal
record structure) with **NFC Forum Type 4 ISO-DEP tag**
(OpenCFS's new RF technology, processed via ISO 14443-4).
These solve different problems.

Bambu/other vendor RFID decoding inside the original OEM
v3.23 is **not** automatically implemented by the new
OpenCFS source: porting multiple RF activation/decoders
requires separate CFS manufacturer HAL and timing proofs.
The existing Kalico API7 bridge may already handle
third-party reads, but Kalico remains untouched until
the first OEM v3.23 firmware image has passed preflight.

## Status

Source-only automated regression, **no committed secret values
or fingerprints**, no key/header copied to CM5 or cloud,
no physical tag read, no MCU Flash/RS485, no motor movement,
no Kalico modifications, and no executable firmware
artifact exported.

The v3.23 **178,568-byte** latest source-pinned preview is
still **not certified to flash**, regardless of these
successful cryptography-preservation checks.
