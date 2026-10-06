# Bambu Lab RFID first-test plan

Bambu Lab filament tags are the first third-party target for the generic CFS RFID work because there is substantial public reverse-engineering data available for comparison.

## Public reference findings

The Bambu Research Group documents Bambu filament tags as 13.56 MHz MIFARE-family tags and provides tooling for recovering/deriving the authentication keys needed to read their data.

Public tag dumps in the Bambu Lab RFID Library identify typical spool tags as:

```text
Device type: Mifare Classic
Mifare Classic type: 1K
ATQA: 00 04
SAK: 08
UID: 4 bytes
```

Example public dump:

- https://github.com/queengooborg/Bambu-Lab-RFID-Library/blob/main/ABS/ABS/Silver/EAFE5CFC/EAFE5CFC.nfc

Reverse-engineering guide:

- https://github.com/Bambu-Research-Group/RFID-Tag-Guide

Tag layout documentation:

- https://github.com/Bambu-Research-Group/RFID-Tag-Guide/blob/main/BambuLabRfid.md

Key derivation reference:

- https://github.com/Bambu-Research-Group/RFID-Tag-Guide/blob/main/deriveKeys.py

This repository also provides a host-side helper:

```text
python tools/bambu_keys.py <UID>
python tools/bambu_keys.py <UID> --sector 0
```

It is covered by an offline fixture using the public Bambu dump UID `EAFE5CFC`, whose sector-0 keys are publicly visible in that dump:

```text
Key A 2FC5F17A68A4
Key B 759F4DF068B6
```

The helper is not embedded into the CFS firmware.

## Why Bambu is a useful compatibility test

The test can be divided into independent stages.

### Stage 1 — RF discovery only

No authentication key is required to validate:

- tag presence;
- ATQA;
- UID;
- SAK;
- anticollision;
- select.

Expected reference values for common Bambu Classic 1K tags:

```text
ATQA 00 04
SAK  08
UID  4 bytes
```

The exact UID will of course differ for each physical spool.

A successful Stage 1 proves that the CFS can observe the Bambu tag below the proprietary Creality parser.

### Stage 2 — authentication

Bambu MIFARE Classic data is protected by per-sector keys.

The public Bambu research provides a UID-based derivation method. For initial validation, keys should be generated outside the CFS firmware and passed to the diagnostic API.

The firmware must not embed Bambu-specific keys or key derivation constants.

This keeps the CFS extension generic.

### Stage 3 — read one known data block

After successful authentication, read one non-trailer data block and compare the returned 16 bytes against a known-good independent dump of the same physical tag.

Do not begin with sector trailers.

Recommended initial candidates:

```text
block 1
block 2
block 4
```

These contain ordinary spool metadata in the public Bambu tag layout.

### Stage 4 — complete read-only dump

A MIFARE Classic 1K tag contains:

```text
16 sectors
4 blocks per sector
64 blocks total
16 bytes per block
```

The authenticated dump helper should:

1. determine the sector for each block;
2. use the correct key for that sector;
3. skip or separately label sector trailers;
4. store raw block data;
5. retain UID / ATQA / SAK alongside the dump;
6. never write to the tag.

## Test order on the real CFS

The recommended first session is:

```text
A. stock Creality tag regression
B. INFO
C. passive CACHED_TAG_INFO
D. Bambu tag: passive cache observation
E. Bambu tag: active POLL
F. compare UID / ATQA / SAK with public expectations
G. derive keys externally from that spool UID
H. authenticate + read one known data block
I. compare against an independent reader/dump if available
J. only then attempt a complete read-only dump
```

Active steps require the v2 host option:

```text
--allow-active-rf
```

## Expected first result

For a typical Bambu spool, the first meaningful success criterion is not decoding filament metadata.

It is simply:

```text
CFS detects the Bambu tag
ATQA == 00 04
SAK  == 08
UID is stable and repeatable
```

If this works, the RF compatibility hypothesis is strongly supported.

The next milestone is authenticated block reading.

## Data comparison

When a physical Bambu spool is tested, record:

```text
spool/material label
reader
logical slot
UID
ATQA
SAK
CL1 bytes
CL2 bytes
BCC status
auth result per sector
block read result
firmware candidate SHA-256
host-tool version
```

Do not publish the user's physical tag UID or derived keys by default.

## No effect on Creality parsing

Bambu-specific decoding belongs on the host side.

The CFS firmware should continue to expose generic RF primitives only.

This prevents support for Bambu, QIDI, or future vendors from changing the stock proprietary Creality tag path.

## Later QIDI test

QIDI can be evaluated after the Bambu baseline.

Public community tooling indicates QIDI filament workflows also use ISO14443-A-compatible tags, including MIFARE Classic 1K in at least some implementations, making the same staged approach useful:

```text
presence -> UID/ATQA/SAK -> classify -> read-only memory -> decode on host
```

No QIDI-specific assumptions should be built into the firmware until physical QIDI tags are measured on the CFS.
