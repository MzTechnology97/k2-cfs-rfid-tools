# K2 CFS RFID Tools

Reverse engineering, diagnostics, and experimental read-only RFID tooling for the Creality K2 CFS.

> **Project status:** research / experimental. No modified firmware published here should be considered production-ready unless explicitly marked as hardware-validated.

## Documentation

- [RFID architecture](docs/architecture.md)
- [Reverse-engineering status](docs/reverse-engineering.md)
- [Experimental RFID protocol](docs/protocol.md)
- [Stock RFID non-interference policy](docs/non-interference.md)
- [Stock RFID manager state / v2.1 guard](docs/stock-rfid-state.md)
- [v2.1 hardware validation and rollback runbook](docs/hardware-validation.md)
- [Bambu Lab first-test plan](docs/bambu-lab-test-plan.md)
- [Roadmap toward generic / third-party RFID support](docs/roadmap.md)

## Goal

The project aims to make the RFID subsystem of the Creality K2 CFS observable and usable as a more generic RFID reader instead of limiting it to the proprietary spool/tag workflow implemented by the stock firmware.

The long-term goal is to support, where the CFS hardware permits it:

- generic ISO/IEC 14443-A tag discovery;
- tag presence / absence detection;
- UID retrieval;
- ATQA and SAK inspection;
- anticollision and select diagnostics;
- read-only memory inspection;
- MIFARE Classic reads when a valid key is supplied;
- Type-2 / NTAG-style read access where compatible with the RF frontend;
- identification and characterization of RFID tags used by third-party filament vendors;
- eventually, a carefully bounded raw RF transceive interface for unsupported tag families.

The primary design principle is **read first, understand first, write later**. Tag write, UID mutation, lock/OTP operations, key changes, and other destructive paths are intentionally excluded from the current diagnostic firmware.

## Target hardware and firmware

Current reverse engineering and patch work targets:

```text
hardware : cfs0_050_G32
firmware : cfs0_000_153
image    : cfs0_050_G32-cfs0_000_153.bin
```

Reference source image:

```text
SHA-256 5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
size    175672 bytes
```

Patch tooling is intended to be **exact-image locked**. A patcher must refuse to operate when the source image hash does not match the expected firmware.

The original Creality firmware image is not distributed by this repository.

## What has already been recovered

Static analysis of CFS 153 has identified the following with high confidence:

- MCU family: GD32F303;
- RFID frontend: Fudan FM17622;
- two physical RFID readers;
- two logical tag positions per reader, for four logical positions total;
- ISO14443-A request / wake-up flow;
- cascade-level anticollision;
- SELECT handling;
- UID collection;
- ATQA collection;
- final SAK collection;
- MIFARE Key A authentication;
- 16-byte `0x30` read primitive;
- stock MIFARE `0xA0` write primitive;
- an RF discovery cache populated before the higher-level Creality/vendor tag validation path.

The important consequence is that the stock firmware already contains RF primitives that operate below the proprietary spool parser.

## RF discovery cache

A 16-byte per-slot RF cache was recovered at runtime RAM beginning at:

```text
0x20004410
```

Record layout:

```text
+0x00..01  ATQA
+0x02..05  CL1 anticollision bytes
+0x06..09  CL2 anticollision bytes
+0x0A..0C  stock/private working bytes
+0x0D       current BCC working byte
+0x0E       final SAK
+0x0F       stock/private working byte
```

The cache is filled before the proprietary tag parser decides whether the detected RFID tag is a supported Creality spool tag. This makes it a useful observation point for third-party tags.

## Read-only diagnostic firmware candidate

A first diagnostic patch has already been built locally against the exact G32 / 153 image.

Candidate identity:

```text
cfs0_050_G32-cfs0_000_153-rfid-diag-ro.bin
SHA-256 f1ed544892c6b7c881fe641b25fc6f85d94d708bb6860585c9a2c3cc9c8ce59d
size    176230 bytes
```

Current validation status:

```text
static validator      OK
offline/unit tests    13/13 OK
reproducible build    byte-identical
hardware tests        NOT PERFORMED
firmware flash        NOT PERFORMED
```

The patch modifies four bytes in the original dispatcher to redirect one unused/fallback opcode to an appended read-only diagnostic handler.

### Diagnostic opcode

The current experimental command uses CFS opcode:

```text
0x57
```

This slot was found to fall through the invalid/fallback path in the analyzed 142, 150, and 153 command tables.

API v1:

```text
0x00  INFO
0x01  CACHED_TAG_INFO
0x02  POLL
0x03  READ_BLOCK
0x04  READ_BLOCK_AUTH_A
```

No tag-write operation is exposed.

### API v2 development candidate

A second locally built candidate keeps the same opcode and read-only call boundary while widening only the **unauthenticated** `0x30` read index to the full 8-bit range:

```text
API version              2
unauthenticated index    0..255
authenticated block      0..63
output SHA-256            0ea0b638efd63b947783460867fe6211b9a150ce8b0ec78e959adef86aeb4357
static validator          OK
v2 offline tests          5/5 OK
hardware flash            NOT PERFORMED
```

The v2 validator still proves that only the four dispatcher hook bytes differ inside the original stock image and that the original stock jump targets are preserved.

The v2 host client refuses active RF commands unless `--allow-active-rf` is explicitly supplied. Passive `INFO` and `CACHED_TAG_INFO` do not require this flag.

### API v2.1 guarded candidate

The v2.1 candidate adds a passive view of the stock RFID manager state and a firmware-side busy check before active diagnostic RF operations.

Recovered stock state:

```text
state base        0x200001F0
active-slot byte  0x200001F2

0..3  stock RFID manager is handling that logical slot
>=4   no stock slot is currently managed
```

New diagnostic behavior:

```text
0x05  STOCK_STATE
status 7 = stock RFID busy
```

`POLL`, unauthenticated reads and authenticated reads return status 7 instead of touching the RF frontend when the stock active-slot byte is below 4.

Current local candidate:

```text
revision                 2.1
protocol api_version     3
SHA-256                  3cf3385dcbc56960c9fe3adcaff516a7d66a0f8ad2b43b5d47d40c341824549c
static validator         PASS
v2.1 offline tests       7/7 PASS
hardware flash           NOT PERFORMED
```

This is a guard, not a shared atomic mutex; controlled-idle hardware testing is still required.

## Current capabilities

### INFO

Reports diagnostic API version, reader count, slot count, capability flags, supported read index range, and cache record size.

### CACHED_TAG_INFO

Returns the stock 16-byte RF discovery record without initiating a new RF transaction.

This is intended to be the lowest-risk first hardware diagnostic.

### POLL

Uses the stock CFS reader path to perform ISO14443-A discovery and return the RF cache containing UID/ATQA/SAK information.

### READ_BLOCK / READ_PAGE

Uses the existing stock `0x30` RF read primitive and returns 16 bytes.

For MIFARE Classic this behaves as a block read.

For ISO14443-A Type-2-like tags, `0x30` normally represents a 4-page read window. The exact memory model must therefore be interpreted by the host according to the detected tag family rather than assuming MIFARE Classic.

### READ_BLOCK_AUTH_A

Performs stock Key-A authentication followed by a read. The key is supplied by the caller; no proprietary key is embedded in the patch.

## What is intentionally not implemented yet

A fully arbitrary `RAW_TRANSCEIVE` command is not exposed yet.

The FM17622 driver is low-level enough that such an interface appears feasible, but the following behavior still needs to be mapped precisely before it can be considered safe and reliable:

- RF error/status bits;
- collision register semantics and collision position;
- FIFO length and overflow behavior;
- CRC generation/check configuration;
- parity behavior;
- IRQ/status semantics;
- timeout units;
- RF cleanup and error recovery;
- concurrency with normal CFS RFID polling.

The next implementation phase is therefore to extend generic **read-only** compatibility before exposing unrestricted transceive.

## Safety boundary

Current project policy:

- no automatic flashing;
- no tag writes;
- no UID mutation;
- no lock/OTP writes;
- no key changes;
- no firmware erase/update during RFID diagnostics;
- modified firmware must remain tied to an exact source image hash;
- stock behavior for unrelated CFS commands must be preserved;
- every firmware candidate must be reproducibly built and statically validated before any hardware test.

## Repository plan

```text
docs/
    architecture.md
    protocol.md
    reverse-engineering.md
    roadmap.md

tools/
    patch builder
    static validator
    host RFID utility

patches/
    manifests and validation metadata only

tests/
    offline protocol and patch tests

evidence/
    machine-readable reverse-engineering evidence
```

Original vendor firmware images should not be committed.

## Scope

This project is currently focused on the **Creality K2 CFS G32 hardware running CFS firmware 153**. Findings from older firmware versions may be used for differential analysis, but patches must never be assumed portable across versions without independent validation.

## Disclaimer

This is an independent reverse-engineering and interoperability research project. It is not affiliated with or endorsed by Creality or Fudan Microelectronics.

Firmware modification can render hardware unusable. Do not flash experimental images without a tested recovery path and a verified original firmware image.
