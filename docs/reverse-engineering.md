# Reverse-engineering status

This document records the findings currently established for the Creality K2 CFS RFID subsystem.

## Reference target

All current patch development is based on the exact firmware image:

```text
hardware token : cfs0_050_G32
application    : cfs0_000_153
filename       : cfs0_050_G32-cfs0_000_153.bin
size           : 175672 bytes
SHA-256        : 5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
```

Older CFS firmware has been useful for differential analysis, but it is not the patch target.

## Hardware findings

### CFS MCU

The analyzed firmware and peripheral layout are consistent with a GD32F303-family MCU. The current working identification is GD32F303VET6 with high confidence.

### RFID frontend

The firmware contains an `fm176xx` driver and the recovered RFID path is consistent with a Fudan FM17622 frontend.

The transport used by the MCU for the reader frontend appears to be a two-wire / I2C-like bit-banged interface rather than a normal SPI peripheral despite stock strings containing generic SPI-related board information elsewhere in the image.

### Reader topology

The CFS exposes:

```text
2 physical RFID readers
2 logical tag/spool positions per reader
4 logical positions total
```

The recovered cache addressing reflects a 0x20-byte stride per reader and 0x10-byte record size per logical slot.

## RF discovery path

The stock application already implements an ISO14443-A style discovery flow below the Creality tag parser.

Recovered operations include:

1. reader initialization / RF mode setup;
2. request / wake-up using `0x52`;
3. cascade-level-1 anticollision;
4. SELECT CL1;
5. optional cascade-level-2 anticollision;
6. SELECT CL2;
7. ATQA / UID / BCC / SAK storage;
8. higher-level tag processing.

This separation is central to the project: a tag can be successfully detected at the RF layer even when the stock Creality parser later rejects it as unsupported.

## RF discovery cache

The RFID discovery cache begins at:

```text
RAM 0x20004410
```

There are four 16-byte logical records:

```text
reader 0 / slot 0 : base + 0x00
reader 0 / slot 1 : base + 0x10
reader 1 / slot 0 : base + 0x20
reader 1 / slot 1 : base + 0x30
```

Recovered layout:

```text
+0x00..01  ATQA
+0x02..05  CL1 anticollision bytes
+0x06..09  CL2 anticollision bytes
+0x0A..0C  stock/private working bytes
+0x0D       current BCC working byte
+0x0E       final SAK
+0x0F       stock/private working byte
```

For a single-level UID, useful UID bytes are present in the CL1 area.

For a cascade UID, the CL1 response may begin with cascade tag `0x88`, and the final UID must be reconstructed using both CL1 and CL2 data.

The BCC byte at offset `+0x0D` is reused by the stock discovery routines and therefore represents the most recent cascade level rather than storing an independent BCC for every level.

## Recovered stock RFID primitives

The firmware contains distinct lower-level functions for:

- RF mode setup / cleanup;
- tag discovery / reader probe;
- MIFARE Key A authentication;
- 16-byte read using command `0x30`;
- MIFARE write using command `0xA0`.

The existence of the stock write path is documented for completeness only. It is deliberately excluded from the current diagnostic extension.

## Failure stages

The recovered discovery path distinguishes several failure stages rather than returning only a single generic unsupported-tag result.

The diagnostic mapping currently uses:

```text
0  OK
1  malformed / invalid request
2  request stage failed / no tag
3  anticollision failed
4  select failed
5  authentication failed
6  read failed
```

This distinction is important when testing third-party tags because it allows us to differentiate:

- no RF response;
- collision/anticollision incompatibility;
- selection incompatibility;
- tag detected and selected but proprietary parser rejection;
- authentication failure;
- memory read failure.

## CFS application protocol extension

The current experimental extension uses opcode:

```text
0x57
```

During analysis this opcode fell through the invalid/fallback path in the available CFS 142, 150, and 153 command tables.

The G32/153 candidate changes only four bytes inside the original image to redirect the relevant dispatcher path to an appended handler.

Dispatcher hook:

```text
file offset  : 0xC3A0
runtime addr : 0x0801C3A0
handler addr : 0x0803AE38
```

Original bytes:

```text
2a e2 af e1
```

The handler preserves the original behavior of unrelated opcodes and returns to the stock common response/control-flow path after handling opcode `0x57`.

## Read-only API v1

Subcommands:

```text
0x00  INFO
0x01  CACHED_TAG_INFO
0x02  POLL
0x03  READ_BLOCK
0x04  READ_BLOCK_AUTH_A
```

### INFO

Reports:

- API version;
- physical reader count;
- slots per reader;
- capability flags;
- maximum advertised read index;
- cache record size.

### CACHED_TAG_INFO

Reads the 16-byte stock discovery cache without initiating an RF transaction.

This is intended to be the first hardware test because it introduces minimal behavioral change.

### POLL

Invokes the recovered stock discovery/select path and returns the resulting 16-byte RF cache record.

### READ_BLOCK

Performs discovery/select and invokes the stock `0x30` read primitive.

The primitive accepts an 8-bit index. The first local candidate artificially constrained the index to `0..63`; this restriction is part of the diagnostic patch, not an established limitation of the stock read primitive, and is scheduled to be widened for generic Type-2/NTAG-style testing.

### READ_BLOCK_AUTH_A

Performs discovery/select, Key-A authentication, and a `0x30` read.

The key comes from the caller. The diagnostic firmware does not embed a vendor key.

The currently validated authenticated path is intentionally conservative and should not be generalized to every MIFARE memory geometry without additional analysis.

## Candidate build

The locally generated first read-only candidate is:

```text
cfs0_050_G32-cfs0_000_153-rfid-diag-ro.bin
size    176230 bytes
SHA-256 f1ed544892c6b7c881fe641b25fc6f85d94d708bb6860585c9a2c3cc9c8ce59d
```

Validation performed:

```text
static validation      PASS
offline/unit tests     13/13 PASS
reproducible build     PASS
hardware flash         NOT PERFORMED
hardware RFID tests    NOT PERFORMED
```

The static validator checks, among other things:

- exact source SHA-256;
- exact dispatcher hook bytes;
- expected modified original offsets;
- handler disassembly coverage;
- allowed external call targets;
- absence of calls to the known RFID write primitive;
- absence of calls to the known BL24Cxx write primitive;
- preserved stock fallback/control-flow targets.

## Current external calls used by the diagnostic handler

The first candidate only calls the recovered read-side primitives:

```text
0x0801914C  RF mode / cleanup
0x0801959E  reader probe
0x080195D8  MIFARE Key A authentication
0x08019824  16-byte read
0x0801BAF2  CFS response builder
```

Known write-side targets are not reachable from the diagnostic handler.

## Raw transceive status

A fully generic raw transceive interface is not yet exposed.

The low-level FM17622 driver appears sufficient to implement one, but exact behavior still needs to be recovered for:

- RF error bits;
- collision status and collision position;
- FIFO capacity and overflow;
- CRC generation/check;
- parity configuration;
- IRQ/status interpretation;
- timeout units;
- RF cleanup after partial/failing transactions;
- concurrency with normal stock polling.

Until those details are understood, unrestricted raw transceive remains outside the hardware test boundary.

## Confidence labels

When extending this documentation, findings should be described using explicit confidence levels:

- **confirmed live** — observed on real hardware;
- **high confidence static** — directly supported by firmware control flow/data use;
- **inferred** — plausible interpretation that still needs independent validation;
- **unknown** — not yet established.

Do not convert an inferred behavior into a confirmed fact merely because it matches a known ISO14443 or MIFARE convention.
