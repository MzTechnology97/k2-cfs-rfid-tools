# Roadmap

This roadmap tracks the work required to move from a Creality-specific RFID workflow toward a generic, read-only RFID inspection layer for the K2 CFS.

## Primary objective

The project is not intended only to decode Creality spool tags.

The target is to make the existing CFS RFID hardware useful for identifying and reading compatible RFID tags from other filament vendors and custom tags, while preserving normal CFS behavior and keeping the first implementation strictly read-only.

The desired generic workflow is:

```text
tag enters RF field
        |
        v
detect ISO14443-A presence
        |
        v
recover ATQA / UID / SAK
        |
        v
classify tag family where possible
        |
        +--> directly readable memory
        |
        +--> authenticated memory
        |
        +--> unsupported by current high-level primitives
                 |
                 v
          future raw transceive
```

## Phase 0 — completed research baseline

Completed or substantially completed:

- identify the G32 / CFS 153 target image;
- recover source image SHA-256;
- identify FM17622 RFID frontend;
- identify two physical readers and four logical positions;
- reconstruct ISO14443-A request / anticollision / select path;
- identify RF cache layout;
- recover UID / ATQA / SAK path;
- recover MIFARE Key A authentication primitive;
- recover `0x30` read primitive;
- identify the stock `0xA0` write primitive;
- identify a usable unused/fallback application opcode;
- build a read-only diagnostic handler;
- build host-side protocol tooling;
- build an exact-image-locked patcher;
- build a static validator;
- obtain 13/13 passing offline tests;
- demonstrate reproducible patched-image generation.

No firmware has been flashed as part of this project yet.

## Phase 1 — generic read-only API on G32 / 153

Current immediate work.

### 1. Preserve exact target locking

All work remains based on:

```text
cfs0_050_G32-cfs0_000_153.bin
SHA-256 5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
```

The patcher must abort on any other source image.

### 2. Widen non-authenticated read index

The stock `0x30` primitive receives an 8-bit index.

The first diagnostic build imposed an artificial `0..63` limit.

For generic read-only interoperability testing, the non-authenticated read command should support:

```text
0x00 .. 0xFF
```

This is especially relevant to ISO14443-A Type-2 / NTAG-style memory layouts where the argument is interpreted as a page index and `0x30` returns a multi-page window.

The authenticated MIFARE path should remain conservative until larger-sector geometry is handled correctly.

### 3. Improve tag classification

Host-side classification should use RF data as hints, not absolute proof.

Inputs can include:

- ATQA;
- SAK;
- UID length;
- cascade behavior;
- read success/failure pattern;
- page/block geometry inferred from non-destructive reads.

The tool should avoid claiming an exact chip model unless the evidence is sufficient.

### 4. Generic dump strategy

Implement a safe host-side reader that can:

- poll;
- display UID / ATQA / SAK;
- attempt bounded read-only `0x30` windows;
- stop cleanly on first invalid/unreadable region;
- export raw data in binary / hex / JSON;
- retain the exact RF metadata associated with the dump.

The dump tool should never automatically retry with write/authentication-changing operations.

## Phase 2 — first controlled hardware validation

The first flash should happen only after a verified rollback path exists.

Recommended test order:

1. verify exact original CFS firmware image and hash;
2. verify CFS loader/update recovery path;
3. install the read-only candidate;
4. confirm normal CFS boot and stock operation;
5. call `INFO`;
6. call `CACHED_TAG_INFO` with no active RF transaction;
7. test `POLL` with no tag;
8. test `POLL` with a normal Creality tag;
9. test `POLL` with a known non-Creality ISO14443-A tag;
10. compare UID / ATQA / SAK with an independent NFC reader;
11. test bounded unauthenticated `0x30` reads;
12. test authenticated MIFARE reads only on a controlled test tag;
13. stress normal CFS polling and the diagnostic API together;
14. verify reboot and rollback.

A failed diagnostic request must not make the stock CFS RFID workflow unusable.

## Phase 3 — third-party spool/tag characterization

Build an evidence set from filament tags from multiple vendors.

For every tested tag, record:

```text
vendor / spool
known or unknown tag family
UID length
UID
ATQA
SAK
CL1 / CL2 behavior
unauthenticated read result
readable index range
authentication required?
memory dump hash
notes
```

Do not publish secret authentication keys obtained from third parties unless publication is clearly authorized.

The objective is interoperability and technical characterization, not bypassing unrelated access-control systems.

## Phase 4 — raw FM17622 transaction model

Only after read-only high-level primitives have been hardware-validated.

Recover and document the FM17622 register model needed for a generic exchange:

- command register;
- FIFO data / FIFO level;
- interrupt/status registers;
- error register;
- collision register;
- framing / bit-length controls;
- CRC configuration;
- parity handling;
- timer configuration;
- RF field state;
- transceive start/stop;
- cleanup after errors/timeouts.

Build an offline emulator/test harness for the command builder before adding a firmware opcode.

## Phase 5 — bounded RAW_TRANSCEIVE

Add a read-only-oriented generic exchange primitive only after the register model is sufficiently understood.

The API should explicitly control:

- TX bytes;
- TX bit length when needed;
- expected RX maximum;
- timeout;
- CRC mode;
- parity mode;
- collision reporting;
- raw status/error return.

The first raw implementation should not expose convenience commands for tag writes.

## Phase 6 — broader tag-family support

Potential families to evaluate when technically compatible with the FM17622 and antenna design:

- MIFARE Classic;
- MIFARE Ultralight-compatible tags;
- NTAG / Type-2-like tags;
- other ISO14443-A tags that fit the recovered RF capabilities.

Support must be determined experimentally and from RF behavior, not assumed from product branding.

## Out of scope for the current phase

The following are intentionally not current objectives:

- cloning vendor tags;
- changing UID;
- modifying immutable/OTP areas;
- tag locking;
- rewriting authentication keys;
- automatic tag-format conversion;
- automatic firmware flashing;
- bypassing access-control/security systems.

## Repository milestones

### M1 — documentation baseline

- README;
- reverse-engineering findings;
- roadmap;
- protocol documentation;
- firmware-hash policy.

### M2 — reproducible tooling

- patch builder;
- validator;
- host reader;
- offline tests;
- machine-readable patch manifest.

### M3 — G32/153 hardware validation

- safe installation;
- stock regression;
- generic tag polling;
- third-party UID / ATQA / SAK comparison;
- safe memory reads.

### M4 — generic RFID layer

- improved tag classification;
- 8-bit read index;
- structured dump format;
- third-party spool evidence.

### M5 — raw RF layer

- FM17622 register map;
- error/collision semantics;
- raw transceive;
- hardware regression suite.

## Success criterion

The project reaches its first meaningful interoperability goal when a stock CFS G32 can, using the modified 153 firmware and host tooling:

1. detect a non-Creality compatible RFID tag;
2. report UID, ATQA and SAK without relying on the Creality spool parser;
3. perform safe read-only memory access when the tag permits it;
4. return useful low-level failure information when it cannot;
5. continue to operate normally with standard CFS functionality.
