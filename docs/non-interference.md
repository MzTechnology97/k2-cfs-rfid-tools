# Stock RFID non-interference policy

The primary compatibility requirement of this project is that the normal Creality CFS RFID path must continue to work exactly as before when the diagnostic API is not being used.

This requirement is stricter than simply "the firmware still boots".

## Invariants

Every candidate firmware must preserve all of the following.

### 1. Exact source identity

The patcher must accept only the expected source image:

```text
cfs0_050_G32-cfs0_000_153.bin
SHA-256 5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
```

Any other source image must be rejected.

### 2. Minimal modification of stock image

For the current architecture, the only modified bytes inside the original firmware image are the four dispatcher bytes at:

```text
file offset 0xC3A0..0xC3A3
```

The diagnostic handler is appended after the original image.

The static validator checks that no other original byte changes.

### 3. Preserve stock dispatcher behavior

The hook must preserve the original control-flow targets:

```text
opcode 0x51  -> original stock 0x51 path
opcode 0x57  -> diagnostic handler
other values -> original invalid/fallback path
diagnostic completion -> original common tail
```

Current validated stock targets:

```text
0x0801C704
0x0801C7F8
0x0801C808
```

A future build must fail validation if these targets unexpectedly change.

### 4. No background behavior

The extension must not:

- create a new RFID polling task;
- change stock RFID polling intervals;
- modify timer configuration;
- modify interrupt vectors;
- replace the normal tag parser;
- change the stock cache format;
- alter the existing proprietary tag read flow;
- automatically start an RF transaction.

The diagnostic path executes only when application opcode `0x57` is explicitly received.

### 5. Read-only internal call allowlist

Current diagnostic firmware is allowed to call only:

```text
RF mode / cleanup
reader probe / select
MIFARE Key-A authentication
0x30 read
CFS response builder
```

Known write-side functions must not be reachable from the diagnostic handler.

### 6. Passive-first testing

The first hardware-validation sequence must use only:

```text
INFO
CACHED_TAG_INFO
```

before any active RFID command is enabled.

The v2 host tool therefore requires:

```text
--allow-active-rf
```

for commands that initiate RF activity.

This is an operator-side safety gate. It does not replace firmware-side synchronization.

## Concurrency risk

Static analysis has not yet demonstrated a dedicated mutex around the low-level FM17622 reader primitives.

The stock application contains a higher-level RFID path and internal state handling, but the current diagnostic handler calls the recovered reader primitive directly in order to observe tags independently from the proprietary spool parser.

Therefore the following remains an explicit hardware-validation risk:

> an active diagnostic RF transaction could collide with normal stock CFS polling if both operate on the same reader at the same time.

Until synchronization is proven, active diagnostic commands should only be issued during controlled tests while normal CFS activity is idle.

## Hardware regression checklist

Before testing any third-party RFID tag, validate a known-good Creality tag.

For each normal CFS slot under test:

1. boot the modified firmware;
2. confirm CFS reports normal/idle state;
3. insert a known-good Creality RFID spool;
4. confirm the stock printer UI recognizes it exactly as before;
5. remove and reinsert it several times;
6. verify normal unload/reload behavior;
7. reboot the printer and repeat;
8. call passive `INFO`;
9. call passive `CACHED_TAG_INFO`;
10. verify the stock Creality tag is still recognized after those diagnostic calls.

Only after these tests pass should active diagnostic `POLL` or memory reads be attempted.

## Acceptance criterion

A diagnostic firmware candidate is not considered hardware-safe merely because diagnostic commands work.

It must satisfy both:

```text
diagnostic functionality works
AND
stock Creality RFID behavior remains unchanged
```

Any regression in normal proprietary tag reading blocks further testing and requires rollback to the original CFS image.
