# Stock RFID manager state and diagnostic guard

This document records the stock CFS RFID state that is used by the v2.1 diagnostic candidate to avoid starting an active diagnostic RF transaction while the normal Creality RFID manager is already processing a slot.

## Why this matters

The low-level FM17622 access routines are GPIO-driven / bit-banged and do not contain an internal mutex.

The relevant lower layer is:

```text
0x08018C20  GPIO/data-line helper
0x08018C2E  GPIO/data-line helper
0x08018C3C  bus start
0x08018C74  bus stop
0x08018CAE  byte write
0x08018D48  byte read
0x08018DD4  FM17622 register write
0x08018E3A  FM17622 register read
```

Static analysis did not identify a lock around these primitives.

Also, the delay helper used by the RFID implementation is an RT-Thread sleep/delay path and expects the scheduler to remain enabled. For that reason, globally disabling scheduling around a complete RFID transaction was rejected as an unsafe synchronization strategy.

## Shared stock RFID state

Multiple stock functions reference the same RAM state object:

```text
base: 0x200001F0
```

The same base is materialized through several literal aliases in the firmware.

### Byte 0

Address:

```text
0x200001F0
```

Observed use:

- read at `0x0801A3AC`;
- written at `0x0801A3C2`;
- set to `0x40` at `0x080195D2` after a successful low-level reader probe.

This byte is used as an authenticated-sector/block cache/invalidation value by the recovered MIFARE helper.

It is **not** used as the v2.1 busy indicator.

### Byte 1

Address:

```text
0x200001F1
```

It is read by `0x0801A7F8` as a stock state/gate byte.

Its exact semantic meaning is not yet considered fully established.

### Byte 2 — active stock RFID slot

Address:

```text
0x200001F2
```

This byte has strong static evidence for representing the slot currently managed by the stock RFID manager.

#### Stock operation start

Manual Thumb disassembly of the region that Ghidra did not recover correctly shows:

```text
0x0801AA0C  ldr   r0, [...]
0x0801AA0E  strb  r5, [r0, #2]
```

At this point:

```text
r5 = requested logical slot
0 <= r5 < 4
r0 = 0x200001F0
```

Therefore the stock manager writes the selected logical slot to:

```text
0x200001F2
```

#### Stock manager task

The manager task reads the same byte:

```text
0x0801AC98  load state base 0x200001F0
0x0801ACA6  ldrb active_slot, [state, #2]
0x0801ACAA  cmp active_slot, #4
0x0801ACAC  branch if active_slot >= 4
```

So the stock task itself treats values outside the four logical slots as "nothing to process".

#### Completion / reset

The stock completion path writes:

```text
0x0801A9AE  load state base
0x0801A9B0  movs r0, #4
0x0801A9B2  strb r0, [state, #2]
```

This establishes the working interpretation:

```text
0..3  stock RFID slot active / managed
>=4   no stock RFID slot currently managed
```

Confidence: **high static**.

## v2.1 guard

The v2.1 diagnostic handler does not modify the stock manager.

Before any diagnostic command that starts RF activity, it checks:

```text
active_slot = *(uint8_t *)0x200001F2

if active_slot < 4:
    return STATUS_STOCK_RFID_BUSY
```

Status:

```text
7  stock RFID busy
```

The guarded operations are:

```text
POLL
READ_BLOCK / READ_PAGE
READ_BLOCK_AUTH_A
host-side range/dump operations built from those commands
```

Passive operations remain available:

```text
INFO
CACHED_TAG_INFO
STOCK_STATE
```

## Passive STOCK_STATE command

API v2.1 adds subcommand:

```text
0x05 STOCK_STATE
```

It returns the first four bytes beginning at:

```text
0x200001F0
```

The host tool interprets byte 2 as:

```text
0..3  busy, active slot = value
>=4   idle according to the stock manager rule
```

This command does not start a new RF transaction.

It is intended for the first hardware validation so the state transition can be observed while inserting/removing a normal Creality RFID spool before any active diagnostic command is permitted.

## Binary validation

The dedicated v2.1 validator independently checks the appended handler for:

- exactly two materializations of RAM address `0x200001F0`;
- one active-slot guard signature containing:
  - read `[state + 2]`;
  - compare against `4`;
  - branch to the busy status path;
- one passive stock-state export path;
- unchanged external-call allowlist;
- unchanged stock dispatcher targets;
- absence of known write targets;
- exactly four modified bytes inside the original stock image.

Current locally generated v2.1 candidate:

```text
size:    176300 bytes
SHA-256: 3cf3385dcbc56960c9fe3adcaff516a7d66a0f8ad2b43b5d47d40c341824549c
```

Status:

```text
static validator: PASS
v2.1 tests:      7/7 PASS
hardware flash:  NOT PERFORMED
hardware tests:  NOT PERFORMED
```

## Important limitation: this is not an atomic mutex

The v2.1 check prevents a diagnostic transaction from starting when the stock manager is **already** active.

It does not create a shared atomic mutex with the unmodified stock firmware.

A theoretical race remains:

```text
1. diagnostic sees active_slot >= 4
2. stock firmware starts a new RFID operation
3. diagnostic starts its RF operation
```

The window is expected to be small during a controlled idle test, but it exists.

For this reason v2.1 should currently be used as follows:

1. printer/CFS mechanically idle;
2. verify `STOCK_STATE` repeatedly;
3. verify a normal Creality tag with the stock UI;
4. only then explicitly enable active diagnostic RF commands.

The host utility retains the separate `--allow-active-rf` operator gate.

## Non-interference principle

The guard is intentionally implemented only in the appended diagnostic handler.

The following stock components are not patched:

- stock RFID manager task;
- stock Creality tag parser;
- stock FM15L013/security path;
- stock FM17622 routines;
- stock timers;
- stock polling cadence;
- interrupt vectors.

When opcode `0x57` is not used, the diagnostic extension has no active behavior.

A future production-grade concurrency solution must be evaluated separately and must not weaken this property.
