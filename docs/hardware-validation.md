# v2.1 hardware validation and rollback runbook

This runbook defines the first controlled hardware validation of the read-only CFS RFID diagnostic extension.

It is intentionally conservative: **normal Creality RFID behavior is the primary acceptance gate**. Third-party testing begins only after the stock proprietary workflow has been shown to continue working normally.

> This document does not authorize a flash by itself. No flash is performed by CI or by the repository tooling.

## Target

Exact stock image:

```text
hardware family : cfs0_050_G32
application     : cfs0_000_153
filename        : cfs0_050_G32-cfs0_000_153.bin
size            : 175672 bytes
SHA-256         : 5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
```

Current v2.1 candidate generated locally:

```text
filename        : cfs0_050_G32-cfs0_000_153-rfid-diag-ro-v2_1.bin
size            : 176300 bytes
SHA-256         : 3cf3385dcbc56960c9fe3adcaff516a7d66a0f8ad2b43b5d47d40c341824549c
protocol API    : 3
candidate rev   : 2.1
```

The vendor image and generated candidate are intentionally not committed to this repository.

## v2.1 safety properties

The candidate has been statically validated to preserve the following:

```text
stock bytes changed        only 0xC3A0..0xC3A3
stock dispatcher targets   preserved
known RFID write calls     absent from diagnostic handler
background RFID task       none added
raw transceive             not implemented
tag writes                 not exposed
UID mutation               not exposed
key writes                 not exposed
```

The appended handler uses only the existing read-side stock primitives.

### Stock manager guard

Recovered stock RAM state:

```text
state base       0x200001F0
active-slot byte 0x200001F2
```

Interpretation established by static analysis:

```text
0..3  stock RFID manager is handling that logical slot
>=4   no stock RFID slot is currently managed
```

Before active diagnostic RF operations, v2.1 checks this byte.

If the stock manager is already active, the request returns:

```text
status 7 = stock RFID busy
```

Passive commands remain usable:

```text
INFO
CACHED_TAG_INFO
STOCK_STATE
```

This is a guard, not a shared atomic mutex. A narrow theoretical race remains if the stock manager begins a new transaction immediately after the check.

For that reason active diagnostics are initially restricted to controlled idle testing.

## Stock updater/recovery evidence

The recovered stock CFS OTA path uses the normal Creality RS-485 updater and the stock MCU power-cycle sequence.

Static analysis of two K2 Pro host generations recovered the same high-level CFS sequence:

```text
stop Klipper
power-cycle stock MCU rail
run CFS mcu_update
read updater-discovered identities
perform stock A1/A0 address management
perform F0 update state machine
start application
```

The stock power-cycle helper uses GPIO 140 / PE12:

```text
1 = power off
sleep 2 s
0 = power on
```

The CFS application is linked at:

```text
0x08010000
```

which leaves the lower 64 KiB region outside the application image.

The stock RS-485 updater owns flash placement; the host does not transmit an arbitrary destination flash address.

However, interrupted-update recovery has **not** been proven to be guaranteed. Therefore rollback preparation is mandatory before any write.

## Pre-flash gate

Do not start a firmware write unless every item below is satisfied.

### Image verification

Verify the stock source:

```text
SHA-256 5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
```

Verify the candidate:

```text
SHA-256 3cf3385dcbc56960c9fe3adcaff516a7d66a0f8ad2b43b5d47d40c341824549c
```

Rebuild the candidate from the exact stock image and require byte-identical output.

Run:

```text
tools/validate_patch_153_v2_1.py
tests/test_rfid_diag_v2_1.py
```

Expected:

```text
validator: PASS
errors:    0
tests:     7/7 PASS
```

### Recovery image

Keep the original unmodified 153 image on persistent storage under a separate rollback path.

The rollback copy must be hash-verified independently.

Do not overwrite it with the diagnostic candidate.

### Live identity

Immediately before the write, obtain the live CFS identity using the stock updater discovery path.

Required acceptance:

```text
boot/hardware target = cfs0_050_G32
application target   = cfs0_000_153 or otherwise explicitly understood
```

Do not infer G32 solely from application version.

The normal application VERSION_SN path may expose the application revision without proving the boot/hardware token.

### Printer state

Before loader entry:

- printer idle;
- no print running or paused;
- heaters off;
- no filament movement;
- no CFS load/unload activity;
- no concurrent process owns the RS-485 transport;
- recovery stock image and candidate both present and verified.

## Rollback boundary

Rollback uses the same stock CFS loader/update mechanism with the exact original 153 image.

Rollback hash:

```text
5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
```

If the application fails but the CFS remains discoverable by the stock updater, re-run the stock update flow using the original image.

If the CFS is no longer discoverable through the stock loader/update path, stop experimentation.

Do not:

- erase the lower boot region manually;
- replace the bootloader;
- issue arbitrary flash-address writes;
- improvise a SWD recovery sequence as part of this test.

## Hardware validation sequence

### Stage 0 — stock firmware baseline

Before flashing the diagnostic candidate, capture normal behavior.

Use at least one known-good Creality RFID spool.

Record:

- CFS application version;
- stock material recognition;
- stock color recognition;
- slot number;
- load/unload behavior;
- reinsertion behavior;
- CFS inventory state;
- normal buffer/motor behavior.

Repeat insertion/removal enough times to establish a useful baseline.

If possible, perform the baseline on more than one logical slot.

## Stage 1 — candidate boot, no diagnostic opcode

After flashing v2.1, **do not send opcode 0x57 yet**.

Verify:

- CFS boots;
- normal RS-485 communication returns;
- stock inventory is present;
- motors/buffer/sensors work;
- no watchdog/reset loop occurs.

Then insert the same Creality spool used in Stage 0.

Required acceptance:

- same spool is recognized;
- correct material remains visible;
- correct color remains visible;
- load/unload still works;
- repeated remove/reinsert still works.

Any regression here means immediate rollback.

This stage is the most important compatibility gate in the entire project.

## Stage 2 — passive INFO

Send:

```text
0x57 / 0x00 INFO
```

Expected v2.1 data:

```text
03 02 02 7F FF 10
```

Meaning:

```text
API version        3
physical readers   2
slots per reader   2
capabilities       0x7F
max read index     0xFF
cache record size  0x10
```

This command does not initiate an RF transaction.

After INFO, verify the Creality spool still behaves normally.

## Stage 3 — passive STOCK_STATE

Send:

```text
0x57 / 0x05 STOCK_STATE
```

Observe byte 2.

Expected idle interpretation:

```text
active_slot_raw >= 4
stock_rfid_busy = false
```

While performing a normal stock Creality RFID action, capture the state repeatedly and verify that the byte can enter:

```text
0..3
```

for the corresponding logical slot.

This is the first live validation of the recovered busy-state semantics.

Do not run active diagnostic RF commands during this observation.

## Stage 4 — passive CACHED_TAG_INFO

With the known-good Creality spool present, retrieve cached records for the relevant reader/slot.

Record:

- raw 16-byte cache;
- ATQA;
- CL1;
- CL2;
- BCC;
- SAK;
- reconstructed UID.

Then verify the stock Creality material/color data still remains correct.

The cache command must not initiate a new reader transaction.

## Stage 5 — validate busy rejection

This is a controlled test of the v2.1 guard.

While `STOCK_STATE` reports byte 2 in the range `0..3`, issue one active diagnostic request.

Expected:

```text
status 7
stock RFID busy
no RF primitive invoked by diagnostic path
```

Do not retry aggressively.

The purpose is only to verify that the guard behaves as designed.

## Stage 6 — no-tag active POLL

Only when:

```text
printer mechanically idle
STOCK_STATE active_slot_raw >= 4
```

enable the host active-RF gate explicitly.

Then remove the tag and issue a single POLL.

Expected no-tag result is normally:

```text
status 2
```

or another clearly staged RF discovery failure if hardware behavior differs.

Afterward, verify normal Creality recognition again.

## Stage 7 — active POLL of a Creality tag

With the known-good Creality tag inserted and the stock manager observed idle, run a single active POLL.

Record:

- UID;
- ATQA;
- SAK;
- CL1/CL2;
- BCC validity;
- returned status.

Immediately verify that the normal stock parser still reports the same Creality spool material/color.

Do not proceed if any stock behavior changes.

## Stage 8 — Bambu Lab first third-party test

Bambu Lab is the first interoperability target.

Public reverse engineering indicates common Bambu spool tags are MIFARE Classic 1K with typical:

```text
ATQA 00 04
SAK  08
UID  4 bytes
```

The first goal is **not** full filament decoding.

It is only:

1. detect the tag;
2. obtain stable UID;
3. obtain ATQA;
4. obtain SAK;
5. confirm select/anticollision succeeds.

Test order:

```text
passive CACHED_TAG_INFO
STOCK_STATE idle check
single active POLL
compare repeated UID/ATQA/SAK
```

If the tag reports values compatible with Classic 1K, move to authenticated reading.

## Stage 9 — Bambu authentication

Bambu sector-key derivation stays on the host.

Use:

```text
python tools/bambu_keys.py <UID>
```

Do not embed Bambu-specific keys or derivation constants in the CFS firmware.

Start with one known data block, not a sector trailer.

Recommended first blocks:

```text
1
2
4
```

For the selected block:

1. derive the correct sector Key A;
2. ensure stock RFID state is idle;
3. issue one authenticated read;
4. record the returned 16 bytes;
5. compare with an independent NFC reader/dump if available.

No writes are performed.

## Stage 10 — Bambu read-only dump

Only after single-block authenticated reads are reliable.

For MIFARE Classic 1K:

```text
16 sectors
4 blocks per sector
64 blocks total
16 bytes per block
```

Dump rules:

- derive keys on host;
- authenticate sector-by-sector;
- read blocks only;
- label sector trailers separately;
- retain UID/ATQA/SAK with the dump;
- do not publish physical tag UID/keys by default;
- stop on repeated RF or stock-state anomalies.

## Stage 11 — QIDI

QIDI testing begins only after the Bambu path is understood.

Use the same vendor-neutral sequence:

```text
presence
-> UID / ATQA / SAK
-> classify from observed behavior
-> bounded read-only memory access
-> vendor decoding on host
```

Do not add QIDI-specific firmware behavior before measuring the physical tags.

## Stage 12 — repetition / regression

After third-party testing, repeat the original Creality tests.

Required:

- normal material recognition;
- normal color recognition;
- repeated removal/insertion;
- multiple slots where practical;
- load/unload;
- reboot;
- stock behavior after reboot.

The diagnostic extension is not considered successful unless the stock proprietary path remains normal after third-party tests.

## Stop conditions

Stop active testing and rollback if any of the following occurs:

- Creality tags stop being recognized;
- material/color becomes incorrect;
- CFS resets unexpectedly;
- repeated RS-485 communication errors appear;
- reader state remains stuck after a diagnostic call;
- STOCK_STATE behavior contradicts the recovered model;
- normal load/unload becomes unreliable;
- candidate hash does not match;
- live boot/hardware identity does not match the intended G32 target.

## Current confidence

Before hardware validation:

```text
exact-image patching              high
stock dispatcher preservation     high
read-only call boundary           high
active-slot state interpretation  high static
busy guard binary presence        validated offline
Creality runtime non-regression   not yet hardware-tested
Bambu runtime compatibility       not yet hardware-tested
QIDI runtime compatibility        not yet hardware-tested
atomic concurrency safety         not proven
```

The first hardware milestone is therefore:

> boot v2.1 and prove that normal Creality RFID behavior remains unchanged before performing any active third-party RFID operation.
