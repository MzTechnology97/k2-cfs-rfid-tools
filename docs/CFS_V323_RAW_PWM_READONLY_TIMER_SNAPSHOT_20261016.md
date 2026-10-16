# CFS v3.23 raw PWM output-enable diagnostic — firmware-only draft

*16 October 2026 · source-only preview stacked on draft #45.*

## Why this feature is useful

Previous reverse engineering confirmed that the original CFS
`BOX_STATE == IDLE` can coexist with live feeder or hub motion.
Our current experimental `0x57/0x12` CONFIG SET and `0x57/0x13`
RESET paths therefore **must remain disabled** until an MCU-side
motor start/stop + RT-Thread/ISR-safe interlock is proven.

The original Creality 5 PWM devices can be identified from the
physical GD32F303 APP ROM and TIMER register map:

| Original motor PWM | Timer output | Output-enable register / bit |
| --- | --- | --- |
| `pwm1` hub PE13 | TIMER0 CH2 | `0x40012C20` / `0x0100` |
| `pwm3` feeder PD12 | TIMER3 CH0 | `0x40000820` / `0x0001` |
| `pwm4` feeder PD13 | TIMER3 CH1 | `0x40000820` / `0x0010` |
| `pwm5` feeder PD15 | TIMER3 CH3 | `0x40000820` / `0x1000` |
| `pwm8` feeder PD14 | TIMER3 CH2 | `0x40000820` / `0x0100` |

These register identities are independently source-grounded by
`cfs_pwm_timer_channel_register_provenance.py` and
`cfs_motor_multisignal_observation_plan.py` against the exact
SHA-pinned OEM v3.13/v3.22 ROM.

## Firmware extension: strictly read-only RS485 command

The new in-memory firmware source construction
`firmware/v3.22-readonly-state-probes/cfs_v323_raw_pwm_output_snapshot_candidate.py`
adds one **experimental, nonstandard** extension:

`0x57 / 0x16` — **raw PWM output-enable snapshot**

Request: normal CFS `0x57` envelope, `subcmd=0x16`, exact
submessage length **4**. Success: original manufacturer response
with status `0` and 8-byte data payload:

- bytes `0..3`: raw 32-bit little-endian `TIMER0_CHCTL2`,
- bytes `4..7`: raw 32-bit little-endian `TIMER3_CHCTL2`.

Malformed request or unsupported command returns the original
bad-request status **1** with empty payload.

The code uses the existing 8-byte stack area of the original
`0x57` handler, performs exactly **two 32-bit MMIO reads**,
and uses the original response sender. It does not touch
PWM compare values, motor direction, duty, firmware flags or
peripheral control registers. No timer write, RFID action,
motor action, RAM parameter change or new host feature
negotiation is added.

The earlier read-only `0x57/0x15` BOX_STATE snapshot and
`0x57/0x10` INFO, `0x57/0x11` GET are preserved.
SET `0x57/0x12` and RESET `0x57/0x13` remain
**unconditionally blocked** at MCU code entry, returning
`STOCK_BUSY=7`, exactly as in #45.

The opcode `0x16` is experimental: production clients should
not send it until the new firmware identity/capability is
separately negotiated and real hardware tests have qualified
the expected raw-register semantics.

## Offline full firmware build and regressions

The builder uses source-pinned original APP v3.13 plus the exact
saved v3.22 and reconstructs all previous v3.23 work: read-only
snapshot, type4 live usage, Creality manufacturer-tag initialization,
two FM15L013 secure guards, spool removal and #45's **read-only
configuration fence**.

It physically relinks the complete handler at `0x0802DE38`
from APP base `0x08003000`, verifies all **18 existing OEM
incoming hooks** and **21 OEM outward calls**, original
manufacturer prefix integrity, heap pointer and header
CRC16. No BIN/HEX/ELF image is persisted.

- Previous #45 preview APP: **178,416 bytes**.
- New diagnostic preview APP: **178,464 bytes** (**+48**).
- Exclusive end `0x0802E920`, still Flash page **93**,
  well below archived loader parameter region `0x0807F800`.
- CRC16 `0x3779`, transient SHA-256
  `4b3319a5c83ed451b30040ccccea116ee97875134c81b4bd9f59b0da376fe293`.
  These identify the **in-memory experimental build only**.

ARM Unicorn tests exercise actual new Thumb code, map only
the two known TIMER MMIO pages and assert *exactly two
4-byte MMIO reads* and **zero nonstack writes**:

- **13 command scenarios:** all zero, each of five outputs
  enabled separately, all enabled, arbitrary high bits,
  malformed short/long requests, prior `0x15` and
  unimplemented `0x14/0x17`.
- **14 manufacturer CONFIG regressions:** 12 SET/RESET cases
  across every BOX_STATE 0..5, plus working INFO and GET.
- OEM heap boot wrapper is re-executed and proves reset of
  volatile sidecar magic + active mask.
- **3 negative mutations:** replacing either timer source
  address with the other, or invalidating the request-length
  opcode, is rejected by the raw-IO emulation.

## What the 8 bytes DO NOT prove

- An output-enable bit tells us that a PWM hardware **output is
  configured/enabled**, not the actual duty, rotor rotation,
  load, motor-current, braking state or torque.
- An enabled output can have zero duty; a non-enabled PWM output
  does **not** exclude another GPIO-driven motor path.
- Absence of PE11 hub FG pulses does not prove the hub stopped;
  the FG line is not a sensor for all four feeders.
- Reading TIMER0 and TIMER3 sequentially does not provide an
  RTOS-atomic, power-domain-verified multi-motor snapshot.
- `BOX_STATE=IDLE`, missing FG pulses and all five output
  bits disabled are **still insufficient to authorize SET
  or RESET**.

Only genuine MCU motor-start/task/interrupt synchronization,
independent hardware evidence and real controlled testing can
qualify writable runtime profiles.

## User constraints and next steps

- **Do not modify Kalico now**: the existing CM5
  `klippy/extras/box_cfs_runtime.py` already supports
  Runtime Config API v2; its `0xD7` bench-gating keeps
  configured `auto_apply` from writing to the old firmware.
- Preserve Kalico/config untouched until the MCU firmware
  candidate is ready for physical test.
- Continue mapping motor start/stop and timer command
  lifecycles, then implement a fail-closed atomic exclusion
  gate. Only then qualify individual RAM speed/timeout/buffer
  parameters; most IDs 9..27 remain storage-only.
- Historical RS485 loader/recovery is documented, but
  installed-loader identity, true concurrent motor interlock
  and interrupted upgrade have not been hardware-tested.

**Status:** source-only, not a flash-approved candidate;
no MCU, motor, SWD, RS485, Klipper/Kalico or firmware file
has been modified.
