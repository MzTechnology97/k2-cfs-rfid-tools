# CFS v3.21 — busy-guard forensic findings and safe design

**Status: investigation and tests only. No v3.21 firmware BIN is built, flashed, or approved for release.** The printer stays on the proven-to-boot experimental v3.20 image (API2, `0xB7`), with all runtime values restored to stock after prior experiments. The v3.13 image remains the rollback.

## Confirmed physical reproduction, 2026-10-10

The v3.20 SET and RESET assembly at `op_config_v2_set` / `op_config_v2_reset` checks:

```armasm
ldr  r0, state_base     @ STOCK_STATE = 0x200001F0
ldrb r0, [r0, #2]      @ STOCK_STATE.active_slot_raw
cmp  r0, #4
blo  status_busy       @ BUG: RFID slot is not physical CFS motor activity
```

The actual CFS returned the following **read-only** results using `BOX_RFID_DIAG_STATE` and the Klipper box status:

| Observation | RFID state raw | Active RFID slot byte | Box state | Filament loaded | Head sensor |
| --- | --- | --- | --- | --- | --- |
| Before loading | `40000400` | 4 | IDLE | -1 | clear |
| After `BOX_LOAD SLOT=1` | `40000100` | 1 | PRINT | 1 | triggered |
| After successful `BOX_UNLOAD MANUAL=1` | `40000100` | 1 | **IDLE** | **-1** | **clear** |

The value 1 is a **retained RFID slot identity**, not proof that a motor is still running. This explains repeated `CONFIG_V2_SET/RESET rejected while stock CFS task is busy` failures after a successful unload.

The evidence was saved on the authorized CM5:
`/home/alfio/cfs-rfid-v320-timing-lab/V321_STOCK_STATE_FORENSICS.json`.
This file was not published in full because it is a local device capture.

## Do NOT attempt these shortcuts

- Do not remove the firmware's busy guard altogether.
- Do not overwrite the RFID worker's `active_slot_raw` with 4 to make SET work; it is shared Creality application state.
- Do not trust host `box.state=IDLE` alone: it is an asynchronously polled view, and serial/device activity can change between observation and writing.
- Do not treat `CMD_BOX_STATE (0x0A)` payload bytes as a documented motor-active variable without verifying their meaning for this exact MCU firmware.
- Do not enable auto-apply or bulk parameter writes during testing.
- Do not change motor speed/motion hooks merely to debug the guard.

## Proposed fix with independent safety predicates

### Host preflight (defence in depth)

A manual SET or RESET should only be dispatched when a *fresh* CFS state sample proves all of:

1. `box.state == IDLE`, no current `box.operation.active`;
2. no physical slot loaded, and the printhead sensor reports clear;
3. no active CFS RFID transaction (must come from a real task/transport lock, **not** the retained RFID slot byte);
4. no sensor/status communication errors.

The included `tests/test_host_idle_predicate.py` is a **pure model** of these conditions with fail-closed negative cases. It intentionally does not send requests, change settings, or validate the MCU guard.

### Mandatory independent MCU check

Before any v3.21 firmware SET/RESET implementation can be flashed, identify the **actual** physical CFS task/motor activity flag or stock routine in the `cfs0_000_153` application. The wire `CMD_BOX_STATE=0x0A` reports useful information, but a reliable internal MCU flag/source and any races must first be confirmed. A correct firmware guard rejects writes during active load, unload, RFID work, a hardware fault, an unknown state, and controller transition. It must permit writes only after a fully completed idle transition without disturbing existing RFID data.

If an authoritative MCU-side flag cannot be identified, keep SET/RESET fail-closed. Do **not** ship a 'fix' based only on a host-provided idle bit or on an unverified RAM address.

## Regression acceptance before declaring v3.21 ready

- Static and ARM emulator tests verify unchanged v3.20 timing hooks 7/8, image integrity, ROM footprint and RFID wrappers.
- A matrix of snapshots covers initial idle, fully unloaded idle with retained RFID slot 1, active feed, active unload, loaded/print state, active RFID operation, unexpected/invalid state, restart and stale data.
- On real hardware, SET/GET/RESET is rejected while CFS is moving and succeeds **immediately** after confirmed unload without a rail power-cycle.
- Re-run at least three repeated PLA cycles per configuration (default, ID7 changed, ID8 changed), each followed by successful parameter reset, independently timestamping motor/encoder and head sensor if telemetry supports it.
- Only then merge the firmware and installer changes and publish the paired Kalico guard. Retain the v3.13 rollback and require explicit interactive flashing.

## Current blocking issue

[Issue #7: confirmed RFID active-slot / motor-busy conflation](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/7). The v3.20 firmware and installer PRs remain experimental and **must not be merged as production-safe** on the basis of GET/SET/RAM tests alone.
