# CFS v3.21 — busy-guard forensic findings and safe design

**Status: v3.21 flashed and physically tested (2026-10-10), but NOT approved for production release.** The reference printer is now running API2/28 with feature `0x97`, with all parameters at stock values; v3.13 remains the known-good rollback.

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

The original Creality `CMD_BOX_STATE=0x0A` response routine at `0x0801BD26` obtains its state from the structure at `0x200037D0`: instruction `0x0801BD7A` loads byte `[r5,#2]` and `0x0801BD7C` stores it in response payload byte 3. The **CFS operation state is therefore `0x200037D2`**, independently of RFID `STOCK_STATE` at `0x200001F2`. Stock enum: `0=IDLE`, `1=PRELOAD`, `2=PRINT`, `3=RELOAD`, `4=ERROR`, `5=TEST`. Unknown states fail closed. The new v3.21 SET/RESET guard reads this actual source and requires exactly `0`. The host adds a fail-closed empty-CFS, clear-sensor, standby and RFID-lock preflight. The state guard is verified in real hardware for permitting idle SET/RESET after unloading, but remains **unproven as an independent guard against motor activity**: the CFS can report `BOX_STATE=IDLE` during an early active `feeding_to_buffer` stage, while Kalico `box.operation.active=true`. Kalico rejected the attempted SET during that stage. This race must be addressed before release. A correct firmware guard rejects writes during active load, unload, RFID work, a hardware fault, an unknown state, and controller transition. It must permit writes only after a fully completed idle transition without disturbing existing RFID data.

If an authoritative MCU-side flag cannot be identified, keep SET/RESET fail-closed. Do **not** ship a 'fix' based only on a host-provided idle bit or on an unverified RAM address.

## Regression acceptance before declaring v3.21 ready

- Static and ARM emulator tests verify unchanged v3.20 timing hooks 7/8, image integrity, ROM footprint and RFID wrappers.
- A matrix of snapshots covers initial idle, fully unloaded idle with retained RFID slot 1, active feed, active unload, loaded/print state, active RFID operation, unexpected/invalid state, restart and stale data.
- On real hardware, SET/GET/RESET is rejected while CFS is moving and succeeds **immediately** after confirmed unload without a rail power-cycle.
- Re-run at least three repeated PLA cycles per configuration (default, ID7 changed, ID8 changed), each followed by successful parameter reset, independently timestamping motor/encoder and head sensor if telemetry supports it.
- Only then merge the firmware and installer changes and publish the paired Kalico guard. Retain the v3.13 rollback and require explicit interactive flashing.

## Current blocking issue

[Issue #7: confirmed RFID active-slot / motor-busy conflation](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/7). The v3.20 firmware and installer PRs remain experimental and **must not be merged as production-safe** on the basis of GET/SET/RAM tests alone.

## Local v3.21 candidate built and checked — 2026-10-10

The draft branch contains `handler-v3_21.S`, `build-v3_21.py`, `bench_preflight_v3_21.py`, `emulate_v3_21.py`, and reproducible static and ARM evidence. The BIN is staged and running on the reference CFS; publication as a production release is deferred until its independent MCU movement safety is verified.

- Target: `cfs0_050_G32 / cfs0_000_153`; v2 catalogue=28, experimental feature marker `0x97`.
- SHA-256 of built BIN: `4a918febbee1e411ae736acb7fd79eb718e3401a641ee947008bbecf1e6c0b19`; 178100 bytes; container CRC16 `0xC0DE`? **Use the authoritative static validation JSON and Creality validator**, not this illustrative CRC text.
- Actual CRC-16 from the verified container: decimal `49374` (`0xC0DE`).
- ROM end `0x0803B7B4`, 76 bytes before the **inferred, unproven** `0x0803B800` footprint boundary.
- ARM emulation PASS: all 28 GET, 21 advanced individual SET/GET/RESET, 42 rejected out-of-range writes, stock ID protection, immutable GET, retained RFID slot `1` with CFS `IDLE=0` accepts SET/RESET; states `1..6` and `0xFF` reject both SET and RESET with no sidecar writes; unchanged execution of both timing hook callsites.
- Kalico host-safety mock PASS: write lock, standby/idle/empty box, head sensor clear, active RFID/read rejection and unknown-state fail-closed.
- The CM5 installer manifest includes this exact SHA, with v3.20 and v3.13 available as rollbacks. The reference printer was subsequently flashed to v3.21 (`0x97`) and passed 28/28 GET and physical load/unload tests.
- **Historical flash blocker, resolved by operator:** `sudo -n true` previously hung on CM5. The operator later flashed v3.21 manually using the installed updater. First-boot hardware checks confirmed feature `0x97`.

Rebuild using the exact already patched v3.13 BIN in the sibling `../v3.19-volatile-ram/` folder, then `python3 bench_preflight_v3_21.py` and `python3 build-v3_21.py --base ../v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin --out /tmp/v321-rebuilt.bin`. Run `python3 emulate_v3_21.py` with optional Unicorn installed, after placing the rebuilt firmware under the emulator's expected output filename.

**Release gate remains closed:** post-unload SET/RESET now passes on actual hardware without any MCU reset. An active-load SET was rejected by Kalico before the movement finished. However, `BOX_STATE=IDLE` was observed while `box.operation.active=true` during `feeding_to_buffer`; the independent MCU guard cannot yet be relied upon to reject every unsafe motor-active state. The unload-time probe was queued until after the movement and cannot substantiate the unload-time guard. Strengthen/verify the MCU physical-activity predicate before merging.

## Real hardware v3.21 — 2026-10-10

The exact detailed [hardware validation report](hardware-validation-2026-10-10.json) records all tests and remaining safety caveats:

- **PASS:** first boot API v2, signature `0x97`, 28/28 default GET, CFS `IDLE`, printer `ready/standby`, no runtime error.
- **PASS:** pre-motion ID7 `3200 → 3220 → 3200` and ID8 `700 → 720 → 700`; protected stock ID write, out-of-range value and APPLY rejected.
- **PASS:** slot-1 PLA load (11.529 s) and heater-free unload (14.536 s); printhead sensor tracked arrival/removal, path cleared.
- **PASS — main v3.20 regression fixed:** after unloading, the retained stock RFID slot still reports `active_slot_raw=1` while CFS is `IDLE`; both ID7 and ID8 SET/GET/RESET work **immediately** without rebooting the MCU.
- **PASS:** during an active `feeding_to_buffer` stage, a harmless ID18 SET was rejected by the v3.21 Kalico host preflight **before loading finished**. A similar probe sent during unloading was processed **after** unloading, when the CFS was safely IDLE; it was accepted then reset, so this does not validate rejection during unloading.
- **PASS:** after **two** real load/unload cycles, **all 21** advanced IDs (7–27) accepted individual SET/GET/RESET; every override was cleared, all 28 baseline values unchanged, no MCU power cycle.
- **IMPORTANT safety limitation:** during the active feeding stage, Kalico exposed `box.operation.active=true` but `box.state=IDLE`. The existing MCU candidate only checks the stock BOX_STATE byte `0` and thus is **not proven to independently protect writes during all motor-active stages**. Host safety blocked the attempted SET. Do not disable or bypass host protections, do not enable auto-apply, and do not merge the experimental release until the independent guard is adequately verified or strengthened.

Final reference-printer state: Klipper `ready/standby`, CFS `IDLE`, loaded slot `-1`, head sensor clear, feature `0x97`, no error, ID7 `3200`, ID8 `700`, ID18 `400`, heater targets `0`.
