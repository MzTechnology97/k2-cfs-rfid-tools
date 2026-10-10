# CFS v3.22 — read-only internal-state probes

**EXPERIMENTAL · HARDWARE BOOT/READ-ONLY/LOAD/UNLOAD VALIDATED · NOT A FIX FOR THE INDEPENDENT MCU MOTION GUARD**

This branch adds four read-only diagnostic IDs to the existing CFS v3.21 code. It does not change physical motor control, the two v3.20 timing hooks or the firmware's existing SET/RESET guard. The reference CFS was subsequently flashed with v3.22 `0xD7`, and normal communications and physical operations were validated on 2026-10-10.

Target: `cfs0_050_G32`, application `cfs0_000_153`. The normal CONFIG API is still v2 with **28 configurable parameters**; v3.22 identifies itself through a unique feature byte **`0xD7`**. The paired Kalico host requires this exact signature to read the four diagnostic IDs.

## Experimental diagnostic reads

| Read-only GET ID | RAM address | Data |
|---|---|---|
| 28 | `0x2000057E` | Two bytes of a candidate workflow/motor structure |
| 29 | `0x20000580` | Next two bytes of the same structure |
| 30 | `0x20003904` | Two bytes of a shared stock-task structure |
| 31 | `0x20003906` | Next two bytes of that structure |

The firmware returns their raw little-endian 16-bit values. **These bytes have not been proven to indicate motor activity or the absence of movement.** Their meaning must be established by correlating snapshots with physical CFS phases, sensor changes, idle periods and error recovery. Do not apply any of these values as a SET/RESET permission test. The new IDs cannot be SET or RESET, GET ID32 is rejected, and generic RAM reads are not implemented.

The existing `BOX_STATE` code reports an operating mode which can still be `IDLE` during early `feeding_to_buffer`. The remembered RFID slot also remains non-empty after unloading, and a separate status byte is cleared by a status query. None of these alone is an independently reliable motor-busy flag. Host-side movement/write exclusion remains **mandatory**.

## Offline verification (10 October 2026)

- Static preflight: passed.
- ARM ISA simulation: 28 original defaults, 21 SET/GET/RESET, 42 bounds rejections, two unchanged timing hook callsites, and four additional diagnostic GETs with exact injected RAM values: passed.
- Emulated GET 28–31 writes nothing outside normal reply/stack scratch; emulated SET/RESET of 28–31 are refused. GET32 is refused.
- Host-side mock: signature gating, fixed set of four GETs, no write operations, shared RFID lock correctly released even on error: passed.
- Rebuild of the flash image from these staged sources matched the laboratory BIN **byte for byte**.
- **Image: 178,140 bytes; SHA-256 `40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`; CRC16 `0xC36F`.**
- Image end `0x0803B7DC`, only **36 bytes below the inferred `0x0803B800` footprint boundary**. This boundary remains a hypothesis, not a verified safety limit.

## Reproduce

Requires Python 3, `arm-none-eabi-gcc`, GNU binutils and the exact existing patched v3.13 baseline BIN available under `../v3.19-volatile-ram/`. Unicorn (`pip install unicorn`) is needed for the optional ARM emulation.

```bash
python3 bench_preflight_v3_22.py
python3 build-v3_22.py \
  --base ../v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin \
  --out CFS-v3_22-PROBE-EXPERIMENTAL-UNFLASHED.bin
sha256sum CFS-v3_22-PROBE-EXPERIMENTAL-UNFLASHED.bin
python3 emulate_v3_22.py
```

**During the offline design and build stage no flash, reset, motion or heating was performed.** Subsequently the operator flashed v3.22 and a heater-free physical load/unload test completed successfully. Any future on-device validation must verify the exact image SHA, installer identity checks, Kalico feature handling, rollback and serial stability before physically correlating candidate bytes with movement. Even successful correlation does not automatically establish an atomic MCU motor-activity interlock.

Tracking issue: [independent motor-activity guard #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9).
## 2026-10-10 on-device validation and G-code sampling limitation

After the operator flashed v3.22, initial Klipper startup displayed `NO_RESPONSE` / timeouts. Klipper had been stopped by the updater; starting it and one controlled MCU-rail cycle did not immediately clear the condition. Later the CFS **recovered normal RS485 communications** (exact recovery mechanism not determined). A manual `BOX_CFS_CONFIG_INFO` showed API2/28 with expected feature **`0xD7`** and no runtime error. This supersedes the initial suspected flash failure; there is **no confirmed flash corruption**.

- Eight CFS `IDLE` diagnostic snapshots stable: `motor_candidate=0000:0000`, `task_candidate=0001:0000`.
- Bambu PLA Basic slot1 physical load **11.435 s**, unload **14.681 s**, both without heater commands, status/sensor checks passed.
- Final device state: Klipper `ready/standby`, CFS `IDLE`, loaded slot `-1`, head sensor false, feature `0xD7`, 28 normal values, ID7=3200, ID8=700, targets 0, runtime error null.
- **Sampling caveat:** calls to `BOX_CFS_CONFIG_SNAPSHOT` dispatched at ~0.65s during load/unload were queued by Klipper/Moonraker until the operations completed. They took **10.545 s** and **13.797 s**, respectively, and returned just *after* the movement finished. Their values are therefore **POST-motion samples only**; they cannot establish an independent MCU motor-active predicate.
- Firmware still has the original v3.21 `BOX_STATE`-based write guard, which was already shown to be insufficient alone during early `feeding_to_buffer`. Keep Kalico's motion/write interlock enabled, auto-apply off, and issue #9 open until an independently timestamped MCU-side activity flag is validated.

Evidence is stored locally on the CM5 as `~/cfs-rfid-v322-readonly-probe-lab/V322_IDLE_BASELINE_HARDWARE.json` and `V322_PHYSICAL_SNAPSHOT_20261010.json`. These device snapshots were not published in full. An event-driven read-only MCU/serial trace is needed to observe candidate bytes *during* movement; another G-code-queued request will not provide valid in-motion data.
