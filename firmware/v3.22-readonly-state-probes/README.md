# CFS v3.22 — read-only internal-state probes

**EXPERIMENTAL · NOT FLASHED · NOT A FIX FOR THE INDEPENDENT MCU MOTION GUARD**

This branch adds four read-only diagnostic IDs to the existing CFS v3.21 code. It does not change physical motor control, the two v3.20 timing hooks or the firmware's existing SET/RESET guard. The printer remains on v3.21 until a controlled diagnostic installation is explicitly validated.

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

**No flash, reset, motion or heating was performed while developing the diagnostic firmware.** Any future on-device validation must verify the exact image SHA, installer identity checks, Kalico feature handling, rollback and serial stability before physically correlating candidate bytes with movement. Even successful correlation does not automatically establish an atomic MCU motor-activity interlock.

Tracking issue: [independent motor-activity guard #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9).