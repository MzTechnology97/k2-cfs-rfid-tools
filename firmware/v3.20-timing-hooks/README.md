# CFS v3.20 — first timing hooks (experimental)

> **Experimental K2 Pro CFS firmware.** Not approved for routine filament loading or printing until motion tests pass. Retain v3.13 rollback.

Target: `cfs0_050_G32`, application `cfs0_000_153`.

- API v2, 28 GET/21 writable advanced IDs; feature signature **`0xB7`**.
- Only two stock immediate constants are hooked: **ID 7** `hub_transition_wait_ms` (3200 ms default, instruction at `0x08011116`) and **ID 8** `insert_sensor_timeout_ms` (700 ms default, instruction at `0x080112CA`).
- Other 19 advanced parameters remain writable in RAM but **not connected to motion**. Six stock speed IDs and ID 6 remain read-only in API v2. Stock RFID wrapper instructions remain unchanged from validated v3.19.
- No automatic SET/APPLY. Host Kalico must recognize feature mask `0xB7` and refuse auto-apply before this firmware is used.
- Volatile override storage: 64 bytes beginning at `0x20006EE8`; heap begins `0x20006F28` and the original heap initializer clears the sidecar header. The flash-footprint limit `0x0803B800` is *inferred, not definitively characterized*.

**Image:** `cfs0_050_G32-cfs0_000_153-runtime-config-v3_20-TIMING-ID7-ID8-EXPERIMENTAL.bin`

**SHA-256:** `ecc1718700792843a6fd4a93ec0806f1591c1dd8f187621d98fdb793ba343dac`

**Size:** 178096 bytes. Internal container CRC16: `0xD24C`.

## Validation 2026-10-10

- ARM simulation: 28 default GET, all 21 SET/GET/RESET, 42 out-of-range rejects, invalid memory fallback, busy-state rejection, plus exact execution of the two new patched `BL` callsites at both original defaults and overridden values. Non-output registers and APSR verified; BL necessarily updates LR, while the original stock callers save their return address.
- Physical MCU **PASS**: API `0xB7`, all 28 default GET values, Klipper ready/CFS IDLE/no errors after first boot.
- Physical MCU **PASS**: ID 7 3200→3220→3200, ID 8 700→720→700, with all 28 values restored and no motor movements.
- **NOT TESTED:** physical filament load/unload to demonstrate timing-hook execution under real workload, repeated rail power cycles with v3.20, any other advanced motion hooks, long-duration printing or alternative CFS hardware revisions.

## Rebuild and check

Requires `arm-none-eabi-gcc`, GNU binutils, Python 3 and the exact *already patched* v3.13 base binary stored in sibling `../v3.19-volatile-ram/`.

```sh
python3 bench_preflight_v3_20.py
python3 build-v3_20.py --base ../v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin --out /tmp/v3.20-rebuilt.bin
sha256sum /tmp/v3.20-rebuilt.bin
# expected: ecc1718700792843a6fd4a93ec0806f1591c1dd8f187621d98fdb793ba343dac

# For offline emulation, install Unicorn (pip install unicorn).
python3 emulate_v3_20.py
```

Use the [K2-OpenHost installer helper](https://github.com/MzTechnology97/k2-openhost-installer-helper) menu 40 for explicit local flash, retaining v3.13 rollback. Ensure CFS and printer idle before flashing. After loading the paired Kalico extra, first run the read-only `BOX_CFS_CONFIG_DIAG ALL=1` and verify signature `0xB7` / 28 GET; avoid load/unload until physical validation.
