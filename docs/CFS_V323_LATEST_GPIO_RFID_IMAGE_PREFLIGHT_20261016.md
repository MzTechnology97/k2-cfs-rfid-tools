# CFS v3.23 — latest combined GPIO/RFID APP preflight (offline)

*16 October 2026. Source-only follow-up to draft PR #53.*

## Why this is needed

The [earlier first-test preflight in draft PR #51](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/51)
was correct for its own **178,520-byte** v3.23 candidate, but it
does **not** authenticate the later **178,568-byte** firmware
assembled after the [GPIO output-latch diagnostic in PR #52](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/52)
and the OEM configuration-unit analysis in PR #53.

This independent preflight uses the exact saved manufacturer
v3.13 and installed/previously-tested v3.22 APP inputs,
then rebuilds **the entire latest combined firmware in RAM only**.
It does not copy any proprietary binary into GitHub and emits no
persistent firmware BIN, HEX or ELF. It does not modify Kalico,
the live CFS, GPIO, motors, RS485, loader or Flash.

## Exact current candidate

| Property | Source-checked result |
| --- | --- |
| Physical APP base | `0x08003000` |
| APP length | **178,568 bytes** |
| Exclusive APP end | `0x0802E988` |
| Stored and recomputed manufacturer CRC16 | `0xBA83` |
| SHA-256 | `946197ff853762815d5e5d9b3c0827469b0a916ec49491334a65552bf58773d1` |
| OEM initial MSP | `0x20006EE8`, unchanged |
| OEM reset vector | `0x0801A969`, unchanged |
| 2-KiB erase pages | **6–93** (88 pages) |
| 128-byte RS485 chunks | **1,396** |
| 256-byte internal write buffers | **698** |
| Padded final write end | `0x0802EA00` |
| Manufacturer loader pages | **0–5**, not covered |
| Reserved parameter page | **255**, starting `0x0807F800`, not covered |
| Known working fallback | Saved v3.22 APP, SHA-256 `40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7` |

Exact geometry does **not** constitute proof of installed-bootloader
identity, flashability, interrupted-update recovery or safe operation
on the user's only working CFS.

## Firmware safety / compatibility checks

The script
`firmware/v3.22-readonly-state-probes/cfs_v323_latest_image_preflight.py`
extends the older image-format inspection for the latest full
source-built GPIO candidate, including:

- Manufacturer original RFID reader and selection routines,
  remaining-clear, FM15L013 secure paths and OEM consumption writer
  checked against unchanged saved v3.22 instruction bytes.
- Existing custom `0x57/0x15` read-only BOX state,
  `0x57/0x16` raw PWM output-enable, `0x57/0x17`
  hub command duty/FG and **`0x57/0x18` raw GPIOD/GPIOE
  output latch** entries present in the rebuilt firmware.
- MCU CONFIG SET `0x57/0x12` and RESET `0x57/0x13`
  physically branch to `status_busy` without accessing
  runtime override data. Twelve actual ARM/Thumb Unicorn
  requests across all six BOX_STATE values confirm **status 7**,
  unchanged sidecar RAM and no nonstack writes.
- Hardware source literals for `GPIOD_OCTL 0x4001140C` and
  `GPIOE_OCTL 0x4001180C` are checked against the linked APP.
- Four execution tests of the **latest complete image** sample
  original ARM GPIO-latch diagnostics: all zeros, all feeder
  bits high, hub DIR/BRAKE latch high and malformed request.
  Only the expected MMIO reads occur and no nonstack writes.
- Twelve independently rejected mutation fixtures, including
  loader-image base/size, APP length, CRC, reset vector, stock
  manufacturer RFID reader, removed SET/RESET branch protection
  and swapped GPIO register source addresses.

## Release qualification remains separate

The GPIO latch and PWM enable registers are **MCU command/output
states, not external motor-stop feedback**. Four feeder drivers
are directly GPIOD-controlled in the original OEM firmware,
not proportional PWM devices. Motor RT-Thread/task/ISR race
exclusion, physical motor de-energization and safe RAM tuning
writes remain **unimplemented**.

The documented manufacturer RS485 bootloader can recover an APP
in principle without reflashing itself when the loader pages and
parameter region remain intact. Actual installed-loader identity,
a real rollback/power-cycle test and physical RFID/print tests
remain pending. The user has no spare CFS to risk.

The v3.23 candidate is **not flash-approved**; Kalico's existing
`box_cfs_runtime.py` is intentionally unchanged, and CONFIG
SET/RESET remain disabled until a genuine motor-safe interlock
is developed and validated.
