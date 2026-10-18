# CFS v3.22 — read-only internal-state probes

> **ADDRESS CORRECTION — 2026-10-12:** The saved APP is **linked at `0x08003000`**, not `0x08010000`. Its 178,140-byte image ends physically at `0x0802E7DC`, *not* at the older documentation's `0x0803B7DC`. These older labels were based on a nominal file-offset origin 0xD000 too high. The original saved reset vector, all five PWM device names and three callback prologues have been verified in offline CI. The existing experimental builder still uses the old nominal origin for offsets/ELF placement, and its absolute external ROM references have **not yet been migrated or runtime-validated**. Do **not** reinterpret apparent extra Flash capacity as a loader-approved expansion, alter pointer literals blindly, or flash a new build. See [verified link-base and PWM recovery](../../docs/CFS_REAL_LINK_BASE_AND_PWM_NAME_RECOVERY_20261012.md).


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
## Use on the reference printer (2026-10-10 to 2026-10-18)

- **Published image:** `cfs0_050_G32-cfs0_000_153-runtime-config-v3_22-READONLY-DIAG-EXPERIMENTAL.bin`, 178,140 bytes, SHA-256 `40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`. It is the image installed on the reference CFS, and it is published here so the installer helper can verify and flash it. The builder above reproduces the same bytes from the v3.13 base.
- **Prints:** two complete 30 h PETG-CF prints ran on v3.22.
  - 2026-10-14/15: slot 3 ran out, and the automatic runout swap loaded slot 4 in about 43 s.
  - 2026-10-16/17: slot 4 ran out, and the swap loaded slot 1 in about 46 s.
  - Each print had 370k RS-485 requests with no CRC error. One periodic GET to the Y motor timed out once, with no effect.
- **Paired Kalico:** kalico-k2pro #75 and #80.
  - Auto-apply and bulk APPLY are skipped, and stock IDs 0..6 are read-only.
  - Only IDs 7 and 8 accept a manual SET, because the others have no stock callsite.
  - SET/RESET hold the host motion/RFID lock.
  - The first probe waits for CFS enumeration (#77), and each CFS is a separate unit (#79).
- **OpenCFS tests, 2026-10-17/18:** other images were flashed for the tests, and v3.22 was restored afterwards. On 2026-10-18 `BOX_CFS_CONFIG_INFO` read API2/28, `0xD7`.
- **Status unchanged:** experimental, with issue #9 still open.

## 2026-10-10 on-device validation and G-code sampling limitation

After the operator flashed v3.22, initial Klipper startup displayed `NO_RESPONSE` / timeouts. Klipper had been stopped by the updater; starting it and one controlled MCU-rail cycle did not immediately clear the condition. Later the CFS **recovered normal RS485 communications** (exact recovery mechanism not determined). A manual `BOX_CFS_CONFIG_INFO` showed API2/28 with expected feature **`0xD7`** and no runtime error. This supersedes the initial suspected flash failure; there is **no confirmed flash corruption**.

- Eight CFS `IDLE` diagnostic snapshots stable: `motor_candidate=0000:0000`, `task_candidate=0001:0000`.
- Bambu PLA Basic slot1 physical load **11.435 s**, unload **14.681 s**, both without heater commands, status/sensor checks passed.
- Final device state: Klipper `ready/standby`, CFS `IDLE`, loaded slot `-1`, head sensor false, feature `0xD7`, 28 normal values, ID7=3200, ID8=700, targets 0, runtime error null.
- **Sampling caveat:** calls to `BOX_CFS_CONFIG_SNAPSHOT` dispatched at ~0.65s during load/unload were queued by Klipper/Moonraker until the operations completed. They took **10.545 s** and **13.797 s**, respectively, and returned just *after* the movement finished. Their values are therefore **POST-motion samples only**; they cannot establish an independent MCU motor-active predicate.
- Firmware still has the original v3.21 `BOX_STATE`-based write guard, which was already shown to be insufficient alone during early `feeding_to_buffer`. Keep Kalico's motion/write interlock enabled, auto-apply off, and issue #9 open until an independently timestamped MCU-side activity flag is validated.

Evidence is stored locally on the CM5 as `~/cfs-rfid-v322-readonly-probe-lab/V322_IDLE_BASELINE_HARDWARE.json` and `V322_PHYSICAL_SNAPSHOT_20261010.json`. These device snapshots were not published in full. An event-driven read-only MCU/serial trace is needed to observe candidate bytes *during* movement; another G-code-queued request will not provide valid in-motion data.

## Independent 2026-10-11 stock-to-v3.22 audit (offline only)

The exact unmodified Creality G32/application-153 BIN was recovered locally and
SHA256-pinned to `5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea`
(175,672 bytes). It is **not distributed or committed** in this repository.
The audited v3.22 image remains byte-identical to the physical-test build:
SHA256 `40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`
(178,140 bytes).

- Against the stock original: **63 bytes** changed in the common original image,
  and **2,468 bytes** were appended. Changes comprise firmware header metadata,
  handler dispatch, RFID/remaining hooks, timing hooks and volatile-sidecar init.
  This is not a claim that the appended code is production-safe.
- Against the SHA-pinned v3.13 intermediary: **1,956 common bytes** differ and
  **440 bytes** were appended. No byte differences *before the appended handler*
  fall outside the manifest's known callsites, container CRC and heap literal.
- The assembly retains all principal v3.12 API7 RFID capture, guarded
  redundant-retry acceptance and stock-geometry remaining routine bodies;
  the only 2 operative advanced motion hooks are IDs **7/8**.
- IDs **9–27** accept bounded `SET/GET/RESET` in the MCU but **do not
  influence original motor, delay, RFID or protection callsites**. Treat these
  as no-op RAM bench values. The paired Kalico audit branch now fails closed
  before sending manual SETs to them; legacy stock speed IDs 0–6 remain read-only.
- `0x14 CONFIG_V2_DESCRIBE` and API1 `0x0D–0x0F` are not dispatched.
  Some historical comments/documentation incorrectly described them as present.
  Comments in the assembly are corrected; **executable bytes are unchanged**.
- The six-byte historical `config_defaults` table and the unused
  `config_v2_ensure` code path have no verified live callers. Do not remove
  them in an unvalidated release: doing so shifts executable handler placement
  near the unverified application flash boundary.
- CFS third-party remaining uses a fixed **330,000 mm nominal type-4 odometer**
  and the original stock geometry-derived initial percentage. This was
  intentionally inferred from a Creality RFID `len=0330` hardware record.
  It is a *reference*, not the true spool length for every material. Kalico
  can separately track actual third-party lengths from the tag/profile/material
  estimates. Do not alter this stock-style behavior without hardware tests.
- `BOX_STATE==IDLE` remains a **non-atomic, insufficient MCU write guard**.
  The four v3.22 diagnostic reads are not proven activity flags. Auto-apply and
  unattended runtime writes remain prohibited. v3.23 512-byte event-ring work
  remains *offline only*, with SRAM/bootloader safety gates unresolved.

Reproduce the comparison with the unmodified 175672-byte vendor image kept
outside this public repository:

```sh
python3 firmware/v3.22-readonly-state-probes/audit_stock_vs_v322.py \
  --stock /private/path/to/unmodified-v153.bin \
  --base firmware/v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin \
  --modified /private/path/to/CFS-v3_22.bin
```

The checker pins each image's size/hash and rejects unexplained changes
outside its declared code sites. It neither creates a firmware image nor
communicates with a CFS. This audit does **not** approve v3.22 for production.
