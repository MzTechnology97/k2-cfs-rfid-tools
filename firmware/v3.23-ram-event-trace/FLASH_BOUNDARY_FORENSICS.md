# Forensic flash-boundary assessment — 2026-10-11

**This is a conservative empirical bound, NOT a bootloader flash-partition dump. Do not flash a larger image based on the physical MCU datasheet.**

## Device and software

Original Creality CFS target `cfs0_050_G32` / app `cfs0_000_153`. The exact MCU SKU is not verified by a fresh chip marking photograph; GD32F303VET6 is a previously proposed fit. GigaDevice's GD32F303VET6 product sheet states 512 KB physical flash and 64 KB SRAM, but this capacity does **not** establish the vendor CFS updater's effective address range. See https://www.gigadevice.com/product/mcu/mcus-product-selector/gd32f303vet6 .

The original updater `/usr/bin/mcu_util_485` was examined **offline** after copying its bytes from the T113. SHA-256: `dcf3a63136d5ef5766812c22ac243640e26b5600400ef951091ff72fcc0784d8` (32-bit ARM EABI5 executable). Its string table contains `erase_flash`, `get_sector_size` and `start_app`. No verified app-length limit could be extracted from the string examination or the raw constant search. The `get_sector_size` operation of an independent community flasher concerns RS485 transfer chunks; it cannot be assumed to report total flash capacity or app size. We **did not** invoke the updater or enter the CFS bootloader.

## Empirical evidence from archived on-device tests

| Revision | Image size | App end | Hardware observation |
|---|---:|---|---|
| v3.13 | 177700 B | `0x0803B624` | Prior working rollback image |
| v3.15 | > inferred `0x0803B800` | beyond cutoff | CFS API2/28 present but GET IDs 7–27 all 65535; failed |
| v3.16 | **179128 B** | **`0x0803BBB8`** | API2/28 present, but all 21 advanced GETs returned 65535; failed |
| v3.18 compact | **177684 B** | **`0x0803B612`** | **All 28 GETs passed on hardware** |
| v3.19 | 178068 B | `0x0803B794` | Later verified on hardware |
| v3.22 | **178140 B** | **`0x0803B7DC`** | **Feature 0xD7, GETs and physical load/unload passed** |

Archived sources on the authorized CM5: `cfs-rfid-v315-sidecar-lab/V315_HARDWARE_READBACK_FAILURE.json`, `cfs-rfid-v316-guarded-lab/V316_FIRST_BOOT_READBACK.json`, `cfs-rfid-v316-guarded-lab/V316_READBACK_FAILURE_ASSESSMENT.json`, `cfs-rfid-v318-compact-lab/V318_HARDWARE_READBACK_PASS.json` and `cfs-rfid-v322-readonly-probe-lab/V322_PHYSICAL_SNAPSHOT_20261010.json`.

### Disassembly localization supporting the cutoff hypothesis

Original v3.16 injection was linked at `0x0803AE38`, with `handler_end=0x0803BBB6`:

- `param_desc` table itself: `0x0803B386` (in the lower region).
- **`param_desc_ptr=0x0803BB98` (well beyond `0x0803B800`)**.
- `config_defaults=0x0803BBAA` (also beyond).
- v3.16 app end `0x0803BBB8` exceeded the proposed cutoff by **952 bytes**.

A CFS that executes the low-address API handler but sees a missing/erased descriptor pointer or constants could produce the observed `65535` raw values. That is a **plausible explanation, not a proven causal diagnosis**: alternative causes include invalid pointers, mismatched runtime code and serial parsing. In particular, successfully booting v3.16 does not establish that bytes past `0x0803B800` were actually programmed.

The compact v3.18 moved its `handler_end` back to **`0x0803B612`** and achieved expected GET data on real hardware. The later tested v3.22 ends at **`0x0803B7DC`**, leaving **36 bytes** relative to `0x0803B800`.

**Practical decision:** treat `0x0803B800` as a conservative, empirically motivated **maximum candidate image end** until actual bootloader/erase-region behavior is established using a safe, independently reviewed procedure. Never infer a larger writable application region from the physical MCU capacity alone.

## Impact on v3.23 instrumentation

The stand-alone RAM trace helper compiles to **320 bytes ARM Thumb text**, before even including a motor-hook trampoline, clock capture, read-only dump protocol or safety checks. The current proven v3.22 has only **36 bytes** of conservative headroom. Therefore **a v3.23 instrumented BIN is NOT ready**.

The next design stage must explicitly reclaim space within the empirically safe boundary without losing existing functions, or otherwise obtain independently verified evidence of a larger application programming range. Changes to the heap boundary for a proposed 512-byte trace buffer also remain unvalidated.

No MCU write or on-device bootloader transition was performed during this audit.
