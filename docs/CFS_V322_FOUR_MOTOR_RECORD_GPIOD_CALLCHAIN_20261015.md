# CFS v3.22 — four OEM motor records and GPIO control path

Source-only firmware analysis, 15 October 2026. Reviewed pinned v3.13 and exactly rebuilt saved v3.22 original APP images; physical linked Flash base `0x08003000`. The production CFS MCU and Kalico are unchanged.

## Original motor structures

The original manufacturer controller `0x08010054` calculates an object address using the selector multiplied by `0x2B` then shifted left two bits. This yields a record stride of `0xAC` (172 bytes), starting from RAM `0x20000270`. The original scatter source decompresses exactly 716 input bytes into 3012 bytes of initial SRAM.

| Record | Initial SRAM | OEM pin IDs at offsets +4/+5 | ROM pin table physical pins |
|---|---|---|---|
| 0 (M1 wiring) | `0x20000270` | `0x32 / 0x33` | PD2 / PD3 |
| 1 (M2 wiring) | `0x2000031C` | `0x30 / 0x31` | PD0 / PD1 |
| 2 (M3 wiring) | `0x200003C8` | `0x3E / 0x3F` | PD14 / PD15 |
| 3 (M4 wiring) | `0x20000474` | `0x3C / 0x3D` | PD12 / PD13 |

The motor naming corresponds to the operator-confirmed PCB wiring. Each pin has an exact original 16-byte board-table record at `0x0802AD5C + 16*pin_id`, with GPIOD base `0x40011400` and a one-hot pin mask.

## Actual OEM GPIO calls

The original function computes `r4 = 0x20000270 + 0xAC * r6` and branches to `0x0801019C`. Original `LDRB` instructions at `0x080101EA`, `0x08010204` and `0x0801020A` fetch pin IDs through `[r4,#4]` or `[r4,#5]`. Three source-checked 32-bit `BL` sites at `0x080101EE`, `0x08010206` and `0x0801020E` call the authenticated RT-Thread GPIO dispatcher `0x08018EEC`; the branch at `0x080101F8` also reaches the last call.

These three direct calls were absent from the earlier source-classified 91 of 122 candidate branches. The independently checked source-classification count is now **94 of 122**, leaving **28 direct candidate branches unclassified**. Indirect and tail-branch paths also remain to be investigated.

The new source-only audit `cfs_oem_four_brushed_motor_pin_provenance_audit.py` validates both pinned generations, four initialized motor structures, eight GPIO board table entries, source arithmetic and branches, and rejects **14 deliberate corruption scenarios** in CI.

## Safety boundary

This proves source-level GPIO command connectivity for the four motor records, **not** that all motor/task/IRQ callsites were recovered, that register values equal their initial RAM state at runtime, or that any motor is physically stopped. The false-IDLE scenario of issue #9 still requires an independent, atomic motor-state interlock. **No v3.23 firmware flash or motor-active MCU SET/RESET is authorized.**