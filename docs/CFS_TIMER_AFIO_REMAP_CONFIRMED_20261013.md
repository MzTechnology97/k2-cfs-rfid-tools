# CFS v3.22 — Original TIMER0/TIMER3 remap setup in GD32 AFIO

*13 October 2026. Offline read-only source audit on saved, SHA-pinned
v3.13 and v3.22 images. No actual CFS registers read or written.*

## Result: manufacturer ROM really selects both remap modes

Earlier offline evidence proved five PWM alternate-function GPIO outputs
and found `TIMER0`/`TIMER3` ROM literals, but left the **AFIO remap**
configuration as a hypothesis. The original code now supplies a direct
link: `0x0801B28E` reads a selector byte at `[r6+0x18]` and
**calls the manufacturer's pin-remap configuration function**
`0x0802384C` at `0x0801B2B8`.

| Original selector | OEM original instructions | Remap argument `r0` | Hardware AFIO bits |
| --- | --- | --- | --- |
| `[r6+0x18] == 1` | `0x0801B2AE` (`r1=1`), `0x0801B2B0` (`r0=1<<12`) | `0x00001000` = **TIMER3_REMAP** | AFIO_PCF0 bit 12 |
| `[r6+0x18] == 2` | `0x0801B2B4` (`r1=1`), `0x0801B2B6` (ROM load) | `0x001600C0` = **GPIO_TIMER0_FULL_REMAP** | AFIO_PCF0 bits 7:6 = `11` |

The manufacturer's original ROM value at **`0x0801B514`**
is `0x001600C0`. Both branches arrive at the **same**
`BL 0x0802384C` instruction. The ARM Thumb routine at
`0x0802384C` obtains `0x40010000` (GD32 AFIO base) via the
PC-relative literal at **`0x08023950`**, reads the word at
`[r4+4]`, modifies bits, and writes it to **`AFIO_PCF0 =
0x40010004`** at `0x0802389A`.

The original GD32F30x definitions confirm the remap values:
[GD32F30x GPIO header](https://github.com/CommunityGD32Cores/ArduinoCore-GD32/blob/main/system/GD32F30x_firmware/GD32F30x_standard_peripheral/Include/gd32f30x_gpio.h).

## Correlation with the five CFS PWM alternate-function pins

Combining this **new code-level remap evidence** with the
independently reconstructed `[obj+0x48]` GPIO port,
`[obj+0x4C]` GPIO mask and `[obj+0x50]/[obj+0x5C]`
OEM selector values gives a stronger static mapping:

| CFS PWM name | GPIO output | AF timer/channel compatible with OEM remap code | Evidence limit |
| --- | --- | --- | --- |
| `pwm1` | PE13 | TIMER0_CH2, full remap | OEM selector/group 2/2 |
| `pwm3` | PD12 | TIMER3_CH0, remap | OEM selector/group 0/1 |
| `pwm4` | PD13 | TIMER3_CH1, remap | OEM selector/group 1/1 |
| `pwm5` | PD15 | TIMER3_CH3, remap | OEM selector/group 3/1 |
| `pwm8` | PD14 | TIMER3_CH2, remap | OEM selector/group 2/1 |

**These are pinned original configuration paths, not a runtime
measurement.** No one has read AFIO_PCF0, TIMER0/TIMER3 CHx
control/compare registers or actual drive enable/status on the
installed CFS. The board routing and GPIO peripheral API context
remain to be independently validated on hardware.

The manufacturer's remap function is also called at
`0x0801063E` from another subsystem; its arguments should
not be conflated with these timer configurations.

## What this does NOT prove

- A TIMER's `CHx` output being enabled is not equivalent to the
  physical motor/filament being stationary.
- PWM commanded duty `0`, control/output latch reads, the
  PE11 GPIO pulse counter and software countdown may each be
  stale, direction-dependent, or unrelated to one or more motors.
- The original `[r6+0x18]` selector proves the two OEM software
  branches; it does not prove which one ran on the deployed CFS
  after boot or after a firmware upgrade.
- A concurrency-safe MCU write lock must exclude *all* actual
  feeder, hub and buffer motion start paths and handle ISR races.
  The policy remains **reject any SET/RESET on unknown motor state**.

## Automated checks

`firmware/v3.22-readonly-state-probes/cfs_pwm_timer_afio_remap_provenance.py`
validates all original branch instructions, the two exact
manufacturer remap constants, the PC-relative AFIO-base ROM
reference, the real register read/modify/write path and the five
already authenticated GPIO descriptors **in both saved firmware
versions**. No vendor binaries or hardware memory are uploaded or
changed.

This finding helps target future motor-enable and timer-compare
dataflow probes; it does **not** unlock v3.23 firmware flashing
or MCU SET/RESET during motor movement.
