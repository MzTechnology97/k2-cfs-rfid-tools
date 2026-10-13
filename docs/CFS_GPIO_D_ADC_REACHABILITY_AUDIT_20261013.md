# CFS original GPIO_D and ADC motor-current reachability

**13 October 2026 | PR #24 | Research only — no MCU interaction**

## What the current verified source proves

The original v3.13 and v3.22 images are linked at **0x08003000**.
The independently documented PCB wiring, confirmed by the CFS
operator, identifies:

| Motor | Physical driver inputs | Feedback PCB connection |
| --- | --- | --- |
| BLDC | PE13 PWM, PE3 direction, PE4 brake | PE11 FG tach pulses |
| M1 | PD3/PD2 | PC5, ADC-channel candidate 15 |
| M2 | PD1/PD0 | PC0, ADC-channel candidate 10 |
| M3 | PD15/PD14 | PA1, ADC-channel candidate 1 |
| M4 | PD13/PD12 | PA0, ADC-channel candidate 0 |

The **GPIO_D** port base is `0x40011400`. The vendor register
map describes `CTL0` at +0x00, `CTL1` at +0x04,
`ISTAT` at +0x08, `OCTL` at +0x0C,
`BOP` at +0x10 and `BC` at +0x14.
Reference: [GD32F30x standard peripheral header](https://github.com/CommunityGD32Cores/ArduinoCore-GD32/blob/main/system/GD32F30x_firmware/GD32F30x_standard_peripheral/Include/gd32f30x_gpio.h).

Two independently discovered PC-relative literal loads in the saved
original binary refer to that peripheral base:

| Thumb PC in linked CFS APP | Physical ROM literal slot | Literal value |
| --- | --- | --- |
| `0x0801B686` | `0x0801B75C` | `0x40011400` |
| `0x080236F6` | `0x08023948` | `0x40011400` |

New `cfs_gpio_d_physical_literal_access_audit.py` source-pins these
addresses across both saved firmware generations and records *bounded*
Thumb instructions and possible `[r4 + offset]` accesses following
each load. Such offsets are only hints: the analysis has **not
proven that r4 remains unchanged along a reachable motor-control
path**, or that those blocks were executed. No motor GPIO register is
read on the installed CFS.

### ADC reachability clarification

The original ROM has a generic `ADC0_RDATA` read routine at
`0x08022BBC`, loading `ADC0_CTL1` from
`0x08022C88` and reading the register at
`0x4001244C`. However, the latest pinned scan reported:

- **0** direct `BL` candidates to that function;
- **0** aligned 32-bit ROM pointers to its Thumb entry;
- no authenticated rank/channel selection for the four
  current-feedback inputs PC5/PC0/PA1/PA0;
- no proven caller that stores ADC results into RAM for
  a motor task.

This does **not** prove the helper is dead code. Non-obvious
dispatch, MOVW/MOVT address formation, hand-written veneers, unaligned
constants and other ADC paths remain possible. Reading ADC result
registers on a live MCU may also modify EOC state, so an
unapproved diagnostic poll is **not** safe.

The separate source scan found **122** candidate `BL` sites
for `0x08018EEC`, but no nearby `r0=0x30..0x33`
immediate candidate in the narrow predecessor windows. It therefore
does not establish which call sites own M1 or M2, nor all task/ISR
motor-start paths.

## Required follow-up and safety criteria

1. Review the two GPIO_D bounded Thumb contexts for real
   `GPIO_D+0x0C/0x10/0x14` stores and their register-liveness.
2. Correlate the actual calling functions with M1/M2 driver
   ownership, not just GPIO port address loads or proximity to a
   16-bit immediate.
3. Trace **reachable** ADC conversion setup, channel selection,
   result consumption, sampling cadence and error handling before
   using a signal as current feedback.
4. Test read-only signals on the actual hardware **only through a
   verified safe path**, ensuring the observations do not affect ADC
   EOC/driver state or motor timing.
5. Even authenticated motor current or BLDC tach feedback must
   not by itself override the firmware's motor-active fail-closed
   guard: stopped rotor, deenergized driver, incomplete sensor
   coverage and atomic SET/RESET synchronization are distinct.

**No new flashable v3.23, no motor command, no MCU GPIO/ADC read,
no CM5/Kalico changes, no relaxation of issue #9.** PR #24 remains
draft while a release gate is outstanding.
