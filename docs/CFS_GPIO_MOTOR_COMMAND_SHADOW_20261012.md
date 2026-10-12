# CFS motor signals: GPIO device outputs versus physical motion feedback

**12 October 2026 — read-only investigation, saved original v3.13/v3.22.**

## New established relationships

Correctly decoding the original APP linked at `0x08003000`
reconstructs the entire 3,012-byte initialized SRAM area, including
five RT-Thread type-9 `pwm*` device descriptors. Each object's
`+0x48` field is a **GPIO peripheral base address**; `+0x4C`
is a one-hot **GPIO pin mask**; `+0x50` is one additional
small manufacturer-specific descriptor value, whose exact runtime
semantic has **not** been established.

| RT-Thread name | GPIO base from saved RAM | GPIO pin | Raw +0x50 |
| --- | --- | --- | --- |
| `pwm1` | `GPIOE 0x40011800` | `PE13` | `2` |
| `pwm3` | `GPIOD 0x40011400` | `PD12` | `0` |
| `pwm4` | `GPIOD 0x40011400` | `PD13` | `1` |
| `pwm5` | `GPIOD 0x40011400` | `PD15` | `3` |
| `pwm8` | `GPIOD 0x40011400` | `PD14` | `2` |

Port names use the GD32F30x vendor GPIO peripheral address map.
They do **not** prove which feeder/hub/buffer motor each pin controls,
or whether the pin reads back actual rotor speed. The names `pwm*`
are application identifiers, **not evidence** of hardware TIMER
capture/feedback.

The original peripheral initialization loop at `0x0801B3D0`
uses 96-byte device strides, loads `[device+0x48]` and
`[device+0x4C]` into the GPIO configuration call
`0x08023770`, with constant argument values `0x18` and `3`.
Registration subsequently reads the real saved
`[device+0x54]` name pointer and calls the real constructor
`0x0801944A`. Both v3.13 and v3.22 match this logic.

## Motor power/duty control updates *software command shadows*

The genuine motor duty entry is `0x080110CC`; the forward
and reverse wrappers are `0x08011164` / `0x0801117E`;
the zero-duty **command** wrapper is `0x08011198`.
Two literal loads at `0x080110E8` and `0x080110EA`
read the same SRAM root `0x20004960`. Subsequent code
adds `0xB4` to the first pointer:

| Address | Original code | Meaning supported by code |
| --- | --- | --- |
| `0x20004A1A` | `STRH r0,[r4,#6]` | Software-stored *requested* duty |
| `0x20004A1C` | `LDRH r1,[r4,#6]; STRH r1,[r4,#8]` | Previous requested duty |
| `0x20004990` | `STR r6,[r7,#0x30]` | Cleared command-side flag |
| `0x20004994` | `STR r6,[r7,#0x34]` | Cleared command-side flag |

The same original routine calls `0x08019516` and
`0x08019488` (downstream driver/device operations). This
identifies a plausible next static audit target. These
instructions **do not read physical rotor/encoder feedback**,
and `0x20004A1A == 0` is NOT a motor-stopped interlock.
A zero requested duty is compatible with a decelerating
rotor, an unresponsive driver or a command that has not
yet reached the peripheral. Treat those cases as UNKNOWN/BUSY.

The online CFS remains untouched; in particular no GPIO
registers were read from the operating printer and no
motor movement was commanded. This test only decodes
a locally saved, exact SHA-pinned binary.

## Regression and safe next steps

The CI now runs
`firmware/v3.22-readonly-state-probes/cfs_gpio_motor_command_shadow_audit.py`
on **both SHA-pinned v3.13 and v3.22**. It pins 27 original
Thumb instructions to physical `0x08003000`-based addresses,
checks five independent ROM names/pin masks and asserts that
none of these command shadows grants physical STOP feedback.

The remaining MCU safety requirement from issue #9 is unchanged:
identify independent physical motor/driver/encoder activity
**covering all feeder, hub and buffer paths**, and ensure the
future SET/RESET guard is atomic with all task/IRQ start paths.
The present GPIO and shadow mapping is useful for
reverse engineering but **is not that proof**.

Related findings:
- [Correct image link base and PWM name mapping](CFS_REAL_LINK_BASE_AND_PWM_NAME_RECOVERY_20261012.md)
- [Motor busy-guard specification](CFS_MOTOR_BUSY_GUARD_CONTRACT_20261012.md)
- [v3.23 release gates](CFS_V323_RELEASE_READINESS_20261012.md)
