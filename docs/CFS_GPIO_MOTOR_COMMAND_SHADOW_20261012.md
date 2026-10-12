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

## The original RT-Thread PWM 0x1E04/0x1E05 callback is not a motor sensor

Original physically linked `0x080110CC` invokes the generic
PWM driver wrappers `0x08019516` and `0x08019488`.
Those wrappers call the generic RT-Thread dispatcher
`0x08016A92`, which selects the object's callback
from `[device+0x38]`; that real original callback
starts at `0x0801939C`.

The `0x0801939C` handler computes `r1-0x1E00-4`.
It takes two special branches for request IDs
`0x1E04` and `0x1E05`. In those branches it stores
a **constant one or zero** to `[response+0x14]`,
respectively; this branch never reads motor encoder,
GPIO input-status, or TIMER counter registers.
Therefore those command responses are **not independent
motion-state observations**.

`cfs_pwm_control_status_not_motor_feedback.py`
pins the complete 22-instruction original dispatch/response
chain and additionally runs the true saved Thumb instructions
under two bounded synthetic request scenarios, asserting
that no hardware-MMIO reads occur. The original v3.13
and current saved v3.22 have identical behavior. The
indirect driver path for other request IDs, including
`0x1E02`, is explicitly **outside this narrow proof**.

This matters because a value of `0` from a callback,
a zero commanded PWM duty, and `BOX_STATE=IDLE`
are three different concepts. None can serve alone
as the physical-motor-stop guard required by issue #9.

## Initial backing-driver function for forwarded requests

The same reconstructed initial SRAM carries a separate pointer
at `0x20000758`: **`0x0801B395`**, an original Thumb function
entry (physical code PC `0x0801B394`). During the device
initialization loop, the constructor receives
`0x2000075C - 4 = 0x20000758` as the shared backing context
and writes it to device field `+0x40` for the five named
PWM objects. The manufacturer's real callback at
`0x0801939C` uses `LDR r4,[r0,#0x40]`,
`LDR r4,[r4]`, then `BLX r4` for operations not
handled as fixed `0x1E04`/`0x1E05` responses.

The new offline audit
`cfs_pwm_backing_driver_entry_audit.py` reconstructs the
manufacturer pointer from original compressed SRAM and
enters the real `0x0801939C` callback with a **synthetic**
`0x1E02` request. It **stops emulation at the backing
entry**, before any actual driver instruction is executed;
no physical GPIO/TIMER/encoder is read or touched.

The next physical original driver at `0x0801B394`
has been reached successfully in an emulator on **both
saved v3.13 and v3.22 images**, but the emulation was
stopped *before its body could touch hardware*.

Static disassembly of its `0x1E02` path identifies
`0x0801B28E`: it loads the configured GPIO base/mask
from the backing device descriptor and invokes a GPIO
configuration helper at `0x08023770`; other calls
and arithmetic prepare additional peripheral parameters.
This is **a driver configuration/operation path**, not
proof of a sensor that reports rotor activity or stop.
Names like `gpio_get` are deliberately avoided here,
because the original branch performs GPIO initialization.

The continuation from `0x0801B28E` to potential timer,
DMA or encoder registers still requires a verified
instruction/dataflow audit, followed by controlled
hardware validation. A CFS actively feeding may report
`BOX_STATE=IDLE` and/or have a zero stored commanded
duty; neither establishes true safe stoppage.

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
