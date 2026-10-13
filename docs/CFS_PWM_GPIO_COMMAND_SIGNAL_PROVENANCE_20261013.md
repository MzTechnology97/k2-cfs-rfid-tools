# CFS v3.22 PWM/GPIO and motor-activity signal provenance

*13 October 2026 — original APP and CFS snapshots inspected offline only.*

## Context and verified source

The manufacturer-saved CFS v3.13 and v3.22 images are linked
at **0x08003000**, not the legacy analysis origin 0x08010000.
The SHA-pinned v3.22 original scatter source
`0x0802DB6C..0x0802DE38` yields 3,012 bytes of initialized SRAM
starting at `0x20000000`. The new
`cfs_motor_gpio_signal_provenance.py` repeats that decompression
independently for both saved firmware versions, reads each actual
named PWM object and pins the precise original Thumb instructions
connecting the motor controller to software RAM state.

The GD32F30x GPIO definitions identify
`GPIOD=0x40011400`, `GPIOE=0x40011800`,
`GPIO_ISTAT(base)=[base+0x08]`, and
`GPIO_BOP/BC=[base+0x10/0x14]`.
Reference: [GD32F30x peripheral driver header](https://github.com/CommunityGD32Cores/ArduinoCore-GD32/blob/main/system/GD32F30x_firmware/GD32F30x_standard_peripheral/Include/gd32f30x_gpio.h)
and [manufacturer manual](https://www.gd32mcu.com/data/documents/userManual/GD32F30x_User_Manual_Rev2.9.pdf).

| Registered device | Original RT-Thread object | Object +0x48 port base | +0x4C pin mask | GPIO |
| --- | --- | --- | --- | --- |
| pwm1 | `0x2000075C` | `0x40011800` | `0x2000` | PE13 |
| pwm3 | `0x200007BC` | `0x40011400` | `0x1000` | PD12 |
| pwm4 | `0x2000081C` | `0x40011400` | `0x2000` | PD13 |
| pwm5 | `0x2000087C` | `0x40011400` | `0x8000` | PD15 |
| pwm8 | `0x200008DC` | `0x40011400` | `0x4000` | PD14 |

These prove **original firmware port/pin assignments**, not
which motor is turning, the output's direction or whether the
actual motor rotor has stopped. It is not safe to assume these
pins are genuine encoders or that reading an output level would
provide independent motion feedback.

## Original duty command controller and RAM flag

- `0x080110CC`: original motor-duty command routine.
  It calls `0x08019516` to configure command data and
  `0x08019488` for a further PWM-related operation.
- `0x080110EA` loads the original literal at
  `0x08011244` => RAM base `0x20004960`.
- `0x0801114A` loads `0x14`; `0x0801114C`
  writes that byte to `[RAM base+0x3C]` = **`0x2000499C`**.
- `0x080111AA` / `0x080111AC` reads that same flag.
  It returns **0 when the flag is nonzero** and **1 when zero**
  using the original branch sequence.
  Its three direct Thumb BL callers in saved v3.22 are
  `0x080038AE`, `0x08003932`, and `0x08003C8A`.
- `0x080111F4` reads the same base pointer, and
  `0x080111F6` loads a floating-point value at
  **`0x2000498C`** (offset `+0x2C`).
  The same code takes absolute value and converts to integer,
  but its origin, update semantics and relationship to actual
  encoder feedback are **not yet demonstrated**.

The read/write evidence makes `0x2000499C` a valuable
**software command/status candidate**, but it is not a
physically independent motor-STOP signal. Zero/nonzero and
software flags do **not** prove the rotor is stationary.
Likewise, the float cannot be promoted to position feedback
without its producer/interrupt flow and hardware provenance.

## Independent GPIO input reader is generic

The saved firmware contains
`0x0802382C: LDR R0,[R0,#8]; 0x0802382E: ANDS R0,R1`,
a straightforward read of the hardware GPIO input-status
register (`ISTAT`) masked by a pin bit.
A wrapper at `0x0801ABAA` looks up a configured GPIO
device then calls the generic reader at `0x0801ABBA`.

This demonstrates that the firmware **can sample input
pins**. It does **not** demonstrate that any of the five
PWM-named pins is a filament sensor or encoder,
that a relevant sensor changes when motor motion stops, or
that the reader is used in all load/unload transitions.
A complete mapping of actual CFS sensor peripherals and
motor start/stop events is still required.

## Security and release decision

The existing v3.22 `SET`/`RESET` guard only checks
`BOX_OPER_STATE+2`. A real CFS load occurred while
BOX_STATE reported IDLE, so this is **not a valid
motor-idle interlock**. The new GPIO audit labels all
candidate hardware/software values conservatively and
will fail CI if any of its pinned manufacturer instructions
or initial SRAM port assignments differs.

For v3.23, first prove authenticated producer semantics
for actual encoder/motor-active and all task/ISR start
paths. Then implement an MCU-side atomic reject on
motor-active or unknown conditions and validate on safe
test hardware. The 512-byte event ring, Flash/heap
reservations and recovery/flash-size limit remain
separate release blockers.

**NO MCU writes, flash, motor movement, RS485 commands,
production Kalico modifications or reboot were performed.**
