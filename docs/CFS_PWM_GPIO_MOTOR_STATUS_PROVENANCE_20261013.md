# CFS v3.22: five PWM GPIO descriptors and motor-state candidate
*Static, SHA-pinned, read-only investigation — 13 October 2026*

## Findings from physical `0x08003000` APP link origin

The original 716-byte compressed scatter record
(`0x0802DB6C..0x0802DE38`) expands to 3012 bytes of
initialized SRAM. Five RT-Thread device names and their original
GPIO configuration fields are now recoverable **from that real
initialized image**, without guessing object order:

| Name | Object RAM | GPIO base at `+0x48` | Pin mask `+0x4C` | GPIO |
| --- | --- | --- | --- | --- |
| `pwm1` | `0x2000075C` | `0x40011800` | `0x2000` | GPIOE13 |
| `pwm3` | `0x200007BC` | `0x40011400` | `0x1000` | GPIOD12 |
| `pwm4` | `0x2000081C` | `0x40011400` | `0x2000` | GPIOD13 |
| `pwm5` | `0x2000087C` | `0x40011400` | `0x8000` | GPIOD15 |
| `pwm8` | `0x200008DC` | `0x40011400` | `0x4000` | GPIOD14 |

At `0x0801B3D0..0x0801B3E0`, the original manufacturer
loops over each 96-byte object, reads `+0x48` and `+0x4C`,
and calls GPIO configuration at `0x08023770`. A second loop,
`0x0801B3F4..0x0801B408`, uses the `+0x54` name and
registers the device at `0x0801944A`. The device's
`+0x38` control entry is reached from a generic dispatch at
`0x08016AC2..0x08016AD0`.

The manufacturer peripheral helpers read GPIO input status at
`GPIO_base+8` (`0x0802382C`) and output status at
`GPIO_base+0x0C` (`0x0802383C`). Neither is a verified
independent encoder/rotor-stop measurement; for an output used to
drive or enable a motor, output readback generally represents an
electrical level, not confirmed mechanical standstill.

## Original motor command controller and possible state byte

The original command hub is `0x080110CC` (correct physical
address). A PC-relative literal at `0x08011244` contains
`0x20004960`, used as the common motor software structure
root by both the duty routine and a status getter.

- The controller adjusts a per-motor RAM structure at
  `0x20004960+0xB4 = 0x20004A14` and invokes existing
  device control routines. Its forward, reverse and zero-duty
  wrappers are `0x08011164`, `0x0801117E` and
  `0x08011198`, respectively.
- At `0x0801114A..0x0801114C` it writes `0x14` to
  `[r7+0x3C]`, i.e. **`0x2000499C`**, on its
  zero-duty handling path.
- The function at `0x080111AA` reads that same byte and
  returns **0 if nonzero, 1 if zero**. The three literal
  direct BL callsites are `0x080038AE`, `0x08003932`
  and `0x08003C8A`.

Thus `0x2000499C` is a concrete **software-status /
possible countdown candidate**, *not* a hardware-confirmed
motors-stopped signal. The exact countdown/update path, IRQ
and all feeder/hub/buffer motor start routes have not been
validated. We do not assume that this flag covers them.

## Automated proof / scope limits

`firmware/v3.22-readonly-state-probes/cfs_pwm_gpio_and_motor_status_provenance.py`
verifies the physical image base, decompresses original SRAM,
checks all five GPIO descriptors and their names, pins 27
manufacturer Thumb instructions in the GPIO/device-control
chain, verifies the common motor RAM-root literal, and checks
the three software-status callsites.

These are **original saved firmware binary facts**.
They do *not* establish the firmware currently installed
on the user's CFS, a sensor that proves physical motor stop,
atomicity of any prospective SET/RESET guard, memory safety,
or bootloader authorization to flash v3.23.

**Release consequence:** treat any unknown GPIO/byte value,
stale software state, concurrent motion, unverified ISR path,
or inaccessible motor feedback as BUSY (fail-closed).
The v3.22 SET/RESET handler still checks BOX_STATE alone;
the source audit and synthetic guard contract do not
implement a production MCU interlock. Do not enable
motor-active writes or flash a v3.23 based on this work.

No production Klipper/Kalico files, CFS Flash, NVM, serial,
commands, or motor hardware were modified or interrogated.
