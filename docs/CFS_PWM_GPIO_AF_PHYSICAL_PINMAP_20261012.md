# Original CFS PWM GPIO alternate-function outputs — verified offline
*12 October 2026; saved v3.13 and v3.22 firmware only.*

## Discoveries

Decoded first scatter region of each SHA-pinned saved application
(`0x0802DB6C..0x0802DE38` → **3012 bytes initialized SRAM**)
contains five RT-Thread PWM objects at 96-byte stride. The
`[object+0x54]` field points to their original ROM names;
`[object+0x48]` and `[object+0x4c]` provide an MCU peripheral
base address and one GPIO pin mask. All five are unchanged in
saved v3.13 and v3.22.

| RT-Thread name | Object in SRAM | GPIO port peripheral base | GPIO pin mask | Physical MCU pad | Initial configuration |
| --- | --- | --- | --- | --- | --- |
| `pwm1` | `0x2000075C` | `0x40011800` GPIOE | `0x2000` | **PE13** | AF push-pull output |
| `pwm3` | `0x200007BC` | `0x40011400` GPIOD | `0x1000` | **PD12** | AF push-pull output |
| `pwm4` | `0x2000081C` | `0x40011400` GPIOD | `0x2000` | **PD13** | AF push-pull output |
| `pwm5` | `0x2000087C` | `0x40011400` GPIOD | `0x8000` | **PD15** | AF push-pull output |
| `pwm8` | `0x200008DC` | `0x40011400` GPIOD | `0x4000` | **PD14** | AF push-pull output |

**Important distinction: these are GPIO PORT BASES, not TIMER
peripheral base addresses.** The names `pwm*` refer to RT-Thread
devices whose pins are configured for *alternate function* operation.
The dedicated PWM source could be a timer, but neither the specific
timer/channel assignment nor the actual motor has yet been proven.

The real saved Thumb first-pass loop at `0x0801B3D0` iterates
through the five device descriptors and calls original firmware
function `0x08023770` as follows:

- `r0 ← [object+0x48]`: GPIO port base
- `r1 ← 0x18`: GD32F30x `GPIO_MODE_AF_PP`
- `r2 ← 3`: GD32 GPIO 50MHz output-speed setting
- `r3 ← [object+0x4C]`: GPIO single-bit mask
- `BL 0x08023770`: original GD32 GPIO configuration
  logic, which accesses `GPIOx_CTL0` (`+0x00`) and
  `GPIOx_CTL1` (`+0x04`), selects per-pin configuration
  and writes updated port control words.

The mode, register offsets and GPIO port addresses are corroborated
against the open GD32F30x standard peripheral header:
[GD32F30x GPIO header](https://github.com/CommunityGD32Cores/ArduinoCore-GD32/blob/main/system/GD32F30x_firmware/GD32F30x_standard_peripheral/Include/gd32f30x_gpio.h).
In that header `GPIO_MODE_AF_PP = 0x18` and
`GPIO_OSPEED_50MHZ = 0x03`.

## Read status is not physical motor stop

In the same original firmware there are GPIO accessors:
`0x0802382C` reads `GPIOx_ISTAT` (port + 0x08) and
`0x0802383C` reads `GPIOx_OCTL` (port + 0x0C).
These operations can read **electrical pin input status**
or **an output control latch**, respectively, but do not directly
measure motor encoder velocity or guarantee completion of asynchronous
motion. Neither proves the driver's enable, actual timer count,
spindle inertia, mechanical position or physical rotor stop.

Consequently do **not** use those reads, the OEM GPIO pin metadata,
the `pwm1` device name, `BOX_STATE=IDLE`, or duty command zero
as an independent MCU safety interlock. Motor-busy issue #9 remains
open pending evidence of active feeder, buffer and hub hardware,
and an atomic task/IRQ state snapshot.

## Code and evidence

`cfs_pwm_gpio_af_pinmap_audit.py` in
`firmware/v3.22-readonly-state-probes/` is reproducible in GitHub
Actions. It validates the exact ROM and decoded SRAM on **both**
SHA-pinned versions, checks **14 original Thumb instruction pins**
throughout GPIO initialization and driver helpers, and rejects
**5 deliberate in-memory descriptor mutations**. Results are only
metadata: not a copy of the vendor firmware.

The script *does not* read or write GPIO on any actual MCU,
change firmware, alter Kalico, stop/restart services or touch motors.

## Logical next step

Determine exact TIMER peripheral and AF remap selections used
for these five AF pins. Then correlate timer channel enable,
compare/duty state and selected IRQ/task start/stop transitions
to each physical motor. Until all motor owners and motor-start
paths are covered, the MCU write guard and v3.23 flash release
must remain blocked.
