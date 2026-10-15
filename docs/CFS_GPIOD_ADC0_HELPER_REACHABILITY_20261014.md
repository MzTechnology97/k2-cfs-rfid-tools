# CFS v3.22 — physical GPIO-D and ADC0 helper reachability
*14 October 2026 · offline OEM source inspection only*

## Why this matters

The user-confirmed CFS circuit routes DC motors M1/M2 to **PD0–PD3**
and their current-sense amplifiers to **PC5/PC0**. Pin and peripheral
addresses alone are not sufficient to claim that the OEM firmware
samples current or provides a motor-stopped state.

This audit maps actual **physical** ARM Thumb addresses using the
verified saved application origin **0x08003000**, not the superseded
artificial 0x08010000 mapping. The checks compare independently
SHA-pinned v3.13 and v3.22 images.

## Verified manufacturer instructions and ROM literals

| OEM source | Verified bytes/semantics | Interpretation boundary |
| --- | --- | --- |
| `0x0801B53E` | `BL 0x0801B684` | Called in a loop loading entries from a table; not identified as a motor feedback callback |
| `0x0801B684` | `PUSH {r4,lr}`, then `LDR r4,[pc,#0xd4]` | Source literal `0x0801B75C` is `0x40011400` (GPIO-D base) |
| `0x080236F4` | `PUSH {r4,lr}`, then `LDR r4,[pc,#0x250]` | Other GPIO-D-base helper; literal `0x08023948` also contains `0x40011400` |
| `0x08022926` and `0x08022932` | Load literal `0x08022C88`, set/clear bit `0x800000` | Original ADC0 register control operations; no authenticated motor-current sampling chain |
| `0x08022BBC` | `LDR r0,[pc,#0xc8]; ADDS r0,#0x44; LDR r0,[r0]; BX LR` | Literal `0x08022C88` stores `0x40012408`; effective read address is **`0x4001244C`** |

The GigaDevice GD32F30x user manual identifies ADC0 as
`0x40012400` and **ADC_RDATA** as base + **`0x4C`**:
[manufacturer GD32F30x user manual](https://www.gd32mcu.com/data/documents/userManual/GD32F30x_User_Manual_Rev2.9.pdf).
Therefore the original helper at `0x08022BBC` does read
the ADC0 routine data register **if it is actually called**.

**Important side effect:** The ADC status EOC flag may be cleared by a
read of ADC_RDATA, according to the manufacturer's ADC_STAT description.
Do **not** add an unsynchronized debug/telemetry read of ADC_RDATA
while the real CFS is running; it could consume a conversion result
or disturb the application's ADC completion handling.

## Narrow direct-call census

`cfs_gpio_d_adc0_helper_reachability_audit.py` also scans halfword
boundaries of the saved APP for direct `BL` instructions and
aligned ROM words containing the entry pointers. The only directly
identified BL among the covered helper entries is:

`0x0801B53E -> 0x0801B684`.

Within this specific scan no direct `BL` references were found to
`0x080236F4`, `0x08022926`, `0x08022932` or
`0x08022BBC`.

**This is a deliberately incomplete direct-call inventory.** All
the helper functions may still be used through `BLX`, runtime
driver pointers, register-loaded function pointers, interrupt paths,
or generic ADC/GPIO APIs. Counts from disassembling every halfword
also need reachability verification. Zero direct callers is **not**
proof that motor-current conversions never run.

## What remains unknown

- Whether ADC channels **15, 10, 1, 0** are actually configured
  for M1/M2/M3/M4, and which firmware task or IRQ consumes results.
- Actual current-sense filtering, fault/disconnect handling, stall
  detection, sample freshness and calibration.
- Whether GPIO-D PD0–PD3 are set by generic RT-Thread helper calls,
  direct register writes or another motor-specific owner.
- Independently reliable **physical motor idle**, including driver
  deenergization and complete IRQ/task motor-start synchronization.

This audit does not authorize a read from any live ADC MMIO
register, a new motor-active SET/RESET gate, or a v3.23 flash.
The nine release conditions remain **false**. No printer/CFS
firmware modifications, commands, motor movement, NVM writes,
CM5 production service restart or Kalico configuration edits occurred.

Reproduction:
`firmware/v3.22-readonly-state-probes/cfs_gpio_d_adc0_helper_reachability_audit.py`,
run in SHA-pinned GitHub Actions.
