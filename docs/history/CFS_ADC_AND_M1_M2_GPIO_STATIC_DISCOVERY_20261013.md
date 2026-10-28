> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# GD32F303 motor ADC/GPIO peripheral-use discovery — 13 October 2026

## Scope

Continued CFS v3.23 reverse engineering after successful recovery of
all 16 manufacturer RT-Thread pin IDs and operator confirmation that the
physical BLDC/DC wiring agrees with the published CFS motherboard
reverse engineering. This note does **not** claim that an analogue
current signal has been read or calibrated on the running machine.

A new read-only script:
`firmware/v3.22-readonly-state-probes/cfs_adc_gpio_literal_xref_discovery.py`
scans the SHA-pinned original v3.13 and saved v3.22 application images,
linked at physical `0x08003000`, for aligned constant words
representing GD32F30x ADC0/ADC1/ADC2 and GPIOD MMIO addresses, then
looks for Thumb PC-relative literal loads referencing those words.
The findings are discovery *candidates*, not proven code execution.
The scan cannot identify registers synthesized with MOVW/MOVT or
indirect driver pointers and is not a complete control-flow analysis.

The chip's ADC peripheral base addresses are as follows:

| Peripheral | Base | Reason for checking |
| --- | --- | --- |
| ADC0 | `0x40012400` | Possible analogue current conversion |
| ADC1 | `0x40012800` | Possible analogue current conversion |
| ADC2 | `0x40013C00` | Possible analogue current conversion |
| GPIOD | `0x40011400` | PD0–PD3 command candidates for DC M1/M2 |

The register ranges are grounded in the [GD32F30x manual]
(https://www.gigadevice.com/product/mcu/main-stream-mcus/gd32f30x-series/gd32f303),
not inferred from an arbitrary four-byte literal.

## Existing externally corroborated physical pins

| Motor | Driver inputs | Current sense pad | Possible ADC channel |
| --- | --- | --- | --- |
| M1 | PD3, PD2 | PC5 | 15 |
| M2 | PD1, PD0 | PC0 | 10 |
| M3 | PD15, PD14 | PA1 | 1 |
| M4 | PD13, PD12 | PA0 | 0 |

The user has confirmed the matching board wiring, but the channel
identifiers only follow silicon pin-multiplexing rules. Original OEM
ADC initialization, rank scheduling, data buffer destinations and
motor-specific current scaling remain **unverified**.

## Why raw ROM references are not enough

A peripheral address in a constant pool does not establish that code
executes it. Thumb disassembly starting at arbitrary halfword positions
can produce false code matches over data. Conversely, a compiler may
create addresses from register arithmetic without storing a complete
constant in ROM. Therefore this audit reports raw literal sites and
**candidate** PC-relative loads, with no affirmative assertion about
ADC reads, control-flow coverage or physical motor inactivity.

The next evidence threshold is a real, validated code path from
ADC clock/channel configuration through conversion trigger and data
read, to a RAM consumer and an associated motor. The corresponding
GPIO-D requirement is a manufacturer call path showing which
routine *actually drives* PD0–PD3.

## Safety and release disposition

Tachometer FG at PE11 is specific to the BLDC; absence of pulses does
not prove the BLDC disabled or mechanically stopped. DC current-sense
channels, if used, could indicate electrical load but zero current
does not prove stopped inertia or a disengaged mechanical mechanism.
No combination of these *potential* signals authorizes the CFS
volatile SET/RESET mechanism until every motor and IRQ/task start path
has an independent, atomically sampled no-motion condition.

**No installed CFS register was read, no motor was moved, no Kalico or
CM5 changes, no firmware patch or flash.** The nine v3.23 release
gates remain false.
