> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.23 — Original ADC0 conversion-data code recovered

*13 October 2026. Evidence: SHA-pinned saved CFS v3.13 and v3.22 applications; no live MCU access.*

## Verified new distinction: firmware supports a generic ADC result read

The original manufacturer code at physical Thumb PC
`0x08022BBC` contains the four instructions below:

```asm
0x08022BBC   ldr   r0, [pc, #0xc8]   ; ROM[0x08022C88] = 0x40012408
0x08022BBE   adds  r0, #0x44         ; 0x4001244C
0x08022BC0   ldr   r0, [r0]          ; reads ADC0_RDATA
0x08022BC2   bx    lr
```

The GD32F30x manual identifies `0x40012408` as `ADC0_CTL1` and
`0x4001244C` as the ADC0 routine conversion data register
`ADC_RDATA`. This is **stronger than finding a constant address in ROM**:
there is an original Thumb helper whose instructions **would**
read the ADC conversion-result register if executed. We have
**not proved that the stock application actually invokes it**.

The saved ROM also contains helpers at `0x08022926` and
`0x08022932` setting/clearing mask `0x00800000` in
`ADC0_CTL1`; another at `0x08022988` derives `ADC0_CTL0`
(`ADC0_CTL1 - 4`) and updates selected bits. Those are
peripheral-control operations, **not direct evidence that the CFS
application calls them to measure a particular motor**.

## Original callsite census: zero direct BL references

The bounded saved-ROM census found **zero directly encoded Thumb
`BL` calls to physical address `0x08022BBC`**, in both the
v3.13 and v3.22 images. This prevents interpreting the helper
as evidence that a motor current is being sampled.

The subsequent independent scan also found **zero aligned
32-bit ROM words** containing either the physical helper pointer
`0x08022BBC` or the Thumb entry pointer `0x08022BBD`.
This strengthens the possibility that it is **unreachable
library code retained in the image**, but does not establish
dead-code status: indirect addresses may be computed, stored
through relocation, or reached via a less direct control path.

Neither scan proves any brushed-motor current measurement.

## Crucial missing link

The four externally verified brushed-motor current-sense pins
are PC5 / PC0 / PA1 / PA0 (possible channels 15/10/1/0).
The existence of a generic `ADC0_RDATA` helper alone does
**not establish** that the original firmware configures
those channels, triggers their conversions, or routes their
results to M1–M4 motor control.

The next evidence needed is a *source-accurate callgraph* from
ADC channel selection and conversion initiation to the
`ADC0_RDATA` helper (or a DMA path), followed by the exact
consumer/threshold state in RAM. No invented channel list or
current calibration has been applied.

## Warning: a “read” may affect peripheral state

GD32F30x documents that reading `ADC_RDATA` can clear its
end-of-conversion (EOC) flag. Therefore this is **not a
license to periodically poll the live ADC data register from
the CM5, debugger or an ad-hoc MCU hook**: such access can race
the firmware's conversion state and affect its normal operation.
The offline code only disassembles saved ROM and does not touch
hardware.

The matching script
`cfs_adc0_rdata_source_provenance.py`
pins 17 original instruction sites in the saved v3.13/v3.22
images and enumerates direct Thumb BL callsite candidates.
`cfs_adc0_ctl1_original_source_trace.py`
preserves bounded surrounding manufacturer instructions.

## PD0–PD3 controls are still unqualified

An independent scanning pass
`cfs_m1_m2_gpio_helper_callsites.py` found **122
candidate direct BL sites** to original GPIO-helper PC
`0x08018EEC`, but none paired with immediate
`r0 = 0x30..0x33` in the narrow preceding heuristic
window. This is *not evidence* M1/M2 are unused:
the pin identifiers could originate in tables, registers,
or other helper callpaths. Complete dataflow remains open.

## Release status

- Saved v3.22 rebuild and manufacturer ADC0 code analysis are offline.
- Operator-confirmed wiring and OEM 16-pin logical table remain valid.
- **No actual current values measured; no calibrated physical motor
  stop/driver deenergization or atomic IRQ/task exclusion proven.**
- **No v3.23 flash authorization.** The original firmware and
  host Kalico remain unchanged.

References: [GD32F303 vendor documentation]
(https://www.gigadevice.com/product/mcu/main-stream-mcus/gd32f30x-series/gd32f303)
and the saved original firmware in this project.
