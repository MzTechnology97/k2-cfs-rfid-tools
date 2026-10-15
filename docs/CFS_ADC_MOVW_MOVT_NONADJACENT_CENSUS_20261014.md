# CFS v3.22 — bounded, non-adjacent ADC address construction census

*14 October 2026 — offline, SHA-pinned v3.13/v3.22 firmware inspection. No device I/O.*

## Motivation

Prior ADC research verified an original GD32 ADC0 result-reading
helper at physical PC `0x08022BBC`, which would access
`ADC0_RDATA=0x4001244C` if called. Original direct BL and
aligned ROM-function-pointer scans did not identify its callers.
An adjacent `MOVW/MOVT` search found no direct ADC register
addresses, but it did not examine addresses assembled across a
few intervening instructions. This test closes **only** that
specific syntax gap.

A potential live ADC_RDATA read may clear EOC, therefore
current telemetry must NOT poll that register independently.

## Added reproducible audit

`cfs_adc_movw_movt_bounded_reachability.py` scans original
saved APP ROM as linked at **`0x08003000`**:

1. Decode possible Thumb `MOVW Rn,#imm16` starts on halfword
   boundaries, including a small number of false data decodes.
2. Advance at most **12 original contiguous instructions**.
3. Stop on branch, conditional IT block, indirection, decode
   failure or any intervening write to the tracked register.
4. Accept only a later `MOVT` on the **same register**;
   assemble the 32-bit immediate and compare with the
   documented GD32 ADC0/1/2 MMIO ranges.
5. Keep address-construction matches separate from evidence
   of an actually reachable ADC conversion or a motor-current
   consumer.

The decoder has an artificial MOVW/NOP/MOVT fixture
forming `0x4001244C`, verified independently by
the Capstone ARM Thumb disassembler. This is a
**synthetic unit test**, not a CFS firmware hit.

## Findings from initial CI output

| Metric | Saved v3.13 | Saved v3.22 |
| --- | ---: | ---: |
| Potential `MOVW` halfword starts | 363 | 364 |
| Bounded candidates constructing an ADC0/1/2 address | **0** | **0** |

The extra v3.22 `MOVW`-shaped start is consistent with changed
binary contents; source-wide candidate counts are not required
to match across distinct builds. CI now checks the actual
version-specific counts and **equal empty ADC candidate lists**.
The first test run's failed assertion required whole-scan
identity in error; it was corrected without changing either
firmware binary.

## Safety and limitations

These findings do not constitute whole-program control-flow
proof. Firmware can construct an ADC address through nonadjacent
register arithmetic, ROM tables, generic peripheral drivers,
runtime pointers, ISRs, DMA, or RAM code. A byte-disassembly
candidate may also fall inside non-executable ROM data.

**Still unproven:** channel 15/10/1/0 configuration,
actual current conversions, firmware ADC consumers and
calibration, all PD0–PD3 motor owner paths, driver
deenergization and independent physical standstill,
atomic motor-active SET/RESET rejection, RAM/Flash
release limits and a hardware recovery path.

The test runs without reading hardware and explicitly
reports `safe_to_read_live_ADC_RDATA=false`,
`motor_active_SET_RESET_write_or_v323_flash_allowed=false`
and `real_device_interaction=false`.

No firmware BIN, CFS/CM5/Kalico changes, motion, NVM or
flash operation were performed.
