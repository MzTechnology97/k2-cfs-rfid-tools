# CFS v3.23 — original ADC register-operation dataflow audit

*14 October 2026 · PR #24 · offline disassembly of saved, SHA-pinned v3.13 and v3.22 binaries.*

## Scope and next hypothesis

The CFS operator confirmed the board connections for all five
motor assemblies. The four brushed-motor current-amplifier signals
are **PC5 (candidate ADC channel 15), PC0 (10), PA1 (1), PA0 (0)**.
The GD32F30x user manual documents ADC0/ADC1/ADC2 peripherals and
registers. That hardware capability does **not** prove the OEM
firmware sampled these four motor currents.

A previous audit source-pinned a genuine manufacturer Thumb helper
at **`0x08022BBC`** which, if invoked, performs a read of
**ADC0_RDATA at `0x4001244C`**; zero direct BL and zero aligned
ROM pointer references to the helper were found. It might be an
unreachable generic library routine or accessed indirectly.
A live read of RDATA could clear EOC and disturb the firmware.

## New bounded register dataflow

`cfs_adc_bounded_register_dataflow.py` independently scans the
original saved v3.13 and v3.22 image bytes under the verified
physical APP link base **`0x08003000`**. It finds aligned ROM words
representing ADC0/ADC1/ADC2 register addresses, checks the actual
PC-relative Thumb `LDR` loads and follows **a single straight-line
register base** through strictly recognized immediate `ADD/SUB`
operations and direct memory `LDR/STR` instructions.

Register role classification is grounded in the GD32F30x manual:

| Register | Offset from ADC peripheral base | Purpose |
| --- | --- | --- |
| `CTL0` / `CTL1` | `0x04` / `0x08` | Control |
| `SAMPT0` / `SAMPT1` | `0x0C` / `0x10` | Channel sampling times |
| `RSQ0` / `RSQ1` / `RSQ2` | `0x2C` / `0x30` / `0x34` | Regular conversion rank sequence |
| `RDATA` | `0x4C` | Result register (potential EOC side effect) |

The analysis stops at any branch, indirect transfer, unknown tracked
base clobber, or 15 instructions. Even an identified register read
or write is a **source-level candidate**, not proof that the
operation is reachable, executed, synchronized with a motor task or
safe to mirror from another debugger.

For regression the tool must rediscover the original ADC0_RDATA read
at `0x08022BC0` and fail if the manufacturer instructions
no longer support the operation. Other RSQ/SAMPT candidates are
reported for follow-up rather than accepted as a completed current
feedback solution.

Official GD32F30x manual:
https://www.gd32mcu.com/data/documents/userManual/GD32F30x_User_Manual_Rev2.9.pdf

## Executed CI finding (14 October 2026)

The first complete GitHub Actions execution
[run 38527464975](https://github.com/MzTechnology97/k2-cfs-rfid-tools/actions/runs/38527464975)
**succeeded**. The original SHA-pinned v3.22 image produced
**nine candidate local ADC0 accesses** in the strictly bounded
Thumb syntax windows:

| ADC0 register | Local reads | Local writes |
| --- | ---: | ---: |
| `CTL0` | 2 | 2 |
| `CTL1` | 2 | 2 |
| `RDATA` | 1 | 0 |
| `RSQ0`, `RSQ1`, `RSQ2` | 0 discovered | 0 discovered |
| `SAMPT0`, `SAMPT1` | 0 discovered | 0 discovered |

The workflow now **pins these exact results** to detect accidental
regression. The saved ROM clearly contains generic ADC0 control and
result-access helpers, but this analysis has not linked them to
conversion rank configuration, the motor current pads, the running
motor task, or ADC result RAM consumers.

Importantly, the zero RSQ/SAMPT result is **bounded to this
literal-plus-short-sequential-Thumb method**, not an exhaustive
whole-program finding: generic helpers may calculate register
addresses dynamically, use MOVW/MOVT, indirect calls, DMA or runtime
function pointers. Calling the ADC unused would therefore
overstate the evidence.

## Safety status

**Not yet proven:** selection or triggering of ADC channels 15/10/1/0,
conversion consumer/threshold data in RT-Thread tasks or RAM,
brushed-motor driver current calibration, electrical fault diagnosis,
mechanical stopped state, all start/IRQ coverage, atomic MCU
SET/RESET exclusion, loader partition safety, or hardware recovery.

The nine-condition v3.23 release gate remains CLOSED. No firmware
BIN is produced, no live ADC or GPIO register is read, and no
CFS/CM5/Kalico files or motor positions are changed.
