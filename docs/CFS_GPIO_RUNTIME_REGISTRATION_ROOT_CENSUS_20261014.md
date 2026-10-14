# CFS v3.23 — RT-Thread GPIO runtime callback boundary
*14 October 2026 · source-only continuation of PR #24*

## Confirmed starting point

The original saved v3.13/v3.22 applications are linked at
`0x08003000`. At physical PC `0x08018EEC`, the RT-Thread GPIO
helper accepts a **logical pin in r0** and a **requested value in
r1**. It accesses a runtime global object at `0x20004C44` and
loads the registered device field at `0x20004C84`. It then
fetches the driver's operation from `[device + 4]` and
dispatches indirectly via `BX r3`.

`0x20004C84` is in the application's **zero-initialized BSS**,
not the 3,012-byte compressed initial SRAM block. Consequently
the saved firmware is not a valid *post-RTOS-initialization memory
snapshot*: the actual installed GPIO callback cannot simply be
recovered by reading an APP ROM literal or the decompressed image.

Original known direct example:
`0x0801119A MOVS r1,#1;`
`0x0801119C MOVS r0,#0x44;`
`0x0801119E BL 0x08018EEC` controls BLDC PE4 brake.
Prior audits found 122 candidate ROM BL encodings, but
only nine immediately adjacent pinned arguments related to
PE3/PE4. M1/M2 PD0–PD3 arguments remain unproven by that
restricted method. Their physical wiring and OEM logical pin
IDs are known, but callsite and driver ownership are not.

## This continuation's new source audit

`firmware/v3.22-readonly-state-probes/cfs_gpio_runtime_registration_root_census.py`
enumerates aligned original ROM constants matching the known
global object `0x20004C44` or the derived device field
`0x20004C84`. It validates PC-relative Thumb load candidates
and follows at most 20 instructions of a deliberately narrow
straight-line subset to report potential direct field reads or
writes. A branch, unmodelled opcode, unknown base, or
indirect transfer **ends the trace** rather than inventing
pointer values or continuing beyond uncertain source.

The source-pinned dispatcher loads at `0x08018EEE` and
`0x08018F10` must be represented among the candidates.
Results from independently pinned v3.13/v3.22 are compared.
The published script explicitly withholds any assertion that
a candidate field write is reachable or that the post-init
driver function pointer has been recovered.

This bounded source scan is **not** a whole-program
control-flow graph. An original GPIO registration writer may
use a different base pointer, a generic allocator, an
indirect function, or multi-basic-block dataflow that
the scan intentionally does not track.

## CI-confirmed bounded census

[GitHub Actions run 38549228653](https://github.com/MzTechnology97/k2-cfs-rfid-tools/actions/runs/38549228653)
completed successfully on 14 October 2026. The same pinned
results were obtained for v3.13 and v3.22:

| Bounded source statistic | Verified count |
| --- | ---: |
| Original aligned ROM constants pointing to `0x20004C44` | **1** |
| Candidate Thumb PC-relative LDRs of that constant | **15** |
| Candidate short traces reading `[global+0x40]` | **7** |
| Candidate short traces writing `[global+0x40]` | **0** |

For example, the original `0x08018E32` LDR of
`0x20004C44` is followed at `0x08018E38` by
`LDR r0,[r4,#0x40]`, reading physical BSS field
`0x20004C84`. This helps isolate the ROM code that
**consumes** the registered device, but still does
not identify the registration-time writer or
`[device+4]` callback.

A zero write count applies **only** to the narrow constant-plus-
straight-line syntax accepted by this script. It is not proof
that no code initializes the device: generic register
functions, indirection, multi-block flow, RAM-loaded pointers
and computed addresses remain possible.

The workflow now pins the exact counts to detect unexpected
changes in the manufacturer/source evidence. Such counts
are **not** proof of firmware runtime execution.

## Focused source neighborhood after the initial census

[CI run 38549755204](https://github.com/MzTechnology97/k2-cfs-rfid-tools/actions/runs/38549755204)
completed successfully. The source-only window
`0x08018D80..0x08019000` yielded **one** Thumb halfword
decoded as a potential `STR [register,#0x40]` writer:

```asm
0x08018DFE  LDR r1, [PC, #0x36C]  ; ROM literal -> 0x20004C44
0x08018E1A  STR r4, [r1, #0x40]   ; candidate target 0x20004C84
```

It also found additional `LDR [register,#0x40]` patterns,
including independently authenticated original reads of the
device BSS field. There are 29 halfword candidates for `BL`,
four `BLX`, three `B` and six `BX` in the bounded region.
These counts include possibly unrelated or ambiguous code
decodings and are **not function-level execution counts**.

**Most promising next check:** the sequence between
the original `0x08018DFE` global root LDR and
`0x08018E1A` store. The new
`cfs_gpio_registration_store_r1_liveness_audit.py` pins
both manufacturer instructions, verifies the global ROM literal
and conservatively records all intermediate writes to r1 and
branch/stack barriers. Even if the source has no such barriers,
a runtime registration trace is **not** yet proven.

## Registration-field writer: original source-level dataflow verified

The dedicated [CI run 38550226589](https://github.com/MzTechnology97/k2-cfs-rfid-tools/actions/runs/38550226589)
passed for both saved original v3.13 and v3.22. It disassembles
the **contiguous original Thumb instructions** between the
literal load and the unique candidate store:

```asm
0x08018DFE  LDR  r1, [pc, #0x36c]  ; ROM literal = 0x20004C44
0x08018E00  MOVS r3, #0x19
0x08018E02  STRB r3, [r1, #0x14]
0x08018E04  MOVS r3, #0
0x08018E06  STR  r3, [r1, #0x1c]
0x08018E08  STR  r3, [r1, #0x20]
0x08018E0A  STR  r3, [r1, #0x24]
0x08018E0C  STR  r3, [r1, #0x28]
0x08018E0E  STR  r3, [r1, #0x2c]
0x08018E10  LDR  r3, [pc, #0x35c]
0x08018E12  STR  r3, [r1, #0x30]
0x08018E14  LDR  r3, [pc, #0x35c]
0x08018E16  STR  r3, [r1, #0x34]
0x08018E18  LDR  r3, [pc, #0x35c]
0x08018E1A  STR  r4, [r1, #0x40]   ; physical BSS field 0x20004C84
```

Capstone independently reports **no write to r1**, no
intervening branch, and no stack barrier in this range.
Thus the source is sufficient to attribute the store
**at `0x08018E1A` to `0x20004C84` if that block executes**.
This is a stronger finding than the earlier local-register census,
which began tracing only at the literal load and did not
recognize every intervening instruction.

The original source demonstrably initializes numerous global
fields and writes the runtime GPIO device pointer field from
register `r4`. This still does **not** identify the value of
`r4`, establish when the register-init block is called,
or authenticate the installed callback at `[device+4]`.
The run is emulated/source-only; no real MCU execution trace or
live BSS memory was acquired.

**Next source task:** trace where register r4 obtains the device
pointer in the function preceding `0x08018DFE`, and connect
that function's entry/callers to the OEM GPIO registration
flow. Only then investigate the operation callback and M1/M2
ownership. An apparent producer of the device pointer is not
motor-idle feedback.

## Separation of evidence levels

- **Verified source address:** ROM literal and exact Thumb
  instruction sequence from SHA-pinned saved firmware.
- **Candidate local dataflow:** arithmetic and memory operations
  within a short straight-line trace. No task reachability
  or runtime callback installation is implied.
- **Hardware wiring reported by operator:** BLDC PE13/PE11/
  PE3/PE4; DC motor M1 PD3/PD2 with PC5 current sense,
  M2 PD1/PD0 with PC0, M3 PD15/PD14 with PA1, M4
  PD13/PD12 with PA0. This does not prove live MMIO activity.
- **Still missing:** actual GPIO device-registration
  callback, M1/M2 command producers, ADC channel conversion
  ownership, measured electrical current, motor stop evidence
  and synchronization of MCU SET/RESET against all
  motor start/IRQ paths.

## Next source inspection

First use the bounded candidate counts to select the smallest
verified registration-writing function. From there, reconstruct
the runtime device object initialization from the *real
registration path*, without assuming that the pointer in
zeroed SRAM has a compile-time value. Only after its actual
callback is established can PD0–PD3 GPIO operations be
attached to an original motor start/stop producer.

Reading `ADC_RDATA` from live CFS remains inappropriate
without a verified non-invasive path because it may alter
EOC status. No CFS, CM5 or Kalico files, registers,
motor positions or flash were changed by these audits.

**Release decision:** the v3.23 safety interlock, Flash
partition and hardware regression gates remain OPEN
as problems (release denied); no flashable v3.23 BIN
or motor-active MCU write authorization is provided.
