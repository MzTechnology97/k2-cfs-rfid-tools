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
