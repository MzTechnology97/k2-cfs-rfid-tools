# CFS GD32 OEM `pin` registration, GPIO write callback and M1/M2 PD0–PD3

*15 October 2026 · Original saved v3.13/v3.22, SHA-pinned · source-only, no CFS interaction.*

## Previously unresolved GPIO driver pointer — now recovered at the source level

The original manufacturer code performs pin-device registration through a
**tail branch**, not through a direct `BL`. The earlier zero-`BL`
census for `0x08018DFA` was accurate but incomplete.

| Source PC | Manufacturer instruction | Static evidence |
| --- | --- | --- |
| `0x0801AE2A` | `LDR r1,[pc,#0x30]` | `ROM[0x0801AE5C] = 0x0802B45C` |
| `0x0801AE2C` | `MOVS r2,#0` | Register third argument |
| `0x0801AE2E` | `ADDS r1,#0x40` | `r1 = 0x0802B49C` |
| `0x0801AE30` | `ADR r0,#0x2C` | `r0 = 0x0801AE60`, ASCII `pin\0` |
| `0x0801AE32` | `B.W 0x08018DFA` | Tail-call manufacturer RT-Thread pin registrar |
| `0x08018DFA` | `PUSH {r4,lr}` | Verified function entry |
| `0x08018DFC` | `MOV r4,r1` | Captures ROM table argument |
| `0x08018DFE` | `LDR r1,[pc,#0x36c]` | `ROM[0x0801916C]=0x20004C44` |
| `0x08018E1A` | `STR r4,[r1,#0x40]` | Installs `0x0802B49C` in **BSS** field `0x20004C84` **if initializer runs** |

This provides a concrete *candidate value* for the formerly unknown BSS
registration pointer, based on original ROM **caller argument provenance**
rather than assuming zeroed SRAM contained a runtime snapshot.

### Original startup init table makes the source chain traceable

The initializer is **not an orphan function**. ROM slot
`0x0802D764` holds Thumb function pointer `0x0801AE2B`,
which is the original `pin` registrar initializer at `0x0801AE2A`.
The manufacturer's early initialization loop
`0x0801D584` loads the start `0x0802D758` from literal
`0x0801D620`, loads the exclusive end `0x0802D774`
from `0x0801D624`, then executes `LDR r0,[r4]; BLX r0;
ADDS r4,#4; CMP r4,r5; BLO ...` to invoke each of the
seven ROM function pointers in that range. The initializer
pointer `0x0802D764` is **inside** this exact range. Original
`0x0801A8E0 BL 0x0801D584` calls the loop.

This materially strengthens the GPIO registration evidence:
we can now identify a source-level OEM startup caller and its
indirect callback table rather than merely an isolated helper
plus speculative BSS initialization. It is **not** a successful
physical boot trace, a proof that this loop always executes,
or evidence of active motor status.

### Exact six-entry GPIO device operations table

Each entry contains the real Thumb function pointer (low bit set):

| Slot | OEM function | Pointer stored at ROM `0x0802B49C + slot*4` |
| --- | --- | --- |
| `+0x00` | mode | `0x0801AB4F` |
| `+0x04` | write | `0x0801AB91` |
| `+0x08` | read | `0x0801ABAB` |
| `+0x0C` | attach_irq | `0x0801ABC7` |
| `+0x10` | detach_irq | `0x0801AC3F` |
| `+0x14` | irq_enable | `0x0801AC87` |

The OEM helper `0x08018EEC` fetches `[global + 0x40]` via
`0x08018EF4 / 0x08018F04`, then fetches callback `[ops + 4]`
at `0x08018F0A`, dispatching using `BX r3` at `0x08018F12`.
This matches the ROM operation `write` at `0x0801AB90`.

### Output drive chain down to GPIOD BOP / BC

`0x0801AB90` (manufacturer `pin_write`) calls the OEM logical-pin
table lookup `0x0801AB38`, loads `[pin_record+8]` to r1
(one-hot pin mask), loads `[pin_record+4]` to r0
(GPIO peripheral base), and tail-jumps `B.W 0x0802381E`.

At `0x0802381E`, the original code checks `r2` (requested
output value). A nonzero value stores the mask to
`[r0+0x10]` (GPIOD **BOP** set register), while zero
stores the mask to `[r0+0x14]` (GPIOD **BC** clear register).
The ROM callback does not infer or sample electrical feedback;
it **commands** GPIO levels.

The board pin lookup is a 16-byte record table at
`0x0802AD5C + (logical_id << 4)`:

| Logical ID | Motor wire | Physical pad | Base | Mask |
| --- | --- | --- | --- | --- |
| `0x30` | M2 input | PD0 | `0x40011400` | `0x01` |
| `0x31` | M2 input | PD1 | `0x40011400` | `0x02` |
| `0x32` | M1 input | PD2 | `0x40011400` | `0x04` |
| `0x33` | M1 input | PD3 | `0x40011400` | `0x08` |

Therefore the OEM's GPIO helper is *capable* of driving
M1/M2 via the same identified registered operations callback.
**We have not established which motor tasks, interrupts or
higher-level calls issue PD0–PD3 writes**, nor whether all physical
paths use this driver.

## Reproducibility and safety guards

`firmware/v3.22-readonly-state-probes/cfs_gpio_pin_ops_registration_and_m1m2_gpiod_audit.py`
pins source opcodes, literal/ADR arithmetic, six actual function
pointers, the BSS registrar argument chain, callback dispatch, GPIO
write implementation, and four M1/M2 physical pin table records
against **both** saved SHA-pinned firmware generations. The audit
includes **nine corruption fixtures** (table pointer, registrar
branch, write branch, GPIOD BOP write opcode, PD0 pin record,
device string, startup vector pointer, startup loop start bound and BLX opcode); all are rejected by code-specific assertions.

**Local CM5 result: 6/6 pin ops, 4/4 PD0–PD3 records, 9/9 fail-closed
mutation scenarios.** The CI independently reproduces the source-only
audit against the exact rebuilt v3.22.

## Still unproven / forbidden

- The board registration entry `0x0801AE2A` is source-confirmed;
  a *live runtime invocation* of that entry on the production CFS,
  the populated SRAM value and ISR/task schedule have **not** been
  independently observed.
- GPIOD BOP/BC writes are **commands**, not independent proof that
  motor drivers or shafts responded. No actual PD0–PD3 level,
  current, encoder speed or motor standstill has been captured.
- Caller ownership of M1/M2 start/stop functions, M3/M4 coverage,
  and atomicity across interrupts remain unknown. The observed
  `BOX_STATE=IDLE` during feeding still prevents any MCU
  SET/RESET release (see issue #9).
- No changes to Kalico, no real firmware BIN for deployment,
  no serial operations, no live peripheral reads or motor actions.
  **v3.23 flash and motor-active MCU writes remain blocked.**
