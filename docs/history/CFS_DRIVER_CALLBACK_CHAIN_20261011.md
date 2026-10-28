> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# Original CFS motor-related driver callback chains — 2026-10-11

**Status: offline ROM and differential Unicorn evidence; not a physical motor test.**

This audit extends the source-accurate motor callgraph in
[PR #18](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/18).
It compares original Creality CFS application 1.5.3 (SHA256
`5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea`)
against the tested v3.22 (SHA256
`40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`).

No firmware, MCU peripheral, bootloader, serial interface or operating
printer was accessed. The ROM source is privately held on the CM5;
the repository contains no Creality original binary.

## Path A — typed device request, ultimately indirect

Stock `0x0801E0CC` calls `0x08026516` and
`0x08026488` after computing a duty-related value. These are
device command **encoders**, not direct MCU PWM register accesses.

- `0x08026516`: prepares a stack request and uses ID **`0x1E02`**.
- `0x08026488`: uses IDs **`0x1E05`/`0x1E04`** based on
  a numeric sign, then **`0x1E00`**.
- Both use `0x08023A92`, which validates the device object via
  `0x0802E198` and a type code `9`. It loads a callback from
  **`[object + 0x38]`** at `0x08023AC2`, then tail-calls via
  **`BX R3`** at `0x08023AD0`.
- When the object's callback pointer is zero, original ROM returns
  **`0xFFFFFFD3`**; no physical peripheral callback is invoked.
- When the callback exists, its return code is propagated. A
  `0` callback return remains `0`; a synthetic `0x5A` callback
  return remains `0x5A`. This demonstrates an arbitrary software
  callback result, **not successful mechanical completion**.

The referenced request IDs are internal ABI constants of a generic
device driver. Their physical mapping and timing still require
tracking the *actual object instance*, its registered callback owner,
and its peripheral/hardware implementation.

## Path B — output line / GPIO-like global callback table

The forward/reverse wrappers `0x0801E164`/`0x0801E17E`
and zero wrapper `0x0801E198` all invoke
`0x08025EEC` (typically a line/index such as `0x44` and value
0/1) as part of control preparation.

The original ROM accesses the root pointer literal
`0x0802616C = 0x20004C44`, loads an interface pointer via
`[root + 0x40]`, then the callback at
`[interface + 0x04]` and jumps to it via `BX R3`
at **`0x08025F12`**.

Separate original setup code at `0x08025DFA` assigns a provided
interface pointer into `[root+0x40]` at `0x08025E1A`.
This registration is a caller-provided pointer; the motor-facing
callback owner's implementation was **not established**.

A simulated callback returning 0 or `0x5A` produces the same
return code in this call path. That makes this interface an
indirection/transport boundary, not an independent motor
`stopped` acknowledgement.

These are two **different** driver dispatch schemes and MUST NOT
be conflated into a single vtable or assumed to belong to the
same physical motor.

## Additional relevant original code

The initializer at `0x0802644A` separately stores a function
pointer loaded from literal `0x08026868 = 0x0801939D`
into **`[object+0x38]`**. Its single direct BL caller is
`0x08028408`. Although this is an interesting possible
provider of an object callback, proving that the runtime *object
instance* behind `0x08023A92` is initialized by
`0x0802644A` requires further object-identity/flow work.
We **do not assert** that the assignment is the motor callback.

The separate GPIO-like interface has callbacks underneath
`0x20004C44 + 0x40`; its actual owner is likewise unproven.
The existence of callbacks does not tell us whether their
responses mean request accepted, bus transmission completed,
position achieved or actual rotor stopped.

## Exact original-v3.22 emulator experiment

[`motor_driver_callback_chain_audit.py`](https://github.com/MzTechnology97/k2-cfs-rfid-tools/blob/0ad22669248cc845a3c8d22dd613500c4b95feb3/firmware/v3.22-readonly-state-probes/motor_driver_callback_chain_audit.py)
runs the original Thumb dispatch routines with **synthetic**
device objects and callback tables in Unicorn.

| Interface | Installed callback | Mock result | Dispatcher result |
| --- | --- | ---: | ---: |
| Device request 0x1E02 | Yes | `0` | `0` |
| Device request 0x1E02 | Yes | `0x5A` | `0x5A` |
| Device request 0x1E02 | No | N/A | `0xFFFFFFD3` |
| GPIO-like global | Yes | `0` | `0` |
| GPIO-like global | Yes | `0x5A` | `0x5A` |

The emulator intercepts the instruction pointer at a *fake*
`0x08050000` callback and injects a deterministic result. No
hardware function is actually run. The two dispatcher models,
original and v3.22, returned identical results for all five
cases.

Safety controls:

- **27 original Thumb instructions** in the interface paths
  are validated by exact disassembly at known ROM addresses,
  including the indirect `BX R3` instructions.
- **Nine deliberately modified original instructions/pointers
  with recomputed valid application CRC** are all rejected.
  The BX test flips a *meaningful* opcode bit rather than an
  unused encoding bit.
- The script pins both source SHA256 hashes; no original vendor
  BIN is committed.
- The public CI rebuilds the verified exact v3.22 and repeats
  the five simulation cases and nine mutations.
- A return value from a synthetic callback MUST NOT be used
  as proof of motor activity, mechanical completion, encoder
  feedback or configuration-write safety.

## Remaining v3.23 MCU requirements

1. Find the concrete object identity and the callback implementation
   used for the feeder/hub devices, including any shared IRQ,
   DMA or asynchronous completion queues.
2. Obtain independently meaningful motor running/stopped/encoder
   or drive-enable feedback, not merely a software command
   or generic dispatcher return.
3. Prove actual MCU stack, heap and timing headroom for the
   event-ring instrumentation, including RTOS/ISR ownership.
4. Verify the real Creality bootloader app length/erase
   boundary: the old `0x0803B800` engineering cap remains
   unverified but empirically important.
5. Keep [firmware safety issue #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9)
   and [offline v3.23 PR #12](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/12)
   blocked until those gates are independently satisfied.

**Do not flash a new CFS binary or weaken the existing
Kalico motion/write exclusion based on these mock callbacks.**
