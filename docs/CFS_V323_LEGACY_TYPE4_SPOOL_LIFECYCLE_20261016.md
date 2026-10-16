# CFS v3.23 — legacy type-4 spool removal lifecycle

*2026-10-16 — source-only, strictly OFFLINE functional prototype stacked on #43.*

## Purpose and scope

The earlier v3.23 drafts #39–#41 enable **live remaining-filament
percentage** on legacy (no FM15L013) CFS boards and protect two OEM
secure-element calls during the original usage task.

Their type-4 RAM record and displayed percent can become **stale
after physically removing a spool at rest**, because the original
Creality inlet-removal event does not clear the private usage
record. Merely clearing a record whenever the inlet becomes empty,
however, would be unsafe **during an ongoing print/runout**.

This change adds the smallest possible dedicated lifecycle hook for
**legacy type-4, valid, not-printing records**. It never replaces
the original Creality event handler, and does **not** treat a
physical inlet transition as proof of safe motor state.

## Verified manufacturer callsites

Two **SHA-pinned original** CFS APP versions v3.13 and v3.22
were independently disassembled:

| Original ROM PC | Meaning |
| --- | --- |
| `0x08006414` | OEM filtered inlet insert/removal processing |
| **`0x080064A6`** | original `BL 0x08005654` on a removed slot |
| `0x08005654` | OEM sets inlet-present flag to 0, slot event 2, pending-event flag 1 |
| `0x0800DC70` | OEM runtime clear: sets record valid=0, used_mm=0, dirty=0, mode=0 |
| `0x080053E4` | OEM percent setter for `0x2000391C + 0x58 + slot` |
| `0x0800DC94` | existing OEM usage task — **never invoked by this hook** |

The OEM runtime table at `0x20004590 + 100*slot`
contains `valid(+0x17)`, `mode(+0x16)`,
`type(+0x63)`, consumed millimetres `(+0)`.

One additional source-only Thumb wrapper substitutes the BL at
**`0x080064A6`**:

1. Always call **original** `0x08005654` with the same logical slot,
   preserving the firmware's original sensor event and FIFO behavior.
2. Reject slot outside 0..3; do not touch its record.
3. Do **nothing additional** if FM15L013 hardware flag is present
   (or unexpectedly nonzero): secure boards stay OEM.
4. On chipless boards only, validate the **existing RAM runtime
   record**, requiring `valid==1`, `type==4` and `mode!=1`.
5. Call the **original OEM runtime-clear** for this slot and
   **original percent setter with 255 (`0xFF`)**. This invalidates
   the stale old spool data without writing to the tag or adding
   persistent storage.

**Critical print/runout distinction:** if a record is in
`mode==1` (PRINT), only the original OEM removed event is
emitted; the runtime and displayed percentage are not cleared
mid-print. A confirmed printer runout is a separate BOX_STATE
status **`0x50`**, and the host must handle that state
(persist/reset consumed spool status) distinctly from ordinary
spool removal at rest. The firmware cannot reliably infer whether
an inlet drop is user removal or runout from that signal alone.

## Compilation and full OEM callsite emulation

The script
`firmware/v3.22-readonly-state-probes/cfs_v323_type4_spool_lifecycle_candidate.py`
regenerates the **exact 178,352-byte** #40 application in memory,
rebuilds the expanded source and validates only approved new
inbound BL hooks, original ROM prefix, physical-address relocation,
the same heap pointer, original firmware header and CRC16.

- Previous type4+FM15L013 candidate: **178,352 bytes**.
- Extended slot-removal candidate: **178,416 bytes (+64)**.
- Physical APP end exclusive **`0x0802E8F0`**,
  page index **93**, far below parameter-page start
  **`0x0807F800`**; actual installed loader restrictions are
  **not** thereby qualified.
- Incoming old 14 OEM hooks, 1 type4 live gate,
  2 FM15L013 guards + **1 new removal hook = 18**.
- External OEM code references: 18 from the parent,
  + original removal callback + original clear +
  original percent setter = **21**.
- No additional global SRAM, ring buffer, hidden tag state,
  GPIO, RFID reader/backend or firmware-output file.

The regression actually runs the original OEM instructions
`mov r0,r6; BL ...` at `0x080064A4/0x080064A6`
under ARM Thumb Unicorn, NOT merely calls the new wrapper.
All **four physical slots** are covered across eight
record/chip/mode combinations (**32 scenarios**).

Assertions include:

- Every scenario preserves original manufacturer event **2**
  and slot-absent flag.
- Valid chipless type4 in mode 0 or 2: original record clear,
  `valid=0`, reported `0xFF`.
- Valid chipless type4 **printing mode 1**: no premature
  clear; percent and valid record survive the removed event.
- Missing record, type 7, secure board, or unexpected chip
  flag: **only original OEM event**, no additional cleanup.
- ABI preservation for R4/R5/R6 and return PC after OEM
  original BL.
- A negative mutation reverts exactly the new incoming BL
  and executes the **original callsite**; it reproduces the
  stale type4 valid record and 62% report.
- Full modified image only exists in memory. The OEM
  firmware image and installed CFS are unmodified.

## Host integration contract (NOT implemented in Kalico)

The host should make the state transition explicit and scoped
to **slot and spool identity**, not only latest percentage:

- **Physical removal/event 2 while not printing:** clear
  the corresponding saved consumed/remaining snapshot and
  invalidate any pending restore-to-CFS request. A new spool
  of the same type is not a continuation of the prior spool.
- **Confirmed runout `0x50` for active print:** record 0%
  for the depleted spool and coordinate replacement. Do not
  reinit its old runtime as 0xFF during active motion.
- **CFS reset with installed same spool:** retain saved
  host record and explicitly restore it only after UID/slot
  association is revalidated, never by matching slot alone.
- **Reinsertion of a new spool:** perform stock RFID
  measurement and initialize a new starting percentage.
  Reject stale counts from a previous spool or slot change.
- **Without the live-RFID capability advertised:** keep
  existing Kalico fallback behavior. Capability advertisement
  is deferred until the real firmware is validated.

## Still unproven / no flash authorization

- Real RT-Thread task scheduling and interrupt interactions
  between the removal event, usage task and the record-clear
  calls have not been fully proved. The new wrapper's type/mode
  snapshot and its calls are **not an atomic hardware guard**.
- A physical inlet drop **during a print** is deliberately
  not taken as permission to clear the active record. End
  of print/recovery host sequencing still needs integration tests.
- Runout `0x50`, restore `0x57/0x0B`, persistent
  `filament_box.json`, spool UID and status reporting need a
  separate tested host integration. Do not claim persistence
  already works.
- No binary Flash image is emitted. Power-cycle recoverability,
  user-installed loader byte identity, and hardware tests are
  still pending. Original nine release gates are **not met**.

This is an **offline candidate and source-level behavior test**,
not permission to flash the production CFS.
