# CFS v3.23 type-4 live usage: secondary OEM secure-sink safeguards

*16 October 2026. Draft engineering change stacked on type-4 candidate PR #39.*

## Why a second guard is needed

The earlier type-4 live accounting patch enables the manufacturer OEM
`rfid_mgr_fila_task` only for a valid, currently printing runtime record
on boards without an FM15L013. However the initial guard executes
**before** the RTOS task's body. Concurrent unload, tag removal or
record changes can make that entry-time check stale.

Two actual original ARM-Thumb callsites within the manufacturer
usage task are independently present in both saved v3.13/v3.22:

| OEM task callsite | Original target | Purpose |
| --- | --- | --- |
| **`0x0800DE68`** | `0x0800D83E` | Detect/revalidate tag through secure-element path |
| **`0x0800DEC2`** | `0x08015A42` | Write consumed usage to the **FM15L013 module**, not to the physical RFID tag |
| `0x0800DFDA` | `0x0800D670` | Downstream tag reread after a successful detection, not patched in this step |

The other agent's corrected [OpenCFS PR #6](https://github.com/MzTechnology97/OpenCFS-Firmware/pull/6)
demonstrated that type 7 updates the *secure element's keyed
record*, not the RFID tag. Our added protection targets the
actual dangerous secure-element entries, not an imaginary
tag-writing routine.

## Minimal source modification (strictly offline)

`firmware/v3.22-readonly-state-probes/cfs_v323_type4_secure_sink_guards_candidate.py`
builds on PR #39, **without editing or replacing its original source**,
and redirects only these two manufacturer task BL instructions to
small wrappers.

Each wrapper checks `hw_flag` at `0x20000000`:

- **`1`:** tail-branch to the exact original OEM function, with
  the existing `r0/r1` arguments and original caller LR intact.
  Secure-element equipped CFS continues its manufacturer routine.
- **`0` or unexpected value:** return **nonzero failure code 2**,
  without entering the OEM secure-element function. This is a
  secondary check made **at the sensitive callsite**, after the
  main live-task gate, so a stale record cannot by itself make
  a chip-less board execute these specific functions.

The source preserves all earlier 15 inbound OEM hooks, adds two
new callsites (**17 total**), and retains the 16 earlier
external OEM branches plus two original secure calls
(**18 external branches**). Firmware image changes are confined
to original known BL sites, handler extension, and CRC/length
metadata. The earlier heap modification is unchanged.

## Results

- Prior in-memory candidate: **178,320 bytes**.
- Candidate with secure-sink wrappers: **178,352 bytes**, **+32**.
- End exclusive **`0x0802E8B0`**, still physical Flash page **93**.
- CRC16 trial **`0x4BAE`**; SHA-256 trial
  `0457448fdfe2da2989fab886c988ab1997fc0b5ba93a69aa2725a2a61e74adc1`
  (identifiers of **unreleased in-memory candidates**, no firmware file).
- Six Unicorn ARM-Thumb scenarios across both callsites and
  `hw_flag=0/1/2`; require zero writes to any OEM global RAM and
  unchanged original `r0/r1` call arguments on secure board.
- All preceding type-4 gate and Creality initializer tests execute
  first through PR #39, along with source-pinned saved-v3.22 parity.

## Remaining safety limits

**The new wrappers reduce the impact of stale type-4 record state
on these two callsites, but do not establish a fully atomic RTOS
guard.** This is not a proof that no other secure access, tag
reread, motor movement, preload side effect or interrupt-driven
operation is possible. In particular the tag reread at
`0x0800DFDA` remains manufacturer code, and every relevant
control-flow branch must be qualified against hardware and
concurrency tests.

Hardware chip identity, bootloader acceptance of page 93,
power-interrupted update recovery, UART/Kalico capability
negotiation, CM5 persistence, spool removal and live printing
regressions all remain unverified. All nine mandatory v3.23
flash-release gates are false.

**No CFS MCU, Flash, RS485 hardware, motor, GPIO, installed Kalico
service or OpenCFS repo is modified. No flashable BIN/ELF is emitted.**
