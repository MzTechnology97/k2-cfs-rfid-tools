# CFS v3.23 — readiness after the real Flash base correction
*Engineering status: 12 October 2026 — offline analysis only.*

## 16 October clarification — stock RS485 recovery is documented

[OpenCFS's recovered OEM loader specification](https://github.com/MzTechnology97/OpenCFS-Firmware/blob/ca73d2ec99b6b03b9a2c98b4613f32224641e5ec/docs/spec/08-loader-and-recovery.md)
already describes the **existing manufacturer's RS485 recovery
mechanism**; this is not a missing new bootloader feature. Its
update-command and Flash/FMC programming geometry were independently
checked against the SHA-pinned historical 2025 full Flash ROM in
[k2-cfs-rfid-tools draft #38](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/38).

- Bootloader: `0x08000000..0x08002FFF` (the archive has its own vectors).
- APP update starts at `0x08003000` and advances sequentially.
- The loader receives 128-byte chunks and writes buffered 256-byte
  blocks; it erases the 2-KiB Flash pages touched by the new image.
- Reserved parameter page begins at **`0x0807F800`**. A correctly
  bounded image must end **at or before** that address (exclusive);
  a one-byte overflow would touch the parameter page. The *theoretical*
  distance from APP start to that page is `0x7C800` = **509,952
  bytes**, **not** an approved maximum image size.
- Our current **in-memory** type4+secure-sink candidate from
  draft [#40](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/40)
  is **178,352 bytes** and ends at **`0x0802E8B0`** (page 93).
  Thus its size alone does not threaten the historical loader or
  parameter page. Actual linker/Flash/RTOS safety is still separate.
- The **documented** manufacturer recovery rules: invalid APP CRC
  keeps the historical loader active; a valid but nonfunctional APP
  can be bypassed by power-cycling and enumerating within its
  **approximately 30-second** initial RS485 window. A damaged loader
  needs SWD. No destructive recovery test has been run here.

**Updated conclusion:** firmware recovery is **documented and
source-corroborated on the archived OEM loader**, and reasonably
expected to work on the installed board (reported boot version
`cfs0_050_G32` matches the archive). Do not describe the recovery
*protocol itself* as unknown. The open evidence point is **installed
loader identity and actual recovery validation**, not absence of a
loader/recovery design.

The original nine release gates remain false; no release approval
is implied. User has no spare CFS. Do not run RS485 update, reset,
parameter erase, Flash write or motors as a result of this note.

## Decision

**Not ready to flash v3.23.** The v3.22 image has been reliably rebuilt,
validated by SHA, and now fully decoded with its correct physical Flash
origin (`0x08003000`). That solves several false reverse-engineering
blockers, but it does **not** establish all hardware and fault-recovery
properties needed to replace firmware on a real CFS.

The new regression gate is
[`cfs_v323_corrected_release_gate.py`](../firmware/v3.22-readonly-state-probes/cfs_v323_corrected_release_gate.py).
It reconstructs the five PWM names from compressed SRAM and rejects
release if any critical qualification remains undocumented.

## Recalculated v3.22 Flash headroom

| Fact | Previous address mapping | Correct mapping |
| --- | --- | --- |
| APP base | `0x08010000` (wrong) | **`0x08003000`** |
| Saved v3.22 size | 178,140 B | 178,140 B (unchanged) |
| APP end (exclusive) | `0x0803B7DC` (wrong) | **`0x0802E7DC`** |
| Last occupied 2048-byte erase page | 118 (wrong) | **92** |
| Arithmetic bytes below old `0x0803B800` policy | 36 (wrong) | **53,284** |

**Do not interpret 53,284 as certifiably free Flash.** The old limit
`0x0803B800` was a local build policy, never independently authenticated
as the CFS loader's maximum application boundary. The loader may own
pages at other addresses, use image-length restrictions, preserve
calibration data or perform recovery erases. The new origin changes
the geometry, but not those missing facts.

This also changes the old "only 36B left" feasibility finding in
draft PRs #11–#17: the calculation was based on a wrong Flash origin.
Those audits' low-level code bytes remain useful, but their printed
address and Flash-capacity conclusions must be **re-derived**, not
silently used as release evidence. Do not globally change
`flash_ram_phase2_audit.APP_BASE` yet; prior tests use the synthetic
coordinate system and require controlled migration.

## Resolved offline

1. Original code starts at a valid Thumb reset trampoline under the
   `0x08003000` mapping (verified in pinned v3.13 and v3.22).
2. The entire **716-byte** compressed source expands into **3012 bytes**
   of initial SRAM (251 tokens).
3. All five named PWM device objects are recovered in the v3.22 saved
   image: `pwm1/pwm3/pwm4/pwm5/pwm8`.
4. The constructor callback pointers at offsets `+0x30/+0x34/+0x38`
   resolve to real Thumb function prologues; the preceding ABI alarm
   was caused by the old mapping. **Do not patch those pointers.**
5. Original v3.22 firmware rebuild and RFID regression are green.

## New 13 October motor-status provenance (not a release gate closure)

The saved original v3.22 SRAM contains five distinct GPIO-backed
`pwm` device objects at GPIOE13, GPIOD12/13/15/14. The real
motor-command controller at `0x080110CC` references the software
RAM root `0x20004960`. Original code at `0x0801114C` writes
`0x14` at `0x2000499C`; a routine at `0x080111AA`
reads that byte and returns zero when nonzero, one when zero.
Three direct original Thumb BL references to the getter have been
identified at `0x080038AE`, `0x08003932` and `0x08003C8A`.

Further source-accurate Thumb analysis now **proves this byte
is a software countdown**, not merely a timeout candidate.
Routine `0x08010E60` loads the same `0x20004960` root,
reads the byte at `0x08010EBE`, decrements it at
`0x08010EC4` when nonzero and writes it back at
`0x08010ED4`; another branch reloads `0x14`.
A zero countdown is not independent physical rotor/driver
feedback. It cannot establish that every motor/ISR start path
is covered or that a future check-and-write guard is atomic.
All nine release conditions remain unchanged and false.

See [read-only GPIO and status-byte audit](CFS_PWM_GPIO_MOTOR_STATUS_PROVENANCE_20261013.md).
Do not enable motor-active MCU writes from these values.

## Still must be resolved before a v3.23 build is flash-qualified

- **Physical motor-safety guard (issue #9).** During real active feeding,
  `BOX_STATE` can still report IDLE. A SET/RESET guard checking only
  that byte can misclassify active motion. A verifiable MCU motor/task
  idle state with atomic rejection is needed; host-side Kalico preflight
  is useful but insufficient as an MCU safety proof.
- **Loader/recovery hardware qualification (design already recovered).**
  The **historical loader's** RS485 update, image base, 2-KiB page
  erase, reserved parameter region, 30-second recovery window and
  checksum requirements are documented. Before flashing the user's
  CFS, verify the installed loader is equivalent, preserve/backup
  the parameter page and check length/CRC/last programmed page; an
  actual interrupted-update recovery and MCU rail/power-cycle have
  not been validated. Do not use the production unit for destructive
  protocol experiments.
- **RAM ownership.** The prospective 512-byte logging ring would occupy
  the current heap region `0x20006F28..0x20007127`. Reserving it
  requires moving the heap and proving actual RTOS stack/DMA/interrupt
  high-water and concurrent writer safety.
- **Hook/ABI/timing.** Any tracing of motor start/stop must preserve
  original Thumb registers, flags, IRQ state, motor timing and all
  relevant feeder/hub tasks.
- **End-to-end validation.** Rebuild a dedicated, unflashed v3.23
  candidate only after those design gates are resolved, run immutable
  stock-vs-candidate diff, CRC/length/fault-injection and complete
  RFID/regression tests, followed by controlled test hardware with a
  recovery route. The user has no spare CFS, so staging against a
  production machine deserves extra caution.

## Release gate snapshot

The CI's **nine release conditions** are deliberately false until
each has independently authenticated evidence. The script prints
`approve_v323_firmware_flash: false` and
`approve_v323_motor_active_writes: false` and creates **no new
firmware BIN**.

### Recommended next development order

First normalize every address-sensitive analyzer and document
which routines are mapped physically versus using the older
artificial `0x08010000` offsets. Then design an MCU motor-idle
observation strategy from authentic original timer/driver feedback
and add a fail-closed guard without modifying the active CFS.
After that, prove SRAM ownership/IRQ behaviour and recover actual
Flash update limits before implementing the full new event-ring
feature. This is the shortest path to a v3.23 release that is
actually supportable rather than merely flashable.

**No real MCU, CM5 or Kalico files were accessed or changed by
these offline CI checks.**
