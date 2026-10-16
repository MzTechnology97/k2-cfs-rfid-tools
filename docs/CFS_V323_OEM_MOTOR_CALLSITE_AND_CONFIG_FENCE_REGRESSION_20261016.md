# CFS v3.23 — Original motor callsites and integrated write-denial regression

*16 October 2026 · offline-only safety audit stacked on draft PR #46.*

## Purpose

The first-test v3.23 candidate already includes a manufacturer
`0x57/0x16` **read-only** TIMER PWM output-enable snapshot.
The independent motor-stop interlock remains **unimplemented**; the
preceding PR #45 therefore unconditionally denies `CONFIG_V2_SET`
and `RESET` instead of trusting `BOX_STATE=IDLE`.

This audit makes sure that adding the diagnostic has not changed the
**known original Creality motor command paths**, and that PWM and
CONFIG requests remain safe **when issued consecutively on the
same Cortex-M4 emulation instance**.

## Pinned original motor command ABI

Both saved OEM APP versions are hash checked. The known physical
manufacturer `BL` callsite inventory is taken from the earlier
source-proved `motor_command_callgraph_audit.py` and corrected
real base `0x08003000`, not the older nominal `0x08010000`.

The reconstructed 178,464-byte v3.23 experimental APP is compared
**byte-for-byte at all known original motor BL sites** against
saved v3.22:

| Command family | Physical ROM entry | Original BL callsites |
| --- | --- | ---: |
| Forward-like motor call | `0x08011164` | 33 |
| Reverse-like motor call | `0x0801117E` | 17 |
| Zero-duty/stop-like command | `0x08011198` | 50 |
| Direct common duty setter | `0x080110CC` | 2 |
| **Total direct callsites** | | **102** |

Three known original wrapper tail-branches to the common duty
setter are preserved as well. An intentional in-memory mutation
of one motor `BL` at `0x08003E84` must cause the audit to fail.

**Limit:** this is an inventory of source-proved **direct branches**,
not proof of all indirect calls, RT-Thread worker dispatches,
interrupt-driven motor starts or machine stop feedback.
Original zero-duty API calls are not confirmation that a motor
is physically stopped.

## Integrated real-ARM command sequence

New script:
`firmware/v3.22-readonly-state-probes/cfs_v323_motor_start_write_fence_regression.py`

It compiles the existing PR #46 experimental v3.23 candidate
entirely **in memory**, then executes real Cortex-M4 Thumb
instructions in one Unicorn MCU per scenario. Each instance
receives three serial-protocol handler requests in succession:

1. `0x57/0x16`: raw TIMER0 and TIMER3 output-enable snapshot;
   exactly two reads at `0x40012C20` and `0x40000820`.
2. `0x57/0x12`: SET attempt, expected **status 7** (denied).
3. `0x57/0x13`: RESET attempt, expected **status 7** (denied).

The virtual CFS RAM sidecar is pre-filled with a plausible
configuration magic and **all override bits set**, to ensure
that no apparent previous initialization changes the result.

Ten hardware-state simulations cover:

- `BOX_STATE=IDLE` with both PWM-enable words **zero**;
- `BOX_STATE=IDLE` with the hub enabled;
- each feeder enabled independently;
- all PWM channels enabled;
- busy states with PWM channels both disabled and enabled;
- a second busy code with all outputs enabled.

**All ten cases passed locally** (30 command executions):
the read-only result matched both test registers, while
both SET and RESET were rejected. No other MMIO read was
performed for SET/RESET; no non-stack/global SRAM or MMIO writes
occurred in these command paths, and original TIMER enable
words and the config sidecar remained byte-identical.

The first scenario is particularly important: *both* PWM
enable registers can read zero while `BOX_STATE=IDLE`
and CONFIG **still must be denied**. Such a snapshot does
not constitute an independently verified all-motors-stopped
condition or atomic exclusion from motion starts.

## Exact scope and release status

The test does not execute real OEM motor-control routines or
physical electrical outputs; it proves they remain byte-identical
at the inventoried callsites and exercises only the RS485
command handler under synthetic MMIO. It does not qualify ISR
preemption, hub brake/FG feedback, GPIO-driven motors, ISR
and task critical-section coverage, an installed bootloader
version or interrupted firmware update.

- No new MCU firmware features or hook code in this PR.
- In-memory experimental APP stays **178,464 bytes**,
  SHA-256 `4b3319a5c83ed451b30040ccccea116ee97875134c81b4bd9f59b0da376fe293`.
- No BIN/HEX/ELF is emitted.
- **Kalico and its pre-existing `box_cfs_runtime.py`
  are deliberately left unchanged** until the firmware
  reaches a safe physical-test milestone.
- `CONFIG SET/RESET`, motor motion, and Flash release
  remain forbidden by the ongoing fail-closed profile.

Next task: prove all original motor start/stop and ISR/task
edges before designing a **genuine RT-Thread synchronized
write interlock**. A source-only regression cannot make
unknown paths safe.
