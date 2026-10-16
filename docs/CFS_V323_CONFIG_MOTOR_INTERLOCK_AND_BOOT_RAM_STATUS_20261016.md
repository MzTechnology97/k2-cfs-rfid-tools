# v3.23 Motor-status and boot-time RAM tuning: actual implementation status

*16 October 2026 · offline code audit and fail-closed first-test profile. No production changes.*

## What is completed vs only staged

This note addresses the user-requested two firmware capabilities before
Kalico integration:

1. **Motor safety:** distinguish task states, PWM/GPIO commands, current/
   ripple/blocked indicators and FG pulses, and permit parameter writes
   only when *all relevant motor start/ISR paths* are synchronized
   against an independently verified motor stop.
2. **Boot RAM profile:** allow custom tuning of motor speeds, spool buffer
   and timeouts on each CFS boot through RAM (never edit Flash or NVM),
   to be supplied by Kalico **later**.

### Confirmed source facts from the real v3.22 assembly

`firmware/v3.22-readonly-state-probes/handler-v3_22.S` currently has:

| Feature | True status |
| --- | --- |
| 64-byte scratch sidecar `0x20006EE8..0x20006F27` | allocated before heap by moving OEM heap pointer to `0x20006F28` |
| Startup hook | `heap_init_sidecar_wrapper` invokes the original OEM heap init and **clears the first 8 bytes**: magic + active override bitmask |
| Config v2 INFO/GET | implemented under `0x57` subcmds `0x10/0x11` |
| Stock speed IDs 0..5 | **read only**; original table entry bytes are not overwritten |
| ID6 reverse-detooth | read only |
| IDs 7/8 | only two motor-related manufacturer timing callsites actually read sidecar overrides after host SET |
| IDs 9..27 | bounded values can be **stored** by the older SET implementation but **are not wired into execution**; includes e.g. RFID speed, buffer fill timeout ID25 and load retry count ID27 |
| `CONFIG_V2_DESCRIBE` 0x14 | **not implemented** |
| SET/RESET 0x12/0x13 (prior builds) | gate checks only the current Creality `BOX_STATE=0`, which was observed during live motor movement. This is **not** a safe atomic busy/stop guard |
| Restore custom settings after MCU reset | **not implemented**. Magic and enable bitmask are cleared; stored bytes become inert |
| 512-byte event ring | **not allocated or proven safe** |
| Reliable active/idle status for all five motors | **not proven**. Software PWM, FG no-pulse, stall/blocked and `BOX_STATE=IDLE` cannot separately certify unpowered motors |
| Atomic MCU START/STOP versus volatile config writes | **not implemented**; source-only abstract contract in `cfs_motor_busy_guard_contract.py` |

**Important:** timing IDs 7/8 are genuinely hooked, but we must not
advertise them as safely adjustable until the motor exclusion is
implemented and hardware-qualified. The other 19 advanced tuning IDs
are **storage-only** and **not actual motor, RFID or buffer tuning**.

### New v3.23 first-hardware-test configuration variant

New source-only script:

`firmware/v3.22-readonly-state-probes/cfs_v323_safe_config_readonly_preview.py`

This compiles the current `#44` combined type4+FM15L013+slot-removal
trial as **an in-memory complete firmware image** and changes **only
the two command ENTRY Thumb instructions** for SET and RESET.
Both are replaced with exact PC-linked `B.W` branches to the
**existing** OEM-protocol status `status_busy` (error code 7).
No other executable APP body, original OEM callsite, RFID handler or
heap pointer is modified. Image header CRC is recomputed in memory.

- Original `0x57/0x12` SET (at physical `0x0802E0A0`)
  and `0x57/0x13` RESET (`0x0802E120`) are always blocked.
- Original INFO `0x57/0x10` and GET `0x57/0x11` remain active.
- This is a **release-readiness fence**, not a finished motor guard
  and not a permanent decision to remove configurable speeds.
- Size unchanged: **178,416 bytes**, end `0x0802E8F0`,
  last Flash page **93**. Reserved parameter page
  `0x0807F800` is not reached by image length.
- The full image exists only in memory; the script emits JSON, not a
  flashable BIN, HEX or ELF.

### Original ARM emulation

Real assembled code was executed under Unicorn with a synthetic
host RS485 message: `0x57` INFO, GET, SET, RESET. The original
OEM send-response was stubbed to capture return status; global SRAM
writes were trapped and the sidecar was snapshotted.

- **12** blocked SET/RESET scenarios across all 6 original
  `BOX_STATE` values 0..5.
- **6** additional SET/RESET scenarios with unexpected/valid
  previous sidecar magic and masks.
- **2** positive INFO/GET cases confirming backward-compatible reads.
- The new variant always returns **status 7**, does not change
  the sidecar and does **zero global SRAM writes** for attempted
  SET/RESET (beyond stack).
- Negative source differential: run the *previous* #44 firmware
  under `BOX_STATE=IDLE`: original SET returns **success 0**,
  **writes two non-stack global SRAM locations**, and changes
  the RAM sidecar despite missing physical stop evidence.
- The actual existing MCU heap-init wrapper is emulated and
  **clears only magic and active override mask**, without loading
  a custom profile at startup.

All tests are offline; the real CFS MCU is not accessed.

## Order of future implementation: firmware first, Kalico last

1. Consolidate first v3.23 RFID-only trial with this fail-closed
   SET/RESET profile. The feature catalog must **not** advertise
   effective writable speed/timeout controls.
2. Complete an audited MCU interlock for *every* feeder/hub/
   preload/print/task/ISR motor start and stop route, with a lock,
   generation/epoch and real motor command outputs; any unknown or
   stale status must deny a new parameter write.
3. Prove correct motor and parameter callsite compatibility.
   Carefully enable ID7/8 and then additional *individually proven*
   speed/timeout/buffer controls; do not activate all IDs 9..27
   indiscriminately.
4. Define a boot protocol: source defaults → RTOS/peripherals
   initialized → MCU ready capability → atomic, bounded RAM
   profile applied → explicit success/readback. A CFS power-cycle
   returns to defaults until a trusted host sets the profile again.
5. **Only then**, integrate Kalico to send the chosen profile
   at each boot, persist it on CM5 and respect motor state and
   the firmware capability flags.

The 512-byte event ring is distinct from the *filament buffer*
or its timeouts. Neither should be confused with the current
64-byte sidecar config store.

**No SET/RESET motor authorization or v3.23 firmware Flash
authorization results from this PR.**
