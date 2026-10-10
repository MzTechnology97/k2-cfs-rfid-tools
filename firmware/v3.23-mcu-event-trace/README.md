# CFS v3.23 — MCU-side motion event capture architecture

**Status: design and recovery-gate specification only. No v3.23 firmware binary exists, and nothing in this branch has been flashed.** Existing experimental CFS v3.22 `0xD7` remains installed and operational. The independent MCU motor-active predicate from [issue #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9) is **not yet validated**.

## What the hardware experiments proved

A v3.22 host-side snapshot requested as G-code while loading PLA was queued for 10.545s and returned after load; during unloading it waited 13.797s and returned after unload. To distinguish G-code scheduling from serial ownership, we additionally developed and physically tested a temporary independent Python-thread sampler using the existing `serial485` request worker, GET **28–31 only**, 1Hz max, error stop, RFID read exclusion and no writes.

- Five idle samples completed in **7.84–9.57ms** apiece: motor candidate `0000:0000`, task candidate `0001:0000`.
- Real PLA load **11.299s**, unload **14.475s**, both successful; no new RS485 timeouts/CRC errors.
- A background GET begun in `feeding_to_buffer` took **10,679.96ms**, returned only near `verifying`, and therefore crossed the active phase.
- A background GET begun in `retracting_to_cfs` took **13,567.06ms**, returning **after** unloading.
- **Zero** GET snapshots both began and ended within the same known active CFS movement phase.

Conclusion: the **transport** has an exclusive request session around physical CFS operations. A separate host thread is not sufficient. **Never bypass the session** to force reads during movement. The temporary worker and its additional host RFID lock were reverted and the proven v3.22 host code restored; Klipper `ready/standby`, CFS `IDLE`, all 28 defaults intact and no new MCU flashing.

Evidence: [hardware timing data](../v3.22-readonly-state-probes/async-capture-2026-10-10.json).

## Proposed ON-MCU recorder — requirements

The next prototype must log selected **events inside MCU execution context**, while the stock controller is actually scheduling or completing motor work. Afterward, the host reads the *bounded* trace through normal serial transport **only once the stock operation has finished**. This avoids command-queue and transport-session delays from falsifying capture times.

The proposed ring is a design candidate, not an address reservation:

- Up to **16 bounded entries** (provisional), each with an event ID, firmware monotonic tick, raw candidate words from the v3.22 diagnostic addresses, a phase/task indicator, and a sequence/generation number.
- Capture at **verified stock motor-task entry, active-state transition and completion** for both feeder and hub, with differentiated event IDs. Include aborted/retry/error paths where possible.
- **No UART logging**, no dynamic allocation, no waits, no EEPROM/RFID writes and no user-controlled addresses in event hooks.
- Single-producer or proven atomic reservation. A two-phase generation marker must allow a reader to reject torn records; the capture routine must be bounded in runtime and preserve registers/flags required by the original firmware.
- An explicit compile-time option disables hooks in recovery builds. Every event hook needs an exact-original-instruction assertion and a matching ARM emulation test, including interrupt/stack register preservation.
- Readback must be **GET-only**, paginated or bounded, performed while the CFS reports no active operation. Reading the trace must never enable SET/RESET or serve as a substitute for a tested independent physical-motor interlock.

### Mandatory blockers before implementation or flash

1. **MCU identity and memory ownership:** derive SRAM/stack/heap layout from the original firmware and linker/startup behavior. Verify that any trace region is not used by vendor tasks, heap, stack, DMA, or the existing volatile config sidecar. A static search for a literal pointer alone is not sufficient to establish unused RAM.
2. **Flash footprint:** the v3.22 image ends at `0x0803B7DC`, only **36 bytes below a *hypothesized*, unverified bound `0x0803B800`**. We did NOT find a reliably identified flash code cave. A 131-byte zero-filled range around `0x0803AACD` is *not evidence of executable free space*: it may be structured data or alignment. Do not overwrite it without proof.
3. **Independent timing source:** identify a stable monotonic firmware tick already available to these motor routines. Do not assume DWT_CYCCNT is enabled or that a copied host timestamp identifies MCU execution time.
4. **Event hook semantics:** map the actual commands to feeder/hub motor tasks, startup, completion, pending queue transitions, and error/retry states. For an independent busy guard, events alone are insufficient unless every path is covered, including races when operations begin after a check.
5. **Atomic busy predicate:** once actual motor/task-active state is verified, SET/RESET must check it in an appropriate critical section or other concurrency-safe mechanism, failing closed for unknown states. The retained RFID slot byte and `BOX_STATE` load-mode byte are independently known to be unsuitable alone.
6. **Recovery and hardware gating:** repeat ARM emulator, exact-target firmware container checksum/CRC, updater handshake and power-cycle regression; maintain the verified v3.21/v3.13 recovery images. Only then authorize a separate diagnostic MCU flash. **Never use these candidate diagnostic values to allow in-motion writes.**

## What remains working

The reference K2 Pro CFS is running v3.22 with existing Kalico host-exclusive motion/runtime-write protection and all auto-apply disabled. No new firmware changes are needed until SRAM, flash, hook semantics and timestamp assumptions pass the gates above.

**This design document is NOT a firmware patch and does not close issue #9.**
