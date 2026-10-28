> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS motor activity: independent MCU busy guard and physical callgraph
*12 October 2026 — offline research, no firmware candidate or MCU changes*

## Hardware failure scenario that must be prevented

On a real CFS, an active `BOX_LOAD SLOT=1` in the
`feeding_to_buffer` phase produced `box.state=IDLE` at the host,
despite the physical load still in progress. A write attempt was
intercepted by Kalico host preflight, **not by a proven MCU guard**.
This is documented by [issue #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9).

The saved v3.22 handler currently uses the sequence
`ldr r0,box_operating_state_ptr; ldrb r0,[r0,#2];
cmp r0,#0; bne.w status_busy` before allowing volatile
SET or RESET. That byte **cannot independently prove motion stopped**.

## What this change adds

- `cfs_motor_busy_guard_contract.py`: checks both original SET and
  RESET paths in the saved handler source and runs **10 synthetic**
  safety scenarios, including real observed BOX_STATE=IDLE while
  feeding, unknown feeder/hub/buffer state, unverified sensor meaning,
  stale measurements, a motor start between check and commit, a missing
  motion lock and an unprotected ISR/task start path.
- `cfs_motor_command_real_address_audit.py`: re-decodes the old
  102 original motor-command BL instructions under the **correct
  physical image base `0x08003000`** (not `0x08010000`).
  The corrected shared controller address is `0x080110CC`, with
  forward/reverse/zero-command wrapper addresses
  `0x08011164`, `0x0801117E`, `0x08011198`.
  Previously published 33/17/50/2 direct-call counts are
  reproducible under the rebased address system, but they show
  **software command control flow only**.
- GitHub CI validates these audits against the exact reproducibly
  rebuilt v3.22 saved image, and the BL audit cross-compares the
  separately pinned v3.13 bytes. None of these checks alters
  a production MCU image.

## Mandatory criteria for a future actual MCU guard

A future firmware would need an independent, physically meaningful
observation for **every relevant motor and feed task**, a documented
meaning of each feedback value (actual rotor stopped vs command
accepted), and a means of protecting the *interval between status
check and commit* from a concurrent start by another task or IRQ.
The specimen lock/epoch simulation in the test is **not a concrete
RT-Thread implementation** and does not prove interrupt safety.

The safe decision for any missing source, unknown signal, pending
movement, stale sample, unmatched state, unprotected ISR path or
concurrent transition is **BUSY / reject write**. A synthetic positive
case is simply a unit test of the policy, not permission for actual
SET/RESET operation. Kalico's own motion/RFID lock remains required
as a second, independent host-side protection.

**Do not** infer physical stopped state from:
- `BOX_STATE=IDLE` alone;
- a zero-duty command, `pwm1` name or RT-Thread registration;
- a generic driver callback returning zero;
- a delayed serial GET reply after movement.

## Remaining work before v3.23 firmware compilation/flash

1. Identify **actual physical motor-running/stop evidence**
   (timer channel enable plus verified drive/encoder status, or
   another authenticated task/peripheral status), and prove that
   it covers feeder, hub, buffer and all ISR/task start paths.
2. Identify task-level/IRQ serialization that permits an **atomic**
   MCU write rejection during all motor transitions; demonstrate
   at least one synthetic motor-start race that fails closed.
3. Prove Flash app page and maximum loader-accepted image length,
   SRAM/heap/DMA/stack ownership and interrupt timing.
4. Keep the nine release gates in
   [v3.23 readiness](CFS_V323_RELEASE_READINESS_20261012.md)
   false until independent physical evidence and hardware tests
   exist. **No flashable v3.23 is authorized**.

The saved v3.22 baseline and Kalico remain untouched.
