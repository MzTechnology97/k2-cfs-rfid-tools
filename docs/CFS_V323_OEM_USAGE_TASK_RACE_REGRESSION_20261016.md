# v3.23 RFID type-4: actual OEM usage-task execution and post-gate races

*16 October 2026 — read-only test development stacked on draft PR #40.*

## What the earlier tests missed

Drafts [#39](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/39)
and [#40](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/40)
built an experimental type-4 live-remaining firmware and two secure-element
sink guards. Their early Unicorn tests checked isolated guard/wrapper
entrypoints, **not** the full original Creality usage manager.

This audit now executes the original **ARM Thumb + VFP**
`rfid_mgr_fila_task` at **`0x0800DC94`** as compiled in the saved
manufacturer firmware, inside BOTH exact internally reconstructed
v3.23 candidate applications:

- Earlier #39 image: **178,320 bytes**, type-4 entry gate only.
- Subsequent #40 image: **178,352 bytes**, entry gate plus two
  additional FM15L013 secure-sink guards.

The script `firmware/v3.22-readonly-state-probes/cfs_v323_original_usage_task_race_emulator.py`
compiles both candidates **only in Python memory**, without saving
the images. It uses synthetic SRAM, the original OEM machine code,
Unicorn Cortex-M Thumb/VFP, and explicitly stubbed hardware-dependent
odometer, clock, logging, external percent callback, tag-detect,
FM15L013 secure writer and tag-reread functions.

**Neither the original firmware RFID routines nor an actual GPIO,
motor, physical tag, RS485 or serial port are executed.** This is a
bounded task-flow regression, not a real printing test.

## Verified original source / callsites

| Physical PC | OEM operation |
| --- | --- |
| **`0x0800DC94`** | Original unchanged usage manager task entry |
| `0x0800DCCC` | Reads odometer via original `0x0800E730` |
| **`0x0800DE68`** | Original call to secure-dependent `rfid_detect_tag` `0x0800D83E` |
| **`0x0800DEC2`** | Original call to FM15L013 secure-module write `0x08015A42` |
| `0x0800DFDA` | Separate original tag-reread helper `0x0800D670`; unchanged |

The full OEM task's normal type-4 path calculates used millimetres
and percent without any secure-element entry. A dirty record in
unloading or a record invalidated during the task can reach
`0x0800DE68`. A successful secure detect and matching synthetic tag
ID can then reach `0x0800DEC2`.

## Direct original-CFS algorithm validation

With a valid type-4 runtime record:

- Starting percent **80%**, total **250,000 mm**.
- 5,000 mm simulated printer odometer → **78% remaining**.
- 25,000 mm odometer → **70% remaining**.
- 55,000 mm odometer → **58% remaining**.

These values are produced **by the unchanged original OEM task**,
not by a rewritten C++ formula. Both builds produce the same values
and zero original secure-element accesses for this normal path.

## Injected transitions demonstrate why two guards are required

Fifteen scenarios run on **both compiled candidate images**, including
idle, normal type4 print, dirty print, unload, invalid record,
type7 on legacy/secure hardware, and four synthetic record changes
just before the original task's save-state branch.

| Scenario | #39 original secure entries | #40 original secure entries |
| --- | ---: | ---: |
| Dirty type4 unloading, legacy/no FM15L013 | 1 | **0** |
| Missing record during task, legacy | 1 | **0** |
| Type7 dirty record, legacy | 2 | **0** |
| Print → unload after earlier gate accepted | 1 | **0** |
| Valid record → removed after earlier gate | 1 | **0** |
| Type4 → type7 after earlier gate | 2 | **0** |
| Dirty mode/type change after earlier gate | 1 | **0** |
| Synthetic detect status forced to success after first guard | 2 | **0** |
| Type7 secure-board stock path | 2 | **2** |

The script first independently emulates an initial *successful*
`live_type4_usage_gate` check, **then** makes the configured state
change as the original usage task executes. This tests the precise
gap between the earlier check and the OEM callsites.

Two fail-closed single-hook removal mutations reinforce the result:
replacing either one of the new #40 hooks with its **original
manufacturer BL** (from #39) makes an OEM secure sink reachable in a
matching scenario, while the intact build blocks it.

## Limits, not release evidence

- Unicorn runs **synthetic transitions at specific instruction PCs**,
  not actual asynchronous RT-Thread preemption or interrupts.
- The caller state used for the mock external odometer, tag ID,
  clock and FM15L013 functions does not prove real electrical response
  or performance.
- An FM15L013 hardware-present flag is assumed trustworthy. No
  diagnostic exists yet to authenticate the installed chip electrically.
- Other secure-module and re-read callsites outside these two guarded
  task paths have not been exhaustively proved harmless, and a
  physically safe motor-idle/ISR interlock is still absent.
- Bootloader page-93 ownership, accepted v3.23 firmware length,
  interrupted flash recovery, and Kalico integration remain unproven.

**Do not flash the v3.23 experimental image.** This PR only adds
offline task-flow tests and documentation: no firmware patch, BIN,
Flasher, CFS command or live hardware interaction.
