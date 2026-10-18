# CFS CFG5 — Experimental Status (EN)

Do not flash either image yet: both are laboratory candidates, not
hardware-qualified or registered in the Helper. The CFS still runs v3.23 CFG4.

## CFG5: effective ID20 and ID22
Path: separate CFG5 laboratory image
SHA256: c62d233355b8e7134687000ae63ffba5f62246fa374012933e5e740ca2812d01
Identity: K2OH v323-cfg5, API v2, features 0xE7.

- ID20 feed_total_timeout_ms: stock 25000ms, 5000..60000 in exact 20ms
  steps. At 0x08032C72 the wrapper converts host ms into stock ticks.
- ID22 odometer_stall_timeout_ms: stock 500ms, 100..2000 in exact 20ms
  steps. At 0x08032CEC the wrapper preserves the original increment and
  comparison flags, with programmable threshold.
- Pass: GET/SET/RESET, bounds, differential stock ABI/flags, and
  offline T113 container validator.

## CFG5 Type4: selective task gate trial
Path: cfs0_050_G32-cfs0_000_153-runtime-config-v3_24-K2OH-CFG5T-TYPE4-EXPERIMENTAL.bin
SHA256: 78c83416afaa4795de8a018533aea884f4def396f4829cc98c77fcce48155a55
Distinct identity: K2OH v323-cfg5t, features 0xE5.

This includes ID20/22 and patches ONLY the original periodic accounting
task gate at 0x08013684. On boards without FM15L013, the original task is
entered only when the active slot has valid type-4 metadata and is in
printing mode 1. Legacy type7 cannot unlock the task without the chip.
The original secure-chip path is preserved.

The stock print-start function at 0x0801A8AC sets mode 1, and the stock
type-4 accounting path uses odometer millimeters. The 12 Unicorn
gate-entry cases pass, but the full accounting task was NOT emulated and
live CMD 0x03 changes have NOT been measured in a real print.

## Paired Kalico (offline worktree)
~/cfs-v323-build/kalico-cfg5-lab/klippy/extras/box_cfs_runtime.py
Both distinct signatures are recognized. Writes remain restricted to
IDs 1,2,3,5,7,8,20,22, from startup CFG only; ID20/22 require exact 20ms
steps. Installed firmware, live extra and printer CFG were not changed.

Hardware qualification and live-consumption validation remain open.
Keep installed v3.23 CFG4 and proven v3.22 recovery available.
