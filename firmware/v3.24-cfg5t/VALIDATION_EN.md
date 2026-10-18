# CFG5T — Experimental validation (English)

**Not hardware qualified, not for production.** This image is provided only for an explicitly supervised first test on the G32/APP153 CFS.

## Changes versus CFG4

- ID20 feed total timeout: stock 25,000ms; adjustable 5,000–60,000ms in 20ms increments.
- ID22 odometer stall timeout: stock 500ms; adjustable 100–2,000ms in 20ms increments.
- Type-4 remaining accounting: stock consumption task can run without FM15L013 only with an active valid type-4 slot in printing mode. The type-7 hardware path is preserved.
- Unique identity: 0x7A K2OH, revision v323-cfg5t, feature 0xE5.

## Completed offline verification

Reproducible byte-for-byte build, preflight, T113 container validation and RS-485 protocol tests pass. Differential Unicorn tests preserve the caller ABI and status flags of the ID20/22 callsites. ARM emulation executes stock print start/finish, odometer-based accumulation, percentage setter and CMD 0x03-backed getter. All four slots, type-7 exclusion, no double-count, 1% floor and a 42%-to-41% transition after 4100 simulated mm have been checked.

**Physical printing remains untested.** Extended RS-485 operation, loss of communication, real RFID/odometer, slot changes and interrupted updates need hardware qualification.

## First supervised test

Install through the Helper experimental-cfs menu only while the printer is idle, with a working CFG4 rollback image. Initially keep the old Kalico runtime extra without applying CFG values; verify RS-485, X/Y discovery, CFS and K2OH identity first. Deploy the paired Kalico CFG5T extra only after this read-only smoke test succeeds, then enable auto_apply deliberately.

[Validazione italiana](VALIDATION_IT.md) | [Firmware information](README.md)
