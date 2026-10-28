> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFG6 status and GitHub review — 18 October 2026 (EN)

## Installed firmware and configuration

- **Physical CFS** reports `K2OH v323-cfg6`, feature `0xE3`, API2, 28 IDs; 23 effective writable and five GET-only (0/4/10/25/26).
- **CM5 Kalico:** `k2-pro-openhost` with merged CFG6 runtime; active `box.cfg` has `auto_apply: True`. While printer was `standby`, CFS `IDLE` and no axes were homed, **23 startup settings were applied**, independently confirmed by **23/23 matching readbacks** and 28 valid GET responses.
- **Verified overrides:** hub transition/insert/reverse 220/100/150, RFID measure speed 150, RFID neighbour retry count 1, pretension cycle count 1.
- **No actual motion during these checks:** no G28, Z homing, filament loading/unloading, moving-spool RFID test or print. Real type-4 live consumption during a print remains unverified.
- **RS-485:** first post-flash boot needed a motor-enumeration retry with timeout/CRC warnings; motors subsequently became ready. Klipper-only restart enumerated on first attempt, with a broadcast timeout. Extended transport stability is unqualified.
- **Rollback:** keep CFG5T and v3.22 images. CFG6 is experimental rather than production-qualified.

## Current documentation

- [Full 28-parameter CFG6 behavior, risks, units and CM5 values (EN)](https://github.com/MzTechnology97/k2-cfs-rfid-tools/blob/0ad22669248cc845a3c8d22dd613500c4b95feb3/firmware/v3.25-cfg6-lab/PARAMETERS_EN.md)
- [Riferimento completo italiano](https://github.com/MzTechnology97/k2-cfs-rfid-tools/blob/0ad22669248cc845a3c8d22dd613500c4b95feb3/firmware/v3.25-cfg6-lab/PARAMETERS_IT.md)
- [Kalico CFG6 EN guide](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_RUNTIME_CFG6_EN.md) · [IT](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_RUNTIME_CFG6_IT.md)
- [Installable experimental CFG6 firmware and source](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3/firmware/v3.25-cfg6-lab)
- [Helper manifest](https://github.com/MzTechnology97/k2-openhost-installer-helper/blob/main/firmware/custom-cfs/manifest.json)

## GitHub PR and issue triage

**Archived as superseded historical release steps without merging; original branches are retained:**
- [Firmware PR #34](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/34): legacy v3.22/v3.23 relink and byte-parity milestone. Not all historical audits were carried into CFG6.
- [Firmware PR #43](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/43): historical v3.23 loader/readiness wording; original loader audit details remain accessible.
- [Kalico PR #83](https://github.com/MzTechnology97/kalico-k2pro/pull/83) was already closed when this review began; its CFG5T integration has been overtaken by merged [CFG6 PR #86](https://github.com/MzTechnology97/kalico-k2pro/pull/86).

**19 firmware research PRs remain open by design** because their contents include unique or unintegrated evidence:
- Type-4 RFID and secure-sink race guards: **#39, #40, #41, #44**.
- Motor safety / fail-closed, PWM, GPIO and RS-485: **#37, #45, #46, #47, #49, #50, #52**.
- Historical loader, OEM, crypto source audits: **#35, #36, #38, #42, #53, #55**.
- MCU event-ring design not integrated into CFG6: **#11, #12**.

**Safety issue stays open:** [#9 — MCU BOX_STATE can be IDLE during feeding](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9). Successful 23/23 SET/GET **when physically idle** is not proof of an atomic firmware motor-stop interlock. Keep Kalico host guards; never send raw SET/RESET during motion.

**Other repositories:** Kalico and Helper have no open PRs/issues at this review. OpenCFS-Firmware has no open PRs; [issue #2](https://github.com/MzTechnology97/OpenCFS-Firmware/issues/2) (incomplete protocol corpus) and [#3](https://github.com/MzTechnology97/OpenCFS-Firmware/issues/3) (motor/loader/recovery release blockers) remain valid.

**Triage rule:** do not close a PR solely because its label says v3.23; close only when superseded or fully integrated, preserving unique source/reverse-engineering evidence.