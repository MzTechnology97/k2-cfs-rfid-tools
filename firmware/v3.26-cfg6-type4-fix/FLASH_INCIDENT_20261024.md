# CFG6 v3.26 — Incident after failed experimental flash (24 October 2026)

**Status: BLOCKED / NOT FOR FLASH.** This branch is **not** ready for hardware installation or merge. The v3.25 downgrade restored the physical CFS. No changes to Kalico, `box.cfg`, the active CFS, or Klipper are part of this report.

## Grounded observations

| Evidence | v3.25 working | v3.26 attempted |
|---|---|---|
| SHA-256 | `6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6` | `7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb` |
| Bytes | 178,968 (`0x2bb18`) | 178,980 (`0x2bb24`), +12 |
| Creality metadata | CRC16 `0x571e`, length matches | CRC16 `0x2f88`, length matches |
| T113 official `validate_custom_cfs_container` | PASS | PASS |
| Copy staged on T113 | SHA matches | SHA matches |
| Actual flash | **24 Oct 10:38–10:39: two verified `update: ok` records** | **24 Oct 10:30: transfer failure** |
| Application boot | CFG6 v3.25 running; Klipper READY, CFS IDLE, motors ready, 23/23 applied | **Not observed**: loader remained reachable, application unavailable |

The only source change is a guard in `remaining_init_wrapper` to preserve a printing type-4 RFID record on rescan. The new code lengthens the ARM handler by 12 bytes. Due to position-dependent Thumb branch displacements and PC-relative literal references, the binary comparison naturally shows additional relocated bytes; this is not evidence of arbitrary unrelated source changes. Existing offline ABI/protocol/RFID tests had passed, but **they did not exercise the real Creality updater over RS-485**.

### Failed flash log

At `10:30:19.519786`, the stock updater logged `state: erase_flash, get ACK`, and selected the CFS at address `01`. At `10:30:24.575238`, it logged `send fw data to slave [01] failed, 0, retry...`; attempts 1 and 2 also timed out at `10:30:25.075939` and `10:30:25.576414`, followed by `update fw bin fail!`.

The attempt numbers `0/1/2` are **retry indices**; the log does **not identify the failing firmware block offset**. Therefore it was incorrect to claim unequivocally that the **first block** failed. The loader was later detected as address 01 in bootloader mode. We have **no evidence that the v3.26 application was ever written completely or executed**.

The user's downgrade used the original CFG6 v3.25 image. On 24 October at 10:39:05 and 10:39:37, stock T113 updater logs reported `addr [01] dev [cfs], update: ok`. At 10:40:51, Moonraker reported `printer ready`, `CFS IDLE`, `motor_ready=True`, `K2OH v323-cfg6`, and `applied 23 value(s)`.

### Why this is not yet attributed to ARM application code

- Both images pass the **actual T113 container validator**, not only our standalone builder. Both contain the same correctly aligned initial MSP and Thumb reset-vector target.
- Correct Creality CRC16 and 32-bit length field for each image.
- Both persistent T113 staged copies match their build SHA-256.
- No application startup/crash trace exists for v3.26: the updater timed out **during transfer**.
- Firmware lengths with `size % 8 == 4` had previously been used successfully (e.g., CFG5T). Therefore 8-byte alignment alone is not a supported explanation.
- A possible RS-485 framing, bootloader programming or image-dependent transfer edge case remains **unresolved**. It would be unsafe to blame the 12-byte ARM guard or to categorically rule it out without additional evidence.

### Containment and next steps

1. **Do not reflash the candidate.** It was removed from the local CM5 Helper manifest, leaving CFG4, CFG5T and the working CFG6 v3.25 selectable. The v3.26 BIN remains preserved for offline analysis. The prior manifest is backed up at `~/cfs-v323-build/helper-manifest-quarantined-v3.26-20261024.json`.
2. Keep this pull request in **draft/blocked** state. Do not publish this BIN as a production image or merge it into `main`.
3. Investigate the stock updater's data-transfer handshake and the CFS bootloader ACK/timeout behavior **offline**, including boundaries, packet sizing and the recorded RS-485 byte stream, before further physical writes.
4. Add a full update transport validation strategy, and improve device-side diagnostics in a dedicated subsequent test when appropriate.
5. Keep the original type-4 accounting issue open: the Unicorn reproduction of the rescan-reset defect remains valid, but the transport failure is a distinct problem.

**Important:** This report does not claim that any hardware was permanently damaged. The CFS was restored successfully by the user's downgrade.

## Follow-up — 25 October 2026 (local staging only)

The **24 October quarantine** described above is a historical record of the containment decision. On **25 October**, the operator expressly asked to re-enable the v3.26 candidate as **entry 4 on the CM5's local Helper manifest** to consider a second **manual** attempt after printing ends. The existing 178,980-byte BIN was SHA-256-verified against `7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb`; the manifest was atomically restored using its pre-quarantine backup, preserving the other three candidates. The prior three-entry manifest was backed up to `~/cfs-v323-build/helper-manifest-pre-restage-20261025.json`. Helper menu and T113 custom CFS tests passed; no flash, restart or CFS command was sent. Kalico and `box.cfg` were unchanged.

**This re-staging does not resolve or waive the previous failure.** The candidate remains unmerged/not hardware-qualified and is not part of the public Helper manifest. The original loader/transport root cause and failed request offset remain unknown. Do not interpret the current selectable menu entry as a declaration that the image is safe. Any future supervised hardware trial must be a separate operator action, with fully idle printer/heaters, verified prior v3.25 rollback, exclusive transport ownership, full acknowledgment and stop-on-error behavior. A repeat failure requires investigation, not repeated flash attempts.
