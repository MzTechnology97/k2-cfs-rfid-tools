# CFG6 — experimental RFID type-4 rescan accounting fix

**LAB ONLY: DO NOT FLASH DURING A PRINT. NOT hardware-qualified.** This branch changes CFS firmware only, not Kalico or box.cfg.

## Bug reproduced in the original ARM code

When CFG6 reinitializes a successfully captured type-4 RFID tag while its slot is already printing, remaining_init_wrapper resets the running accounting fields: used millimetres from 8200 to 0, odometer checkpoint from 497500 to 0, print mode from 1 to 0, and CFS percentage from 33% back to 35%.

The defect is reproduced by ARM emulation against the exact original image. It could explain a stalled live percentage, but repeated rescans during the observed physical print have NOT yet been proven. Issue: https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/59.

## Proposed firmware-only fix

When a type-4 runtime is already valid and in print mode, the RFID initialization returns success without touching consumed millimetres, odometer baseline, mode or CFS percentage. Normal initialization while idle remains unchanged; other tag types stay on the original stock path.

The API2 identity remains K2OH / v323-cfg6 / feature 0xE3. The paired Kalico extra needs no changes. Distinguish the fixed image from the old one using its filename and SHA-256.

**Do not blindly flip the odometer sign:** the actual stock function at 0x0801B730 already performs vneg.f32. A separate regression executes the original sign inversion, showing that negative raw readings are normalized before accounting.

## Offline validation

- Exact byte-for-byte reproduction of the original CFG6 image and SHA-256.
- ARM-level regression reproduces the print-mode reset bug and verifies preservation for all four slots.
- Fresh/idle type-4 initialization still works.
- Complete existing stock accounting/start/finish/getter, CFG5/CFG6 ABI and advanced-hook regression tests.
- Dedicated raw negative odometer sign inversion test.

## Experimental BIN (NOT FOR FLASH)

File: CFG6-TYPE4-RESCAN-FIX-NOT-FOR-FLASH.bin

SHA-256: 7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb

**Status update (25 Oct):** the image was quarantined after the 24 Oct failed RS-485 upload and **re-added to one CM5's local Helper manifest at the operator's explicit request** for a possible supervised second attempt. It is **entry 4 on that CM5 only**, not an official/public Helper release. The working CFG6 v3.25 remains installed and available for rollback. Re-staging did **not** cause another flash. **Menu availability does not imply hardware qualification:** the root cause of the transport timeout remains unknown. Any operator-supervised retry must use Helper's safety gate with the printer idle and heaters off, a verified rollback and no bypasses; stop on a repeat failure. Kalico and `box.cfg` were not modified.

[24 Oct incident](FLASH_INCIDENT_20261024.md) · [RS-485 forensics](FLASH_FAILURE_AUDIT_20261024_IT.md) · [PR #60 closed without merge](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/60).

The Kalico BOX_RFID_DIAG_REMAIN_STATE command requires API7 and cannot inspect CFG6/API2 internal runtime. No CFS commands were issued during this firmware work.

[Italiano](README.it.md) · [Regression test](test_type4_rescan_preserves_print.py)
