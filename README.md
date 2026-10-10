# K2 CFS RFID v3.12

This repository contains my current hardware-validated **Creality K2 Pro CFS RFID v3.12 / API7** firmware and the host-side work I use with K2-OpenHost/Kalico.

I started this project to add third-party filament RFID interoperability while keeping Creality's original CFS worker in control of the RF frontend. I do not replace the stock RFID task and I do not expose tag-write operations.

The current v3.12 release includes three pieces of functionality that I have validated on hardware:

- the API7 MIFARE Classic Key-A override/capture path introduced in v3.3;
- guarded fast-accept handling that removes redundant third-party retry rotations;
- stock-style **remaining-filament estimation for third-party API7 captures**, using the CFS's own geometry calculation and type-4 runtime odometer.

Bambu material/colour recognition is hardware validated. QIDI PET-CF recognition through the generic MIFARE decoder is also hardware validated. The new v3.12 remaining path has so far been hardware validated with Bambu.

## Experimental v3.19 CFS runtime-parameter firmware (2026-10-10)

A **separate, NOT production-ready** v3.19 volatile-RAM bench image is now published under [`firmware/v3.19-volatile-ram/`](firmware/v3.19-volatile-ram/README.md). On an actual K2 Pro CFS the 28 default GET values and feature marker `0xF7` passed; one manual SET/GET/RESET of advanced ID 18 also passed. All other advanced writes and any movement effects remain unvalidated. Advanced motor/RFID movement hooks are disabled. Do not use the v3.19 image for regular CFS operations.

The directory contains a reproducible patched-v3.13 base, the full v3.19 assembly and builder, offline tests, exact SHA-256 and rollback guidance. The companion [Kalico extra](https://github.com/MzTechnology97/kalico-k2pro) and [installer helper manifest](https://github.com/MzTechnology97/k2-openhost-installer-helper) are updated separately. **v3.12 remains the most recently independently validated RFID/motion release.**

## Validated firmware target

I built and tested this release only against:

```text
CFS hardware          cfs0_050_G32
stock application     cfs0_000_153
stock SHA-256         5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea

v3.3 base SHA-256     5bab3acff49253a54089e779ea473d2cf587db09ab0d9c07c4d6c2e31b810388
v3.12 size            177400 bytes
v3.12 SHA-256         fe436e33a3b86339673b559d345703593e1a8e9ec3237261027e9ae48d048198
container CRC16       0x1609
handler address       0x0803AE38
handler size          1728 bytes
diagnostic opcode     0x57
API                   7
capabilities          0xE8
```

I do not recommend applying these offsets to another CFS firmware version. I would re-identify every symbol and callsite first.

## What v3.12 does

### Third-party RFID capture

For a supported MIFARE Classic tag I let the host derive or select the required Key A values, arm API7, and then ask Creality's normal force-read path to perform the RF transaction.

The firmware substitutes the temporary keys only at the original stock authentication/read callsites. Successful reads are copied into API7 scratch for host-side decoding.

The normal Creality record remains untouched.

### Faster third-party reads

I found two independent retry paths in the stock RFID state machine. I added guarded terminal-success handling only after a complete API7 capture, so genuine RF failures and normal Creality reads retain the stock behavior.

This substantially reduced unnecessary spool rotations in my hardware tests.

### Remaining filament

The most important v3.12 change is that I now reuse the **stock CFS geometry calculation** for a third-party spool instead of inventing a host-side percentage.

The CFS already computes an `area_percent` while rotating the spool and stores the current remaining byte at:

```text
0x20003974 + slot
```

For a completed third-party API7 read I create a short-lived internal latch before the geometry phase. This lets the stock remaining branch continue even though the tag does not contain a valid Creality 40-byte record.

I then initialize the existing stock type-4 runtime with:

```text
initial_percent = stock CFS area_percent
nominal_total   = 330000 mm
runtime type    = 4
```

I chose 330 m because the genuine Creality RFID record I recovered from hardware contains `len=0330`.

The existing stock `CMD_RFID_REMAINING (0x03)` then reports the value normally. No Bambu block 14 parsing is required and no new Kalico remaining protocol is needed.

## Hardware validation

On 2026-10-08 I validated the complete v3.12 remaining path on my K2 Pro with a real Bambu PETG HF spool.

After a complete API7 read:

```text
CMD 0x03 payload      0CFFFFFF
Bambu slot remaining  12%
```

The existing Kalico/GUI path received the same value:

```text
rfid_reported_percent  = 12
rfid_percent           = 12.0
rfid_estimated_percent = 12.0
```

I then reread a genuine Creality RFID spool as a regression check. The stock path remained functional and returned:

```text
CMD 0x03 payload      FF21FFFF
Creality slot         33%
```

An earlier scan of the same Creality spool had returned 38%, which is consistent with this being an approximate geometry-based estimate rather than an absolute measurement.

## Repository layout

```text
firmware/
  v3.12-remaining/
    cfs0_050_G32-cfs0_000_153-rfid-remaining-v3_12.bin
    handler-v3_12.S
    build-v3_12.py
    link.ld
    static-validation.json

  v3.3-stockcapture/
    ... historical hardware-validated API7 base

host/kalico/
  box_rfid_diag.py
  box_rfid_bambu.py
  box_rfid_mifare.py

docs/
  v3.12-remaining.md
  v3.3-stock-capture.md
  standalone-implementation.md
  third-party-tags.md
```

## Rebuilding v3.12

I made the published builder reproducible directly from the **published v3.3 binary**, so the intermediate development builds are not required.

```text
cd firmware/v3.12-remaining

python3 build-v3_12.py \
  --base ../v3.3-stockcapture/cfs0_050_G32-cfs0_000_153-rfid-stockcapture-v3_3.bin \
  --out cfs0_050_G32-cfs0_000_153-rfid-remaining-v3_12.bin
```

A clean rebuild produces exactly:

```text
fe436e33a3b86339673b559d345703593e1a8e9ec3237261027e9ae48d048198
```

## Documentation

- [v3.12 stock-geometry remaining implementation](docs/v3.12-remaining.md)
- [Standalone implementation guide](docs/standalone-implementation.md)
- [Third-party RFID/NFC compatibility](docs/third-party-tags.md)
- [v3.3 API7 stock-capture history](docs/v3.3-stock-capture.md)

## Safety boundary

I intentionally keep the third-party path read-only.

v3.12 does not add:

- RFID tag writes;
- UID mutation;
- sector-trailer writes;
- lock/OTP writes;
- EEPROM writes;
- direct host ownership of the CFS RF frontend.

The known stock MIFARE write routine at `0x0801970E` and EEPROM write routine at `0x08017F7E` are not referenced by the appended handler.

This is my independent interoperability/reverse-engineering work and is not affiliated with Creality, Bambu Lab or QIDI.
