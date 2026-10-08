# K2 CFS RFID v3.3

This repository contains my hardware-validated **Creality K2 Pro CFS RFID v3.3 / API7 stock-capture** implementation.

I developed this firmware to add Bambu Lab RFID interoperability without replacing Creality's normal RFID worker and without exposing tag-write operations. I intentionally kept the firmware mechanism more generic than the current Bambu host extra: API7 can temporarily supply MIFARE Classic Key-A values to Creality's original stock task and capture successful reads for host-side decoding. This also gives me a path to support additional MIFARE Classic filament formats; at the moment I have implemented and hardware-validated only Bambu.

## Validated target

```text
CFS hardware        cfs0_050_G32
stock application   cfs0_000_153
stock SHA-256       5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
patched size        176744 bytes
patched SHA-256     5bab3acff49253a54089e779ea473d2cf587db09ab0d9c07c4d6c2e31b810388
container CRC16     0x97E9
diagnostic opcode   0x57
API                 7
capabilities        0xE8
```

## What v3.3 does

Creality's original CFS RFID task remains the RF owner.

For a Bambu-compatible MIFARE Classic 1K tag the host:

1. reads the UID already discovered by the CFS;
2. derives Bambu sector Key A values;
3. arms a one-shot API7 key override;
4. asks the **normal Creality force-read path** to reread that slot;
5. the firmware substitutes the derived Key A only at the three original stock authentication/read calls;
6. successful stock reads copy block 4 material detail and block 5 RGBA into scratch bytes;
7. the host reads those scratch bytes and clears the override.

The ordinary Creality RFID record fields are not modified.

The CFS remains authoritative for the slot's remaining-filament percentage. v3.3 intentionally does not use Bambu block 14 for that purpose.

## Hardware result

I validated this build on 2026-10-07 on my K2 Pro with a real Bambu Lab spool:

```text
UID       233A111D
ATQA      0400
SAK       08
material  PLA
detail    PLA Matte
colour    #FFFFFF
```

I also validated the complete automatic path:

```text
Creality stock read -> unknown -> API7 Bambu fallback -> Bambulab PLA Matte / #FFFFFF
```

## Repository layout

```text
firmware/v3.3-stockcapture/
  cfs0_050_G32-cfs0_000_153-rfid-stockcapture-v3_3.bin
  handler-v3_3.S
  static-validation.json
  README.md

host/kalico/
  box_rfid_diag.py
  box_rfid_bambu.py
  README.md

docs/
  v3.3-stock-capture.md
  standalone-implementation.md
  third-party-tags.md
```

I removed the older experimental API revisions, obsolete test firmware, test suites and superseded builders from the main branch to keep the repository focused on the current implementation.

## Using it

For my K2-OpenHost/Kalico setup, I use the host extras in `host/kalico/` together with the matching integration in the `k2-pro-openhost` branch.

If you want to port the same approach to another firmware or host stack, I documented the required steps in the [Standalone implementation guide](docs/standalone-implementation.md).

I keep the current compatibility boundary and the most promising future targets, such as QIDI and Snapmaker, in [Third-party filament RFID/NFC compatibility](docs/third-party-tags.md).

## Safety boundary

v3.3 has no host-exposed tag-write operation and does not add UID mutation, sector-trailer writes, lock/OTP writes or EEPROM writes. The API7 Bambu path does not perform direct host RF transactions.

This is my independent interoperability/reverse-engineering work and is not affiliated with Creality or Bambu Lab.

## Experimental remaining-state research

I am reverse-engineering the stock CFS `CMD_RFID_REMAINING (0x03)` path for Bambu/QIDI tags. The current hardware-validated release remains **v3.3/API7**.

My current findings and the separate **read-only v3.4 diagnostic candidate** are documented in:

- [CFS 1.5.3 remaining-filament reverse engineering](docs/cfs-remaining-reverse-engineering.md)
- [v3.4 REMAIN_STATE experimental candidate](firmware/v3.4-remainstate-experimental/README.md)

The v3.4 directory intentionally does not replace the v3.3 release. Its hardware-validation status is `pending`, and the stable installer manifest remains pinned to v3.3.
