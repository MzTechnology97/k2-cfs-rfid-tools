# CFS RFID v3.12 — stock-geometry remaining

This directory contains my current hardware-validated CFS firmware for `cfs0_050_G32 / cfs0_000_153`.

v3.12 is cumulative: it keeps my API7 stock-task capture and guarded fast-accept work, then adds the remaining-filament path that I validated on a real Bambu spool.

## Candidate identity

```text
published base v3.3    5bab3acff49253a54089e779ea473d2cf587db09ab0d9c07c4d6c2e31b810388
candidate filename     cfs0_050_G32-cfs0_000_153-rfid-remaining-v3_12.bin
candidate SHA-256      fe436e33a3b86339673b559d345703593e1a8e9ec3237261027e9ae48d048198
candidate size         177400 bytes
handler address        0x0803AE38
handler size           1728 bytes
container CRC16        0x1609
nominal total          330000 mm
runtime type           4
```

The original stock image SHA-256 is:

```text
5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
```

## How I make third-party remaining work

The stock firmware already estimates spool fill geometrically. I traced the result to:

```text
0x20003974 + slot
```

The stock path normally refuses to initialize remaining for a third-party tag because the Creality record/validity gates do not pass.

I solved this without fabricating a Creality record.

When the third authenticated API7 read succeeds, I write a temporary `K2RL` latch into scratch that has already been cleared of the Key A data. This happens inside the CFS RFID task, before the geometry/remaining phase.

Later, at the stock remaining gate:

1. I always run the original stock gate first;
2. if stock accepts, I leave the result unchanged;
3. if stock rejects, I permit the branch only for the current logical slot when the third-party API7 latch/capture is valid;
4. if the stock code has replaced the percentage argument with `0xFF`, I recover the just-computed value from `0x20003974 + slot`;
5. I initialize the stock type-4 runtime with 330000 mm nominal length;
6. I call the stock remaining setter;
7. I consume the temporary latch.

The next API7 ARM/CLEAR also wipes the scratch, so I do not carry this state between unrelated reads.

## Why 330 m

From a genuine Creality RFID record captured on hardware I recovered:

```text
len = 0330
```

The stock initializer interprets this as 330 m / 330000 mm. I therefore use the same nominal reference for third-party spools. The percentage remains an approximate CFS geometry estimate, not a precision mass measurement.

## Hardware result

I validated v3.12 on 2026-10-08.

Bambu PETG HF:

```text
CMD 0x03 payload  0CFFFFFF
slot remaining    12%
```

The existing Kalico object then exposed `rfid_reported_percent=12` with no new CM5 remaining implementation.

As a regression test I reread a genuine Creality RFID spool:

```text
CMD 0x03 payload  FF21FFFF
slot remaining    33%
```

This confirmed that the normal Creality remaining path still works.

## Rebuild

I rebased the published builder so it starts directly from the v3.3 binary already present in this repository:

```text
python3 build-v3_12.py \
  --base ../v3.3-stockcapture/cfs0_050_G32-cfs0_000_153-rfid-stockcapture-v3_3.bin \
  --out cfs0_050_G32-cfs0_000_153-rfid-remaining-v3_12.bin
```

I verified that this rebuild is byte-for-byte identical to the image I hardware-tested.

## Safety

I do not write the Bambu/QIDI RFID tag and I do not write CFS EEPROM.

The static validation explicitly reports:

```text
unexpected_changed_bytes     = 0
tag_writes_added             = false
eeprom_writes_added          = false
host_extra_changes_required  = false
```
