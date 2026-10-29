# R3 reference hardware validation — 29 October 2026

R3 BIN SHA-256: `a6dec25c74e7d259eec0387193548a0c3cc78ec9fc4ddc35824f0fe0965385b8`, 185900 bytes. Tested with Kalico code commit `04b2a73c1684637cec9e3ade9b9f2ba7ff6c37fe` on the reference CFS G32/CM5. This records the tested RFID/geometry scope; the source and wire contracts are unchanged.

| Reference | Physical slot | Raw circumference | Measurement | RH1 job time |
|---|---:|---:|---|---:|
| New Bambu PETG HF | 2 | 508.253 mm | generation1, flags0x13 | 24.60 s |
| Nearly empty Bambu PETG HF | 4 | 302.823 mm | generation1, flags0x13 | 20.47 s |

Both tags decoded through RH1. Each manual command increased the RH1 request count once and consumed its pending capture. The CFS returned to IDLE without errors. Metadata byte75 remained zero while both observed UID getters and the resulting same-UID proof were valid. No keys or raw capture scratch are published here.

## Provisional vendor calibration

The operator selected physical slot2 as the full reference and slot4 as the nearly-empty reference. The latter still contains some filament, so this is an operational calibration, not an exact bare-core measurement. Rounded to the protocol's0.1mm units, the active reference host uses:

```ini
vendor_geometries:
    bambu = 1, 302.8, 508.3
```

These are measured circumferences, not diameters. They are not compiled into firmware or enabled in the shipped example. The profile is selected by an explicitly decoded Bambu RFID identity, independently of material/color. Catalog total remains0; each tested UID receives its327000mm nominal length separately.

After a host restart, Kalico uploaded profile1/revision1 to CFS RAM and bound both existing measurements. No additional scan was requested: both generation counters stayed1 and the new host session still had request0.

| Result after binding | Slot2 | Slot4 |
|---|---:|---:|
| Geometry ID / revision | 1 / 1 | 1 / 1 |
| Quality flags | 0x13 | 0x13 |
| Runtime total | 327000 mm | 327000 mm |
| Runtime used | 0 mm | 0 mm |
| CFS percentage | 100% | 1% |
| Kalico remaining | 327.00 m | 3.27 m |

The source of both displayed percentages is CFS. A third slot carrying a native mapped RFID profile was not assigned Bambu geometry just from its material-library brand; it retained its existing cache estimate. All23 configured CFG6 runtime parameters were applied without error.

## Validation limits

The offline suite has15 groups, including164 UID-observation cases; Kalico has557 Box tests. Hardware evidence covers the two manual Bambu reads, UID quality, vendor RAM upload, per-UID length and BIND recalculation. R3 print-time consumption, physical auto-insertion/reconnect behavior, additional tag formats and direct stack high-water are not established by this run. Their existing offline regressions remain part of the suite. The nearly-empty anchor can be refined when a bare-core or accurately known remaining amount is available.

Evidence retained on the reference CM5: `RH1-R3-HARDWARE-SLOT2-20261029.json`, `RH1-R3-HARDWARE-SLOT4-CALIBRATION-20261029.json` and `BAMBU-VENDOR-CALIBRATION-20261029.json`. The active configuration and previous file are backed up outside the source repository.
