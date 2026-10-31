# R3 reference hardware validation — 29 October 2026

R3 BIN SHA-256: `a6dec25c74e7d259eec0387193548a0c3cc78ec9fc4ddc35824f0fe0965385b8`, 185900 bytes. Tested with Kalico code commit `89918b046f18a0a04561ba29ca626d01fb2793c1` on the reference CFS G32/CM5. This records the tested RFID/geometry scope; the source and wire contracts are unchanged.

| Reference | Physical slot | Raw circumference | Measurement | RH1 job time |
|---|---:|---:|---|---:|
| New Bambu PETG HF | 2 | 508.253 mm | generation1, flags0x13 | 24.60 s |
| Nearly empty Bambu PETG HF | 4 | 302.823 mm | generation1, flags0x13 | 20.47 s |

Both tags decoded through RH1. Each manual command increased the RH1 request count once and consumed its pending capture. The CFS returned to IDLE without errors. Metadata byte75 remained zero while both observed UID getters and the resulting same-UID proof were valid. No keys or raw capture scratch are published here.

## Vendor calibration and bare-core refinement

The initial experiment used slot4, still containing filament, as a provisional
lower anchor and produced100%/1%. The operator subsequently measured the empty
refill cardboard outer diameter as approximately83mm. This supersedes that
initial anchor. The historical revision2 profile used before the runout refinement was:

```ini
vendor_geometries:
    bambu = 1, 260.8, 508.3
```

Core circumference is pi times83mm, rounded to260.8mm; full circumference is the
measured508.253mm rounded to508.3mm. These are editable host values, not compiled
firmware constants. The ready-to-include K2 macro now contains the later runout refinement; its generic
include stays optional and the standalone example stays disabled until enabled.
See [the calibration procedure](../../docs/CFS_SPOOL_CALIBRATION.md).

Catalog1/revision2 was uploaded after a host restart and bound to both retained
generation1 measurements. Catalog total stayed0 and each tested UID retained
its327000mm nominal length. No additional scan was requested: both generations
stayed1 and the new RH1 session had request0.

| Result after refinement | Physical slot2 | Physical slot4 |
|---|---:|---:|
| Geometry ID / revision | 1 / 2 | 1 / 2 |
| Quality flags | 0x13 | 0x13 |
| Runtime total | 327000 mm | 327000 mm |
| Runtime used | 0 mm | 0 mm |
| CFS percentage | 100% | 12% |
| Kalico remaining | 327.00 m | 39.24 m |

The slot4 result before integer rounding is approximately12.44%; the displayed
residual is an estimate. Both displayed percentages come from CFS. Another slot
with a native mapped RFID profile was not assigned Bambu geometry from its
material-library brand alone. All23 configured CFG6 values applied without error.

## Validation limits

The offline suite has17 checks, including the published BIN comparison, runout calibration and164 UID-observation cases; Kalico includes the Box test suite and passive RDG2 reader checks. Hardware evidence covers the two manual Bambu reads, UID quality, vendor RAM upload, per-UID length and BIND recalculation. The subsequent run below establishes consumption and one automatic runout swap. Physical auto-insertion/reconnect, additional tag formats and direct stack high-water remain unverified. Their existing offline regressions remain part of the suite. The diameter is approximate; the reference coefficients can be refined with more precise physical measurements.

Evidence retained on the reference CM5: `RH1-R3-HARDWARE-SLOT2-20261029.json`, `RH1-R3-HARDWARE-SLOT4-CALIBRATION-20261029.json` and `BAMBU-VENDOR-CALIBRATION-CORE83-20261029.json`. The active configuration and previous file are backed up outside the source repository.

## Runout refinement (29 October 2026)

Physical slot 4 ran out after 19655 mm counted from its retained measurement,
with total327000 mm, initial12% and current6%; automatic replacement by slot2
completed. The effective core was refined to **284.7 mm circumference**, while
full508.3 stays unchanged. It predicts about6.005% at the old measurement.
This is a single-runout host coefficient, not a newly measured cardboard
diameter. It was saved for the next idle host restart; no live profile change,
scan or firmware flash was performed. Another physical cycle must validate it.
BIND rejects replacement of a protected consumed runtime; do not clear usage.
See the [calibration guide](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_SPOOL_CALIBRATION.md).
