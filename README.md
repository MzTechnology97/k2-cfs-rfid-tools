# K2 CFS RFID — CFG6 SGF1/RH1 R3

**R3 is the current reference image for CFS G32 / stock application cfs0_000_153.**
It adds single-cycle host-key RFID handoff, UID measurement proof and vendor
spool geometry in RAM, while retaining CFG6, API7 and RDG2 interfaces.

[Italiano](README.it.md) · [R3 BIN](firmware/cfg6-spool-profiles/cfs0_050_G32-cfs0_000_153-K2OH-CFG6-SGF1-RH1-R3-CANDIDATE.bin) · [SHA-256](firmware/cfg6-spool-profiles/SHA256SUMS.txt) · [Build](firmware/cfg6-spool-profiles/BUILD.md) · [Hardware evidence](firmware/cfg6-spool-profiles/HARDWARE-R3.md) · [Calibration](docs/CFS_SPOOL_CALIBRATION.md)

## Exact image and matching host

| Item | Value |
|---|---|
| Image | `cfs0_050_G32-cfs0_000_153-K2OH-CFG6-SGF1-RH1-R3-CANDIDATE.bin` |
| Size | 185900 bytes |
| SHA-256 | `a6dec25c74e7d259eec0387193548a0c3cc78ec9fc4ddc35824f0fe0965385b8` |
| Runtime identity | K2OH / v323-cfg6, CONFIG API2, features0xE3 |
| Additional interfaces | SGF1 with slot length, RH1 version1; existing API7/RDG2 retained |
| Host | [Kalico k2-pro-openhost](https://github.com/MzTechnology97/kalico-k2pro/tree/k2-pro-openhost) with `box_spool_profiles` |

The runtime identity is shared by earlier images. Use the image SHA to identify
R3. The filename retains its tested CANDIDATE suffix; its bytes are unchanged.
The published image is checked against a rebuild with the qualified compiler.

## Reference results

Two Bambu PETG HF spools in physical slots2/4 decoded through one RH1 request
each, in24.60s/20.47s. Both measurements returned flags0x13 with matching UID
proof, while the original metadata byte75 remained0. R3 fills both observed
UID buffers when the supported legacy getter lacks its length.

The reference host profile is now `bambu = 1, 284.7, 508.3`, with
circumferences in mm. The effective core was inferred from a physical runout:
slot4 consumed19655mm of327000mm nominal after the original12% scan estimate,
but still reported6%. It predicts6.005% for that retained scan; slot2 remains
full. The physical cardboard diameter about83mm gave the earlier260.8mm
coefficient and is retained as history. The new coefficient awaits another
physical cycle and was saved without changing RAM during printing.

Geometry is selected from a successfully decoded RFID vendor, not from a
filament preset's brand text. Nominal length remains per UID/slot; material
and color do not choose a geometry. On CFS RAM loss, Kalico retains cached
remaining and subtracts odometer use until a later valid measurement is bound.

## Install and calibrate

The [Installer Helper](https://github.com/MzTechnology97/k2-openhost-installer-helper)
menu40 lists R3 first and retains RDG2 as a fallback. Flash only on an idle
printer/CFS using its supervised acknowledgement. Then enable the paired
[Kalico configuration](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/config/k2/macros/box_spool_profiles.cfg)
and follow the [calibration procedure](docs/CFS_SPOOL_CALIBRATION.md).
The reference coefficients are editable host settings, never compiled vendor
constants. Measure an empty support and a known full spool for another geometry.

## Reproduce offline

Use the pinned compiler and dependencies in
[BUILD.md](firmware/cfg6-spool-profiles/BUILD.md), then run:

```sh
python tests/run_spool_family.py
```

Tests map one image at the real application base0x08003000. They execute the
original UID copier/getters, comparator, validator and worker finalizer with
RF/RTOS boundaries modeled. Historical negatives reject the withdrawn native
pointer image and reproduce R2's missing UID proof. The baseline RDG2 runner
remains available as `python tests/run_offline.py`.

Hardware evidence covers RFID, UID proof, RAM geometry, per-UID length and
catalog replacement on the reference machine. Physical auto-insertion/reconnect and direct stack high-water remain separate
hardware checks; offline regressions do not extend physical qualification.

## Fallback and history

[CFG6 RDG2](firmware/cfg6-rdg2/README.md) remains available as the previous
reference: RFID and print remaining39→34 were observed on28October2026.
It has no SGF1/RH1 vendor geometry. The unsafe b7cd RH1 build is withdrawn and
R2 is superseded; neither is offered as an installable image here. Their exact
source history is retained for mandatory regression controls.

[Compatibility](docs/CFS_FIRMWARE_COMPATIBILITY.md) · [SGF1 wire contract](docs/SGF1_CANDIDATE_PROTOCOL.md) · [RH1 evidence](firmware/cfg6-spool-profiles/RH1-CONTRACT.md) · [RDG2 validation](docs/CFG6_RDG2_VALIDATION.md).

Independent interoperability and reverse-engineering work; not affiliated with
Creality, Bambu Lab or QIDI.
