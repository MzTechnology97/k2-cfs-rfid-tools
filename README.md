# K2 CFS RFID — CFG6 v3.25 experimental firmware

**Latest firmware candidate: K2OH CFG6 v3.25** for **Creality K2 Pro CFS G32 / stock APP `cfs0_000_153`**. This repository retains the historical **v3.12 API7 RFID release**, the CFG4/CFG5T intermediate builds and the matching Kalico integration.

[**Guida italiana / Italian README**](README.it.md) · [**Download experimental CFG6 firmware**](firmware/v3.25-cfg6-lab/cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin) · [**CFG6 documentation EN**](firmware/v3.25-cfg6-lab/README.md) · [**CFG6 documentation IT**](firmware/v3.25-cfg6-lab/README.it.md)

## Current version — CFG6 v3.25 (18 October 2026)

| Property | CFG6 v3.25 |
|---|---|
| MCU/hardware | `cfs0_050_G32` / Creality APP `cfs0_000_153` |
| Runtime identification | `K2OH`, revision `v323-cfg6`, API v2, feature byte `0xE3` |
| Runtime parameters | **28 readable; 23 actually writable** through stock execution hooks |
| New writable IDs compared with CFG5T | **6, 9, 11–19, 21, 23, 24, 27** (15 additional controls) |
| GET-only IDs | **0, 4, 10, 25, 26** |
| Installation | [Experimental CFS firmware menu](https://github.com/MzTechnology97/k2-openhost-installer-helper), option **3** in the documented six-candidate manifest |
| Paired host software | [Kalico `k2-pro-openhost`](https://github.com/MzTechnology97/kalico-k2pro/tree/k2-pro-openhost), `box_cfs_runtime.py` and `box.cfg` |
| Status | **Installed and SET/GET tested on one CFS**, experimental; **not motion/RFID or long-running production qualified** |

**Installable image:** [`cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin`](firmware/v3.25-cfg6-lab/cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin)

**SHA-256:** `6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6`

To install through the Helper on a compatible idle K2-OpenHost CM5:

```bash
cd ~/k2-openhost-installer-helper
./helper.sh experimental-cfs
```

Select **CFG6 v3.25** and follow the interactive safeguards. The Helper checks the BIN and its SHA-256 before asking for explicit confirmation. **Flashing is never automatic.** Keep the [CFG5T v3.24](firmware/v3.24-cfg5t/README.md) and [v3.22](firmware/v3.22-readonly-state-probes/README.md) rollback candidates available.

### What CFG6 changes

- **CFS hub loading/unloading:** independent hub forward, transition, insertion and reverse speed controls. These are **raw 1–255 motor commands, not mm/s**. Spool feeders are ON/OFF and their pseudo-speeds (IDs 0/4) remain GET-only.
- **Motion sequencing:** configurable hub waits, insert sensor/odometer stall and feed/recovery timeouts. These alter delays and failure thresholds, **not toolhead extruder speed**.
- **RFID behavior:** configurable seek/measurement/reposition speeds, settle times and neighbor search retry count. Physical performance at all settings still needs printing/RFID qualification.
- **Pretension and reverse de-tooth:** controls for actual pretension loop count (ID27) and gated reverse de-tooth action (IDs 6/24).
- **Remaining filament:** preserves the stock-based type-4 consumption path; its **real-print percentage decrement remains to be qualified**.
- **Runtime contract:** Kalico applies selected overrides from `[box_cfs_runtime]` only at startup with the exact firmware identity and `auto_apply: True`. It does **not** send these CFG6 SET operations to stock Creality, CFG4, CFG5T or OpenCFS.

### Hardware validation achieved — and still pending

On **18 October 2026**, the reference CFS reported `K2OH / v323-cfg6 / 0xE3`. In printer standby with the CFS idle, matching Kalico successfully applied **23/23 configured values** and a separate diagnostic read **28/28 IDs**, matching all **23/23 writable overrides**. Klipper and the motor discovery completed. **No G28, Z homing, axis motion, filament loading/unloading or RFID motion was performed during these checks.**

**Safety warning:** early motor enumeration observed RS-485 timeout/CRC warnings before recovery. More importantly, [issue #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9) remains **open**: the original CFS MCU can report `BOX_STATE=IDLE` while feeding is physically active; a fully proven independent MCU motor-idle/atomic write interlock is still missing. Host-side safety checks and successful idle SET/GET are not evidence of safe writes during physical motion. **Do not send direct SET/RESET during movement. Experimental use only, not production qualified.**

**Detailed documentation:**
- [Every CFG6 parameter (English): effects, stock/defaults, units, limits, caveats](firmware/v3.25-cfg6-lab/PARAMETERS_EN.md)
- [Ogni parametro CFG6 (Italiano): comportamento, valori, limiti e rischi](firmware/v3.25-cfg6-lab/PARAMETERS_IT.md)
- [Firmware source, builder and offline tests](firmware/v3.25-cfg6-lab/)
- [Host integration and configuration (EN)](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_RUNTIME_CFG6_EN.md) · [IT](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_RUNTIME_CFG6_IT.md)
- [Latest development status, PR/issue triage (EN)](docs/CFG6_STATUS_PR_TRIAGE_20261018_EN.md) · [IT](docs/CFG6_STATUS_PR_TRIAGE_20261018_IT.md)

## Firmware version history

| Image | Identity / feature | Directory | Evidence and status |
|---|---|---|---|
| **CFG6 v3.25 — latest** | **`v323-cfg6 / 0xE3`** | **[`firmware/v3.25-cfg6-lab/`](firmware/v3.25-cfg6-lab/)** | **Installed; 23/23 SET/GET verified; still experimental** |
| CFG5T v3.24 | `v323-cfg5t / 0xE5` | [`firmware/v3.24-cfg5t/`](firmware/v3.24-cfg5t/) | 8 writable IDs + gated type-4 task; rollback |
| CFG4 v3.23 | `v323-cfg4 / 0xD7` | [`firmware/v3.23-k2oh/`](firmware/v3.23-k2oh/) | 6 effective writable IDs; historical |
| v3.22 | `0xD7` | [`firmware/v3.22-readonly-state-probes/`](firmware/v3.22-readonly-state-probes/README.md) | Previously field-tested load/unload and prints; rollback |
| v3.21 | `0x97` | [`firmware/v3.21-busy-guard/`](firmware/v3.21-busy-guard/README.md) | Historical incomplete MCU busy-guard |
| v3.20 | `0xB7` | [`firmware/v3.20-timing-hooks/`](firmware/v3.20-timing-hooks/README.md) | Timing hook experiments |
| v3.19 | `0xF7` | [`firmware/v3.19-volatile-ram/`](firmware/v3.19-volatile-ram/README.md) | Volatile RAM bench |
| v3.12 | API7 | [`firmware/v3.12-remaining/`](firmware/v3.12-remaining/) | Historical hardware-validated RFID interoperability and Bambu remaining percentage |

**Historical validation is distinct from CFG6 qualification:** v3.12 has independently tested RFID captures, while v3.22 has prior prints/load-unload results; these do not automatically establish CFG6's dynamic behavior.

## Historical experimental v3.19 CFS runtime-parameter firmware (2026-10-10)

A **separate, NOT production-ready** v3.19 volatile-RAM bench image is now published under [`firmware/v3.19-volatile-ram/`](firmware/v3.19-volatile-ram/README.md). On an actual K2 Pro CFS the 28 default GET values and feature marker `0xF7` passed; one manual SET/GET/RESET of advanced ID 18 also passed. All other advanced writes and any movement effects remain unvalidated. Advanced motor/RFID movement hooks are disabled. Do not use the v3.19 image for regular CFS operations.

The directory contains a reproducible patched-v3.13 base, the full v3.19 assembly and builder, offline tests, exact SHA-256 and rollback guidance. The companion [Kalico extra](https://github.com/MzTechnology97/kalico-k2pro) and [installer helper manifest](https://github.com/MzTechnology97/k2-openhost-installer-helper) are updated separately. **The v3.12 RFID implementation retains separate historical material-tag validation; the installed CFG6 has verified startup configuration/readback, but is not yet mechanically or RFID-qualified.**

## Historical v3.12 validated firmware target

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
  v3.25-cfg6-lab/              # current experimental CFG6 firmware and tests
    cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin
    PARAMETERS_EN.md / PARAMETERS_IT.md
  v3.24-cfg5t/                 # earlier experimental version / rollback
  v3.23-k2oh/                  # CFG4 historical build

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

## Italiano — ultima versione CFG6 v3.25

La versione più recente è **K2OH CFG6 v3.25** (`v323-cfg6`, API2, feature `0xE3`) per CFS G32/APP153. Sono disponibili **28 ID in lettura** e **23 parametri realmente modificabili**: velocità hub, temporizzazioni, ricerca RFID, pretensione e reverse de-tooth. Gli ID 0, 4, 10, 25 e 26 sono solo GET.

Sul CM5 è stata verificata l'applicazione di **23/23 parametri** e la lettura di **28/28 ID** con `auto_apply: True`. Non sono ancora stati qualificati il comportamento fisico di caricamento/scaricamento, il movimento RFID, l'affidabilità RS-485 prolungata e il residuo live durante una stampa. **Il problema di sicurezza [#9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9) resta aperto**: non modificare parametri mentre i motori sono in funzione.

**[README italiano completo](README.it.md)** · [Firmware e BIN CFG6](firmware/v3.25-cfg6-lab/README.it.md) · [Guida di tutti i 28 parametri](firmware/v3.25-cfg6-lab/PARAMETERS_IT.md) · [Helper](https://github.com/MzTechnology97/k2-openhost-installer-helper)
