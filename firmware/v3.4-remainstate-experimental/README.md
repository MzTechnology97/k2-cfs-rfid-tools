# CFS RFID v3.4 REMAIN_STATE diagnostic candidate

This directory contains my **experimental, read-only** extension of the hardware-validated v3.3/API7 CFS firmware.

I built it only to inspect the stock CFS remaining-filament state while reverse-engineering `CMD_RFID_REMAINING (0x03)`. It is **not** the current validated release and it does not replace v3.3.

## What changes

API7 remains API version 7. I add:

- capability bit 4: `REMAIN_STATE`;
- subcommand `0x0A`: read a fixed 40-byte stock remaining-state snapshot.

The snapshot contains only fields already used by the stock CFS remaining manager: stock state/current remaining byte, runtime type/flags, used and nominal-total counters, status, and the four ASCII bytes used as the nominal length field.

I deliberately did **not** add arbitrary RAM reads, stock-RAM writes, direct host RF ownership, tag writes, EEPROM writes or an odometer initializer. The existing API7 Bambu/QIDI capture mechanism remains unchanged.

## Candidate identity

```text
base v3.3 SHA-256  5bab3acff49253a54089e779ea473d2cf587db09ab0d9c07c4d6c2e31b810388
candidate size      176952 bytes
handler address     0x0803AE38
handler size        1280 bytes
container CRC16     0x915D
candidate SHA-256   6da931b20ce8e54f5a4e4b7c5b59999507d9eaefae5afcb9066da4a0acda26cc
API INFO            07 02 02 F8 03 10
```

Static validation and reproducible rebuild passed. Hardware flashing/validation is still pending because I will not bypass the K2-OpenHost root host-evidence safety gate.

## Rebuild

The builder requires the ARM GNU toolchain and the validated v3.3 image:

```text
python3 build-v3_4.py \
  --base ../v3.3-stockcapture/cfs0_050_G32-cfs0_000_153-rfid-stockcapture-v3_3.bin \
  --out cfs0_050_G32-cfs0_000_153-rfid-remainstate-v3_4.bin
```

The builder refuses a base image whose SHA-256 does not exactly match my hardware-validated v3.3 image. It recompiles the handler, repoints only the six stock RFID read callsites whose wrapper addresses move, extends the image tail, and recomputes Creality's CRC-16/BUYPASS and declared length.

A clean rebuild reproduces the candidate SHA-256 above byte-for-byte.

## Host command

With the matching Kalico diagnostic extra:

```text
BOX_RFID_DIAG_REMAIN_STATE SLOT=<0..3>
```

v3.3 fails closed because it does not advertise the new capability.