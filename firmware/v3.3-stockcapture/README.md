# CFS RFID v3.3 stock-capture firmware

This is the experimental CFS firmware I hardware-validated on my Creality K2 Pro.

## Identity

```text
target hardware      cfs0_050_G32
source application   cfs0_000_153
diagnostic API       7
capabilities         0xE8
filename             cfs0_050_G32-cfs0_000_153-rfid-stockcapture-v3_3.bin
size                 176744 bytes
SHA-256              5bab3acff49253a54089e779ea473d2cf587db09ab0d9c07c4d6c2e31b810388
container CRC16      0x97E9
handler address      0x0803AE38
handler size         1072 bytes
```

I built this patch from the exact stock source image with SHA-256 `5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea`.

## Purpose

v3.3 keeps Creality's original RFID task as the RF owner. The host does not directly perform the Bambu authenticated reads. For an armed slot the firmware temporarily substitutes the three Key-A values used by the stock legacy read path. When the stock task successfully reads the expected sector, the patch copies only block 4 (16 bytes of Bambu material detail) and the first four bytes of block 5 (RGBA colour) into scratch bytes of the internal CFS records exposed by diagnostic opcode `0x57`.

The normal Creality RFID record fields are not overwritten.

## API 7

The diagnostic INFO response for this build is:

```text
api=7 readers=2 slots_per_reader=2 capabilities=0xE8 max_index=3 cache_size=16
```

Expected successful one-shot capture state:

```text
hitmask  0x07
okmask   0x07
failmask 0x00
```

Scratch capture markers are `K2C3` for block 4 and `K2D3` for the block 5 RGBA continuation.

## Safety boundary

This build deliberately exposes no tag writes, UID mutation, sector-trailer writes, OTP/lock writes, or EEPROM writes. The API7 Bambu path also does not use direct host RF. The Key-A override is one-shot and cleared after the stock operation. Creality's normal RFID path remains primary; K2-OpenHost invokes Bambu fallback only after the stock result is unknown.

## Hardware validation — 2026-10-07

I tested it on my K2 Pro with the external CM5/OpenHost architecture and a real Bambu Lab spool.

```text
CFS RFID diag API=7 readers=2 slots/reader=2 caps=0xE8 max_index=3 cache_size=16
runtime backend=legacy blocks=4,5,6

UID       233A111D
ATQA      0400
SAK       08
material  PLA
detail    PLA Matte
colour    #FFFFFF
```

I first validated the manual API7 read through Creality's original stock RFID task, then I validated the full automatic path:

```text
normal Creality read
-> stock result unknown
-> Bambu API7 fallback
-> Bambulab PLA Matte / #FFFFFF applied
```

After the test I verified that the stock RFID manager returned idle and that the shared RS-485 link was healthy, with no pending request or consecutive timeout.

The CFS-reported remaining percentage remains authoritative for the slot. API7 v3.3 does not capture Bambu block 14 and does not write usage back to the RFID tag.

## Files

- `cfs0_050_G32-cfs0_000_153-rfid-stockcapture-v3_3.bin` — flashable candidate.
- `handler-v3_3.S` — appended handler source used for this candidate.
- `static-validation.json` — pre-flash structural validation report.

The `flash_performed` field inside `static-validation.json` reflects the state when that static report was generated. I subsequently completed the hardware validation documented above.

## Flashing

Use the guarded K2-OpenHost installer/T113 path. Do not rename the image: the stock Creality updater derives application identity from the filename during this workflow. Keep the stock `cfs0_050_G32-cfs0_000_153.bin` available for rollback.