# Standalone implementation guide

In this guide I describe how I implemented **K2 CFS RFID v3.12 / API7** and what is required to reproduce the same approach outside K2-OpenHost.

I wrote it for anyone building a custom host stack, a different Klipper/Kalico fork, or another controller that already communicates with the Creality K2 CFS over RS-485.

I intentionally kept the design goals narrow:

- keep Creality's stock RFID task in control of the RF frontend;
- expose a format-neutral MIFARE Classic key-override/capture mechanism;
- implement Bambu Lab as the first validated host-side decoder/fallback;
- allow future MIFARE Classic formats to add their own host decoder without embedding vendor tables into CFS firmware where possible;
- do not add tag writes;
- do not require a second process to open the RS-485 port;
- reuse the CFS stock geometry/remaining mechanism instead of inventing a host-side percentage.

## 1. Exact firmware target

I have validated the current v3.12 release only for:

```text
hardware token       cfs0_050_G32
stock application    cfs0_000_153
stock image size     175672 bytes
stock SHA-256        5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea
```

Do not apply the patch logic to another CFS image by offset alone. Re-identify every symbol and callsite first.

Published v3.12 image:

```text
size                 177400 bytes
SHA-256              fe436e33a3b86339673b559d345703593e1a8e9ec3237261027e9ae48d048198
container CRC16      0x1609
handler address      0x0803AE38
handler size         1728 bytes
API                   7
capabilities          0xE8
```

The published v3.12 builder rebuilds directly from my hardware-validated v3.3 binary, so none of the intermediate development candidates are required.

## 2. Firmware architecture

The patch adds one application-level diagnostic command on opcode `0x57`.

Opcode `0x57` itself does **not** start RF reads in API7. It is only used for:

- capability discovery;
- reading stock RFID state;
- reading the CFS internal per-slot record;
- arming a temporary three-Key-A override;
- clearing the override;
- reading runtime backend information.

The actual RFID transaction remains inside Creality's original RFID worker.

### Recovered addresses for stock 153

```text
application base       0x08010000
dispatcher hook        0x0801C3A0
response builder       0x0801BAF2
legacy auth/read       0x0801A39E
secure auth/read       0x08022082

stock RFID state       0x200001F0
legacy block table     0x200001F8
hardware/backend flag  0x20000000
internal records       0x20004460
record size            76 bytes
record count           4
```

Patched original stock read callsites:

```text
legacy backend:
  0x0801A4CC
  0x0801A52C
  0x0801A590

secure/FM15L013 backend:
  0x080225D0
  0x08022604
  0x08022638
```

The full handler source is published as:

```text
firmware/v3.3-stockcapture/handler-v3_3.S
```

### Important validation boundary

The current Bambu capture path is validated only when runtime inspection reports the **legacy backend** and blocks `4,5,6`.

The secure backend wrapper can substitute keys, but result capture/decoding has not been validated there. A standalone implementation should refuse automatic Bambu capture when the runtime backend flag indicates secure mode.

## 3. API7 command model

All requests use CFS command `0x57`.

The subcommands used by v3.3 are:

```text
0x00 INFO
0x05 STOCK_STATE
0x06 INTERNAL_RECORD_76
0x07 ARM_KEYS3
0x08 CLEAR_KEYS
0x09 RUNTIME_INFO
```

### INFO

Request payload:

```text
00
```

Expected six-byte payload:

```text
07 02 02 E8 03 10
```

Meaning:

```text
API version          7
readers              2
slots per reader     2
capabilities         0xE8
max index            3
cache/record size    16
```

### STOCK_STATE

Request payload:

```text
05
```

The four returned bytes are the stock RFID manager state. Byte 2 is the active logical slot.

```text
0..3  stock RFID worker busy on that logical slot
>=4   idle
```

Never arm an override while the stock RFID worker is busy.

### INTERNAL_RECORD_76

Request payload:

```text
06 reader local_slot
```

Each reader has two local slots. Global logical slots 0..3 map as:

```text
reader = logical_slot // 2
local  = logical_slot % 2
```

The response is the 76-byte internal CFS record.

For a conservative MIFARE Classic 1K candidate:

```text
offset 60     ATQA[0] = 0x04
offset 61     ATQA[1] = 0x00
offset 62..65 UID, 4 bytes
offset 74     SAK = 0x08
```

Reject a zero UID or any unexpected ATQA/SAK before deriving Bambu keys.

### RUNTIME_INFO

Request payload:

```text
09
```

Four-byte response:

```text
byte 0  hardware/backend flag
byte 1  legacy read block 0
byte 2  legacy read block 1
byte 3  legacy read block 2
```

My validated K2 Pro returned:

```text
00 04 05 06
```

That means legacy backend, blocks 4/5/6.

### ARM_KEYS3

Request payload:

```text
07 reader local_slot key0[6] key1[6] key2[6]
```

API7 uses three six-byte Key-A values because it wraps the three original stock auth/read calls.

For Bambu blocks 4, 5 and 6 all three reads belong to MIFARE Classic sector 1, so the host sends the same sector-1 Key A three times.

On success the firmware returns the cached four-byte UID. The host must verify that it matches the UID used for key derivation.

### CLEAR_KEYS

Request payload:

```text
08 reader local_slot
```

Always clear after a completed or failed attempt. The firmware is one-shot, but host-side cleanup should still be unconditional.

## 4. Bambu Key-A derivation

For a four-byte tag UID, derive 96 bytes using HKDF-SHA256:

```text
IKM   = UID (4 raw bytes)
salt  = 9A759CF2C4F7CAFF222CB9769B41BC96
info  = ASCII "RFID-A" followed by 00
L     = 96 bytes
```

Split the result into sixteen six-byte keys:

```text
sector 0 -> bytes 0..5
sector 1 -> bytes 6..11
...
sector 15 -> bytes 90..95
```

API7 needs sector 1 for the stock legacy block sequence 4/5/6.

The implementation I currently use is in `host/kalico/box_rfid_bambu.py`.

## 5. Stock-task capture flow

The host sequence must be:

```text
1. INFO
2. verify API7 + required capabilities
3. RUNTIME_INFO
4. refuse secure backend
5. STOCK_STATE
6. require idle
7. INTERNAL_RECORD for target slot
8. validate ATQA/SAK/UID
9. derive Bambu sector-1 Key A
10. ARM_KEYS3 with sector1_key repeated three times
11. release diagnostic request lock/session
12. invoke Creality's normal force-RFID-read for that slot
13. wait for the stock operation to finish
14. reacquire the shared request lock/session
15. read target INTERNAL_RECORD
16. read capture records
17. verify masks and markers
18. decode material + colour
19. CLEAR_KEYS
```

Step 11 is important: do not hold a host request mutex across the stock force-read if that same transport owner must process the stock CFS transaction.

## 6. Scratch layout

While armed, the target internal record uses bytes 4..19 as temporary scratch.

Target record:

```text
4..7    K2O2 marker while armed
8       mode = 3
9       hitmask
10      okmask
11      failmask
12..17  key0
```

The next record stores key1/key2 and the `K2N2` helper marker.

Capture storage is intentionally separate from normal stock record fields:

```text
target + 2 records:
  4..7    "K2C3"
  8..19   block4[0..11]

target + 3 records:
  4..7    "K2D3"
  8..11   block4[12..15]
  12..15  block5[0..3] RGBA
```

Record addressing wraps modulo four.

A successful complete stock read must yield:

```text
hitmask  = 0x07
okmask   = 0x07
failmask = 0x00
```

Do not accept partial masks.

On authentication failure the firmware clears capture scratch. After successful index 2 it disarms keys/markers while preserving the masks and capture records long enough for the host to read them.

## 7. Data decoded by API7

API7 intentionally captures only:

- Bambu block 4, 16 bytes: detailed filament type;
- Bambu block 5, bytes 0..3: RGBA colour.

Example validated result:

```text
block 4 -> "PLA Matte"
RGBA    -> FF FF FF FF
profile -> Bambulab PLA Matte
colour  -> #FFFFFF
```

The host should normalize the material conservatively from the detailed type.

v3.12 does not need Bambu block 14. I reuse the CFS's own geometry-derived remaining percentage. For a completed third-party capture the firmware carries a transient validity latch into the stock remaining phase, initializes stock runtime type 4 with a 330 m nominal reference, and leaves `CMD 0x03` as the host-facing interface.

### Other tag formats

The API7 transport is not intrinsically Bambu-specific. A different MIFARE Classic format can use another Key-A strategy and another host parser while reusing the same stock-task/capture mechanism.

QIDI Box is a particularly promising target because published reverse engineering identifies it as MIFARE Classic 1K with the factory Key A `FFFFFFFFFFFF`, and its material/colour/manufacturer payload begins in block 4, which API7 already captures. It still requires a dedicated host decoder and physical validation before it can be called supported.

OpenSpool, Anycubic ACE, ELEGOO, TigerTag/OpenTag3D and OpenPrintTag use different tag/protocol families and are outside the currently validated API7 MIFARE Classic path. See [Third-party filament RFID/NFC compatibility](third-party-tags.md) for the current matrix and research boundary.

## 8. RS-485 integration requirements

Use a **single owner** for the shared RS-485 port.

If your firmware/host already has a CFS transport, extend that transport with opcode `0x57`. Do not start a second serial reader process in parallel.

The K2-OpenHost request body before the transport-specific framing/CRC layer is:

```text
[address, declared_length, 0xFF, 0x57, payload...]
```

The CFS response decoder used by the reference host expects the normal Creality envelope:

```text
byte 0     0xF7
byte 1     CFS address
byte 2     response length field
byte 3     status
byte 4     command (0x57)
byte 5..N  payload
last byte  CRC8
```

If your stack already talks to the CFS, reuse its existing framing and CRC implementation rather than reimplementing the physical transport from this document.

## 9. Minimal host interfaces

A non-K2-OpenHost host implementation needs only three logical interfaces.

### A. Diagnostic request client

It must be able to issue the API7 subcommands above and serialize them with all other CFS traffic.

### B. Stock force-read operation

You need the equivalent of:

```text
force_rfid_read(slot_mask)
```

This must invoke Creality's existing CFS force-read command, not a new host-side RF primitive.

### C. Normal stock inventory/remaining-percent path

Keep the normal Creality/CFS result as primary. Only when the stock record is empty/unknown should Bambu fallback run.

After Bambu profile identification, keep using the ordinary CFS remaining-percentage query. With v3.12 the CFS itself initializes the third-party type-4 runtime from its stock geometry estimate, so the host still reads the ordinary `CMD 0x03` value. I do not infer remaining percentage from Bambu block 14.

## 10. Kalico reference integration

I publish the exact extras I use on my validated setup under:

```text
host/kalico/box_rfid_diag.py
host/kalico/box_rfid_bambu.py
```

In my integrated Kalico branch I also added:

- `0x57: RFID_DIAG` to the shared RS-485 command description table;
- `auto_bambu_rfid_fallback` to `[box]`;
- fallback hooks in the normal RFID-result path;
- Bambu profile creation/matching;
- the two config sections.

Reference configuration:

```ini
[box]
auto_bambu_rfid_fallback: true

[box_rfid_diag]
serial: serial485
address: 1
allow_active_rf: false
require_idle: true

[box_rfid_bambu]
serial: serial485
address: 1
```

`allow_active_rf: false` is correct for normal API7 use. API7 Bambu fallback does not use the older direct diagnostic POLL/READ/AUTH commands.

## 11. Firmware build/porting notes

The published handler source is linked at:

```text
0x0803AE38
```

The validated image changes only the documented original-image regions plus the appended handler. The static validation report lists those regions.

When rebuilding the cumulative v3.12 image:

1. require the exact hardware-validated v3.3 base SHA-256;
2. verify every expected original instruction before patching;
3. repoint the six stock auth/read callsites to the relocated v3.12 wrappers;
4. patch the guarded UID-consistency callsite at `0x08012DDC`;
5. patch the guarded stock message-validation callsite at `0x08012E62`;
6. patch the remaining gate at `0x08013380`;
7. patch the remaining initializer call at `0x08013394`;
8. patch only the `CMD 0x03` validity callsite at `0x0801BF9E`;
9. preserve each original function ABI;
10. append the handler at the expected aligned application end;
11. update the CFS container's declared application length;
12. recompute the container CRC16;
13. verify reset vector/MSP remain valid;
14. disassemble the final image and allowlist external calls;
15. explicitly reject known write primitives;
16. compare all bytes inside the original image against the expected changed-region list.

The v3.3 base already contains the opcode-`0x57` dispatcher hook, so the published v3.12 builder does not need to patch that dispatcher again.

During my validation I explicitly kept these known write functions unreachable from the diagnostic handler:

```text
0x0801970E  stock MIFARE write block
0x08017F7E  BL24Cxx EEPROM write
```

If porting to another CFS firmware version, do not reuse the stock-153 addresses. Recover the symbols and callsites again.

## 12. Validation checklist

Before flashing:

- exact stock hash confirmed;
- final binary hash recorded;
- declared length equals file size;
- container CRC valid;
- handler fully disassembles;
- no unexpected changes in the original image;
- no diagnostic path to tag-write/EEPROM-write functions;
- rollback stock CFS image available.

After flashing, I test in this order:

```text
INFO -> expect API7 / 0xE8
RUNTIME_INFO -> expect legacy backend and blocks 4,5,6
STOCK_STATE -> idle
INTERNAL_RECORD -> valid UID/ATQA/SAK
normal Creality spool -> unchanged RFID behavior
Bambu spool -> API7 capture complete masks 07/07/00
automatic fallback -> material/colour applied
CMD 0x03 after Bambu reread -> value in 1..100
Kalico object -> rfid_reported_percent matches CFS value
normal Creality reread -> stock CMD 0x03 still returns a valid percentage
reboot/power cycle -> firmware remains installed unless your updater reflashes CFS
```

## 13. Failure handling

If any of these occur, abort Bambu fallback and clear the override:

- INFO shape mismatch;
- secure backend reported;
- stock manager busy;
- invalid UID/ATQA/SAK;
- ARM_KEYS returned UID mismatch;
- stock force-read timed out;
- incomplete masks;
- missing `K2C3` / `K2D3` markers;
- malformed material string;
- transport error.

Never retry by opening the serial device from a second process.

## 14. Updating/rebooting the host

The modified CFS firmware is stored on the CFS MCU itself. A normal host or T113 reboot does not inherently replace it.

Whether it survives a reboot depends on your boot/update scripts. Ensure your platform does not automatically flash a stock CFS image at startup.

K2-OpenHost slot B explicitly suppresses automatic CFS reflashing; a standalone implementation must provide equivalent policy if its vendor updater normally flashes CFS at boot.

## 15. Reference files

Current v3.12 release:

- firmware image: `firmware/v3.12-remaining/cfs0_050_G32-cfs0_000_153-rfid-remaining-v3_12.bin`
- firmware handler: `firmware/v3.12-remaining/handler-v3_12.S`
- reproducible builder: `firmware/v3.12-remaining/build-v3_12.py`
- static validation: `firmware/v3.12-remaining/static-validation.json`
- remaining design/validation: `docs/v3.12-remaining.md`

Host reference:

- Kalico transport extra: `host/kalico/box_rfid_diag.py`
- Kalico Bambu extra: `host/kalico/box_rfid_bambu.py`
- generic MIFARE/QIDI extra: `host/kalico/box_rfid_mifare.py`

Historical/rebuild base:

- v3.3 image: `firmware/v3.3-stockcapture/cfs0_050_G32-cfs0_000_153-rfid-stockcapture-v3_3.bin`
- v3.3 design summary: `docs/v3.3-stock-capture.md`