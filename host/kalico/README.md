# Kalico host extras

These are the exact host-side extras I use in my K2-OpenHost/Kalico API7 implementation:

- `box_rfid_diag.py` — opcode `0x57` transport, API7 decoding, internal-record access and key-arm/clear operations.
- `box_rfid_bambu.py` — Bambu HKDF Key-A derivation, API7 stock-task orchestration and material/colour parsing.
- `box_rfid_mifare.py` — generic API7 MIFARE Classic decoder registry; QIDI is the first hardware-validated provider.

I publish them here both as a reference and to make porting to other Kalico/Klipper trees easier.

## Dependencies

The files expect the K2 branch's existing:

- `extras.serial_485.build_485_body`;
- `extras.box_protocol`;
- shared `serial_485` request queue/session;
- Box driver with `force_rfid_read(mask)`.

Do not open the RS-485 device independently while the printer stack owns it. Use the existing transport owner/queue.

## Configuration

```ini
[box_rfid_diag]
serial: serial485
address: 1
allow_active_rf: false
require_idle: true

[box_rfid_bambu]
serial: serial485
address: 1

[box_rfid_mifare]
serial: serial485
address: 1
```

In my integrated K2 branch, `[box]` also enables:

```ini
auto_bambu_rfid_fallback: true
auto_mifare_rfid_fallback: true
```

Automatic fallback is deliberately restricted to API7. Older direct-auth diagnostic APIs are not used automatically.


## Structured tag diagnostics

The Bambu extra emits the decoded values through Klipper's G-code responder so they are visible in both the console and `klippy.log`: UID, ATQA/SAK, detailed type, normalized material, expected profile name, colour/RGBA and raw captured block 4 / block 5 bytes.

This is useful when a tag is decoded correctly but the local filament-library naming does not match the tag exactly.

## Persistent association to an existing profile

The integrated K2 branch adds:

```text
_BOX_RFID_ASSOCIATE SLOT=<global-slot> FILAMENT_ID=<library-id>
```

The RFID identity is stored in the mapping layer and points to the selected library profile. The library profile remains authoritative for temperatures, pressure advance and max-flow; the live tag remains authoritative for its colour.

## Generic API7 third-party capture

```text
BOX_RFID_DIAG_STOCK_CAPTURE SLOT=<0..3> KEY0=<12hex> KEY1=<12hex> KEY2=<12hex> CONFIRM=1
```

This diagnostic keeps RF ownership in the stock CFS worker and returns UID, capture masks, block 4 and the first four bytes of block 5. I use it to investigate additional MIFARE Classic spool formats without embedding vendor-specific parsing into the CFS firmware.


## Generic MIFARE / QIDI workflow

I use `box_rfid_mifare.py` for MIFARE Classic spool formats that can reuse API7 but need vendor-specific keys or parsing.

For the first identification of an unknown QIDI tag:

```text
BOX_RFID_MIFARE_READ SLOT=<global-slot>
```

The successful decoder name is saved as a UID routing hint. Subsequent normal `_BOX_RFID_READ_SLOT` operations for that UID go directly to the known decoder instead of first trying Bambu.

I hardware-validated this flow with a QIDI PET-CF spool:

```text
UID=37101573
block4=25020100000000000000000000000000
0x25 = PET-CF
0x02 = Black (#060606)
0x01 = QIDI
identity=QIDI:PET-CF
```

The tag then matched my existing `90003 / Qidi PET-CF` library profile, preserving the profile's pressure advance, maximum flow and temperature while taking the live colour from RFID.
