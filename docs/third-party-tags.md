# Third-party filament RFID/NFC compatibility

I designed K2 CFS RFID v3.3 as a **generic MIFARE Classic stock-task enabler**, not as Bambu-only firmware.

I deliberately kept Bambu material tables and parsing out of the firmware itself. API7 gives the host a controlled way to:

- inspect the CFS-cached tag identity;
- inject three temporary MIFARE Classic Key-A values into Creality's original RFID task;
- let the stock CFS perform the RF transaction;
- capture the successful stock reads of blocks 4 and 5 into scratch memory;
- decode those bytes on the host.

The current `box_rfid_bambu.py` extra is the first host-side decoder/orchestrator I built on top of that mechanism.

## Current support status

| Format / ecosystem | Tag technology | Current v3.3 status | Notes |
| --- | --- | --- | --- |
| Creality CFS | MIFARE Classic 1K | **Native / unchanged** | Creality's original path remains primary. |
| Bambu Lab | MIFARE Classic 1K | **Implemented and hardware validated** | API7 + `box_rfid_bambu.py`; material detail and RGBA are captured from blocks 4/5. |
| QIDI Box | MIFARE Classic 1K | **Strong candidate; not yet implemented/tested** | Uses factory Key A `FFFFFFFFFFFF`; material, colour and manufacturer are stored in the first three bytes of sector 1 block 4. API7 already captures block 4, so a QIDI host decoder should likely require no new CFS firmware changes. |
| Snapmaker U1 | MIFARE Classic 1K | **Strong candidate; not yet implemented/tested** | Public KDF is available. Material type/subtype are in block 4 and primary RGB begins in block 5, which matches the existing API7 capture window unusually well. Official tags also carry an RSA signature, relevant to authenticity/creation but not basic decoding of a genuine tag. |
| Anycubic ACE Pro | NTAG213 / MIFARE Ultralight family | **Not supported by current API7 path** | Working third-party generators use NTAG213; requires a Type-2/Ultralight page-read path rather than Classic sector authentication. |
| ELEGOO filament tags | NTAG213 / NFC Type 2 | **Not supported by current API7 path** | ELEGOO publishes the layout openly, but it is page-based NTAG213 with password/access configuration. |
| Prusa / OpenPrintTag | OpenPrintTag; production Prusament uses ISO15693/ICODE-SLIX-style tags | **Not supported by current API7 path** | Open and writable format, but current production tag RF protocol differs from MIFARE Classic. |
| OpenSpool | NTAG215/216, NFC Type 2, NDEF JSON | **Not supported by current API7 path** | Different tag family/protocol from the validated MIFARE Classic stock worker. |
| TigerTag / OpenTag3D | NTAG213/215/216 | **Not supported by current API7 path** | Open formats, but use Type-2 tags instead of MIFARE Classic 1K. |
| Raise3D Pro3 HS | RFID, read/write including spool weight | **Unknown** | Official firmware can read/write RFID and update weight, but no reliable public tag-family/memory-map reverse engineering was found. |
| FlashForge AD5X / Creator 5 family | No confirmed native vendor-spool RFID format found | **No direct match established** | Recent community NFC integrations use an external reader and FlashForge LAN API rather than a confirmed official spool-tag protocol. |

## Why QIDI is especially interesting

Published QIDI reverse engineering describes the QIDI Box tag as a MIFARE Classic 1K card using the standard factory Key A:

```text
FF FF FF FF FF FF
```

The payload is in sector 1 block 4:

```text
byte 0  material code
byte 1  colour code
byte 2  manufacturer code
```

API7 already makes Creality's stock task authenticate/read blocks 4, 5 and 6 and captures all 16 bytes of block 4.

Therefore a future QIDI implementation can plausibly be host-only:

```text
Creality result unknown
-> validate MIFARE Classic candidate
-> ARM_KEYS3 with FFFFFFFFFFFF repeated three times
-> Creality stock force_rfid_read()
-> read API7 block-4 capture
-> decode QIDI bytes 0..2
-> map material/colour/manufacturer
-> clear override
```

I have **not yet tested this on a physical QIDI spool in the K2 CFS**, so I do not consider QIDI supported until I complete hardware validation.

## Why Snapmaker U1 is also interesting

Public Snapmaker U1 research identifies the official tag as **MIFARE Classic 1K** and publishes the KDF used to derive authentication keys.

The published parser places the basic spool identity in exactly the area API7 already captures:

```text
offset 64   version             -> block 4
offset 66   main material type  -> block 4
offset 68   subtype             -> block 4
offset 72   colour count        -> block 4
offset 73   alpha               -> block 4
offset 80   primary RGB         -> block 5
```

API7 currently captures all of block 4 and the first four bytes of block 5, so a basic Snapmaker material/subtype/primary-colour decoder may not require a CFS firmware change.

Official Snapmaker tags also carry an RSA signature. That prevents forging a fully valid official tag without Snapmaker's private key, but it does not prevent a host from decoding the fields of an already genuine tag.

A future implementation could therefore be:

```text
Creality result unknown
-> identify MIFARE Classic 1K candidate
-> derive Snapmaker sector-1 Key A with the published KDF
-> ARM_KEYS3
-> Creality stock force_rfid_read()
-> decode block 4 + first bytes of block 5
-> map material / subtype / colour
-> clear override
```

I have not implemented or tested this on K2 CFS hardware yet.

References:
- https://github.com/SnapmakerResearchGroup/RFID
- https://github.com/paxx12-snapmaker-u1/SnapmakerU1-Extended-Firmware

## Anycubic ACE Pro

Public reverse engineering and working third-party tag generators use **NTAG213** stickers for ACE Pro-compatible tags; NTAG215/216 are also considered likely compatible.

This is a Type-2 / MIFARE Ultralight style memory model, not the MIFARE Classic sector-authentication path used by API7. Supporting Anycubic therefore requires a new page-read path in CFS firmware and verification that the reader frontend can perform the required Type-2 operations.

References:
- https://github.com/Molodos/anycubic-nfc-filament
- https://github.com/Simon-CR/ace2-pro-firmware-research

## ELEGOO

ELEGOO publishes its spool tag layout openly. The official guide specifies **NTAG213**, with user data beginning at page `0x04` and password/access settings near the end of tag memory.

The data format is easy to decode, but its transport is incompatible with the current MIFARE Classic API7 path. It belongs in the same future Type-2/NTAG extension as Anycubic and OpenSpool.

Reference:
- https://github.com/elegooofficial/ELEGOO-RFID-Tag-Guide

## Prusa / OpenPrintTag

Prusa's OpenPrintTag is attractive because the **data format is open, writable and includes remaining-filament information**.

New Prusament spools use OpenPrintTag. Community reader tooling for production tags documents an ISO15693 / ICODE SLIX/SLIX2 workflow. OpenPrintTag as a data format can be represented on other NFC media, but the production Prusament tag path is not the MIFARE Classic 1K path currently exposed by API7.

Therefore the current CFS firmware cannot simply add a new Key A and read Prusament. It would need an ISO15693/NFC-V access path, assuming the CFS reader IC supports it.

References:
- https://github.com/OpenPrintTag/openprinttag-specification
- https://help.prusa3d.com/article/openprinttag_978161
- https://github.com/bkerler/OpenPrintTagGUI

## Raise3D

Raise3D officially documents RFID read/write support on the Pro3 HS family, including writing filament weight back to the tag. That makes it technically interesting because mutable remaining-material state is part of the design.

However, no sufficiently reliable public reverse engineering was found during this research that identifies the tag IC/family, authentication or memory map.

Compatibility with API7 is therefore **unknown** until at least one genuine Raise3D tag is identified/dumped.

Official references:
- https://www.raise3d.com/raise3d-pro3-hs-series/
- https://www.raise3d.com/news/raisetouch-1-8-3-708-release-notes-pro3-hs-series/

## FlashForge

For the current AD5X / Creator 5 family, the public material reviewed did not establish a native FlashForge spool RFID format comparable to Bambu, Creality, QIDI or Anycubic.

Recent community TigerSpool support for FlashForge uses an **external NFC reader** and then writes the selected material into the printer through the LAN API. That is useful integration, but it is not evidence of a native FlashForge spool-tag protocol that the K2 CFS could decode.

For now FlashForge should remain unclassified as a CFS RFID-format target.

## Why OpenSpool is different

OpenSpool uses NTAG215/216 Type-2 NFC tags carrying an NDEF JSON payload. That is not the same memory/authentication model as MIFARE Classic 1K.

The current v3.3 firmware hooks Creality's authenticated MIFARE Classic stock read path. It does not implement:

- NTAG page enumeration;
- NDEF TLV parsing;
- Type-2 tag memory capture;
- ISO 15693 / NFC-V access.

So v3.3 **does not currently make the CFS an OpenSpool reader**.

The project does, however, establish the architectural pattern needed for future expansion: keep the CFS hardware as the RF frontend, add a narrowly scoped firmware bridge, and decode vendor/open formats on the host. Before adding NTAG/OpenSpool support, the CFS reader IC and stock firmware must first be verified to support the required Type-2 operations.

## Design principle

I want to keep the firmware format-neutral wherever possible.

Vendor/open-format knowledge belongs on the host:

```text
CFS firmware:
  tag access + temporary key substitution + raw capture

host extra:
  format detection + authentication/key derivation + field decoding + profile mapping
```

This means additional MIFARE Classic formats may be added as separate host extras without embedding brand-specific material tables into the CFS firmware.

Possible future extras:

```text
box_rfid_qidi.py        # likely reusable with current API7 firmware
box_rfid_snapmaker.py   # basic material/colour likely reusable with current API7 firmware
box_rfid_anycubic.py    # requires new Type-2/Ultralight firmware path
box_rfid_elegoo.py      # requires new Type-2/NTAG firmware path
box_rfid_openspool.py   # requires new Type-2/NDEF firmware path
box_rfid_openprinttag.py # production Prusament requires ISO15693/NFC-V support
```

## Support wording

At the time of writing:

- **Creality**: stock/native.
- **Bambu Lab**: implemented and hardware validated.
- **QIDI**: excellent technical match for the existing API7 capture mechanism, but not implemented or hardware tested.
- **Snapmaker U1**: excellent technical match for basic material/subtype/primary-colour capture; KDF/parser implementation and hardware testing are still required.
- **Anycubic ACE Pro / ELEGOO**: formats are known, but they use Type-2/Ultralight/NTAG media and require a firmware extension.
- **Prusa / OpenPrintTag**: open and attractive format, but production Prusament tags use a different RF protocol and require separate reader support.
- **Raise3D**: RFID read/write exists, but the public tag technology remains insufficiently documented.
- **FlashForge**: no native spool-tag format was confirmed in the public material reviewed.

I do not consider a tag format supported simply because it appears in this document.