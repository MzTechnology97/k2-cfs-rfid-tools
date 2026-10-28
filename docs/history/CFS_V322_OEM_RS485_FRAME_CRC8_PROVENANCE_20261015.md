> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.22 — original MCU RS485 framing and CRC-8 provenance

15 October 2026 · SHA-pinned v3.13 / v3.22 source-only static audit.
Original manufacturer APP physical link base: `0x08003000`.
No original firmware bytes are redistributed.

## Original MCU code evidence

The manufacturer CRC function at **`0x0800E9EC`** starts from zero,
uses polynomial **`0x07`**, XORs each byte and processes eight
MSB-first bit steps without a final XOR. The source function
`0x0800A8CA` builds a scratch CRC input from the original frame's
declared-length, qualifier, command and payload, then calls that CRC
function at `0x0800A8F4`. It excludes the synchronization byte
and bus address from the checksum.

Original transmit helper **`0x0800AA44`** writes `0xF7` as the
synchronization byte, stores the addressed node, computes
**payload length + 3** at `0x0800AA52`, stores a zero qualifier
and the command, copies the payload, then calls the CRC helper at
`0x0800AA66`.

The separate MCU receiving task checks for `0xF7` at
`0x0800F8E8`, enforces minimum declared length **3** at
`0x0800F926`, and calls another envelope checker at
`0x0800F99E`. Manufacturer validity helper
`0x0800A92C` independently checks `0xF7` and tests
`(declared_length - 3) < 0x62` at `0x0800A95C..0x0800A960`,
which implies **at most 97 payload bytes in that particular path**.

This is **not** a global application or updater-stage maximum,
and must not be confused with the 252-byte maximum representable
in a generic 8-bit-length frame. The original code has multiple
receive/check paths. Their complete command and ISR ownership is
not established by this source-only audit.

## Cross-check with previously documented host research

Both read-only documentation vectors validate the recovered CRC
model: `f7 01 04 00 f0 00 4c` (stock version-query stage)
and `f7 01 03 ff 14 06` (version/SN query).
The `0xF0` command also has destructive updater meanings with
different payloads, **none of which is sent or implemented here**.

## Tests and boundaries

New offline script
`firmware/v3.22-readonly-state-probes/cfs_oem_rs485_crc8_frame_provenance_audit.py`
authenticates the exact original Thumb opcodes across both
SHA-pinned saved generations and **rejects 12 altered-source fixtures**.
CI rebuilds v3.22 and repeats the test.

The new receive-only, C11 OpenCFS decoder is maintained separately:
https://github.com/MzTechnology97/OpenCFS-Firmware/pull/4.

**No live CFS GPIO, RS485, motors or firmware flash was performed.**
Source evidence does not establish UART availability, physical
motor-stop feedback, transaction authorization, memory safety of
the OEM runtime, or a recovery-capable bootloader. The firmware
remains unqualified for flashing.
