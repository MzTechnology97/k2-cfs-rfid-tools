# CFS RFID diagnostic protocol

This document describes the experimental read-only RFID diagnostic protocol implemented by the first G32 / CFS 153 candidate.

## Transport context

The CFS is reached over the printer RS-485 device bus.

This project does not redefine the stock transport framing. It adds one application-level opcode to the existing CFS frame format.

## Frame structure

Recovered application frame shape used by the diagnostic extension:

```text
F7 | address | length | status | opcode | payload... | CRC8
```

CRC polynomial:

```text
0x07
```

The experimental RFID extension uses:

```text
opcode 0x57
```

## Why opcode 0x57

Static comparison of available CFS application command tables showed that `0x57` uses the invalid/fallback path in the analyzed versions:

- CFS 142;
- CFS 150;
- CFS 153.

The G32/153 patch redirects only that fallback position while preserving stock behavior for other opcodes sharing the dispatcher area.

This must be revalidated independently for every future firmware version.

## API version 1

Request payload begins with a one-byte subcommand.

```text
00  INFO
01  CACHED_TAG_INFO
02  POLL
03  READ_BLOCK
04  READ_BLOCK_AUTH_A
```

## 0x00 INFO

Request payload:

```text
00
```

Current response data:

```text
api_version
physical_readers
slots_per_reader
capability_flags
max_read_index
cache_record_size
```

The first candidate reports:

```text
01 02 02 1F 3F 10
```

Interpretation of capability byte `0x1F` in the first build:

- cached RF record;
- active poll/select;
- `0x30` read;
- Key-A authenticated `0x30` read;
- cascade-level-2 discovery.

The reported maximum read index `0x3F` is a limitation introduced by the first diagnostic build, not a confirmed limitation of the stock `0x30` primitive.

A later generic-read build is expected to widen the unauthenticated index to the complete 8-bit range.

## 0x01 CACHED_TAG_INFO

Request:

```text
01 reader slot
```

Current bounds:

```text
reader = 0..1
slot   = 0..1
```

No new RF exchange is initiated.

On success, the response contains the exact 16-byte stock discovery record.

Layout:

```text
00..01  ATQA
02..05  CL1 anticollision bytes
06..09  CL2 anticollision bytes
0A..0C  stock/private working bytes
0D      current BCC working byte
0E      final SAK
0F      stock/private working byte
```

This is the preferred first live diagnostic because it observes stock state rather than initiating a new RF operation.

## 0x02 POLL

Request:

```text
02 reader slot
```

The current implementation calls the recovered stock reader-probe path.

Conceptual sequence:

```text
reader setup
REQA/WUPA 0x52
anticollision CL1
SELECT CL1
optional anticollision CL2
optional SELECT CL2
cache RF metadata
cleanup
```

Success returns the 16-byte discovery record.

The diagnostic status preserves the RF failure stage.

## 0x03 READ_BLOCK

Request:

```text
03 reader slot index
```

The stock primitive emits RFID command `0x30` and expects 16 bytes in the receive path.

Interpretation depends on tag family.

### MIFARE Classic

The argument can represent a block number and the 16 returned bytes correspond to a block.

### Type-2 / Ultralight / NTAG-like behavior

For compatible Type-2-style tags, command `0x30` is normally a READ operation starting from a page and returning a 16-byte multi-page window.

For this reason the host interface may expose both `read-block` and `read-page` terminology while preserving the raw 16-byte result.

The tool must not infer memory geometry solely from the command name.

### Current first-candidate bound

The first candidate checks:

```text
index < 0x40
```

Static inspection shows that this bound was introduced by the patch. The recovered stock call receives an 8-bit value.

The next generic read-only candidate should therefore evaluate widening unauthenticated read access to:

```text
0x00..0xFF
```

while keeping hardware testing bounded and conservative.

## 0x04 READ_BLOCK_AUTH_A

Request:

```text
04 reader slot block keyA[6]
```

Sequence:

1. poll/select tag;
2. obtain UID fragment needed by the stock authentication helper;
3. authenticate using Key A / command `0x60`;
4. invoke stock `0x30` read;
5. clean up reader state;
6. return 16 bytes.

The key is supplied by the caller.

No proprietary/default key is embedded in the diagnostic firmware.

The authenticated command should remain conservatively bounded until MIFARE Classic sector geometry above the initially tested range has been explicitly reconstructed.

## Status codes

Current diagnostic status mapping:

```text
0  OK
1  bad request / malformed length / bounds
2  request stage failure / no tag
3  anticollision failure
4  select failure
5  authentication failure
6  read failure / unexpected receive length
```

These values are diagnostic API semantics, not claimed to be native ISO14443 status codes.

## Read-only guarantee of API v1

The first handler is intentionally restricted to known read-side targets.

It does not expose:

- MIFARE `0xA0` write;
- EEPROM write;
- tag formatting;
- UID changes;
- key updates;
- lock/OTP writes;
- arbitrary raw RF transceive.

The static validator checks the handler's external call set against an allowlist.

## RAW_TRANSCEIVE

There is currently no API subcommand for unrestricted raw transceive.

A future command must not be added until the FM17622 behavior required to return trustworthy low-level results has been reconstructed, especially:

- TX bit framing;
- RX bit count;
- collision position;
- FIFO level/overflow;
- error flags;
- CRC;
- parity;
- IRQ completion conditions;
- timer/timeout behavior;
- cleanup/reset behavior.

When implemented, raw transceive should return the RF status metadata to the host rather than reducing every failure to a generic error.

## Compatibility rule

The application-level protocol described here is experimental and versioned independently of Creality's firmware version.

A host tool should always query `INFO` before assuming the availability or semantics of later subcommands.


## API v2 development candidate

API v2 preserves the same application opcode and subcommand numbers as v1.

The deliberate differences are:

```text
INFO api_version              2
INFO max_read_index           0xFF
READ_BLOCK unauth index       0x00..0xFF
READ_BLOCK_AUTH_A block       0x00..0x3F
```

The authenticated path remains conservatively limited to the original 64-block range.

No new external firmware calls were added. The allowlisted call set remains identical to v1 and still contains no write primitive.

The v2 host tool adds an operator-side active-RF gate. Live commands that initiate a reader transaction require:

```text
--allow-active-rf
```

Passive `INFO` and `CACHED_TAG_INFO` remain available without that option.

This guard is intended to prevent accidental interference during early hardware validation. It does not replace future firmware-side synchronization if a stock RFID concurrency condition is identified.


## API v2.1 / protocol v3

The v2.1 candidate keeps application opcode `0x57` and extends the read-only API.

```text
INFO api_version              3
INFO capability_flags         0x7F
READ_BLOCK unauth index       0x00..0xFF
READ_BLOCK_AUTH_A block       0x00..0x3F
0x05 STOCK_STATE              passive
status 7                      stock RFID busy
```

Two new capability bits are advertised:

```text
bit 5  passive STOCK_STATE available
bit 6  stock active-slot guard enabled
```

### 0x05 STOCK_STATE

Request:

```text
05
```

Success returns four bytes beginning at stock RAM address `0x200001F0`.

The current host interpretation is:

```text
byte 0  low-level auth-sector cache/invalidation byte
byte 1  stock state/gate byte; exact semantics not fully established
byte 2  active stock RFID logical slot
byte 3  additional stock state byte; currently exposed raw
```

For byte 2:

```text
0..3  stock RFID manager busy with the corresponding logical slot
>=4   idle according to the stock manager rule
```

This command is passive and does not start an RF transaction.

### Busy guard

Before `POLL`, `READ_BLOCK` or `READ_BLOCK_AUTH_A`, the diagnostic handler reads `0x200001F2`.

If the value is below 4, it returns:

```text
status 7  stock RFID busy
```

without calling the FM17622 reader-probe/read/authentication helpers.

The guard does not modify the stock RFID manager.

It is not an atomic mutex: a theoretical race still exists if the stock firmware begins a new RFID operation after the state check. Active diagnostics therefore remain restricted to controlled idle testing and still require the host-side `--allow-active-rf` opt-in.
