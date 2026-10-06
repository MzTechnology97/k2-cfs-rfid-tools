# RFID architecture

This page describes the current working model of the RFID stack inside the Creality K2 CFS.

## Layered view

```text
+------------------------------------------------------+
| Host / printer                                      |
|                                                      |
|  diagnostic host tool / stock printer application   |
+-------------------------+----------------------------+
                          |
                          | CFS application protocol
                          | RS-485
                          v
+------------------------------------------------------+
| CFS MCU                                              |
|                                                      |
|  stock command dispatcher                           |
|        |                                             |
|        +--> proprietary spool/tag logic              |
|        |                                             |
|        +--> experimental opcode 0x57                 |
|                |                                     |
|                +--> cache inspection                 |
|                +--> poll/select                      |
|                +--> read 0x30                        |
|                +--> Key-A auth + read                |
+-------------------------+----------------------------+
                          |
                          | low-level reader driver
                          v
+------------------------------------------------------+
| Fudan FM17622 RFID frontend(s)                      |
|                                                      |
|  request / anticollision / select / auth / read     |
+-------------------------+----------------------------+
                          |
                          | 13.56 MHz RF
                          v
+------------------------------------------------------+
| ISO14443-A compatible tag                           |
+------------------------------------------------------+
```

## Important architectural separation

The stock CFS contains at least two conceptually different layers:

1. **RF / tag communication**
2. **Creality spool interpretation**

The project targets the first layer.

A third-party tag does not need to satisfy the proprietary spool parser in order to be useful to the diagnostic interface. If the RF layer can discover/select it, its UID and other low-level metadata may be recoverable before the stock application decides that the tag is unsupported.

## Physical reader topology

Current recovered model:

```text
CFS MCU
  |
  +-- FM17622 reader 0
  |      +-- logical slot 0
  |      +-- logical slot 1
  |
  +-- FM17622 reader 1
         +-- logical slot 0
         +-- logical slot 1
```

Total:

```text
2 physical readers
4 logical tag positions
```

The exact antenna switching implementation should remain documented separately from the logical addressing model if later hardware inspection reveals additional details.

## Discovery cache

The stock RF layer maintains a compact record for each logical position.

Base:

```text
0x20004410
```

Addressing:

```text
record = base + reader * 0x20 + slot * 0x10
```

Record size:

```text
0x10 bytes
```

Recovered content:

```text
00..01  ATQA
02..05  CL1 response / UID bytes
06..09  CL2 response / UID bytes
0A..0C  stock/private working state
0D      current BCC
0E      final SAK
0F      stock/private working state
```

This structure is valuable because it reflects RF discovery state before the proprietary application-level tag format is accepted or rejected.

## Stock RF operations recovered

The firmware implements enough low-level behavior to support the current research without replacing the whole RFID driver.

### Discovery

The stock reader path performs:

```text
RF init / mode setup
        |
        v
request / wake-up (0x52)
        |
        v
anticollision CL1
        |
        v
SELECT CL1
        |
        +---- no cascade ----> selected
        |
        v
anticollision CL2
        |
        v
SELECT CL2
        |
        v
selected
```

### Authentication

A stock MIFARE Key A authentication helper has been identified.

The diagnostic extension passes the key from the host instead of embedding one.

### Read

A stock 16-byte read helper issues RF command:

```text
0x30
```

How the index should be interpreted depends on tag family.

### Write

A stock `0xA0` write helper exists.

It is excluded from the current diagnostic handler and should remain outside the read-only interoperability phase.

## Experimental application hook

The first CFS 153 candidate uses application opcode:

```text
0x57
```

The hook is deliberately narrow.

Conceptually:

```text
incoming opcode
      |
      +-- 0x51 ---------> original stock handler
      |
      +-- 0x57 ---------> diagnostic handler
      |
      +-- anything else -> original invalid/fallback path
```

After a diagnostic response, execution returns to the original stock common tail.

The objective is to add observability without replacing the normal CFS application state machine.

## Diagnostic handler call boundary

The first candidate uses only these recovered stock functions:

```text
RF mode / cleanup
reader probe / discovery
MIFARE Key-A auth
0x30 read
CFS response builder
```

The known RFID write primitive is deliberately absent from the handler call graph.

## Host-side architecture

The intended host utility has three roles.

### Protocol transport

Build and parse CFS frames:

```text
F7 | address | length | status | opcode | payload | CRC8
```

### RF metadata interpretation

Decode:

- UID;
- UID length;
- ATQA;
- SAK;
- cascade state;
- BCC state;
- raw cache bytes.

Any tag-family classification should be presented as a hint unless the evidence is conclusive.

### Memory acquisition

Perform bounded read-only acquisition and retain:

- reader/slot;
- UID/ATQA/SAK;
- read index;
- raw 16-byte result;
- error stage;
- firmware/API version.

This allows dumps from third-party filament tags to be compared without requiring the CFS firmware itself to understand each vendor's spool data format.

## Why raw transceive is a later layer

A generic raw exchange should eventually sit below the current high-level operations:

```text
generic tag tool
      |
      +-- poll
      +-- read
      +-- auth + read
      |
      +-- future RAW_TRANSCEIVE
              |
              v
        FM17622 register layer
```

However, exposing arbitrary RF frames before collision, FIFO, timeout, CRC, parity, IRQ and cleanup semantics are understood could produce misleading results or leave the reader in an inconsistent state.

For that reason the project first maximizes generic read-only functionality using known stock primitives.

## Version boundaries

The architecture must be considered in three separate namespaces:

```text
hardware identity   cfs0_050_G32
stock application   cfs0_000_153
diagnostic API      v1, v2, ...
```

Do not assume that:

- another CFS hardware revision has the same peripheral map;
- another stock firmware has the same function addresses;
- another diagnostic API version uses the same payload semantics.

Every firmware patch must resolve and validate its own target addresses.
