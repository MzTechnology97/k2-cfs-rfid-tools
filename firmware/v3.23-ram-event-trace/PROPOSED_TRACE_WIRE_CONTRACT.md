# Proposed v3.23 CFS trace readout (offline contract ONLY)

**This is NOT implemented in live MCU firmware, and no host G-code or flashable BIN is provided.** All command identifiers in this document are engineering proposals, not documented Creality protocol commands.

## Purpose

The CFS driver reserves its RS485 session during each physical load/unload. Therefore even a separate Python worker cannot sample raw RAM values in real time. Proposed solution: a low-impact **MCU-side event logger** writes 30 records to volatile RAM during activity; after the motor session is fully completed and the firmware has autonomously **frozen** the trace, a read-only request transfers its contents.

The writer/freezing logic, synchronization, task ownership and callback coverage are **not yet implemented or proven**. This proposal specifies only the *post-movement export model*.

## Candidate protocol

Existing v3.22 experimental firmware uses function **0x57**, API2 GET `0x11`, and returns one 16-bit parameter per request; its 28 setting IDs and read-only IDs 28–31 are left untouched.

Propose a **new read-only** subcommand `0x15` on 0x57 **for a future, separately signed revision only**. The hypothetical request carries exactly one selector byte. No arbitrary RAM address, write, reset, freeze, unfreeze, task state change, motor start or configuration update is permitted.

| Selector | Response payload | Condition |
|---|---|---|
| `0xFF` | 20-byte immutable trace header | Only when trace is frozen |
| `0x00`–`0x1D` (0–29) | 16-byte indexed chronological trace event | Only when frozen, index must be below header.count |
| `0x1E`–`0xFE` | Protocol error | Unsupported |

Existing serial frame-level CRC/ACK handling must validate each response. The normal public `BOX_STATE` and RFID task locking rules still apply. The host should only request events with print standby, no active CFS operation, no filament movement, and a paired protocol/feature signature proven compatible with this additional command.

### Frozen header layout (20 bytes, little-endian)

| Byte offset | Field | Width |
|---|---|---|
| 0 | magic `0x33544643` | 4 |
| 4 | generation | 4 |
| 8 | head index (next write) | 2 |
| 10 | valid event count (0–30) | 2 |
| 12 | saturated overwritten count | 2 |
| 14 | frozen flag (must be exactly 1) | 2 |
| 16 | tick of latest event | 4 |

### Record layout (16 bytes, little-endian)

| Offset | Field | Bytes |
|---|---|---|
| 0 | MCU monotonic tick (source not yet selected) | 4 |
| 4 | 16-bit sequence | 2 |
| 6 | event code | 1 |
| 7 | flags | 1 |
| 8 | raw motor candidate 0 | 2 |
| 10 | raw motor candidate 1 | 2 |
| 12 | raw task candidate 0 | 2 |
| 14 | raw task candidate 1 | 2 |

**The four raw candidate words are opaque; none is an authenticated motor-BUSY flag.** Actual clock/motor hook integration still requires engineering validation.

## Strict receiver checks

The standalone decoder `trace_readback_host.py` first reads the header, then exactly `count` chronological events, then the header again. If generation/head/count/overwritten/frozen/last tick changed, or records are missing, too short, reordered or contain discontinuous sequence numbers, it **rejects the entire capture**. The frame's CRC must be verified by the future serial driver before any decoded values are trusted.

The new helper `trace_readback.c` has no persistent effects: it **refuses output for unfrozen rings**, invalid pointers, lengths and indices, uses explicit little-endian serialization, and does not alter RAM. Its unit tests compare source buffers byte-for-byte and place guards around the 512-byte area.

## Executed offline checks

- Host GCC ASan/UBSan C readback test **passed**: immutable header and 30 records, 20-/16-byte lengths, range checks, overflow chronology, frozen gate, and memory canaries.
- Python synthetic receiver passed: header double-check, generation tear, truncated events, order/sequence validation and invalid headers.
- ARM cross-compilation: readback function `-O2` costs **204 bytes** of code, `-Os` **248 bytes**; this is in addition to the **380-byte** synthetic integrated motor hook/ring at `-Os`. This **584-byte partial sum** excludes UART dispatch, clock, true task synchronization and final firmware metadata.
- All of these tests use fabricated ring contents in memory or isolated ARM emulation: **no genuine on-device motor states were captured.**

## Build space and release gates

The running v3.22 image ends at `0x0803B7DC`, leaving only **36 bytes** to empirically motivated `0x0803B800` (still not certified by the bootloader). The currently known core plus export already exceeds that margin by at least **548 bytes**, even before protocol dispatch, time source, and synchronization are added. No expansion outside the confirmed app area is authorized.

The proposed 512-byte SRAM area would move the original heap start again, from `0x20006F28` to `0x20007128`; **peak RTOS allocations and task stack margins are not proven**. The real motor entry/stop hook coverage, stack/timing safety, IRQ races, idle freeze and precondition checks remain unverified.

**Next implementation work must not weaken SET/RESET protection, automate configuration writes or change motor routines before these gates pass.** Track the independent MCU guard in [issue #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9).
