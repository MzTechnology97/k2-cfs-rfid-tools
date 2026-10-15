# CFS v3.23 safety research: OEM stage-4 RS485 bypass path

*15 October 2026 · offline-only, two pinned OEM application generations.*

## Why the normal 0x57 dispatcher is insufficient

The other agent's local read-only Ghidra research at
`C:\Users\alfio\Documents\cfs-firmware-re\`
contains 1,135 exported CFS v3.22 functions, callgraph, and specifications
(`docs/04-feeder.md`, `docs/03-rs485-protocol.md`).
The important, independently rechecked fact is that **LOAD stage 4**
processes incoming RS485 bytes **inside the active feed loop** without
calling the main command dispatcher `0x0800F27C`.

The precise original Thumb execution chain, in physical addresses:

| Original function / instruction | Meaning |
| --- | --- |
| `0x080045C6`, BL at **`0x08004658`** | LOAD command stage 4 enters `0x08025C4E` |
| `0x08025C4E`, BL at **`0x08025C84`** | active hub feeding loop calls `0x08025EB2` |
| **`0x08025EB2`** | embedded UART reader; RT-Thread serial `0x080169CE`, waits 2 ms |
| BL at **`0x08025EF0`** | UART reader invokes private validator `0x08025C18` |
| **`0x08025C18`** | compares own address and cmd `0x10`, checks CRC-8 of six bytes, returns stage 5/6, CRC error or 0 |
| `0x08025CBA` | active stage 4 sends its own replies with OEM `0x0800EAF2` |
| **`0x0800F3A0`** | our patched normal dispatcher route into the v3.22/v3.23 `0x57` handler; **not used by this stage-4 reader** |

These are **real** original APP PCs; they are not the old nominal
`0x08010000`-based addresses. The same 30 pinned instruction
sites agree in exact saved v3.13 and v3.22 binaries.

## Bounded original ARM emulation

The new Python/Unicorn script
`firmware/v3.22-readonly-state-probes/cfs_oem_stage4_inline_rs485_reader_unicorn_audit.py`
runs the **original manufacturer receive functions** under emulation
with a synthetic in-memory serial stub. No peripheral registers or
physical UART are accessed.

For sync `F7`, the OEM reader requests **1 byte**, waits **2 ms**,
then requests **exactly 8 more bytes**. This is independent of the
received frame's declared-length field. The inner validator checks
the address, command `0x10`, CRC over **six fixed bytes** beginning
with the declared-length byte, and stage value 5 or 6.

The following behavior was replayed in **both v3.13 and v3.22**:

| Offline synthetic request | Internal UART-reader result |
| --- | --- |
| Canonical LOAD stage 5 | 5 |
| Canonical LOAD stage 6 | 6 |
| Declared length 7 (correct recomputed CRC) | 5 |
| Declared length 2 (correct recomputed CRC) | 5 |
| Header / qualifier `0x00` or `0x99` (correct recomputed CRC) | 5 |
| Wrong unit address, opcode `0x57` or stage 4 | 0 (discard) |
| Bad CRC | 0 after discard/drain |
| Wrong leading sync | 0 after discard/drain |

**CRC error nuance:** the private validator at `0x08025C18`
returns **`0xFF`** on CRC mismatch, but the outer reader at
`0x08025EB2` does **not** propagate this to the feed loop: it
drains the serial queue and returns **0**. In the normal stage-4
read path, therefore, a branch in the feed loop expecting
`0xFF` cannot be assumed reachable from a bad CRC.

**Sync nuance:** `0x08025C18` itself does not check the leading
`F7`; the enclosing UART reader does. The wrong-sync direct
validator and enclosing-reader behavior were tested separately.

Eleven synthetic scenarios were tested twice, plus **13 fail-closed
single-byte source mutations** in the original instruction census.

## What this DOES NOT establish

An emulated private stage-4 UART reader is **not** proof that the
global RT-Thread receive task or any upstream Creality transport
will accept a malformed frame. The tests characterize this
bounded private function, not an externally exploitable condition.

Also, the 0x57 command is not dispatched during this inner feed
loop; a `0x57` request is discarded by this code path. This is
important for **availability and correctness** of the proposed
read-only v3.23 diagnostic: the host must not rely on polling it
during stage-4 feeding.

The new v3.23 snapshot of OEM `BOX_STATE` must never be treated
as physical motor stop evidence. A reliable hardware-proven
RFID/motor exclusion design must account for the direct stage-4
reader, the preload thread, print_check refills, automatic RFID
usage accounting, and all feeder/hub start/stop code paths.

The other agent's C++17 host simulator uses a
`Box::motion_active()` software counter and a
`MotionScope` RAII marker; these are **specification/test models**,
not a verified hardware-atomic safety mechanism for the existing
Creality MCU. No copy of its C++ files or private Ghidra output is
included here.

## Release state

**No change** to actual OEM firmware, any CFS interface, installed
Kalico or OpenCFS files. No firmware BIN was emitted. Prior release
blockers — authentic installed bootloader, safe Flash page ownership,
rollback, motor stop and ISR/task interlocks — are unchanged.
**v3.23 is NOT authorized for flashing.**
