# v3.23 live ROM/heap audit and release gates — 2026-10-11

**Status: no safe-to-flash v3.23 firmware exists.** All observations were
made on byte-exact offline firmware images and the copied stock ARM T113 updater.
The physical CFS was not reset, updated or moved.

## Heap bounds recovered from original stock image

Static analysis of the original `cfs0_000_153` application at
`0x080278D4..0x08027964` identified two adjacent heap-init literals:

| Stock binary address | Original value | Meaning in heap initialization |
|---|---|---|
| `0x0802795C` | `0x20010000` | Upper heap bound / top of the 64KB SRAM |
| `0x08027960` | `0x20006EE8` | Original heap base |
| `0x08027960`, patched v3.22 | `0x20006F28` | Base moved forward 64B to preserve volatile runtime sidecar |
| `0x08027960`, **hypothetical** v3.23 | `0x20007128` | Would reserve 512B more for 30 event records |

The current volatile sidecar occupies `0x20006EE8..0x20006F27`, with the
512-byte candidate ring directly after it at
`0x20006F28..0x20007127`. The allocator would then see approximately
**36,568 bytes**, compared with **37,080 bytes** after the existing
v3.22 sidecar. This would reduce the nominal heap span by **512B (~1.38%)**.

**Not yet established:** worst-case *live* allocation or fragmentation
during RFID authentication, neighboring-spool reads, PLA load/unload,
timeouts/recovery, RTOS task stacks, IRQ nesting, or possible DMA overlap.
The unchanged successful performance of v3.22 does not prove that an
additional 512B can safely be removed. Before a new firmware build, the
reservation needs an independent allocation high-water benchmark or a
verified stock RTOS heap/stack map. No new heap literal patch has been
applied.

## Flash footprint and minimum optimization target

- CFS app ROM base: `0x08010000`.
- Operationally verified v3.22 image: **178,140B**,
  end **`0x0803B7DC`**, CRC/length header consistent.
- Conservatively treated maximum app end: **`0x0803B800`**, corresponding
  to a maximum image length of **178,176B**. This is an *empirical
  engineering cap*, not a verified bootloader partition boundary.
- Current conservative headroom: **36B**.
- Simulated *linked* trampoline + full C RAM logger: **380B** at `-Os`.
  This binary was placed at a deliberately fake emulator address
  `0x08050000`, not at a demonstrated CFS executable memory location.
- **Absolute minimum extra safe code space to recover: 344B** just to add
  that synthetic 380B core. A real MCU tick source, reliable motor
  start/stop event coverage, task synchronization and GET-only log drain
  would add yet more bytes. The final optimization budget is therefore
  **strictly greater than 344B**, not a production size estimate.

The v3.22 handler is already compact and omits disabled advanced hooks.
The C ring itself measures **320B at `-O2` or 280B at `-Os`**.
No change to working RFID/remaining-filament functionality is currently
authorized simply to make room for telemetry.

## What vendor updater inspection can and cannot prove

The Creality `mcu_util_485` executable was copied **read-only** from the
authorized T113. Its subcommands cover bootloader enumeration, version,
transfer block size, application erase, update, firmware length/chunks,
and starting the app. The community-derived
[RS485 protocol](https://github.com/Lamar1007/CFSTool/blob/main/PROTOCOL.md)
matches this general structure: `get sector size` chooses a UART transfer
chunk; it does **not** report the maximum writable application image size.

No proven address/length partition map or authenticated bootloader flash-read
command was identified from this inspection. Therefore attempting a
larger-than-tested image based only on 512KB physical MCU flash or a
successful size transfer ACK is **NOT SAFE**.

### Read-only next path

1. Acquire an **offline, independent, read-only SWD flash dump** or an
   authoritative Creality bootloader linker/map file. This requires suitable
   *separately attached* hardware, valid access permissions and an
   independently reviewed method that does not mass-erase or disable
   readout protection. There is no such debugger accessible from the
   current CM5 connection.
2. Run `python3 memory_gate.py --swd-dump /path/to/private_dump.bin
   --dump-base 0x08000000` to inventory *candidate* address literals.
   **Do not publish a proprietary raw dump.** Literal occurrences do not
   alone prove a partition; disassemble and inspect the actual erase/program
   loops before certifying any limit.
3. Validate peak heap allocation, stack high-water and motor callbacks in
   a non-printing diagnostic bench. The ring in this PR is offline-only,
   never driven by a real CFS motor interrupt.
4. Only when all boundaries are verified, integrate ring and read-only
   drain within the confirmed app region and rerun full ARM differential
   tests. Keep the host motion/SET-RST exclusion active.

## Safe current state

The already installed **v3.22 `0xD7`** is running with 28 normal
parameters, Klipper `ready/standby`, CFS `IDLE`, path clear and no
reported errors at the last read-only query. It was not flashed or
restarted during this v3.23 forensic work.

[Real v3.22 memory audit JSON](V323_REAL_V322_MEMORY_AUDIT.json) has
`safe_to_flash=false` by design. Nothing in this PR is a deployable BIN.
