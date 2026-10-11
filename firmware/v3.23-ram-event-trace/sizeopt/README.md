# v3.23 flash-footprint reduction experiment (OFFLINE ONLY)

**No firmware in this directory is deployable.** The installed CFS remains on
the hardware-validated v3.22 `0xD7` image. This experiment modifies a
temporary copy of v3.22's handler assembly and rebuilds/executes it entirely
offline. It preserves the original 28 parameters, all existing RFID and
filament functions, the two actually-connected timing hooks (ID7/ID8), and
the existing (not independently motor-safe) v3.22 firmware write guard.

## Reproducible result

- Baseline v3.22: **178,140 bytes**,
  SHA-256 `40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`
- Source-only optimized experiment: **178,120 bytes**,
  SHA-256 `06f36ef5c088ee2bb3497c89e30695ab1a3ca3b786b563b6f3d2c368ccf28d19`
- **20 bytes reclaimed**.
- Original end `0x0803B7DC`; optimized end `0x0803B7C8`.
  This leaves **56 bytes** to the empirical, unproven
  `0x0803B800` application ceiling.

## Exact optimization

1. The SET routine previously contained a duplicate 3-byte response
   serializer (ID, little-endian 16-bit value). It now moves the SET
   value from R7 into R0 and branches to the *existing* GET serializer.
   This reuses the same response bytes and the existing return path.
2. Eighteen explicitly wide Thumb branch qualifiers are relaxed from
   `.w` to assembler-selected forms, saving a further four bytes
   where the assembler can prove a short branch is valid.

The firmware's two required **BUSY guards remain present**; the static
preflight was updated to accept either `bne.w` or equivalent narrow
`bne`, while still requiring exactly two matching guards and exactly
two original `BOX_OPER_STATE` references. No sidecar write, RFID code,
stock motion opcode, heap pointer, callsite hook selection, or parameter
catalogue has intentionally been altered.

## How to run

From the repository checkout after installing the ARM GNU toolchain and
Python Unicorn:

```bash
python3 firmware/v3.23-ram-event-trace/sizeopt/offline_rebuild.py
```

The test copies the original exact stock v3.13 and v3.19 images, the
v3.22 builder, preflight and Unicorn emulator into a disposable temporary
directory. It recreates both original and optimized binaries, checks
**exact size and SHA-256** for both, and runs the complete emulation suite
on each. The suite checks 28 stock/default GET values, four diagnostic
GET-only IDs, 21 advanced SET/GET/RESET cycles, 42 invalid bounds, seven
BUSY/unknown states, stock IDs 0–6 write protection, malformed sidecar
rejection, and identical register/flags behavior at the original
stock timing callsites 7 and 8. It compares 16 behavioral result fields
between original and optimized builds. The temporary images are deleted
at exit. GitHub Actions executes this test as part of the PR's offline CI.

**This is not enough for v3.23's trace logger.** Even the older
synthetic integrated hook+ring required 380 ARM bytes (later stress
instrumentation uses 432 bytes), not including all production timing,
motor stop-event coverage, GET-only export and concurrency code.
Against 56 available bytes, the minimum remaining deficit is
**324 bytes** for the older synthetic build, and could be materially
larger in the final logger. The `0x0803B800` boundary remains
empirical rather than bootloader-certified.

Never distribute the test-only binary or install it on a physical CFS.
This optimization must receive its own complete hardware regression
before it can be considered for any deployed build.
