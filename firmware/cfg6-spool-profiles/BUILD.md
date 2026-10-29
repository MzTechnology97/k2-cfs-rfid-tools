# Build and verify SGF1 + RH1 R2 offline

Use Python3.11+, ARM GNU GCC12.2.1 and binutils2.40 and [the pinned test dependencies](../../requirements-test.txt).

From repository root:

```sh
python -m pip install -r requirements-test.txt
python tests/run_spool_family.py
```

The runner recovers the pinned intermediate base from Git history, compiles the assembly hooks and freestanding geometry and handoff C extensions, verifies the container against [the candidate manifest](manifest.json), then runs candidate and inherited regressions. Full Git history is needed for base recovery, as for the maintained RDG2 release.

Outputs:

- `work/build/candidate.bin`: exact SGF1 candidate, not automatically installed.
- `work/build/preflight.json`, `static-validation.json`, `symbols.json`, `spool_family.su`.
- `work/build/rfid-handoff-physical-results.json`: physical-base native call targets, worker cleanup, heap initialization and withdrawn-image negative regression.
- `work/build/sgf-test-results.json`: family, actual caller tail, boot, ABI and modeled IRQ tests.
- `work/test-results/sgf-summary.json` and bounded test logs.

The CRC/length container is rebuilt deterministically with the qualified compiler. Because this candidate adds C code, an arbitrary newer compiler is not promised to produce the same BIN. CI uses Debian bookworm packages [gcc-arm-none-eabi15:12.2.rel1-1](https://packages.debian.org/bookworm/gcc-arm-none-eabi) and [binutils-arm-none-eabi2.40-2+18+b1](https://packages.debian.org/bookworm/binutils-arm-none-eabi), matching the local build. The34 checked patchsites, exact base bytes and allowed byte-difference regions are checked. The nominal build policy is extended by one 2KiB page to0x0803D800 (physical0x08030800), remaining below the fast-fetch and parameter regions. This bound is not certification of the installed loader; [RH1 evidence](RH1-CONTRACT.md) records the source-based reasoning. No C globals/BSS or unresolved library routines are allowed outside the explicitly reserved RAM.

The stable [RDG2 source and binary](../cfg6-rdg2/README.md) are not changed. Its separate offline runner continues to verify the known working artifact. SGF1 shares its regression functions, with the unchanged CFG6 identity expectation and explicit candidate hash/size. Both baseline and candidate use the Cortex-M4 emulator for tests involving PRIMASK.

No command here connects to hardware, reads a physical RFID tag, modifies Kalico, restarts a service or flashes a device. Hardware qualification and real curve calibration remain pending.

Slot-length and handoff evidence is written to work/build/slot-length-results.json and work/build/rfid-handoff-results.json. The latter executes the original validator with modeled RF replies and cooperative thread scheduling.

## Physical execution addresses

The application BIN is loaded at `0x08003000`; the analysis ELF uses `0x08010000`. Relative branches move with the image. Absolute native function pointers must explicitly subtract `0xD000` and retain the Thumb bit. The test fixtures convert only attested code entry points, call sites and flash symbols; SRAM and ordinary register values retain their original values. No duplicate flash mapping is allowed. The seven RH1 native pointers are checked in preflight. The earlier `b7cd0ab3…` RH1 candidate is withdrawn because it used nominal pointers; prior nominal-base test passes are insufficient evidence.
