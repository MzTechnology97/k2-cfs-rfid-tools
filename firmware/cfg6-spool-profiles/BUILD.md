# Build and verify SGF1 offline

Use Python3.11+, ARM GNU GCC12.2.1 and binutils2.40 and [the pinned test dependencies](../../requirements-test.txt).

From repository root:

```sh
python -m pip install -r requirements-test.txt
python tests/run_spool_family.py
```

The runner recovers the pinned intermediate base from Git history, compiles the assembly hooks and freestanding C extension, verifies the container against [the candidate manifest](manifest.json), then runs candidate and inherited regressions. Full Git history is needed for base recovery, as for the maintained RDG2 release.

Outputs:

- `work/build/candidate.bin`: exact SGF1 candidate, not automatically installed.
- `work/build/preflight.json`, `static-validation.json`, `symbols.json`, `spool_family.su`.
- `work/build/sgf-test-results.json`: family, actual caller tail, boot, ABI and modeled IRQ tests.
- `work/test-results/sgf-summary.json` and bounded test logs.

The CRC/length container is rebuilt deterministically with the qualified compiler. Because this candidate adds C code, an arbitrary newer compiler is not promised to produce the same BIN. CI uses Debian bookworm packages [gcc-arm-none-eabi15:12.2.rel1-1](https://packages.debian.org/bookworm/gcc-arm-none-eabi) and [binutils-arm-none-eabi2.40-2+18+b1](https://packages.debian.org/bookworm/binutils-arm-none-eabi), matching the local build. The34 checked patchsites, exact base bytes and allowed byte-difference regions are checked. The same nominal flash policy limit0x0803D000 is retained. No C globals/BSS or unresolved library routines are allowed outside the explicitly reserved RAM.

The stable [RDG2 source and binary](../cfg6-rdg2/README.md) are not changed. Its separate offline runner continues to verify the known working artifact. SGF1 shares its regression functions, with the unchanged CFG6 identity expectation and explicit candidate hash/size. Both baseline and candidate use the Cortex-M4 emulator for tests involving PRIMASK.

No command here connects to hardware, reads a physical RFID tag, modifies Kalico, restarts a service or flashes a device. Hardware qualification and real curve calibration remain pending.
