# R4-PRECISION1 candidate — precise CFS remaining

**Hardware validation pending. R3 remains the reference image.**

This opt-in build adds read-only `0x57/0x1D` SGP1 snapshots. It derives an
initial millimetre estimate directly from the authenticated raw measurement,
then subtracts the existing protected used_mm. Legacy percentages, RFID,
CFG6 startup settings and existing SGF1/RH1 contracts remain unchanged.

There is no new retained SRAM, no motion/RF operation and no counter reset.
The command reply buffer grows from64 to72 bytes (8 stack bytes). The build
stays within the existing nominal0x0803D800 policy; the policy is not expanded.

See [manifest](manifest.json), [SHA-256](SHA256SUMS.txt), and the
[paired host protocol, cache rules and test procedure (Italian)](https://github.com/MzTechnology97/kalico-k2pro/blob/feature/cfs-precise-remaining-20261029/docs/CFS_PRECISE_REMAINING.md).

Build with the existing qualified Debian GCC12.2.1 toolchain:
```sh
python firmware/cfg6-precise-remaining/build.py --base work/base-pinned.bin --out work/build/candidate.bin --build-dir work/build
python tests/run_spool_family.py --precision
```

The complete runner also rebuilds R3 and compares its exact published bytes.
R4 uses the existing physical-base tests, historical negative controls and
new precision/read-only/interleaving cases. No hardware qualification is
inferred from emulator results. The full image hash, not v323-cfg6 identity,
identifies this candidate. A matching Kalico reader is needed to use SGP1;
older Kalico keeps working through the unchanged legacy path.
