# Rebuilding the verified image

The current distributable is the exact binary tested on 28 October 2026. Its SHA-256 is
`7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f` (179976 bytes).
Changing filenames and repository layout does not change this firmware.

Prerequisites: Python 3.11+, GNU `arm-none-eabi-gcc`, `arm-none-eabi-ld`, `arm-none-eabi-objcopy`,
`arm-none-eabi-nm`, and the packages in `requirements-test.txt`.

```sh
python3 -m pip install -r requirements-test.txt
python3 scripts/prepare_base.py
python3 tests/run_offline.py
```

The input is the **intermediate already-patched v3.13 base**, not a raw OEM ROM.
It is recovered from immutable Git commit `0ad22669248cc845a3c8d22dd613500c4b95feb3`,
path `firmware/v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin`.
Its verified size is 177700 and SHA-256 is
`9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff`.
The cache `work/base-pinned.bin` is ignored and is not an installable candidate.
No old firmware images are kept in the current tree.

For shallow clones, fetch the immutable commit first:

```sh
git fetch origin 0ad22669248cc845a3c8d22dd613500c4b95feb3
python3 scripts/prepare_base.py
```

A separately recovered matching input can be supplied using
`python3 scripts/prepare_base.py --from-file /path/to/input.bin`.
No automatic download or device action is performed.

The build emits `work/build/candidate.bin`, ELF, symbols and validation JSON.
The test entrypoint requires byte-for-byte equality with the published current image
before executing the ARM regressions. It preserves the 33 hook sites, CRC/header
contract, heap reservation, and the nominal source origin at `0x08010000`;
the physical application load address remains `0x08003000`.

Optional host integration uses a separate Kalico checkout pinned to
`1d7673da14a4860aa188e9b0ef563c5d97d80428`:

```sh
python3 tests/run_offline.py --kalico /path/to/pinned/kalico
```

The reader is injected only into the test process; no printer files, serial port or
hardware API is opened. The suite includes driver framing/error checks and 43
paired Kalico regressions. CI checks out that pinned dependency automatically.

Internal source labels inherited from v3.23/CFG5/CFG6 identify unchanged stock
hooks, not multiple released images. Historical experiments and tests remain
recoverable in Git history. Do not infer full hardware qualification from CI;
see [hardware validation](../../docs/CFG6_RDG2_VALIDATION.md).
