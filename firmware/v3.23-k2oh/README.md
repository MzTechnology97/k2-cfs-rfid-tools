# CFS v3.23 K2-OpenHost — work in progress

**Draft. Not a flashable release; no BIN is published here.**

v3.23 builds on v3.22 (`../v3.22-readonly-state-probes/`). It keeps the RFID, remaining-filament, runtime-config and diagnostic features, and adds what is listed below.

## Done (step 1)

- **Build identity, command `0x7A`.** The reply has the same layout as OpenCFS: the magic `"K2OH"`, format 1, variant 4 (patched Creality application), bench level 0, flags `0x02` (parameter page never written), the revision `v3.23-k2oh` (12 bytes), and the Creality version from the base image at `+0x200` (`cfs0_000_153`). Kalico applies runtime values only to a CFS that answers with `"K2OH"`.
- **Image size policy:** the limit moves from real `0x0802E800` to real `0x08030000`. The only stock data area above the application is the parameter page at `0x0807F800`.
- **Checks:**
  - `build-v3_23.py` keeps the v3.22 changed-byte check;
  - `bench_preflight_v3_23.py` passes;
  - `emulate_v3_23.py` (Unicorn) checks the `0x7A` reply, a malformed `0x7A`, `0x57` INFO, and the stock `0x51` and invalid paths, with no RAM writes outside the stack.

## Planned

- **Writable parameters:** IDs 1-3 and 5 (hub speeds) and 6 (reverse detooth) become writable in the stock configuration structure, as in v3.13. IDs 0 and 4 stay read-only, because the feeders are driven on/off and a speed has no effect.
- **Hooks:** IDs 9, 11-24 and 27 get hooks at their stock sites (see `cfs-firmware-re` `docs/12-runtime-config.md`). IDs 10, 25 and 26 stay read-only, because their stock code is never executed.
- **Units:** every time value is in milliseconds on the wire. The firmware converts to the stock unit: ID 8 to 10 ms steps, IDs 20 and 22 to 20 ms ticks.
- **ID 17 default:** 400 ms, the stock value; the earlier catalogue had 10.
- **Live type-4 remaining on boards without the FM15L013:** the design is in `cfs-firmware-re` `docs/09-live-remaining-legacy-patch.md`.
- **Writes:** only from Kalico at Klipper start, never from the console. Kalico enforces this.

## Build and check

```bash
python3 build-v3_23.py --base ../v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin --out v3_23.bin
python3 emulate_v3_23.py v3_23.bin   # needs the unicorn package
```

Step 1 output: 178,216 bytes, SHA-256 `536e0e5b1738c27fe7491dba40b02c05be613412f9e74249083f6181c360ca27`. This is a test build, not for flashing.
