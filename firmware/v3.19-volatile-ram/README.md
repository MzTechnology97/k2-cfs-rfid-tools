# Creality K2 Pro CFS v3.19 — experimental volatile RAM bench

> **Experimental, limited hardware validation — NOT a production firmware.** Do not perform CFS load/unload, RFID motion, or print-motion tests with this revision. Keep the known-good v3.13 binary and the original Creality firmware available for rollback.

## Target and integrity

| Field | Value |
|---|---|
| CFS hardware / boot token | `cfs0_050_G32` |
| Stock application identity | `cfs0_000_153` |
| v3.13 patched base SHA-256 | `9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff` |
| v3.19 BIN | `cfs0_050_G32-cfs0_000_153-runtime-config-v3_19-VOLATILE-RAM-BENCH.bin` |
| BIN size | **178068 bytes** |
| BIN SHA-256 | `6af3ac668f36a81f9d403f10bacfa2124737574307049d502bd2ba44ca959f74` |
| Container CRC-16/BUYPASS | `0xCAD5` |
| API7 runtime opcodes | INFO `0x10`, GET `0x11`, SET `0x12`, RESET `0x13` |
| API version / parameter count / feature marker | `2 / 28 / 0xF7` |
| Descriptor opcode `0x14` | Unsupported in v3.19; host catalogue is used for comparisons |

**Firmware capabilities:** GET exposes 28 parameters (IDs 0–27). The 21 advanced IDs 7–27 have manually writable `uint16` overrides and reset commands. IDs 0–6, including the original six speed values and the reverse-detooth switch, are read-only through v3.19; stock motion callsites are **not** connected to the new overrides. The bounds check and idle guard live in the CFS application. Overrides are volatile: they are not persisted to EEPROM or written to RFID tags.

The firmware reserves `0x20006EE8..0x20006F27` (64 bytes) at the former heap boundary; the heap start literal is moved to `0x20006F28`. Boot initialization clears sidecar magic/mask and calls the original heap-init routine. On a CFS reboot these overrides are designed to clear, but **hardware power-cycle retention and RAM-under-load safety have NOT yet been verified**.

## Hardware evidence (2026-10-10)

- **PASS:** real CFS reports API v2, 28 parameters, fingerprint `0xF7`, all 28 default GET values match the expected host catalogue.
- **PASS on real CFS hardware:** **21/21** individual advanced ID 7–27 SET → GET → RESET tests, each restoring the stock value. Crosschecks after IDs 13, 20 and 27 confirmed all advanced defaults remained intact.
- **PASS on real CFS hardware:** four simultaneous advanced overrides were correctly isolated; `RESET ALL` restored all **28/28** baseline values.
- **PASS host protection tests:** attempts to write IDs 0 and 6, two out-of-range values and bulk APPLY were rejected, with all 28 device values unchanged. These are **Kalico host-side** guards, not a direct hardware bypass test of MCU bounds enforcement.
- **PASS read stability:** 60 full-catalogue scans, **1,680 actual GET requests**, with zero errors or data changes; mean scan response approximately 0.065 s.
- **PASS host reconnect:** restarting **Klipper only** preserved a temporary ID18 RAM override (400 → 402), and a subsequent RESET returned it to 400 with all 28 baseline values intact. This does **not** validate power cycling the CFS MCU.
- **PASS in ARM emulation only:** 21 single-ID SET/GET/RESET cycles; 42 out-of-range values rejected; stock IDs 0–6 reject writes; corrupted RAM candidate ignored; busy-state SET rejected; boot-wrapper init contract verified.
- **PASS physical MCU rail power-cycle:** via T113 the MCU supply was observed `ON → OFF (2 seconds) → ON`, and `mcu_cycle` returned success. ID 18 was preset `400 → 405`, then read back as **400** after power restoration without issuing RESET; all **28 values** matched their original baseline. CM5/T113 remained powered, Klipper and CFS recovered to `ready/IDLE`.
- **POST-POWER-CYCLE STARTUP CAVEAT:** CFS startup read initially timed out; a read-only `BOX_CFS_CONFIG_INFO` re-probe succeeded. Motor control discovery succeeded on the **second** startup attempt, with transient RS-485 timeouts. Further boot/reconnect hardening is advisable.
- **NOT YET TESTED:** repeated/long-term physical MCU power-cycle reliability, real filament load/unload and RFID spool movement, motor safety under physical load, firmware bounds rejection bypassing Kalico's host checks, and alternative CFS hardware/firmware generations.

The `HOST_EXPECTED` label in `BOX_CFS_CONFIG_DIAG` is intentional: default/min/max/type come from Kalico, while GET values come from the CFS. The former v3.15/v3.17 `0xFFFF` incident may involve read access to data beyond the validated firmware footprint; **a specific Creality flash-writer size limit is NOT proven**. The current 178068-byte image has a code end at `0x0803B794` and lies below the hypothesized `0x0803B800` boundary, which is likewise not a verified hardware flash-region limit.


The hardware test details are summarized in [`hardware-validation-2026-10-10.json`](hardware-validation-2026-10-10.json). Following the earlier **Klipper-only** restart, motor startup succeeded on the first attempt. Following the later **electrical MCU rail** cycle, motor startup succeeded on the second attempt after transient serial-discovery timeouts; the CFS returned to IDLE and subsequent communication was successful.

## Source files and deterministic build

`handler-v3_19.S` contains the Thumb/Cortex-M3 shim; `build-v3_19.py` checks the exact SHA-256 of the **already patched v3.13** base image and regenerates the output container CRC, length and guarded callsite BL instructions. The generated firmware must match the SHA-256 above. This image is **not** a patch applicable to arbitrary Creality K2/CFS versions.

```bash
# Dependencies: Python 3 and arm-none-eabi-gcc/binutils.
python3 bench_preflight_v3_19.py
python3 build-v3_19.py \
  --base cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin \
  --out /tmp/v319-rebuilt.bin
sha256sum /tmp/v319-rebuilt.bin

# Optional CPU emulation: pip install unicorn
python3 emulate_v3_19.py
```

The base v3.13 BIN is included here solely as the exact supported reconstruction input and rollback reference. Run the full test suite against your own checked-out source; static/emulated tests cannot substitute for hardware acceptance testing.

## Installing through K2-OpenHost installer helper

The helper's `firmware/custom-cfs/manifest.json` approves this exact SHA-256, but its `.gitignore` deliberately excludes firmware BINs. Copy the v3.19 file into the helper's `firmware/custom-cfs/` directory manually. The helper verifies SHA-256 and internal Creality application identity before the flash, requires a physical user confirmation string and calls the stock Creality T113 updater.

```bash
cp firmware/v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_19-VOLATILE-RAM-BENCH.bin \
  /path/to/k2-openhost-installer-helper/firmware/custom-cfs/
```

Menu **40 → experimental v3.19** must only be used on the matching `cfs0_050_G32/cfs0_000_153` CFS. The previous **v3.13** is the rollback option. The helper is intentionally interactive and the normal Creality CFS firmware remains the recovery option.

### Safe first boot check

After flashing, with an idle printer and the companion Kalico `box_cfs_runtime.py` revision installed:

```bash
python3 /path/to/verify_v319_readonly.py
```

This first validation performs only GET and must report feature marker `0xF7`, catalogue 28 and no unexpected defaults. **Do not issue SET, RESET, LOAD, UNLOAD or any CFS movement as part of first boot.** Subsequent manual tests should be individually reviewed and reverted before normal use. The v3.19 Kalico companion disables auto-apply/bulk APPLY for `0xF7` and disallows modification of IDs 0–6.

## Files

- `handler-v3_19.S`, `link.ld`, `build-v3_19.py`: human-reviewable source and exact-image builder
- `bench_preflight_v3_19.py`, `preflight-result.json`, `static-validation.json`: offline patch and flash-footprint checks
- `emulate_v3_19.py`, `arm-emulation-result.json`: Unicorn execution tests and reference results
- v3.13 and v3.19 `.bin` files: rollback baseline and experimental flash artifact, respectively

**Do not treat successful SET/GET/RESET as proof that a parameter affects the original motor or RFID task.** Those 22 movement hook patches remain disabled in this version.
