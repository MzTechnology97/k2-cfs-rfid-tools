# K2 CFS RFID — CFG6 RDG2

**CFG6 RDG2: operation verified in the real case of 28 October 2026.** This branch contains one firmware image for **Creality K2 Pro CFS G32 / stock application `cfs0_000_153`**, its reproducible sources and the matching Kalico diagnostic reader.

[Italiano](README.it.md) · [Firmware image](firmware/cfg6-rdg2/cfs0_050_G32-cfs0_000_153-K2OH-CFG6-RDG2.bin) · [Validation and limits](docs/CFG6_RDG2_VALIDATION.md) · [Compatibility](docs/CFS_FIRMWARE_COMPATIBILITY.md) · [Kalico integration](host/kalico/README.md)

## Exact artifact

| Item | Value |
| --- | --- |
| Image | `cfs0_050_G32-cfs0_000_153-K2OH-CFG6-RDG2.bin` |
| Size | **179,976 bytes** |
| SHA-256 | `7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f` |
| Runtime identity | `K2OH / v323-cfg6`, CONFIG API2, features `0xE3` |
| RFID interface | API7, capabilities `0xE8` |
| Read-only snapshot | Opcode `0x57`, subcommand `0x15`, 64-byte `RDG2` version 2 |
| Matching host reader | `host/kalico/box_rfid_diag.py`, SHA-256 `2b9810456f6bb7ae0f2ebbf82cdf1f293dab84867a9db2799fb3035cb7aef867` |

The runtime identity and the OEM version displayed by the printer do not uniquely identify this build. Check the complete image SHA-256. The CONFIG feature byte and RFID capability byte describe different interfaces.

## What was verified

During a real print with **Bambu PETG HF in physical slot 4** (local index 3), the CFS MCU usage counter advanced through **0 → 51 → 202 → 6,293 → 17,113 mm**. The CFS percentage changed **39 → 38 → 34**, and the normal `CMD 0x03` reply independently returned 34. The operator confirmed the manual RFID read.

The observed RS-485 session recorded **31,548 transmitted and received frames**, with zero recorded timeouts, CRC, length, matching, send, reader or connection errors. RDG2 measured `PRIMASK=1` during the snapshot, `CONTROL=6` and `IPSR=0` on the physical MCU.

These observations establish this operating case. **Unload followed by a reread, other tag formats/backends and worst-case interrupt latency remain to be verified on hardware.** Offline emulation covers additional paths; it does not extend the physical qualification to them. See the [validation record](docs/CFG6_RDG2_VALIDATION.md).

## Firmware and host behavior

The firmware keeps the CFG6 runtime configuration interface and API7 capture path. Its type-4 accounting changes address initialization of supported legacy records, preservation of active accounting across geometry rescans, and the existing delayed unload cleanup. RAM accounting transactions and RDG2 snapshots save and restore the interrupt mask.

RDG2 reads RAM and returns one diagnostic snapshot; it does not start RFID activity or initialize accounting. Kalico continues to obtain the CFS percentage through the normal `CMD 0x03` path. In the verified case the firmware proxy used **330 m**, while the Kalico filament profile used **327 m**; their estimates need not be numerically identical.

The diagnostic and accounting changes add no RFID-tag or EEPROM writes. Existing CONFIG writes remain volatile and require the matching firmware and a controlled startup workflow.

## Reproduce offline

Required tools: Python 3, the `arm-none-eabi` assembler/linker tools, Unicorn and Capstone.

```sh
python3 scripts/prepare_base.py
python3 tests/run_offline.py
```

The preparation script retrieves the **intermediate, already patched v3.13 base** from frozen commit `0ad22669248cc845a3c8d22dd613500c4b95feb3`, checks SHA-256 `9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff` and places it in ignored `work/base-pinned.bin`. It is a build input, not the current installable image or an unmodified OEM ROM.

Current sources are [handler.S](firmware/cfg6-rdg2/handler.S), [build.py](firmware/cfg6-rdg2/build.py), [preflight.py](firmware/cfg6-rdg2/preflight.py) and [link.ld](firmware/cfg6-rdg2/link.ld). The offline runner must reproduce the exact image hash above. These commands do not communicate with the printer.

## Documentation and history

- [Validation, interpretation of remaining percentage and known limits](docs/CFG6_RDG2_VALIDATION.md)
- [Firmware compatibility](docs/CFS_FIRMWARE_COMPATIBILITY.md)
- [Matching Kalico extras and RDG2 command](host/kalico/README.md)
- [Historical 28-parameter reference (EN)](docs/CFS_V323_PARAMETER_GUIDE_EN.md) and [IT](docs/CFS_V323_PARAMETER_GUIDE_IT.md): inherited reference; use the current compatibility document for the CFG6 write set.

Older firmware images and their version-specific tests have been removed from the current branch. Their source, images and research remain accessible in the [frozen historical tree](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Dated research documents describe their original versions and are not current installation instructions. Git history has not been rewritten.

Independent interoperability and reverse-engineering work; not affiliated with Creality, Bambu Lab or QIDI.
