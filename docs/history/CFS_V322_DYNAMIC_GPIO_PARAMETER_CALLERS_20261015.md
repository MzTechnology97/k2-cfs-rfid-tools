> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS OEM parameter-fed GPIO helper: direct caller provenance

Source-only, offline analysis of the original SHA-pinned v3.13 and rebuilt-identical saved v3.22 MCU APP. Physical Flash link base is `0x08003000`. No device access, motion, flash or active configuration changes.

The four outstanding direct GPIO write callsites from the preceding 118/122 census are inside two parameter-driven manufacturer routines: `0x08007264` and `0x080072D0`. Each copies the incoming logical pin argument into `r4`, then calls OEM RT-Thread GPIO service `0x08018EEC` with that pin at two physical callsites.

The new audit scans the saved original binary for direct `BL` callers to both functions and the intermediate two-pass helper `0x080072B0`. Exactly **9 direct callers** of `0x080072D0` provide pin arguments by adjacent `MOVS r0`/`MOVS r1`. Exactly **5 direct callers** of `0x080072B0` do the same. The latter function makes **two** direct calls into `0x08007264`, reversing the pin arguments in the second call.

The nine pairs for `0x080072D0` are 0x37/0x26, 0x36/0x27, 0x35/0x28, 0x34/0x29, 0x47/0x17, 0x48/0x14, 0x49/0x15, 0x4A/0x16 and 0x0B/0x10. The five pairs for `0x080072B0` are 0x38/0x39, 0x21/0x22, 0x23/0x24, 0x0C/0x06 and 0x07/0x04. None uses the manufacturer brushed-motor pin IDs 0x30..0x33 or 0x3C..0x3F **in those 14 particular direct caller contexts**.

The dedicated source audit `cfs_oem_gpio_parameter_direct_callers_audit.py` verifies the original Thumb immediate instructions and calls, indirect-through-two-pass source behavior, full halfword-aligned *direct-BL* census into those three helper entries, and nine fail-closed mutation cases. The extended GitHub Actions workflow checks both SHA-pinned generations.

**Safety limitation:** A complete indirect `BLX`/function-pointer/task/interrupt caller inventory is not established. The four parameter-fed GPIO writes cannot be marked safe merely because their 14 *visible direct callers* supply nonmotor pins. This work does not establish physical motor standstill, atomic RFID changes, MCU flash ownership or loader recovery. **v3.23 release and motor-active MCU SET/RESET remain blocked.**
