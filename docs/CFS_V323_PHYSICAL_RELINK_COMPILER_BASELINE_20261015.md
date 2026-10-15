# CFS v3.23 — physically linked firmware development baseline

*15 October 2026 · continuation of modified Creality CFS firmware work.*

## Concrete compiler milestone completed

Before any new v3.23 behavior is introduced, we now have a
**byte-identical reassembly of the known v3.22 appended handler** using
the *real* CFS application addresses, rather than relying on the old
nominal `0x08010000` address space.

The original v3.22 build workflow was nominally linked at
`0x0803AE38`. After independently recovering the real OEM APP start
`0x08003000`, the handler was found physically at
**`0x0802DE38`**. The nominal-to-physical delta is `0xD000`.

The compiler-stage prototype:
1. Requires both exact SHA-pinned saved v3.13 and v3.22 firmware.
2. Enumerates and independently pins the **13 OEM external
   `.equ` Thumb branch targets** in the v3.22 source; rejects
   added, missing or changed addresses and direct Flash `.word` literals.
3. Uniformly subtracts `0xD000` from these code references and
   changes the temporary linker origin to **`0x0802DE38`**.
4. Independently compiles both historical and corrected sources,
   verifying that the physically relinked handler is **exactly
   2,468 bytes and byte-identical** to the handler already present
   in the hardware-tested v3.22 image.
5. Verifies that all **15 outgoing handler-to-OEM branches**
   land on the identical original manufacturer instruction PCs.
   It separately checks the unchanged **14 OEM-to-handler BL hooks**
   by decoding them at physical execution addresses.
6. Rejects **7 fail-closed source/ELF/linker/image mutations**.
7. Produces only JSON audit output. The temporary assembler
   object/ELF/handler bytes are discarded; **no v3.23 BIN
   is built, offered for flashing, or uploaded**.

All 29 unchanged control-flow edges remain consistent. A mismatch
in even one byte of the prior known v3.22 handler causes failure.

### Reproduce offline

Within `firmware/v3.22-readonly-state-probes`, with source files
available and the exact saved v3.22 image staged privately:

```sh
python cfs_v323_physical_relink_baseline.py \
  --v313 ../v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin \
  --v322 /private/path/v322-exact-saved-UNFLASHED.bin \
  --asm handler-v3_22.S \
  --linker link.ld \
  --builder build-v3_22.py \
  --self-test
```

Expected: SHA-pinned saved-image identity, physically recompiled
handler size 2468, 13 shifted Flash symbols, 15 external control
transfers, 14 patched OEM entry transfers, 7 rejection fixtures.

## Development scope: freeze before adding more features

The next firmware work should use this **physical link baseline** and
not introduce the planned 512-byte event ring immediately:
that ring overlaps the existing v3.22 RT-Thread heap area. We
should first implement a minimal v3.23 *offline prototype*
with read-only diagnostic functionality. Added identifiers must
use independently authenticated SRAM/ROM provenance and have
no SET/RESET semantics; firmware version/feature gating must
prevent an older Kalico extra from misinterpreting those reads.

Before building the first modified v3.23 candidate, preserve
the two existing live v3.22 timing hooks (IDs 7/8) and all
legacy RFID wrapper behavior, and demand a complete branch /
relocation / register ABI comparison against the corrected baseline.
**Do not enable IDs 9–27**, currently storage-only, nor expose
unchecked motor-active writes. A software countdown, PWM duty
register or `BOX_STATE=IDLE` must never be accepted as proof
of physical standstill.

Later milestones, only after evidence:
- independently demonstrated real motor stop and all motor IRQ/task
  command paths sharing the same atomic exclusion region;
- verified loader app partition, page erase and calibration
  persistence, with a recoverable/spare CFS;
- ISR, DMA, stack and heap high-water measurements if the
  event ring or additional code is added;
- emulator, whole-image diff, host/Kalico integration and
  live hardware regression after a trustworthy rescue path exists.

## Safety status

This is an **engineering compiler baseline**, not a firmware
release. The prior v3.22 validation on the user machine
does not establish that a different v3.23 binary can be
safely loaded. The release gate's nine mandatory
qualifications remain open.

The original CFS MCU and the production Kalico installation were not
accessed or changed. The OpenCFS clean-room repository remains
paused while the modified original firmware takes priority.
