# v3.23 — MCU RAM event ring feasibility (source-only)

**Offline model and static firmware audit ONLY. Not a flashable CFS image.**

The reference printer remains on tested firmware v3.22 (feature 0xD7), with the motion/write safety guards unchanged. This proposal does not introduce hooks into its motor routines or alter any firmware bits.

## Storage format

The stand-alone ring consumes **512 bytes RAM**: 32-byte header plus 30 chronological 16-byte records. Each record stores a supplied 32-bit tick, a 16-bit sequence, an 8-bit event code, flags and four raw 16-bit diagnostic words. The buffer overwrites its oldest event when full and has a saturating overwrite counter. Freezing denies any further writes and permits oldest-first readback. No EEPROM, filesystem, heap allocation or hardware motor control exists in the model.

The implementation is deliberately **single-writer only**. It has not been proven safe when called from multiple tasks or IRQs, and the reader must not access it before a proven synchronization/freeze handshake. A genuine MCU monotonic clock source also remains to be identified.

## Firmware audit

The function at **0x0801E0CC** is a candidate motor command/PWM duty setter. Its exact 4-byte Thumb2 prologue is **2de9f041** (push.w of r4-r8 and lr). The associated forward routine at 0x0801E164 and reverse routine at 0x0801E17E lead into the setter. Static scanning found **33 forward** and **17 reverse** direct BL callsites. These references do **not** prove full coverage of all feeder/hub/buffer motors, a safe hook ABI, or minimal impact on the task.

The v3.22 application contains 178140 bytes and ends at **0x0803B7DC**. Only **36 bytes** remain before the *inferred, unverified* boundary **0x0803B800**. The standalone event buffer functions already require **320 bytes of ARM Thumb code** at -O2, excluding all hook trampolines, timestamps and GET-only readout. Therefore it would be unsafe to append a v3.23 firmware image without validating or reorganizing flash placement.

A 512-byte candidate RAM reservation from **0x20006F28 to 0x20007127** would require relocating the heap head to 0x20007128. Its safety has **not** been verified against dynamic allocations, task stacks, DMA and MCU interrupt contexts. The existing runtime override area 0x20006EE8..0x20006F27 must remain untouched.

## Run model tests

Run `sh ./run_offline.sh` from this directory. Optionally provide the exact tested v3.22 firmware binary as its first argument for a Capstone static callsite/ROM/RAM audit. Requires native GCC and arm-none-eabi-gcc; the optional audit additionally requires Capstone for Python.

Test coverage: deterministic ring wrap, chronological readback, freeze, size assertions, memory guard canaries, generation reset, host ASan/UBSan and Cortex-M3 cross compilation. It produces **no flashable binary**.

## Preconditions before a deployable v3.23

1. Confirm the **actual** application flash partition and updater size limit from bootloader/hardware, not a guessed boundary.
2. Prove the SRAM area is unused and can be reserved without RTOS heap, stack or DMA overlap.
3. Verify all motor start/stop sources, the exact instruction boundaries, preserved registers/FPU/flags, task concurrency and interrupt latency.
4. Identify a safe tick source; prove a bounded writer and reader snapshot/freeze handshake even under interrupts.
5. Implement a GET-only event drain usable **after** movement with no configuration-write permission granted by these diagnostic bytes.
6. Run complete ARM differential emulation and rollback checks; only then consider controlled hardware tests.

## 2026-10-11 verified offline follow-up

- The synthetic Thumb trampoline's **30 differential ARM ABI test cases passed** locally and in GitHub Actions. Original registers, CPSR, SP and currently live stack bytes matched after rejoining the stock function. The trampoline leaves freed scratch stack bytes modified because it temporarily consumes **32 additional stack bytes**. The test uses a mock register-clobbering callback, *not* the real RAM logger. See [TRAMPOLINE_ABI_STATIC_REVIEW.md](TRAMPOLINE_ABI_STATIC_REVIEW.md) and [ABI sources](abi/).
- Cross-compiling the independent buffer at `-Os` instead of `-O2` reduces ARM code size from **320 to 280 bytes**, without removing model features. However this remains far too large for the **36-byte** conservative image headroom; any real telemetry hook, clock and readback require still more code.
- [FLASH_BOUNDARY_FORENSICS.md](FLASH_BOUNDARY_FORENSICS.md) documents why we currently treat `0x0803B800` as an **empirical** maximum: earlier oversized v3.15/v3.16 builds returned invalid advanced defaults, while compact v3.18 and currently installed v3.22 passed on-device verification.
- No flashable v3.23 BIN has been generated. The only correct next release gate is **verified application flash bounds and RAM/stack mapping**, together with full real logger + IRQ/motor hook validation.

The independent MCU safety issue remains open: https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9
## Follow-up forensics (2026-10-11)

See [FLASH_BOUNDARY_FORENSICS.md](FLASH_BOUNDARY_FORENSICS.md) for the archived on-device comparison: oversized v3.15/v3.16 firmware returned 65535 for advanced parameters, whereas compact v3.18 and the currently running v3.22 read correctly. This supports a conservative effective address ceiling of `0x0803B800` but does not prove the bootloader's partition map. See [TRAMPOLINE_ABI_STATIC_REVIEW.md](TRAMPOLINE_ABI_STATIC_REVIEW.md) for the proposed motor-entry hook's limited *static* calling-convention analysis; no differential ARM emulator or real firmware hook was validated. The v3.22 linked ELF already omits disabled advanced motor hook wrappers, so removing those wrappers offers no additional image space.
