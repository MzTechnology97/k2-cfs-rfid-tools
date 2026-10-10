# Motor-hook trampoline — static review only (2026-10-11)

**30-case Thumb differential emulator test PASSED. NOT FLASHABLE AND NOT INSTALLED.**

The original stock motor-control function candidate is at `0x0801E0CC`.
The four original bytes `2D E9 F0 41` represent
`push.w {r4, r5, r6, r7, r8, lr}` under ARM Thumb.
The immediately following instruction is `mov r5, r0` at `0x0801E0D0`.

A **48-byte synthetic Thumb trampoline** was cross-assembled locally for a
static calling-convention study at a deliberately non-app executable
address `0x08050000`; a separate 4-byte `b.w` was cross-assembled
for the original entry. This code is not linked with the event ring and
has not been written into a firmware image or flashed. The test uses a
**dummy** internal call that intentionally clobbers R0–R3 and R12, not the
real logging implementation.

## Intended control flow

1. Preserve `r0-r3,r12,lr` (24 bytes) before calling a logger.
2. Snapshot APSR and preserve `r4` (8 additional bytes).
3. Pass original `r0` to the dummy logger; on return restore APSR and
   all previously saved caller registers.
4. Re-execute `push.w {r4,r5,r6,r7,r8,lr}`, the exact original
   overwritten instruction, then branch to the original
   `0x0801E0D0` continuation.

The intended extra stack depth is **32 bytes** at logger call entry,
plus that logger's own stack. This is not an acceptable safety bound
without measuring worst-case motor-task stack headroom. With an initially
8-byte-aligned SP, the two saves each maintain AAPCS alignment.

## Known tests and limitations

- ARM assembler and linker produced a **48-byte trampoline** and a
  **4-byte redirect**; objdump showed the instructions and continuation.
- **Dynamic ARM Thumb emulation now passes 30 differential cases** comparing the original `0x0801E0CC` instruction to a synthetic trampoline that invokes a register-clobbering mock callback and rejoins at `0x0801E0D0`. All original caller-visible R0–R12, LR, SP, CPSR, and the **currently live** 24-byte stack frame matched across all cases. The hook creates **32 bytes of additional temporary stack usage**: freed scratch memory below the final SP differs in all 30 cases, as expected. This is *not* proof of safe real task stack headroom or timing.
- No interrupt nesting, FPU context, memory barriers, RTOS reentrancy,
  physical motor timing or actual logger callback path has been tested.
- Hook coverage is incomplete: static examination found 33 and 17
  callsites to the forward/reverse wrapper functions, but they may not
  include every motor or completion event.
- A real ring writer would consume additional code, RAM and stack,
  possibly violate ISR time limits, and require robust one-writer
  synchronization and a monotonic MCU tick source.
- **Do not redirect a live PWM/motor callback** until the complete
  instrumentation and all these properties are tested in a safe
  emulator plus recovered memory map.

## Space review

The current v3.22 handler's disabled advanced motor wrappers are already
absent from its linked ELF when `ENABLE_ADVANCED_HOOKS=False`; only ID7
and ID8 timing wrappers remain, about 12 and 14 bytes respectively.
There is no easy 300+ byte saving from pruning disabled wrappers.

The existing 36-byte empirical headroom before `0x0803B800` cannot
accommodate a 48-byte trampoline, the 320-byte isolated ring functions,
a clock source and a GET-only drain protocol. Converting this design to
a true CFS firmware needs proven in-bound code-space recovery or new,
independently verified bootloader partition information.

Do not publish a v3.23 flashable BIN under this PR.

## Executable offline ABI test

The `abi/` directory contains two Thumb-2 assembly files, linker scripts and `emulate_hook_abi.py`. `sh abi/run_abi_offline.sh` builds isolated synthetic hook/redirect binaries and compares the original versus instrumented code at the same continuation using Unicorn. It never writes to the MCU or produces a flashable CFS image.

Test inputs: 6 representative PWM values × 5 APSR flag patterns = **30** emulator runs, all passed locally and on GitHub Actions run **38093139272** (`CFS v3.23 RAM ring model (offline only)`). All caller-visible registers, flags and the live stack bytes were identical. The **freed** scratch stack region differs because the hook temporarily pushes 32 extra bytes; this remains an explicit deployment safety gate.

This tests a **mock logger**, not the 512-byte ring implementation, and does not prove the actual MCU's interrupt context, exclusive writer, time budget, handler coverage, flash footprint, clock or DMA semantics. A flashable v3.23 remains blocked.
