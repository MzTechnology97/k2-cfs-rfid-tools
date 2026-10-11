# CFS PWM type-9 names: original scatter decoder compatibility test

**11 October 2026. Strictly offline. No CFS commands or deploy.**

## Why this experiment matters

Five original type-9 RT-Thread devices register using pre-existing
`[object+0x54]` name pointers in the RAM region
`0x20000000..0x20000BC4`. The original APP reset contains
Keil/Arm scatter-loading descriptors at `0x0803AA10..AA30`.
ARM documents that a region descriptor can select a copy,
zero-init, or decompress handler:
https://community.arm.com/support-forums/f/compilers-and-libraries-forum/7240/__scatterload-function-in-arm-c-library/22072

The first record identifies: source `0x0802DB6C`, destination
`0x20000000`, RAM size `0x0BC4` (3012 B), handler at
`0x0800316C`. The second source begins at `0x0802DE38`,
leaving **716 B** of input allocated to the first record.

An APP-internal routine at `0x0801016C` looks like a
compressed block decoder, and an APP routine at `0x080101C8`
looks like a zero-initializer. Each resides **exactly
`0xD000` bytes above** the corresponding *handler address*
embedded in the scatter table (`0x0800316C` and
`0x080031C8`). But those handler addresses are **below**
the dumped APP base (`0x08010000`). We have no bootloader
dump with which to prove equal instruction bytes.

## Offline attempted execution / rejection evidence

`cfs_scatter_candidate_decompress_audit.py` executes the
saved APP routine's **actual Thumb instructions** in an
isolated Unicorn emulator with strict source/RAM bounds.
The run reaches output offset four but Unicorn raises
`UC_ERR_INSN_INVALID` at PC `0x080101BE` after consuming
seven source bytes. A local workaround for an emulator
conditional-branch limitation has been retained
**only as diagnostic experimentation**, not as proof
the actual bootloader runs the same algorithm.

`cfs_scatter_reference_decoder.py` independently models
the APP routine's visible codeword structure in bounded
Python. This candidate does **not decode the saved CFS
source stream into a valid RAM image**: on token two,
after 14 source bytes and 10 output bytes, it requests
an earlier output byte **160 bytes behind the cursor**,
which is outside the initialized output. The reference
experiment therefore **fails closed** rather than
fabricating names, ignoring bounds or accepting a
backreference to unknown RAM.

| Check | Result |
| --- | --- |
| First record output size | 3012 B |
| First record maximum input | 716 B |
| APP routine vs descriptor handler address | +`0xD000` exactly |
| Original APP Thumb pins | 13 unconditional locations |
| CRC-corrected altered inputs rejected | 7 cases |
| Unicorn full candidate decode | **Unsupported / not completed** |
| Python APP-algorithm transcription | **Rejected at invalid backreference** |
| Verified final name pointers for the five PWM objects | **None** |
| Runtime CFS `pwm1` callback identified | **No** |

The failure does not prove that the CFS bootloader
could not initialize RAM. On the contrary, the
operational v3.22 demonstrates it does initialize enough
RAM to function. It proves only that this proposed
reuse of the APP routine is **not validated** against
the actual first-region source. Possible explanations
include different helper implementation, compressed
format, entry assumptions or emulator support.

## Prerequisites for genuine callback identity

1. Recover or otherwise authenticate the original
   handler code at `0x0800316C` and `0x080031C8`,
   without patching or flashing the production CFS.
2. Execute the authenticated loader on an isolated
   original data segment; check all five +0x54 pointers,
   their address ranges, and exact NUL-terminated names.
3. Correlate a named `pwm1` instance with its **actual**
   RT-Thread `+0x38` callback and its separate motor
   hardware feedback/IRQ state.
4. Validate app Flash allocation and SRAM/IRQ safety
   before considering an expanded v3.23 firmware.

**Do not merge this analysis into production, flash any
experimental MCU binary, or use software command ACKs
to authorize writes while a motor could be active.**