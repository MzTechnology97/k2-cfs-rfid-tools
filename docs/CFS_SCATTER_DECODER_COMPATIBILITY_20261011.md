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

## Additional independent historical Flash/RAM evidence (2026-10-11)

The public research repository
[**fake-name/cfs-reverse-engineering**](https://github.com/fake-name/cfs-reverse-engineering)
contains a real GD32 CFS Flash dump of 524,288 bytes and a 65,535-byte
RAM snapshot from a **different, older 2025 firmware**, not from
the user's operational v3.22. GitHub Actions downloads these
read-only artifacts only in its ephemeral runner. Each downloaded
file is checked against its published immutable Git blob SHA-1:

- Flash Git blob: `44e2d48a144356c1ae2b3fe0b4e23175c050e28e`
- RAM Git blob: `80e1103c16dd5e17ddf5c84af6e976ad14bd0d38`

The 92-byte ORIGINAL historical bootloader routine at
**`0x0800316C` matches all 92 corresponding bytes** at
`0x0801016C` in rebuilt SHA-pinned v3.22 APP. This is
the strongest *offline* evidence so far that they contain
the same decompressor. The zero-initialization routines
at `0x080031C8` / `0x080101C8` matched 31 of 32
inspected bytes, so are **not claimed byte-identical**.

The historical CFS image also contains a genuine scatter table:

| Source | RAM destination | Output | Handler |
| --- | --- | ---: | --- |
| `0x080278D0` | `0x20000000` | 2,844 B | `0x0800316C` |
| `0x08027B28` | `0x20000B1C` | 18,692 B | `0x080031C8` |

Unlike the saved v3.22 stream, **the historical compressed
source successfully decodes** under the exact same
33-instruction Thumb-derived token grammar: 222 tokens,
**599 of 600 available source bytes consumed**, and
2,844 bytes produced. A total of **2,321 bytes** of that
reconstruction match the corresponding historical RAM
snapshot; differences are expected because the snapshot
was captured from an already-running system. This is
independent empirical evidence that the parser is sound
for at least one real original CFS generation.

The v3.22 packed source starting at `0x0802DB6C`
continues to fail under that same grammar after 14
source bytes and 10 output bytes, requiring an invalid
160-byte prior output reference. **This is now a genuine
cross-generation input/descriptor inconsistency to
investigate**, rather than simply the absence of a
bootloader dump. It could reflect a stale or incompatible
source pointer, changed compression data, build
packaging, or another unverified assumption; the evidence
does not authorize choosing one explanation yet.

### Historical five PWM names now linked to initialized SRAM

`cfs_historical_pwm_name_xrefs.py` cross-references the historical
2,844-byte decompressed initialized RAM to the **actual old ROM
strings** and confirms all five pointers again in the independent,
already-running historical CFS RAM snapshot:

| Old CFS PWM name | Old ROM string | Name pointer field in historical RAM | Historical object base if +0x54 |
| --- | --- | --- | --- |
| `pwm1` | `0x08026730` | `0x20000710` | `0x200006BC` |
| `pwm3` | `0x08026738` | `0x20000770` | `0x2000071C` |
| `pwm4` | `0x08026740` | `0x200007D0` | `0x2000077C` |
| `pwm5` | `0x08026748` | `0x20000830` | `0x200007DC` |
| `pwm8` | `0x08026750` | `0x20000890` | `0x2000083C` |

There are **five unique names, five initialized RAM pointer
references, and five matching fields in the old live snapshot**.
All fields are separated by 96 bytes, as in the five v3.22
constructor objects. Importantly, the table is **old firmware
memory evidence only**. The v3.22 objects sit elsewhere
(`0x2000075C`, `0x200007BC`, `0x2000081C`,
`0x2000087C`, `0x200008DC`), and their actual names
remain UNPROVEN until valid v3.22 initialization data or a
safe authenticated live snapshot is available.

**Critical limitations:** The installed unit's loader
bytes have not been read, and the old reconstructed RAM
does **not** prove the object layout or callback addresses
of v3.22. The build in GitHub CI and the deployed MCU
must not be assumed identical in every runtime behavior.
No actual device name or independent motor-idle signal
has been recovered by this comparison.

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