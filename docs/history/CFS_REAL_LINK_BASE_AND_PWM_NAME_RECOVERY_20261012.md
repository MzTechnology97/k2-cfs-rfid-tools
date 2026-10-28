> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.13/v3.22: real linked Flash base recovered (2026-10-12)

## Validated result

**These saved CFS application images are linked at `0x08003000`, NOT
`0x08010000`.** Both are SHA-pinned, byte-unchanged inputs. The
difference is **`0xD000` = 53,248 bytes**.

We verified this by a common shift explaining at least four independent
features of the same firmware, not simply by guessing an address:

1. The original vector table starts with MSP `0x20006EE8` and Thumb
   reset pointer `0x0801A969`. At the correctly linked offset this is
   a sensible reset stub: `LDR R0,[PC,#0x24]; BLX R0; LDR R0,[PC,#0x24];
   BX R0`. Interpreting the file as beginning at `0x08010000`
   instead disassembles unrelated register-dependent code.
2. At **physical `0x0802DA10`**, the original Keil scatter table
   describes source `0x0802DB6C` → initialized SRAM `0x20000000`,
   **3012 bytes**, handler `0x0800316C`; its next record starts source
   `0x0802DE38` → SRAM `0x20000BC4`, **25380 bytes**, zero initializer
   `0x080031C8`. These addresses are physically consistent in the
   `0x08003000`-based saved image.
3. The original, independently cross-validated Thumb scatter algorithm
   decompresses the *correct physical* **716-byte source** in
   **251 tokens** to exactly **3012 bytes** of initialized RAM.
   SHA-256 of reconstructed SRAM:
   `553c4915151144282cc2fb33e52e1cd6f5b5d1c372881e91237d3245cdc1930a`.
   Running the same decoder on the image *wrongly mapped* to
   `0x08010000` failed at token 2 with an invalid 160-byte lookback.
   That negative result was a **coordinate-system artifact**, not
   evidence of bad data or an incompatible loader.
4. Three original callback literals and their real Thumb entry bytes
   all reconcile without modifying a byte:

   | Offset | Stored Thumb pointer | Real instruction at entry |
   | --- | --- | --- |
   | `+0x30` | `0x080193C5` | `PUSH {r4,r5,r6,r7,lr}` |
   | `+0x34` | `0x08019401` | `PUSH {r4,r5,r6,r7,lr}` |
   | `+0x38` | `0x0801939D` | `PUSH {r4,lr}` |

   Earlier `0x08010000`-based disassembly incorrectly used the same
   *file offsets* but assigned them physical addresses `0xD000`
   higher, producing misleading “midfunction callback” and stack
   corruption concerns. Tests which synthetically entered the byte
   offset of `0x0801939D` under the wrong mapping executed
   **different instructions** at `0x0802639C`.
   Those synthetic tests are **not evidence of faulty production
   callback ABI**. The historical original CFS PWM callback code matches
   the new saved code at its correctly mapped physical entry.

## All five CFS PWM names reconstructed from *this* v3.22

These are decoded from the original 716-byte compressed source, not
guessed from the older historical CFS:

| RT-Thread device | Object base in initialized SRAM | Name field `+0x54` | ROM string pointer |
| --- | --- | --- | --- |
| `pwm1` | `0x2000075C` | `0x200007B0` | `0x0802C9E4` |
| `pwm3` | `0x200007BC` | `0x20000810` | `0x0802C9EC` |
| `pwm4` | `0x2000081C` | `0x20000870` | `0x0802C9F4` |
| `pwm5` | `0x2000087C` | `0x200008D0` | `0x0802C9FC` |
| `pwm8` | `0x200008DC` | `0x20000930` | `0x0802CA04` |

The source-to-SRAM pointer mapping and the three operation callback
pointers match exactly in SHA-pinned v3.13 and v3.22.

## What the proof DOES and DOES NOT mean

**Proven offline:** address mapping used in these saved images, reset
vector coherence, complete initialized SRAM decode, named PWM-object
associations in initial SRAM, valid callback entry prologues at the real
linked addresses, equality of the results in v3.13/v3.22.

**Not proven:** the device currently installed on the user's production
CFS contains byte-identical image/bootloader; any callback ever being
called for an active motor in production; driver/IRQ/timer hardware idle
state; safe motor-active writes; Flash free-space and stack/interrupt
constraints for a new v3.23.

**Practical outcome:** Do not patch any `+0x30/34/38` callback
pointers to “fix” the previous supposed ABI issue. Such patches
would likely corrupt known-good manufacturer callbacks.
Do not use `0x08010000` as the real ROM origin in subsequent
address-to-file conversion. Check assumptions of every existing script
that imports `APP_BASE` before altering it globally; many previous
tests have hardcoded that older artificial coordinate convention.

## Reproducibility

`firmware/v3.22-readonly-state-probes/cfs_app_real_link_base_audit.py`
runs in GitHub Actions, on both SHA-pinned v3.13 and v3.22 inputs.
It confirms the original physical source, performs bounded
decompression, and independently resolves each decoded pointer to
its 0-terminated firmware string. It is **offline only**, with no
firmware rewrite, serial commands, motion, NVM, or CM5 access.

This document **supersedes contrary conclusions** in earlier
`CFS_SCATTER_DECODER_COMPATIBILITY_20261011.md` and
`CFS_SCATTER_SOURCE_AND_CALLBACK_PROVENANCE_20261011.md`.
Those documents remain useful as a history of what was tested under
the wrong assumed mapping, not as evidence of defective MCU routines.
