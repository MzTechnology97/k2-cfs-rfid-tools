> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.22 — all 29 branch edges at the actual APP Flash origin
*2026-10-15 · Saved v3.13 and v3.22, SHA-pinned, offline only.*

## Result

This audit expands the [11 STOCK branch audit](CFS_V322_STOCK_BRANCH_RELOCATION_20261015.md)
by enumerating **all 15 external ARM/Thumb linker relocations** in the
unchanged v3.22 handler, including four previously uncovered callsites:
`SEND_RESPONSE`, `REMAIN_SET`, `LEGACY_AUTH_READ`, and `ALT_AUTH_READ`.

It also parses the actual `build-v3_22.py` patch list (11 core, two
timing, one heap-init) and confirms that **all 14 patches in the saved
application** are authentic 32-bit `BL` opcodes targeting the expected
handler function symbols, at *physical* execution addresses.

The two separate counts cover **29 branch edges** (15 handler→OEM,
14 OEM→handler). They are **not** an exhaustive whole-program callgraph.
The legacy linker used `0x0803AE38` for the appended handler, and the
old builder assumed APP origin `0x08010000`. The original image is
linked at `0x08003000`, so the saved handler is physically at
`0x0802DE38`; all 29 verified branch targets differ from their nominal
assembler coordinates by exactly `0xD000`.

## Reproducible, exact-source method

`firmware/v3.22-readonly-state-probes/cfs_v322_full_branch_edge_audit.py`:

1. Pins the original v3.13 and unchanged saved v3.22 SHA-256 inputs,
   and performs the separate real-base/scatter integrity audit.
2. Assembles the existing **unmodified** handler in a temporary
   directory, reads the raw ELF relocation table and symbol addresses,
   then verifies that the compiled `2468`-byte handler exactly equals
   the saved application tail.
3. Expects precisely **15** external `R_ARM_THM_CALL` or
   `R_ARM_THM_JUMP24` records, with the pinned manufacturer targets.
   Re-decodes every emitted instruction at both nominal and physical
   program counters, confirming its *actual physical* target is inside
   the saved original manufacturer code. Both versions agree on the
   first four target bytes.
4. Parses and pins every actual builder hook, then decodes each of
   **14** saved replacement `BL` opcodes against its physical handler
   symbol. Unknown/new hooks are rejected, not presumed safe.
5. Examines original assembly `.word` expressions and `.equ`
   definitions. There are **no explicit absolute Flash `.word`
   literals in this handler source**. Arbitrary 32-bit words in Thumb
   instruction encodings must *not* be misclassified as source data.
6. Five synthetic negative fixtures are rejected: changed patched BL,
   unsupported external relocation type, mutated OEM destination,
   unreviewed builder hook, newly added explicit Flash pointer word.

The offline CM5 validation gave **15/15, 14/14, 5/5**. The test does not
write or execute firmware on the actual CFS or alter Kalico.

## What this does not prove

This audit does **not** determine whether all flash-address constants
throughout the original firmware (outside the new handler) are correct,
or whether the manufacturer function entry behavior, pointer lifetimes,
ISR timing, hook register/flag preservation and runtime states are safe
in every circumstance. It does not authenticate the loader's writable
pages, length/CRC format beyond preexisting tests, power-loss rollback,
high-water RAM, or physical motor STOP and driver deenergization.

**v3.23 remains non-flash-qualified**. Issue #9 (IDLE during real
feeding), motor-active MCU SET/RESET, unverified NVM/Flash ownership and
other release conditions remain fully blocked. No new firmware
candidate has been generated for deployment, no loader/serial
operations executed, and no motor moved.
