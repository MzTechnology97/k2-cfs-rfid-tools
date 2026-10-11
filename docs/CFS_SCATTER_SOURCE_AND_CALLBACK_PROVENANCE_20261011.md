# CFS v3.13 → v3.22 provenance and PWM callback entry audit

Date: 2026-10-11. Scope: SHA-256-pinned offline saved firmware only.
All commands are read-only against original bytes in GitHub CI.

## Scatter input evidence

Two application images have different sizes and hashes:

- `v3.13`, 177,700 bytes, SHA256 `9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff`
- `v3.22`, 178,140 bytes, SHA256 `40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`

Nevertheless their original APP scatter descriptors at `0x0803AA10..0x0803AA30`
are byte-identical, and the **716 bytes** at `0x0802DB6C..0x0802DE38` are
byte-identical (SHA256 `6c798b603b4139169f60d03cc7d1be58444f6514d2a7f077230ebd5269e27a66`).
The Thumb codec model rejects both at token 2: source offset 14, output 10,
history distance 160. A deliberately bounded ±2048-byte start-offset search
on v3.22 finds zero fully decoded alternative streams.

This establishes that newer K2RL hooks did not create the mismatch. It does
**not** establish whether that scatter descriptor participates in the real
reset sequence. The original reset-vector branch sequence needs separate
verification before calling the supposed data corruption a runtime defect.

## Reset-vector interpretation is another unresolved prerequisite

The exact first two words of both v3.13 and v3.22 saved APP images
contain `MSP=0x20006EE8` and a Thumb reset-looking pointer
**`0x0801A969`**. Disassembly at the pointed address
`0x0801A968` starts with `add.w r0,r5,r5,lsl #3`,
uses existing working registers / VFP state, and later executes
`pop {r4,r5,r6,pc}`. This does **not** resemble a normal
standalone Cortex-M Reset_Handler called with only defined SP/PC
registers. Contrast the real original older CFS full-Flash bootloader
reset at `0x080005B9`, which disables interrupts, loads SP and
branches through a stored pointer.

This observation **does not prove** the v3.22 application is
unbootable or that its header is corrupt. It means we have **not**
established how the deployed unit enters the code and whether its
APP scatter-loader at `0x08010130` is even reached. The failing
historically unchanged compressed stream may be a vestigial region,
a separately interpreted format or an output of another linker
stage. Those are hypotheses, not findings.

Do **not** infer MCU inactivity, ROM safety, or incorrect
live RAM contents from the APP header until its actual boot chain
has been authenticated.
## Historical old GD32 bootloader evidence

An independently published original CFS dump has a decompression routine
at `0x0800316C` that matches all 92 bytes of the saved v3.22 APP helper
at `0x0801016C`. The historical CFS source successfully expands
2844 bytes of original initialized SRAM from 599 bytes of the available
600-byte packed stream; its separately acquired RAM snapshot independently
corroborates the five PWM strings in 96-byte-stride objects.

The installed unit's bootloader has NOT been read or authenticated.

## Callback `0x0801939D`: structural warning

The v3.22 manufacturer registration routine at `0x0802646E` loads the
ROM literal `0x0801939D` and writes it at the generic device `+0x38`
callback field. The same pointer and all bytes in the inspected ROM window
`0x08019350..0x080193D0` are identical to pinned v3.13.
Thus neither that literal nor the nearby original code is introduced
by the later v3.22 changes.

Disassembly from the surrounding original code labels the Thumb entry
`0x0801939C` as `ldrb r2,[r4,#9]`, with additional register operations
followed by `pop {r3,r4,r5,pc}` at `0x080193AE`, not by an obvious
independent function prologue in the near-entry region. A *plain*
AAPCS function callback at that address would require stronger evidence
for the entry state and stack frame than we currently have.
The firmware also has old 2025 CFS callback pointer `0x08014555`,
which starts with `push {r4,lr}`, but the code sequences are different.

This is a **reason to withhold equivalence and unsafe runtime callbacks**,
not proof that the deployed firmware executes an invalid stack-pop.
Confirm the actual stock 1.5.3 callback bytes and actual device invocation
before assuming a physical motor-controller callback ABI.

## Remaining gates

- Actual `pwm1` object/name in deployed v3.22 is unverified.
- Actual motor-stop feedback from encoder/driver/timer is unverified.
- Physical MCU Flash allocation and SRAM/IRQ stack safety remain unverified.
- No v3.23 binary can be considered flash-ready based on this analysis.

No production device access, flash, serial commands, motor movement, or
Kalico deployment occurred in these tests.