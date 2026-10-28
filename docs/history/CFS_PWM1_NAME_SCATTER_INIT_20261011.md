> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

> **SUPERSEDED — 2026-10-12.** The real saved APP link base is **0x08003000**, not the assumed 0x08010000. The prior decoder failure, supposed missing PWM names, and suspicious midfunction callback/stack inference were artifacts of mapping file offsets to the wrong Flash addresses. See [the validated correction](CFS_REAL_LINK_BASE_AND_PWM_NAME_RECOVERY_20261012.md). Historic findings below are retained for audit history only; do not use them to justify MCU pointer patches or v3.23 release.

# CFS PWM object names: initialized SRAM provenance and scatter loader

**2026-10-11 — offline ROM audit only.** No Creality bootloader dump was
made, and no CFS MCU or Kalico production files were accessed or modified.

## Why routine 0x08028530 is not the name initializer

The exact manufacturer ARM instructions at `0x08028530` scan indexed
configuration entries rooted at SRAM `0x2000093C`, call
`0x08028684` for nonzero entries, and perform timer-related setup.
They do **not** store the five device-name pointer fields.

The five-object registration function at `0x080283BE` loads the
device name with `ldr r1,[r0,#0x54]` at `0x08028406` and passes it to
`0x0802644A`. Consequently that pointer must have been established
before each registration, but the instructions inspected here do not
prove where its initial value came from.

## Nearby store-to-name-field false positives

Original function `0x08027F92` does contain a genuine `STR` at
`0x08027FA0` to an object field at offset `+0x54`.
However its base register is loaded from the original ROM
literal at `0x08028030 = 0x200006E8` and decremented by
`0x10`. The actual computed store target is therefore
**`0x2000072C`**, not any of the five PWM name pointer
fields (`0x200007B0` through `0x20000930`).

A second apparent `STR +0x54` at `0x08028044` lies in
ROM literal/data bytes **after the function has returned at
`0x08028004`**. It is not evidence of an executed store.

These are why a halfword-by-halfword disassembly scan must
be treated as **candidate discovery only**, not as a callgraph
or proof that a RAM field is assigned.
## New startup data

The reset scatter-loader at `0x08010138` reads two PC-relative
bounds at `0x08010164` and `0x08010168` and iterates a sequence of
four-word initialization records. The SHA-pinned v3.22 ROM yields
exactly two records:

| Entry | ROM word 1 | Destination RAM | Length | Function pointer |
| --- | --- | --- | --- | --- |
| `0x0803AA10` | `0x0802DB6C` | `0x20000000` | `0x0BC4` (3,012 B) | `0x0800316C` |
| `0x0803AA20` | `0x0802DE38` | `0x20000BC4` | `0x6324` (25,380 B) | `0x080031C8` |

The lengths sum to `0x6EE8`, matching the original image's initial
stack pointer offset. All five preexisting device name-pointer
fields lie inside the **first** RAM range:

| Device | RAM object | Name-pointer field (`+0x54`) |
| ---: | --- | --- |
| 0 | `0x2000075C` | `0x200007B0` |
| 1 | `0x200007BC` | `0x20000810` |
| 2 | `0x2000081C` | `0x20000870` |
| 3 | `0x2000087C` | `0x200008D0` |
| 4 | `0x200008DC` | `0x20000930` |

The image also contains the ROM strings `pwm1`, `pwm3`, `pwm4`,
`pwm5` and `pwm8` in an 8-byte-spaced string grouping near
`0x080399E4`. However **there are no direct little-endian 32-bit
absolute pointer occurrences** for these five string addresses
in the exact saved application image. The names may be initialized
via relative relocations, loader processing or other functions;
this evidence alone does NOT prove any name-to-object mapping.

## Critical loader limitation

The first descriptor points to a handler at **`0x0800316C`**
and the second at **`0x080031C8`**. These addresses are **below
the application base `0x08010000`**, inside the undumped
bootloader/flash-resident region. Therefore we cannot assert
whether these functions perform memcpy, zero initialization,
decompression or some other data transformation. Reading four
bytes at the hypothetical direct-copy source offsets is a
counterfactual test only, not reconstructed actual RAM state.

### A direct-copy hypothesis fails a basic plausibility check

Using the first descriptor's ROM first word as an ordinary
linear source and copying it to RAM would yield the following
32-bit values in the five +0x54 name pointer fields:

| Device | Word under naive direct memcpy | Pointer-like? |
| ---: | --- | --- |
| 0 | `0x5F545220` | No |
| 1 | `0x2300E9D1` | No |
| 2 | `0x126BF240` | No |
| 3 | `0x6BA86060` | No |
| 4 | `0x42841034` | No |

These are neither valid APP Flash addresses nor valid SRAM
addresses. Therefore a direct memcpy interpretation does
**not** explain how the five names become valid.
The actual loader handler (residing below the dumped
application, at `0x0800316C`) has not been inspected.
This result does NOT justify inventing another loader mapping.
This is a concrete reason NOT to claim the five names have
been identified, even though the register class/type 9 and
`pwm1` lookup code are now understood.

## Reproducibility

- `pwm1_name_init_static_audit.py`: original ROM name preinitializer
  inspection, exact metadata-field and literal references.
- `pwm1_init_ram_origin_probe.py`: SHA-pinned scatter loader descriptors,
  five name-field bounds and *hypothetical* direct-copy byte checks.
- GitHub Actions checks exact descriptors and the five RAM field
  addresses on the independently rebuilt validated v3.22.
- The vendor 1.5.3 binary remains private. Since CM5 Remote Desktop
  Commander has hit its usage limit, this particular new audit
  has not been rerun against the private original 1.5.3 image.

## Release decision

The real type-9 `pwm1` registry object and the callback installed
at its `+0x38` field remain unknown. The software command decoder,
PWM timer register and callback result do not prove rotor stopped.
Firmware v3.23 flashing, motor-active runtime writes and any
claim of adequate SRAM/IRQ stack safety remain **BLOCKED**.

**No device movement, serial command, reboot, flash or NVM write.**