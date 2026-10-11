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