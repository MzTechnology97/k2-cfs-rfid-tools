> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS object registration and callback ownership — offline audit

**11 October 2026. Saved original Creality 1.5.3 and validated v3.22.
Strictly offline. No CFS RS-485, motor operation, flashing, reboot or NVM write.**

This is a focused extension of
[driver callback analysis](CFS_DRIVER_CALLBACK_CHAIN_20261011.md).

## A concrete device constructor now identified

The original function at `0x080283BE` contains a loop that creates
five device objects using the static array base `0x2000075C`.

The Thumb sequence beginning at `0x080283F0` computes
`r0 = 0x2000075C + (index * 3 << 5)`, equivalent to
**96-byte spacing**, and the loop at `0x08028428` ends
after **five** iterations. At `0x08028408` it calls
`0x0802644A` with arguments including the object's
registered name at `[object + 0x54]` and internal per-object
context. This is a *concrete initializer*, not a conjectured
callback table inferred from matching offsets.

The original `0x0802644A` function clears 0x44 object
bytes, stores three literal function pointers, writes `0x1D`
to `[object+0x14]`, and registers the object via
`0x0802377A`. The exact methods stored are:

| Object field | Original Thumb function pointer |
| --- | --- |
| `object + 0x30` | `0x080193C5` |
| `object + 0x34` | `0x08019401` |
| `object + 0x38` | `0x0801939D` |

Other initialized pointers are `[object+0x3C] = object+0x44`
and `[object+0x40] = 0x20000758`, for the direct original
caller arguments validated here.

## Original ARM execution, no actual driver registration

The new offline script
`firmware/v3.22-readonly-state-probes/motor_driver_registration_audit.py`
executes the **original Thumb constructor** for each of five
synthetic RAM objects, using Unicorn. Only original external
`memset` and RTOS registration calls are replaced by strictly
checked mocks; all constructor assignments execute as written
in the actual manufacturer binary.

| Index | RAM object | Verified callback `+0x38` |
| ---: | --- | --- |
| 0 | `0x2000075C` | `0x0801939D` |
| 1 | `0x200007BC` | `0x0801939D` |
| 2 | `0x2000081C` | `0x0801939D` |
| 3 | `0x2000087C` | `0x0801939D` |
| 4 | `0x200008DC` | `0x0801939D` |

All five synthetic constructors return through the mocked OS
registration and create the expected callback entries and
supporting fields. Original stock and v3.22 emulate identically.

The static test checks **28 exact original Thumb instructions**
and original ROM pointer words; **8 mutations with valid
recomputed firmware CRC** are rejected. GitHub CI repeats
the check using the exact SHA-pinned v3.22 image.
No proprietary source binary is published.

## Why this does NOT yet establish the CFS motor backend

The shared motor controller `0x0801E0CC` loads its
device pointer from a **different RAM root** at
`[0x20004960 + 0xB4] = [0x20004A14]`.
It passes that pointer to `0x08026516` and
`0x08026488`. Their common dispatcher
`0x08023A92` reads `[device+0x38]`, but the
fact that another constructor assigns a callback at the
same offset does **not prove** the motor controller's
runtime object points to one of these five constructed
devices. No complete store-to-load identity proof has
been established.

The original function addresses `0x0801939D`,
`0x080193C5` and `0x08019401` are recorded as
**raw original Thumb pointers**, not yet characterized
as particular GPIO/PWM/encoder implementations.
They are *not executed* by this test.

In particular:
- No callback value is certified as physical motor completion.
- The OS/device register call is mocked; the simulation has
  not dynamically proved true class registration, peripheral
  selection or lifecycle.
- A static `0x1D` byte written at `object+0x14`
  is **not** itself the class byte read at `object+0x08`
  by `0x0802E198`; keep these fields separate.
- No use of the unverified Flash area beyond the conservative
  `0x0803B800` limit is permitted.

**Follow-up, 2026-10-11:** The writer of `0x20004A14` has
now been identified. At `0x0801E086`, original startup ROM
stores the result of a **type-9 registry lookup by the name
`pwm1`**; it previously clears that field at `0x0801DFEE`.
See [CFS_PWM1_NAMED_DEVICE_LOOKUP_20261011.md](CFS_PWM1_NAMED_DEVICE_LOOKUP_20261011.md).
Three differential ARM cases show that the store accepts a
pointer into the five-object array, an unrelated pointer,
or NULL — so the concrete registered object identity still
**cannot be inferred** from the common callback offset.

The next substantive step is identifying which actual RTOS
object registers the name `pwm1` with device type 9,
then following that callback to independent peripheral
or motor-feedback evidence. The RAM byte `0x2000499C`
remains software-derived and is not an idle interlock.

The working MCU v3.22 is not modified. Firmware v3.23 release,
live MCU probe/firmware update and the independent motor-active
write guard remain blocked pending actual hardware verification.
