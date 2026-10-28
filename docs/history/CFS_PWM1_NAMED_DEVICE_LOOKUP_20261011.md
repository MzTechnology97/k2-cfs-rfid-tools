> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# Creality CFS `pwm1` device lookup and motor pointer provenance

**2026-10-11 | Original stock application 1.5.3 compared to v3.22 |
Strictly offline; the operational CFS and Kalico are unchanged.**

This analysis resolves the ROM-level provenance of the **device
pointer at `0x20004A14`** used by the shared command controller
`0x0801E0CC`. It does not yet identify the actual registered
device returned by the CFS RTOS, nor prove physical motor feedback.

## 1. The exact application startup dataflow

Original ROM startup procedure `0x0801DFE6` uses
`0x20004960` as its RAM root. The instructions:

| Original ROM | Instruction | Observable effect |
| --- | --- | --- |
| `0x0801DFE8` | `ldr r4,[pc,#0x258]` | loads literal `0x20004960` |
| `0x0801DFEC` | `adds r4,#0xB4` | computes `0x20004A14` |
| `0x0801DFEE` | `str r0,[r4]` | **clears motor device pointer**, with r0=0 |
| `0x0801E080` | `adr r0,#0x208` | loads the original C string at `0x0801E28C` |
| `0x0801E082` | `bl 0x08023774` | **looks up a named device** |
| `0x08023774` | `movs r1,#9` | requests **type 9** |
| `0x08023776` | `b.w 0x0802E1B4` | dispatches to generic name/type registry |
| `0x0801E086` | `str r0,[r4]` | saves returned pointer at `0x20004A14` |
| `0x0801E088` | `cbz r0,0x0801E0A2` | handles a NULL/missing lookup separately |

The original null-terminated string is exactly **`pwm1\0`**
at `0x0801E28C`. The following debug messages mention
`MS3791` and refer to missing enable/PWM devices;
they are diagnostic context, not proof of the chip model
or motor electrical interface.

A separate occurrence of `pwm1` exists in the original
ROM at `0x080399E4` within a grouping of RT-Thread diagnostic
device names including `pwm3`, `pwm4`, `pwm5` and
`pwm8`. The group is useful contextual evidence of multiple
PWM-named devices, but is **not** a registry object, a vtable
or proof that a specific motor uses any of those channels.

This corrects an uncertainty in
[CFS_DEVICE_OBJECT_REGISTRATION_20261011.md](CFS_DEVICE_OBJECT_REGISTRATION_20261011.md):
the root's +0xB4 pointer is populated by a **named `pwm1`,
type-9 device registry lookup**, not a hardcoded reference to
the separately observed five-object array.

## 2. Executable stock ARM test, with registry mocked

The offline script
`firmware/v3.22-readonly-state-probes/motor_pwm1_named_lookup_audit.py`
executes the original Thumb instruction sequences
`0x0801DFE8..` (clear) and `0x0801E080..` (lookup/store),
and executes the real `0x08023774` wrapper, stopping
only at `0x0802E1B4`, where it supplies a synthetic registry
answer. It then resumes original Thumb execution to verify
the original store at `0x0801E086`.

| Simulated registry answer | What original ROM stores at `0x20004A14` |
| --- | --- |
| `0x2000075C` (one of the five independently created objects) | `0x2000075C` |
| `0x20003000` (not in that array) | `0x20003000` |
| `0` (device not found) | `0` |

All three cases pass identically using the SHA-pinned
original Creality APP and working v3.22. The startup
pointer-clear routine is also directly emulated and
verified. **Ten original Thumb instruction encodings and
eight mutated, valid-CRC firmware images** are validated
fail-closed.

The device registry, actual callbacks, motor speed and
peripheral state are **NOT** executed in this test.
The fake result is supplied to the registry interface only.
This is deliberately a counterexample to the claim that
`pwm1` is known to be a member of the five-object array:
the code accepts any pointer the registry returns.

## 3. What is still unknown

The earlier five-object constructor at
`0x0802644A` stores callbacks at `+0x30`, `+0x34`
and `+0x38` in objects at
`0x2000075C, 0x200007BC, 0x2000081C, 0x2000087C,
0x200008DC`.

The fact that the generic motor device dispatcher
`0x08023A92` also calls `[object+0x38]`
is insufficient to show the actual registry returns
one of these five objects. Moreover, the constructor
writes `0x1D` into the field at `object+0x14`,
whereas type checking in the generic registry and
dispatcher involves a different field at `+0x08`.
Those must not be conflated.

The next evidence needed to link the motor to
a concrete implementation is:

1. Identify the registered device **named `pwm1` of
   type 9**, not merely objects with callback field
   at `+0x38`.
2. Identify the matching registry insertion
   and its actual RTOS object identity.
3. Trace the callback handler for that object to
   its peripheral or asynchronous state machine.
4. Find **independent feedback** for a real
   motor-running/stopped condition; command zero,
   RAM status `0x2000499C`, and a successful
   callback return are NOT proof.
5. Validate firmware app-boundary and SRAM/IRQ
   behavior before ever attempting v3.23 hardware
   testing or an independent motor-active write guard.

No enlarged CFS image, update, reboot, GPIO probe,
serial packet or motor operation was generated. The
working v3.22 firmware is untouched.

## Reproduce the audit

```sh
python -m pip install "unicorn>=2,<3" "capstone>=5,<6"
python firmware/v3.22-readonly-state-probes/motor_pwm1_named_lookup_audit.py \
  --stock /private/cfs-original-153.bin \
  --v322 /private/cfs-validated-v322.bin \
  --self-test --json-out /tmp/CFS_PWM1_LOOKUP.json
```

CI executes the same eight CRC-corrected mutation
rejections and all three original Thumb pointer-store
cases against exact v3.22 without publishing the
proprietary vendor BIN. **Motor identity/idle and
expanded-firmware safety all remain unproven.**
