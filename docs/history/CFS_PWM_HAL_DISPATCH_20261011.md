> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS PWM hardware dispatch and timer base investigation — 2026-10-11

**Read-only reverse engineering of original Creality CFS firmware 1.5.3
and validated v3.22, with zero physical MCU/RS-485 operations.**

This extends [PR #19](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/19)
and the verified named `pwm1` lookup. The stock application searches
for an RT-Thread **type-9 device** named `pwm1` and stores the
registry result at `0x20004A14`. The actual object returned by the
device registry is **not yet identified**. RT-Thread's public PWM
API indeed uses named device lookup and device operation callbacks:
<https://www.rt-thread.io/document/site/programming-manual/device/pwm/pwm/>.

## Concrete code discovered

The original ROM contains a generic PWM request handler at
`0x08028394` and a GD32 timer address decoder at `0x08028128`.
The latter selects hardware timer register base addresses for 14
index values, including `0x40012C00`, `0x40000000`,
`0x40000400`, `0x40013400` and `0x40002000`. Other routines
around `0x08028192` call GD32 timer-register helpers.

Unlike the earlier indirect `[device+0x38]` transport layer,
the timer-base decoder returns concrete peripheral addresses.
This demonstrates the presence of actual timer/PWM hardware
control code in the firmware. **It does not prove those hardware
routines are the concrete driver selected for runtime `pwm1`.**

## Original dispatch, executable ARM verification

We ran the original Thumb dispatcher, preserving the manufacturer's
instruction encodings and stopping **before each hardware-specific
destination begins executing**.

| Request to `0x08028394` | Original branch | Result |
| --- | --- | --- |
| `0x1E00` | `0x0802820C` | First enable/disable-like operation, passes value 1 |
| `0x1E01` | `0x0802820C` | Same operation, passes value 0 |
| `0x1E02` | `0x0802828E` | Configuration-like operation, not executed |
| `0x1E03` | `0x080285E0` | Readback-like operation, not executed |
| `0x1E04` | none | Returns integer `5` |
| `0x1E05` | none | Returns integer `5` |

The original request builder `0x08026516` uses `0x1E02`;
builder `0x08026488` also sends `0x1E05`,
`0x1E04`, and `0x1E00`. Those are all preserved
in the validated v3.22 image.

**Critical result:** this particular generic dispatcher returns
`5` for `0x1E04/0x1E05`. Those two original high-level
motor commands therefore do **not** match the *accepted*
command set of this generic dispatcher. This is NOT evidence
that CFS direction control fails in practice. Instead, it
reinforces that a **different or extended actual callback
implementation may handle the registered `pwm1` object**;
the entire object/ops-pointer dataflow has not been established.

The official RT-Thread framework also distinguishes successful
PWM command submission from physical completion:
<https://www.rt-thread.io/document/site/programming-manual/device/pwm/pwm/>.
A software return value cannot independently prove rotor idle.

## GD32 timer hardware map from exact ROM execution

At `0x08028128`, the timer-selector code uses a Thumb
`TBB` jump table and indexed literal addresses. All 14
valid indices were emulated and returned these addresses:

| Index | Timer base address |
| ---: | --- |
| 0 | `0x40012C00` |
| 1 | `0x40000000` |
| 2 | `0x40000400` |
| 3 | `0x40000800` |
| 4 | `0x40000C00` |
| 5 | `0x40001000` |
| 6 | `0x40001400` |
| 7 | `0x40013400` |
| 8 | `0x40014C00` |
| 9 | `0x40015000` |
| 10 | `0x40015400` |
| 11 | `0x40001800` |
| 12 | `0x40001C00` |
| 13 | `0x40002000` |

These are **original firmware's register-base constants**, not
live-read hardware readings and not a proof of which instance
controls the particular feeder/hub motor.

## Other registration clues — do not overclaim

Stock original ROM includes a second `pwm1` at
`0x080399E4`, among 8-byte-aligned `pwm3`,
`pwm4`, `pwm5`, `pwm8` names. A separate initializer
`0x080283BE` iterates **five** objects from
`0x2000075C` at 96-byte intervals and calls constructor
`0x0802644A`. Those are interesting matching counts;
however, the five objects' actual constructor writes
`0x0801939D` to `+0x38`, and an exact
store-to-load dataflow from `pwm1`'s registry lookup
to any of these objects has still **NOT** been established.

It would be a serious reverse-engineering mistake to infer
the identity solely because there are five PWM names and five
constructed objects. The original ROM also contains several
OTHER constructors writing callbacks at `+0x38`, so the
field offset is not unique.

## Tests and limitations

`firmware/v3.22-readonly-state-probes/pwm_hal_dispatch_readonly_audit.py`
compares SHA-pinned exact stock 1.5.3 and v3.22 APPs.

- Original timer selector: **14 executed cases**, no MCU registers
  memory-mapped inside Unicorn.
- Original PWM opcode dispatcher: **six executed cases**, the
  three hardware targets are intercepted and deliberately
  NOT executed.
- **31 exact Thumb instructions** pinned in both images.
- **10 checksum-corrected in-memory corruption cases**
  rejected (each retains a valid original-format APP CRC).
- Original and v3.22 results and instruction bytes identical.
- The machine-readable report explicitly denies both
  `actual_pwm1_registry_driver_identity_proven` and
  `PWM_output_zero_proves_motor_stopped`.
- No new flashable BIN or extended app size is produced.

Reproduce with locally retained private binaries:

```sh
python -m pip install "capstone>=5,<6" "unicorn>=2,<3"
python3 firmware/v3.22-readonly-state-probes/pwm_hal_dispatch_readonly_audit.py \
  --stock /private/cfs-original-153.bin \
  --v322 /private/cfs-validated-v322.bin \
  --self-test --json-out /tmp/CFS_PWM_HAL_ORIGINAL_EVIDENCE.json
```

The GitHub Actions job runs the v3.22-only equivalent without
redistributing vendor code.

## Next decisive analysis

1. Establish where `rt_device_pwm_register()`-equivalent code
   supplies the **name `pwm1` and its actual PWM ops/callback
   pointer** to the RT-Thread device registry. Confirm the
   typed device object identity, rather than treating any
   `+0x38` function pointer as interchangeable.
2. Identify the actual callback's responses for
   `0x1E04`/`0x1E05` and correlate with hardware timer
   settings or external CFS driver transactions.
3. Only then investigate independent motor activity
   from driver enable/encoder/interrupt/tachometer data.
   Timer output register values and command ACKs are
   still NOT direct physical motor-stop feedback.
4. Preserve prior release blockers: loader Flash length
   (36-byte conservative v3.22 headroom), SRAM ring
   ownership, ISR stack safety, and MCU-side motor-active
   guard before considering a v3.23 flash.

**No CFS firmware installation, live serial access, NVM write,
reboot or movement was performed.**
