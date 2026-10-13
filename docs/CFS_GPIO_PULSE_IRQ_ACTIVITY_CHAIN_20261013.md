# CFS MCU pin-interrupt pulse counter: original hardware path

*13 October 2026 — SHA-pinned v3.13/v3.22 static evidence and synthetic tests only.*

## Discovery

The original CFS motor subsystem establishes an **interrupt-like
GPIO event callback** on logical pin `0x4B`, and that callback
increments an SRAM counter used by the motor activity sampling task.
This is distinct from the previously identified software duty command
and the five named output GPIO objects.

| Evidence | Real manufacturer code address | Actual behavior |
| --- | --- | --- |
| Configure GPIO `0x4B` | `0x08011018..0x0801101C` | Configure logical pin |
| Load callback | `0x08011022` | PC-relative literal `0x0801125C` holds Thumb pointer `0x08010FDD` |
| Register callback | `0x08011024..0x08011028` | Pass `R0=0x4B, R1=1, R2=callback, R3=0` into `0x08018E2E` |
| Enable event handling | `0x0801102C..0x08011030` | Pass pin `0x4B`, argument `1` into `0x08018E94` |
| Indirect driver registration | `0x08018E4E, 0x08018E5C` | Loads GPIO operation table `+0x0C` and calls through `BLX R4` |
| Indirect driver enable | `0x08018EAE, 0x08018EBC` | Uses GPIO operation `+0x14` and dispatches through `BX R3` |
| Callback body | `0x08010FDC..0x08010FE4` | `RAM[0x20004990] += 1`, then `BX LR` |

Both ROM literals `0x08011244` and `0x0801125C` resolve to
the expected RAM global base `0x20004960` and callback
`0x08010FDD` respectively. The original instructions
were inspected at the corrected physical saved-image base
`0x08003000`, not the superseded `0x08010000` origin.

### Physical GPIO mapping recovered from the OEM pin table

The saved original pin-lookup function at `0x0801AB38`
takes a logical pin number below `0x70` and selects
a **16-byte table record** using `table + (pin << 4)`.
Its PC-relative ROM literal at `0x0801AE54` points to
the board's original table at `0x0802AD5C`.
The following records have now been checked, byte-for-byte,
in both saved v3.13 and v3.22:

| Original logical RT pin | OEM table address | GD32 physical GPIO | One-hot mask |
| --- | --- | --- | --- |
| `0x43` | `0x0802B18C` | **PE3** | `0x0008` |
| `0x44` | `0x0802B19C` | **PE4** | `0x0010` |
| `0x4B` | `0x0802B20C` | **PE11** | `0x0800` |

The pin `PE11` is separate from the five previously mapped
PWM output pins. The OEM motor initializer configures
`0x4B` using pin-mode integer `2`, then attaches an
interrupt using integer `1` and enables it. In the upstream
RT-Thread pin API, these ordinarily correspond to
**input with pull-up** and **falling-edge trigger** respectively:
[RT-Thread Pin device manual](https://www.rt-thread.io/document/site/programming-manual/device/pin/pin/).
However the actual CFS GPIO driver implementation, physical
wiring and live interrupt trigger semantics have not been
independently verified here; do not generalize from upstream
constants into a confirmed hardware sensor assignment.

### Dataflow through the motor-activity sampling task

`0x08010E60` (original manufacturer code) loads the same
RAM base and performs an unsigned absolute delta calculation
on current counter `+0x30` and previous counter `+0x34`.
It converts the difference through floating-point scaling
and stores a derived quantity at `+0x2C`. It also
updates the activity/debounce byte `+0x3C`.
Finally `0x08010F44` stores the sampled current
counter as the previous reference.

| RAM location | Role inferred from original writes and reads |
| --- | --- |
| `0x20004990` | GPIO callback incremented pulse counter |
| `0x20004994` | Previous counter copied after sampling |
| `0x2000498C` | Derived floating-point activity magnitude |
| `0x2000499C` | Software status/debounce byte |

The original duty-controller path at `0x0801110A` and
`0x0801110C` also clears the current and previous counters.
A separate public helper `0x080111AA` samples the status
byte and maps nonzero to return 0, zero to return 1.
These are useful for understanding the MCU internal
activity classification.

**Evidence is much stronger than a software-only duty flag:**
there is a configured GPIO callback producing the sample counter.
It remains **unproven whether pin 0x4B measures motor
shaft rotation, feeder filament movement, a Hall sensor
or another external event**, or whether this callback
is invoked on a particular production unit with stock
wiring and firmware.

### Why this is not an instant motor-safe interlock

- A motor may still be **energized but physically stalled**,
  producing no pulses. Zero delta does NOT imply an inactive
  motor driver or that modifications are safe.
- The found callback observes only one configured logical
  input; actual feeder, hub, buffer, direction and all
  asynchronous motor start paths have not been covered.
- The task's status byte is a **derived/debounced value**;
  sampling it concurrently with an ISR requires a coherent
  locking/epoch and memory ordering strategy.
- The original subtraction uses absolute unsigned
  32-bit counter difference; rollover may produce a large
  apparent delta. This is not a robust substitute for
  an authenticated motor-run state.
- No direct hardware capture or production CFS RAM read
  has been performed. The saved firmware configuration
  cannot prove hardware wiring or timing.

## Automated release-safety checks

`cfs_motor_pulse_irq_provenance.py` pins more than
25 original Thumb instructions in both SHA-verified saved
v3.13 and v3.22, the two exact pointer literals, and the
counter/metric producer chain. Six synthetic scenarios
explicitly reject write permission when motors remain
commanded on despite zero pulses, feedback is missing,
ISR coverage is incomplete, or pulses were seen.

**No positive scenario authorizes a real v3.23 MCU write.**
This is a static provenance and policy test, not a
new firmware motor guard or installed feature.

The next offline investigation should correlate the
pin `0x4B` interrupt route with actual board sensor
assignment and inspect independent driver-enable/current
signals across every CFS motor. Only after independent
coverage and atomic sampling are demonstrated can an
MCU-side SET/RESET interlock be designed responsibly.

**No CFS flash, live GPIO sampling, motor movement,
MCU writes, serial commands, Kalico changes or reboot.**
