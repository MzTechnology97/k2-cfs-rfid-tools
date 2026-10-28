> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.23 — Multi-signal motor activity evidence matrix
*13 October 2026 — immutable v3.13/v3.22 firmware analysis and synthetic policy tests; no live CFS access.*

## What the latest PR #24 now proves

The `cfs_motor_multisignal_observation_plan.py` audit joins **three
independently reconstructed original OEM firmware paths** and fails
if any of their source-derived pins, addresses, or device identities
disagree between the pinned v3.13 and v3.22 images.

1. **PWM command outputs:** the five original RT-Thread device
   descriptors, GD32 physical output ports, TIMER0/TIMER3 channels,
   channel compare registers and TIMER_CHCTL2 enable masks.
2. **Pulse event input:** the separately configured logical GPIO
   pin `0x4B` / physical `PE11`, with original manufacturer
   `0x08010FDC` callback increasing `RAM[0x20004990]`.
3. **Task sampling:** the prior pulse count `0x20004994`,
   derived floating-point activity `0x2000498C`, and software
   countdown `0x2000499C`.

These signal classes are **not interchangeable**. An output
enable or duty command is not a shaft encoder. A PE11 pulse
counter may observe an external event, but its board wiring is
unknown. A software countdown may decrease while the motor is
stalled or moving.

## Saved-ROM diagnostic observation manifest

The manifest contains *addresses for possible future read-only
instrumentation*, not a successful memory read from a CFS.

| Saved PWM name | OEM pad | TIMER_CHCTL2 | Enable mask | TIMER_CHxCV |
|---|---|---|---|---|
| `pwm1` | PE13 | `0x40012C20` | `0x0100` | `0x40012C3C` |
| `pwm3` | PD12 | `0x40000820` | `0x0001` | `0x40000834` |
| `pwm4` | PD13 | `0x40000820` | `0x0010` | `0x40000838` |
| `pwm5` | PD15 | `0x40000820` | `0x1000` | `0x40000840` |
| `pwm8` | PD14 | `0x40000820` | `0x0100` | `0x4000083C` |

The GPIO remap code configures `AFIO_PCF0` at
`0x40010004`. The PE11 pulse counter is maintained at
`0x20004990`. The firmware's own motor command path may
clear that count and its previous value. **Never** assume a
zero count delta means that no motion is occurring.

**No diagnostic code that reads the table is installed**. Before
any hardware capture is attempted, a safe **read-only** path and
the meaning of each sensor, the physical CFS board wiring,
driver enables, and the complete start/IRQ ownership must be
authenticated.

## New regression contract

The audit runs **16 synthetic cases**, covering:
- all five PWM channel output-enable masks;
- PWM commanded while pulses remain zero (possible stall);
- pulses still occurring after PWM output is disabled;
- 32-bit counter rollover and a reset of the current count;
- old/incoherent snapshots and a motor start between sample epochs;
- missing/unknown IRQ and PE11 physical sensor mapping;
- `BOX_STATE` busy and apparently idle;
- deenergized-looking command outputs with uncovered motors;
- an entirely quiescent **synthetic** scene with no independently
  proven mechanical standstill or atomic MCU write exclusion.

The purely hypothetical classifier may report evidence
`COMMAND_OR_PULSES_DETECTED`. All other outcomes are
`UNKNOWN`. It **never reports MOTOR_STOPPED**, and it never
authorizes an MCU SET/RESET write, including the last fixture
where the synthetic observations all appear quiet. The sample
epoch, sensor freshness and reset markers are placeholders
for future audited firmware facilities, **not existing real CFS
registers**.

One subtlety: the original OEM `0x08010E60` sampler computes
an unsigned absolute difference, which can appear enormous at
counter wrap. This hypothetical audit instead uses a modulo
32-bit delta only after declaring that no counter reset occurred
within the sampling window. That is safer as a *design
requirement*, **not a claim that stock ROM does it**.

## Design and release implications

Use the new diagnostic manifest to guide a possible
**non-invasive hardware validation** and an MCU-side
fail-closed interlock *only after* sensor semantics and all
motor-owner/ISR coverage are proved. The host Kalico motion
interlock should remain independent. Driver energization,
motor pulses, mechanical inertia, and sensor coverage must
be separate dimensions of the safety decision.

For the current v3.23 release, these remain **FALSE**:
verified physical motor-stop feedback, atomic synchronization
of SET/RESET against all motor starts, safe event-ring SRAM
allocation, authenticated flash layout, and hardware recovery.

There is **no firmware BIN, no installed hook, no MCU read,
no motor movement, no CM5 or Kalico changes, no flash.**

Reproducibility:
`firmware/v3.22-readonly-state-probes/cfs_motor_multisignal_observation_plan.py`
and the existing SHA-pinned GitHub Actions audit workflow.
