# CFS v3.23: hub commanded duty and PE11 pulse-counter diagnostic

*2026-10-16. Source-only work stacked on [draft PR #46](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/46).*

## Motor-safe configuration motivation

The previous experimental `0x57/0x16` command reads raw
TIMER0/TIMER3 PWM output-enable registers. Those signals
indicate **hardware output commands**, not real shaft rotation.
A PWM output can remain enabled with duty 0, and missing PWM
does not prove that all motors are electrically deenergized.

This next diagnostic separates the **original OEM hub software
duty request** from its **PE11 IRQ pulse counter**, so a future
engineering test can observe an enabled PWM channel, requested
duty and FG history independently.

**There is no permission to write motor speed or buffer parameters.**
SET and RESET remain blocked in the MCU under all six BOX_STATE
values until a true motor task/ISR exclusion mechanism is implemented
and hardware-qualified. Kalico remains entirely unchanged.

## Exact original manufacturer sources

Audits `cfs_motor_duty_shadow_physical_audit.py` and
`cfs_motor_multisignal_observation_plan.py`, each against the
**two SHA-pinned historical original Creality APPs v3.13/v3.22**,
source-verify:

| Original SRAM | Data |
| --- | --- |
| `0x20004A1A` | u16 current hub requested duty shadow, OEM controller `0x080110CC` |
| `0x20004A1C` | u16 prior requested duty shadow |
| `0x20004990` | u32 PE11 hub GPIO pulse IRQ counter |

These are not independently verified RPM, torque, electrical
driver-off or motor-stop measurements. The pulse counter is associated
with the hub only, not all four feeders.

## Experimental wire contract

New **`0x57/0x17`** request submessage has length exactly **4**;
manufacturer-compatible success response status **0** carries
8 bytes:

| Offset | Field |
| --- | --- |
| 0..1 | little-endian u16 current requested hub duty |
| 2..3 | little-endian u16 previous requested hub duty |
| 4..7 | little-endian u32 PE11 IRQ pulse counter |

Invalid lengths or unknown subcommands return the original
bad-request status **1** and no payload. The code reads the
three exact OEM SRAM locations and only writes into the original
`0x57` handler's 8-byte local stack reply buffer. It does not
write motor commands, PWM registers, RFID tags, calibration or
extra SRAM buffers.

Do **not** send this command to an older firmware that does not
advertise or recognize it. Neither the CM5 Kalico extra nor
`box.cfg` was modified to invoke it.

## Offline proof and regression

Script
`firmware/v3.22-readonly-state-probes/cfs_v323_oem_hub_command_fg_snapshot_candidate.py`
rebuilds the entire APP **in volatile Python memory**, including
earlier RFID type-4 live usage, FM15L013 guards, spool-removal,
read-only `0x57/0x15` and `0x57/0x16` snapshots and the
fail-closed `0x57/0x12/0x13` configuration fence.

The immediate predecessor `cfs_v323_raw_pwm_output_snapshot_candidate.py`
receives optional source-only `extra_dispatch`/`extra_entry`
inputs. Its original no-extra code path remains **byte-for-byte
identical**, including the previously verified SHA-256. No modified
firmware is saved or published as BIN/HEX/ELF.

- Combined in-memory APP: **178,520 bytes**, +56 versus #46.
- Exclusive end `0x0802E958`, still physical Flash page **93**;
  original reserved parameter page starts `0x0807F800`.
- Trial CRC16 **`0xF956`**, trial SHA-256
  `0439c780e75ef78de50e09d11070efecac62e11c0a77f442c601e01be7cdacd0`.
- Original OEM branch accounting is unchanged: **18 inbound hooks**,
  **21 outbound manufacturer references**.
- **9 Unicorn ARM Thumb cases:** zero duty/zero pulses,
  command-without-pulses, previous nonzero duty, pulses after
  command zero, arbitrary and full-width values, malformed
  short/long requests and unsupported subcommand.
- **3 single-source corruption negatives:** changing the original
  hub shadow pointer, pulse-counter pointer or removing the
  request-length check is rejected.
- Prior `0x57/0x16` full five-output PWM readout still passes.
- **12 SET/RESET busy-state regressions** still return 7 with
  no global SRAM writes; OEM boot heap wrapper still clears
  volatile profile magic/mask.

The requested duty is not sampled atomically with the IRQ
counter, nor with TIMER output enable. A concurrent RT-Thread
motor start, IRQ, or zeroing of the counter may interleave with
the diagnostic reads. **No static or dynamic synthetic observation
qualifies a physical stop or a safe write window.**

## Exhaustive motor-guard negative safety contract

The additional source-only
`cfs_v323_pwm_motor_guard_exhaustive_contract.py` exercises
**1024 combinations** of synthetic BOX_STATE, feeder/hub/buffer
state, freshness, feedback authentication, motor lock, complete
start-path coverage, motor-operation epoch, and PWM-enable status.
Only **two model states** with every hypothetical independent
safety condition satisfied yield a synthetic authorization;
the output-enable bit's value must *never* change that result.

This is a **policy test**, not proof that the manufacturer MCU
contains the required synchronization or verified physical
feedback. In the actual first-test CFS firmware, SET/RESET
remain unconditionally denied.

## Remaining steps

1. Source-audit all direct and callback-driven motor start and stop
   paths, and RT-Thread/IRQ critical section semantics.
2. Design a fail-closed, nonblocking motor permission token
   whose validity is revoked on **every** start. Confirm
   timing/interrupt effects of any code patch.
3. Qualify actual motor electrical state, not just software
   command shadows or lack of FG pulses.
4. Only then allow carefully selected runtime speed/buffer IDs
   and a post-boot MCU-ready atomic RAM-profile commit.
5. Integrate the already-existing Kalico extra at the end,
   after there is a firmware candidate ready for controlled test.

**No CFS, CM5 Kalico, physical Flash, UART, SWD, GPIO or motor
hardware access occurred. The new image is not flash-approved.**
