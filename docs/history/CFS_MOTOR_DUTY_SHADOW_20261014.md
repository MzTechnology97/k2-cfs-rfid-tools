> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS motor duty-command shadow and pulse-counter limitations

*14 October 2026 · Original CFS v3.13 / v3.22 saved application · Offline audit only*

## Confirmed source-level RAM layout

A new SHA-pinned, read-only source check in
[`cfs_motor_duty_shadow_physical_audit.py`](https://github.com/MzTechnology97/k2-cfs-rfid-tools/blob/0ad22669248cc845a3c8d22dd613500c4b95feb3/firmware/v3.22-readonly-state-probes/cfs_motor_duty_shadow_physical_audit.py)
follows the original manufacturer ARM Thumb instructions in the common
motor duty controller `0x080110CC`. It verifies the manufacturer
PC-relative literal at `0x08011244` points to a common
runtime base `0x20004960`, and that the controller adds `0xB4`
to access a related PWM command structure.

| Runtime RAM | Verified source role |
| --- | --- |
| `0x20004960` | Manufacturer common motor runtime data base |
| `0x20004A14` | Original PWM command structure (`+0xB4`) |
| `0x20004A1A` | `STRH` of current requested duty (`[r4+6]`) |
| `0x20004A1C` | `STRH` copy of **previous** duty (`[r4+8]`) |
| `0x20004990` | GPIO PE11 interrupt/pulse counter (separately proven) |
| `0x20004994` | Previous sampled pulse counter (separately proven) |
| `0x2000498C` | Derived floating-point pulse/activity metric |
| `0x2000499C` | Original motor software status/countdown byte |

All listed runtime fields lie in the manufacturer's *zero-initialized*
`0x20000BC4..0x20006EE8` region. This means their initial content
is **zero**, not that a physical motor was measured to be stopped.

The `0x080110CC` routine clamps the requested duty to 255,
copies previous `[r4+6]` to `[r4+8]`, invokes the manufacturer
PWM control paths and updates `[r4+6]` with the new request.
A nonzero-duty path also zeros both software PE11 pulse-counter
fields (`+0x30` and `+0x34` off `0x20004960`),
which can erase evidence from a naive one-interval delta check.
A zero command may produce a 20-unit software countdown/status
update. Neither event establishes actual rotor standstill.

**Important:** `0x20004A1A` is a *software PWM command shadow*,
not a measured motor current, encoder, Hall feedback, physical
shaft velocity or actual timer output pin state. A requested value
of zero is insufficient for authorizing MCU SET/RESET while any
motor might be moving or coasting.

## Source-proven distinct signals

- For the BLDC motor, original GPIO logical ID `0x4B` maps to
  **PE11** and is registered as an interrupt source. Its OEM handler
  increments `0x20004990`; an OEM software task samples the counter
  and calculates a derived metric. This does **not** authenticate the
  actual physical PE11 sensor or prove coverage for brushed M1–M4.
- Five timer-channel output enable registers and their PWM
  command channels are separately mapped in
  `cfs_motor_multisignal_observation_plan.py`. Enabled hardware
  PWM is evidence of an output command, not proof the rotor turns.
- The GPIO registration path
  `0x08018DFA` installs a runtime pointer into BSS
  `0x20004C84` from its second argument. The pointer is not
  statically available in the saved firmware after initialization;
  its true active runtime value and indirect driver coverage
  are **not** authenticated.

## Fail-closed motor-stop policy

The new audit includes five synthetic conditions. They verify that
a nonzero requested duty, zero duty with rotor inertia, zero duty
with missing feedback, or a new movement after a brake request must
not be treated as evidence of physical STOPPED.

Even the model's hypothetical qualified stop scenario **never**
grants permission to flash firmware or write on a live MCU.
An actual MCU guard still requires authenticated electrical/physical
feedback for every motor, synchronization with all motor-start
tasks/IRQs, a failsafe read/check/write commit protocol, and
measured interrupt/heap effects.

See [release readiness](CFS_V323_RELEASE_READINESS_20261012.md),
[motor safety contract](CFS_MOTOR_BUSY_GUARD_CONTRACT_20261012.md)
and [GitHub issue #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9).

**All work to date remains offline. No printer commands, firmware
flash, NVM writes, or production Kalico changes.**
