# CFS v3.23: OEM runtime-config timebase and feeder GPIO effects

*16 October 2026 — follow-up to OpenCFS research in [PR #47](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/47#issuecomment-6212351602). Source-only audit on the two saved manufacturer APPs. **Do not flash.***

## Finding A — firmware parameters ID 8 and ID 10 are not milliseconds

The real OEM function **`0x0800E85A`** reads the sensor and
decrements a caller-supplied loop counter; every unsuccessful poll
waits **10 ms** using the original `0x08021E28` delay.
Both saved v3.13 and v3.22 contain the exact same instruction pair:

- `0x0800E87E: movs r0, #10`
- `0x0800E880: bl 0x08021E28`

Two exact ROM callsites illustrate the unit:

| Runtime Config ID | Current compatibility identifier | Raw OEM default | OEM source | Actual nominal timeout |
|---|---|---:|---|---|
| **8** | `insert_sensor_timeout_ms` | **700** | `0x080048C8: mov.w r1,#700`, `0x080048CE: bl 0x0800E85A` | **~7 s**, not 700 ms |
| **10** | `unload_sensor_timeout_ms` | **1000** | `0x08004E14: mov.w r1,#1000`, `0x08004E1A: bl 0x0800E85A` | **~10 s**, not 1000 ms |

**Exact ID8 hook provenance:** the original v3.13 instruction at
**`0x080042CA`** is `MOV.W R1,#700`; the installed v3.22
has already replaced this instruction with the experimental
`BL 0x0802E7CC` configuration wrapper. The second OEM
`MOV.W R1,#700` at **`0x080048C8`** is a distinct,
still-unmodified sensor callsite. This audit explicitly tests both
to avoid falsely claiming that all 700-poll waits use the ID8 override.

These times are **approximate nominal ceilings**, because sensor
success and debouncing can terminate the loop early. They should not
be confused with duration of a successful load or unload. A legal
raw interval `100..5000` would correspond to **~1..50 seconds**,
not `100..5000 ms`.

The existing wire ID, raw default and range are **NOT changed**:
editing catalog naming or `box_cfs_runtime.py` at this stage
would risk silently changing user-config semantics. When host
integration is resumed, present actual units through descriptions
or UI conversion, retaining the original raw count on wire.
In the present v3.23 prototype **ID 8 is hooked but SET is
fail-closed**; **ID 10 is stored-only** and has no effective hook.

## Finding B — the RFID neighbor settle ID 19 hook is exactly 100 ms

`build-v3_22.py` lists the older nominal v3.14 hook
`0x08013078`. With the previously source-verified relink delta
`0xD000`, its true physical OEM address is
**`0x08006078`** — not `0x08005E58`.

The source-pinned original code is:

```text
0x08006072  BL    0x0800D27A        ; OEM stop call
0x08006076  MOVS  R0,#0x64          ; 100 (milliseconds)
0x08006078  BL    0x08021E28        ; rt_thread_mdelay(100)
0x0800607C  ADDS  R4,R4,#1          ; next neighbor-search attempt
0x0800607E  CMP   R4,#3
0x08006080  BLO   0x0800604E
```

There is **another, separate** ROM delay:

```text
0x08005E54  MOV.W R0,#0x1F4         ; 500 ms
0x08005E58  BL    0x08021E28
```

Thus the legacy ID19 name `rfid_neighbor_settle_ms` and
default **100** match its intended physical hook. It must
not be attached to the unrelated earlier 500-ms RFID phase.
All listed bytes match the saved v3.13 and v3.22 APPs.

The ID19 advanced hook has **not** been enabled in the
present v3.23 combined firmware, and no new writable
RFID operation is being activated by this audit.

## Finding C — ID26 is a 300-poll timeout, *not* 300 milliseconds

An additional [PR #47 comment](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/47#issuecomment-6212649588)
raised a suspected mismatch around ID26. Both original APPs and
the legacy v3.14 advanced-hook table resolve it precisely:

- Nominal hook `0x080112E6`, after subtracting `0xD000`, is
  physical **`0x080042E6`**. The instruction is
  `mov.w r8,#0x12c`, i.e. **300 raw polls**.
  `0x080042EE: mov r1,r8` then
  `0x080042F2: bl 0x0800E85A` uses the original 10-ms
  per-poll implementation. Effective timeout **~3 seconds**.
  The intended `cfg26_r8_wrapper` replaces R8's initialized
  raw poll count; **this advanced hook remains disabled in v3.23**.
- The separate call at `0x080048A8` is preceded by
  `0x080048A4: movs r1,#0x32`: **50 polls ≈ 500 ms**,
  not 300 polls. A later `mov.w r7,#300` at
  `0x080048BA` is **not** that call's R1 timeout argument.
- The **retry loop in that other function** is a second
  3-second path: `0x080048BA: mov.w r7,#300` feeds
  `0x080048F4: mov r1,r7` and
  `0x080048F8: bl 0x0800E85A`.
  It has the same **300 × 10ms = ~3s** raw default
  as ID26's planned hook at `0x080042E6`, but is
  **not patched by that hook**. Two independent hooks
  would be required for both paths to change together.
- Another separate call at `0x080048CE` is preceded by
  `0x080048C8: mov.w r1,#700`: **700 polls ≈ 7 seconds**.

**Conclusion:** the catalog ID26 raw default **300** matches
the originally intended site `0x080042E6`, but its name
`transition_detect_timeout_ms` and
`milliseconds_u16` type misstate its unit by 10×.
The `0x080048xx` callsites, including the other 3-second
retry call at `0x080048F8`, are not the intended ID26 hook;
do not change the ID26 raw default to 700, or assume
changing ID26 would adjust both 3-second loops.

## Finding C — feeder IDs 0 and 4 are *binary GPIO commands*

All four OEM initialized motor records, sourced from the original
Thumb-scatter RAM at `0x20000270 + slot*0xAC`, contain:

- `record+0` feeder PWM flag = **0**;
- pointers `record+0x08` and `record+0x14` = **0**;
- individual GPIOD output pin pairs
  **PD2/PD3, PD0/PD1, PD14/PD15, PD12/PD13**;
- `record+0xA8` last commanded speed,
  `record+0xAA` direction.

The active OEM writer `0x08010054`, with PWM flag zero,
reaches direct `rt_pin_write` calls at
`0x080101EE`, `0x08010206`, `0x0801020E`.
The speed input is interpreted as zero versus nonzero:
**a smaller nonzero value cannot slow the feeder**.
The otherwise present software proportional-duty branch is
not used in this configuration.

Consequently host parameter IDs **0**
`feeder_forward_speed` and **4**
`feeder_reverse_speed` must remain read-only or be explicitly
reported as ineffective under OEM GPIO mode. Neither
the TIMER3 PWM-enable telemetry `0x57/0x16` nor the GPIO
output-latch telemetry `0x57/0x18` is evidence of actual
motor movement or absence of motor energization.

Other original hub-speed IDs may affect the true hub PWM
motor, but require an independent source-pinned hook and
atomic motor-start/RT-Thread/ISR safety assessment **per ID**.

## Reproducible offline regression

`firmware/v3.22-readonly-state-probes/cfs_v323_oem_config_units_and_gpio_effect_audit.py`

Checks exact Capstone ARM/Thumb source instructions, recomputes
both original feeder RAM records, verifies their zero-PWM mode
and ID-specific timebases on the two SHA-pinned OEM APP images,
then rebuilds the newest **178,568-byte** #52 firmware
GPIO-diagnostic candidate entirely in memory.

- **Two matching OEM generations.**
- **Four motor records**, with the source-pinned GPIO-only configuration.
- **Twelve deliberate ROM corruption mutants** rejected, including the
  distinct ID26/R8, separate R7 retry, 50-poll and 700-poll timing paths.
- **Twelve SET/RESET command executions** over six stock BOX_STATE
  values: status **7** for every attempt, no runtime-profile
  sidecar or global RAM writes.
- No serial, GPIO hardware, motor operation, Kalico modification,
  firmware output image or Flash access.

### Roadmap implications

The v3.23 release path remains:

1. Preserve the existing fail-closed CONFIG SET/RESET while the
   MCU motion interlock is not fully qualified.
2. Instrument actual feeder writer, hub PID timer, hub DIR/BRAKE
   and MSH direct GPIO/PWM writers. Do not hold an RT-Thread
   critical section across delays, external I/O or long writes.
3. Qualify only effective, correctly unit-labelled RAM hooks
   individually; keep incompatible IDs read-only.
4. **Kalico last**, as requested. Existing installed
   `box_cfs_runtime.py` and `box.cfg` remain untouched until
   an MCU firmware image is ready for physical testing.

**No firmware write, RAM profile apply, or hardware-safe motor
interlock has been released by this PR.**
