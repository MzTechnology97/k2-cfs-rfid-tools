# OpenCFS GD32 board port ↔ Creality CFS v3.22 motor evidence

*2026-10-16 · Offline source audit; stacks on the OEM RFID-race evidence in draft PR #41.*

## New material reviewed

[OpenCFS draft PR #5](https://github.com/MzTechnology97/OpenCFS-Firmware/pull/5),
commit [`ca73d2e`](https://github.com/MzTechnology97/OpenCFS-Firmware/commit/ca73d2ec99b6b03b9a2c98b4613f32224641e5ec),
introduced an original C++ GD32F303 board adapter
(`cpp/board/k2cfs/`). Its host and Cortex-M4 compilation CI
is green; it **does not produce an executable, linker image or
safe Flash updater**.

The port now maps USART1 at PA2/PA3, 230400 baud; the hub to
TIMER0 channel 2 (PE13 PWM), direction PE3, brake PE4, tach
PE11; feeder C/D to TIMER3 channels; and all four potential
ADC current input pads. It also models RT-Thread-independent
motors, LEDs, sensor inputs and the MT6826 odometer.

Its hardware model explicitly marks some details unverified
(MT6826 SPI framing, feeder direction, clock tree). It cannot
yet read physical RFID tags (its hardware adapter currently
returns no RFID tags). The firmware has no startup/ELF/BIN.

## What was independently verified in the OEM ROM

Script
`firmware/v3.22-readonly-state-probes/cfs_opencfs_board_gd32_motor_safety_crosswalk.py`
reuses existing proven OEM motor record, GPIO/pin-table, TIMER PWM and
PE11 pulse counter audits on **both pinned manufacturer APPs v3.13/v3.22**.

Motor record bytes `[+4,+5]` at SRAM
`0x20000270 + slot*0xAC` give:

| Slot | ROM initialized pair, not established IN1/IN2 order | OpenCFS input pair (unlabelled) | Current pad candidate |
| --- | --- | --- | --- |
| A | PD2, PD3 | PD2, PD3 | PC5, channel 15 |
| B | PD0, PD1 | PD0, PD1 | **PC0**, channel 10 |
| C | PD14, PD15 | PD14, PD15 | PA1, channel 1 |
| D | PD12, PD13 | PD12, PD13 | PA0, channel 0 |

The old ROM pin table at `0x0802AD5C`, five original PWM channel
descriptors and interrupt counter at `0x20004990` have
independent source evidence. The crosswalk rejects **four synthetic
incorrect hardware mappings**.

**Important: ROM pin PA/PD assignments prove the wire association,
not the forward direction or the motor-driver IN1/IN2 naming.** The
original motor record's first byte is PD2, while the new OpenCFS
board driver calls PD3 `IN1`. We cannot conclude that the driver
will run in the correct direction by comparing pair membership.

## Two spec discrepancies reported to the other agent

A [review comment on OpenCFS PR #5](https://github.com/MzTechnology97/OpenCFS-Firmware/pull/5)
flags:

1. `docs/spec/06-motors-sensors.md` calls PD2/PD0/PD14/PD12
   `IN1`, but `docs/spec/10-board-port.md` and
   `cpp/board/k2cfs/board_io.hpp` call the opposite pin
   `IN1` on all four feeders. The implementation is not
   necessarily wrong, **the names are inconsistent**. Resolve
   with safe direction/electrical evidence before movement.
2. The older §1 current-sense table says feeder B uses **PC1**.
   The OEM and new board-port mapping use ADC channel **10, PC0**.
   PC1 is also allocated to LCD CS in the newer board mapping.

No files in the other agent's OpenCFS source were modified
by this audit.

## Not yet physical stop evidence

In the original CFS:

- GPIO and TIMER PWM records are **motor command outputs**.
- PE11 rising-edge IRQ increments a RAM **hub FG pulse** counter.
- The no-pulse counter and ADC commutation-ripple monitor are used
  to find **blocked motors**, which may still be energized.
- A reported BOX_STATE of IDLE has been observed during actual
  feeding operations.

Thus **motor blocked**, **zero pulse count**, **zero current sample**
and **BOX_STATE=IDLE** are not individually proofs that *every*
feeder and hub is electrically off and mechanically stopped.
The new OpenCFS C++ software `motion_active()` is a model of
commands, not independent physical evidence. Even multiple
synthetic signals cannot grant MCU SET/RESET permission until
task/ISR exclusion and real sensor attribution are qualified.

## Latest OpenCFS RFID changes and v3.23 boundaries

OpenCFS PR #5 also implements **live type-4 consumption** and
clears its usage record after spool removal (reports `0xFF`),
with a separate zero remaining value after runout.

This is a **new OpenCFS C++ behavior**, not a demonstrated
part of the original patched v3.23. Our current v3.23
experimental type4 code in PRs #39–#41 adds live usage and
protects the FM15L013 sinks, but has **not implemented and
tested the same spool-remove/runout reset lifecycle**.
Do not advertise host persistence/reset or assume the
two firmware implementations behave identically.

## Verification and release state

The script only checks the already-saved v3.13/v3.22 OEM
firmware binary hashes, decoded initialized SRAM, board pin
table, timer/IRQ observations and the pinned public OpenCFS
board-map checkpoint values. It emits **JSON facts only**.

No physical CFS/CM5 is accessed beyond running local
source-analysis scripts; no GPIO/ADC/register is read or
written; no printer movement, firmware rewrite, user Kalico
settings change or BIN output occurs.

**All v3.23 Flash and motor safety-release gates remain false.**
