# CFS BLDC FG and brushed-current crosswalk — independent PCB evidence
*13 October 2026 · offline study, not a measurement of the installed unit.*

## The first independent physical explanation of PE11

The original CFS v3.13/v3.22 saved firmware registers an
interrupt callback on logical pin `0x4B`, **PE11**, then
increments RAM `0x20004990` each time that callback runs.
The historical [CFS motherboard PCB reverse engineering]
(https://github.com/fake-name/cfs-reverse-engineering/blob/21f9a813654b1feb6ba8597f0f48ed4650f51f3d/PCBs.md)
reports four BLDC driver connections:

| Historical physical BLDC signal | MCU pin | Independently matched OEM saved-code usage |
| --- | --- | --- |
| PWM command | **PE13** | `pwm1`, TIMER0_CH2 output |
| FG driver tachometer output | **PE11** | logical `0x4B`, configured GPIO IRQ callback and pulse counter |
| F/R direction | **PE3** | original board-pin table logical `0x43` |
| SS motor brake | **PE4** | original board-pin table logical `0x44` |

**The four-way match between independently documented PCB traces and
four original firmware pin assignments substantially strengthens
the interpretation of PE11 as the BLDC FG/tach input.**
The historical PCB is from a separate CFS in the public research
project, and we have **not verified the same PCB revision, wiring,
driver chip or interrupt activity on the user's device**.

An FG tach pulse is evidence of external driver reporting activity
when it occurs. **No pulses do not prove a BLDC driver is disabled,
unenergized or mechanically safe**: the motor could be stalled,
coasting, changing direction, or the IRQ could be disconnected.

## Four brushed motors remain separate safety owners

The same historical board analysis independently documents these
brushed-motor input/analogue feedback pairs:

| Motor | Driver input 1 | Driver input 2 | Current feedback amplifier |
| --- | --- | --- | --- |
| M1 | PD3 | PD2 | **PC5** |
| M2 | PD1 | PD0 | **PC0** |
| M3 | PD15 | PD14 | **PA1** |
| M4 | PD13 | PD12 | **PA0** |

The saved CFS firmware's five **named** PWM devices have outputs
on PE13 (BLDC), PD12, PD13, PD14, PD15. Thus the PWM objects
correspond to the BLDC speed-command pin and both driver-input
pins for **M3 and M4**, but **not** the historical M1/M2
input pins PD0–PD3. This is a *scope gap in the five-PWM
object map*, not proof that M1/M2 have no firmware control.
No full direct/indirect driver callgraph or motor-owner inventory
has yet been established.

The historical PCB document identifies the four current-feedback
pins with analogue current-sense circuitry. **The CFS saved
firmware's ADC channel setup, calibration, thresholds,
failure handling, motor-driver enable/brake logic and actual
hardware measurements on these four lines have not yet been
authenticated.** Even accurately measured zero current would
not by itself prove a mechanically stopped rotor.

This rules out an unsafe shortcut: using the single PE11 FG
counter as an all-motor idle certificate, or treating all
five PWM output bits being zero as proof every motor is idle.

## Automated reproducible checks

`cfs_historical_pcb_motor_pinout_crosswalk.py`
cross-references *both* SHA-pinned saved APP generations
with an immutable upstream `PCBs.md` Git blob
`8a8345e299e48221f3b4859e8a0d34eefb95672c`.
It asserts the four BLDC pins, all four brushed driver
input pairs and current feedback pads, counts the
uncovered M1/M2 pins, and rejects **two deliberately
tampered public pinout rows** (FG and current sense).

Eight additional synthetic motor safety scenarios reject
writing when a BLDC could be commanded but stalled,
FG pulses persist after PWM off, analog feedback is
unknown/untrusted, or apparent zero current could be
misleading. This code does **not** read ADCs or GPIO,
execute on CFS/CM5, start motors, modify Kalico, flash
firmware or generate a v3.23 BIN.

## Practical next investigation

1. Find the **original GD32 ADC configuration and sampling
   dataflow** for PC5, PC0, PA1 and PA0; verify whether the
   saved firmware reads them, with which channel mappings,
   and what the readings mean when a motor is energized
   but stalled.
2. Complete the **PD0–PD3 control-path** inventory for the
   two brushed driver pairs absent from the five PWM objects.
3. Determine whether PE11 FG and all current-sense inputs
   can be sampled without affecting timing/ISR, *only on
   separately confirmed compatible hardware* and via an
   authenticated read-only path.
4. Before authorizing any SET/RESET write, establish an
   MCU-side atomic no-motion lock covering feeder, hub,
   buffer, BLDC, all four brushed motors and ISR starts.
   Unknown conditions remain BUSY.

**The existing nine v3.23 release gates remain blocked.**
