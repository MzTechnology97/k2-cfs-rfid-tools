# CFS motor pin ownership: operator-confirmed PCB wiring and OEM GPIO table

*13 October 2026 · saved-v3.13/v3.22 offline investigation, not a live MCU measurement.*

## What has changed

The CFS operator confirms that the installed unit uses **the same physical
connections** as the [published historical CFS PCB tracing](https://github.com/fake-name/cfs-reverse-engineering/blob/21f9a813654b1feb6ba8597f0f48ed4650f51f3d/PCBs.md):

| Motor / signal | Physical MCU pin | Hardware or firmware interpretation |
| --- | --- | --- |
| BLDC drive PWM | **PE13** | `pwm1`, TIMER0_CH2 original manufacturer command output |
| BLDC tachometer FG | **PE11** | GPIO `0x4B`, original interrupt pulse counter `0x20004990` |
| BLDC F/R | **PE3** | GPIO `0x43`, direction |
| BLDC SS | **PE4** | GPIO `0x44`, brake |
| DC motor M1, IN1/IN2 | **PD3 / PD2** | Driver control pins; control callpath not yet established |
| DC motor M2, IN1/IN2 | **PD1 / PD0** | Driver control pins; control callpath not yet established |
| DC motor M3, IN1/IN2 | **PD15 / PD14** | Match `pwm5` and `pwm8` output pads |
| DC motor M4, IN1/IN2 | **PD13 / PD12** | Match `pwm4` and `pwm3` output pads |

The historical board also routes M1/M2/M3/M4 current-feedback amplifier
outputs to **PC5/PC0/PA1/PA0** respectively. The GD32F303 pin-function
tables designate their *possible* ADC inputs as **ADC_IN15 /
ADC_IN10 / ADC_IN1 / ADC_IN0**, respectively. PC5/ADC15 is
documented for ADC0/ADC1; PC0/PA1/PA0 can be serviced by supported
ADC instances as defined by the MCU variant. This **does not** prove
the original CFS firmware has enabled or sampled any such channel.

### New automated source inspection

`cfs_motor_adc_pin_table_inventory.py` reconstructs the saved
manufacturer's 112-record RT-Thread GPIO lookup table at physical
ROM `0x0802AD5C`, independently for SHA-pinned original
v3.13/v3.22. It enumerates lookup-table records matching all
operator-confirmed pads, retaining their original logical RT pin,
record ROM position, clock selector and pin encoding.

The script checks the already authenticated original associations
`0x43=PE3`, `0x44=PE4`, and `0x4B=PE11`. Pins absent
from the original RT-Thread lookup table are **reported absent**,
not silently assigned invented IDs. A missing table record does not
mean that the firmware cannot address the pin directly through GPIO
or ADC registers.

**Nothing in this source inventory reads a live GPIO/ADC register.**
The entries identify physical pin mappings only. They do not
classify control logic, ADC calibration, direction, current
thresholds, tach signal reliability, physical motor stop or
driver deenergization.

## Next critical development work

1. Track the original firmware's ADC initialization and conversions
   for channels 15, 10, 1, and 0; identify actual RAM destinations,
   ADC channel sequence, resolution, sample interval, current
   calibration and detection of disconnected/op-amp failure.
2. Recover the GPIO motor command owner and timer/driver control
   paths for **PD0–PD3**, which are not covered by the five
   `pwm*`-named devices.
3. Correlate a CFS live read-only observation of BLDC FG,
   electrical drive/enable, and DC current with commanded motion,
   using a verified safe interface. Human-verified wiring is
   not the same as a real signal measurement.
4. Ensure the v3.23 MCU busy guard rejects SET/RESET if any
   motor, feedback source, IRQ/task start path, or sample atomicity
   condition is unknown. Physical immobility and driver
   deenergization must be assessed separately.

**Release stays blocked:** board wiring confirmation does not
prove all motors stopped; the nine v3.23 release conditions remain
in force. No firmware flash, production MCU read/write, motor
motion, Kalico or CM5 modifications were made by this audit.
