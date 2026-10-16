# CFS v3.23 — Four-feeder GPIO output and hub command latch read-only snapshot

*16 October 2026 · strictly offline experimental MCU work, stacked on draft PR #49.*

## Source correction: most feeder activity is not observable from TIMER enable bits

The previous v3.23 diagnostic `0x57/0x16` samples TIMER0/TIMER3 output-enable registers. That is helpful but **does not represent the whole feeder motor command state**.

Exact SHA-pinned Creality APP v3.13 and v3.22 initialized RAM has
four 0xAC-byte feeder records starting at `0x20000270`:
all four records' **PWM selection byte is 0**, with
two AT8236 driver inputs each mapped through the original
ROM GPIO table `0x0802AD5C` to GPIOD. As observed in
OpenCFS's recovered motor spec, these OEM feeder paths use
**GPIO output commands**, not the configurable PWM mode.

| Feeder slot | Original record pins |
| --- | --- |
| A | PD2, PD3 |
| B | PD0, PD1 |
| C | PD14, PD15 |
| D | PD12, PD13 |

The hub has additional **GPIOE PE3 (DIR) and PE4 (BRAKE)**
command outputs. None of these bits constitutes actual
motor-current, driver enable, physical brake or rotor-speed feedback.

The GD32F303 register map, independently corroborated by the
OpenCFS GD32 port, identifies **GPIO_OCTL at offset `0x0C`**
relative to each port base.

## Added firmware command: `0x57/0x18`

In the experimental original-OEM-based v3.23 firmware, the
new **read-only** request `0x57/0x18` requires submessage
length 4 and replies with exactly 8 bytes:

- `[0..3]`: LE32 `GPIOD_OCTL`, physical MMIO `0x4001140C`
- `[4..7]`: LE32 `GPIOE_OCTL`, physical MMIO `0x4001180C`

This is a raw **output-latch** snapshot, not a pin-input
sense value. The command contains only 32-bit register
reads, bounded writes to its existing temporary stack buffer,
and the manufacturer response routine.

Malformed length or unsupported opcode returns manufacturer
status **1** without reading those registers.

The extension builds **on top of PR #49** and preserves:

- original `0x57/0x16` TIMER enable snapshot;
- original `0x57/0x17` hub duty/current previous duty and FG pulse snapshot;
- all **18** previously verified OEM inbound source hooks and
  **21** outbound original OEM references;
- CFS original RFID handling, serial backend and MCU motor-control routines;
- fail-closed `0x57/0x12` and `0x57/0x13` SET/RESET denial;
- original 64-byte RAM sidecar boot mask/magic reset.

### Offline result

In-memory reconstructed image:

| Property | Value |
| --- | --- |
| #49 experimental APP size | 178,520 bytes |
| New experimental APP size | **178,568 bytes** (+48) |
| APP end exclusive | `0x0802E988` |
| Last occupied Flash page | 93 |
| Archived OEM parameter page | `0x0807F800` |
| Trial CRC16 | `0xBA83` |
| Trial SHA-256 | `946197ff853762815d5e5d9b3c0827469b0a916ec49491334a65552bf58773d1` |

The new script
`firmware/v3.22-readonly-state-probes/cfs_v323_raw_gpio_feeder_drive_snapshot_candidate.py`
validates the GPIO pin pairs from **both saved original
APP versions**, independently reconstructs the full combined
APP, source-authenticates literal MMIO addresses and emulates
the new Thumb handler.

**13 original-ARM regression cases** cover zero latch data,
individual feeder input pins, combined feeder high bits,
hub DIR/BRAKE commands, all 32-bit bits, malformed
lengths and unknown opcode. The new command performs
exactly two expected MMIO reads, **zero non-stack writes**.
All cases pass offline.

Three intentionally corrupted test images swap the port
source addresses or bypass the request length check; the
same emulator rejects all three. Separate regressions re-run
the parent PWM snapshot, hub duty/FG snapshot, original
boot-time sidecar reset and 12 CONFIG SET/RESET denies.

## Why this is still not a motor-safe interlock

The GPIO latch does not sense the actual level on the motor
driver pins, the motor electrical current, active brake
torque or physical rotor motion. The two reads are sequential,
not synchronized with RT-Thread tasks or hardware interrupts.
For example, the motor could be energized by a task immediately
after a completely normal 8-byte read.

**No combination** of `BOX_STATE=IDLE`, raw PWM register
bits, GPIOD/GPIOE output latches and FG pulse counts can
yet independently qualify the write path.

A real MCU-side interlock still requires audited coverage
of every feeder/hub/preload task and ISR start/stop path,
shared lock or epoch semantics and reliable electrical
state/driver feedback. This script **does not enable CONFIG
SET/RESET, speed overrides, automatic boot profile loading,
Flash or motor operations**.

The installed CM5 Kalico extra
`klippy/extras/box_cfs_runtime.py` remains untouched, as
requested, until a flash-qualified MCU firmware is ready
for testing. No persistent firmware BIN/HEX/ELF is emitted.
