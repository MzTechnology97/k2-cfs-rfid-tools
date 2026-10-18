# CFS v3.23 CFG4 — All 28 runtime parameters (English)

**Strict compatibility:** this configuration is supported only by matching K2-OpenHost modified firmware distributed in the k2-cfs-rfid-tools repository. Stock Creality and arbitrary third-party images are not compatible. OpenCFS is detected as a separate OCFS firmware family, but is NOT compatible with the K2OH CFG4 SET opcode.

**W = writable, effective stock callsite; R = read-only/no proven effect.** All writes come exclusively from the CFG during Klipper startup, not the console.

| ID | Config key | Original default | Purpose | Bounds | CFG4 |
|---:|---|---|---|---|:---:|
| 0 | feeder_forward_speed | 255 | Feeder forward speed; read-only, the feeders are on/off.  Feeders use binary GPIO on/off, not variable proportional speed. | 1–255 | R |
| 1 | hub_forward_speed | 100 | Hub forward speed; stock 100.  | 1–255 | W |
| 2 | hub_transition_speed | 200 | Hub transition speed; stock 200.  | 1–255 | W |
| 3 | hub_insert_speed | 155 | Hub insert speed; stock 155.  | 1–255 | W |
| 4 | feeder_reverse_speed | 255 | Feeder reverse speed; read-only, the feeders are on/off.  Feeders use binary GPIO on/off, not variable proportional speed. | 1–255 | R |
| 5 | hub_reverse_speed | 80 | Hub reverse speed; stock 80.  | 1–255 | W |
| 6 | reverse_detooth_enable | 1 | Reverse de-tooth switch; stock on.  | 0–1 | R |
| 7 | hub_transition_wait_ms | 3200 | Wait after the hub push before the buffer path, ms; stock 3200.  | 100–10000 | W |
| 8 | insert_sensor_timeout_ms | 7000 ms | Time allowed for the hub sensor during insertion, ms; stock 7000. Stock 700 polls of 10ms equals 7000ms; values must be multiples of 10ms. | 1000–50000ms, multiples of 10ms | W |
| 9 | hub_pullback_timeout_ms | 5000 | Buffer wait while unloading, ms; stock 5000.  | 500–15000 | R |
| 10 | unload_sensor_timeout_ms | 1000 | Read-only: stock code never executed. Unreachable stock path; original units are 10ms polls. No writable hook in this build. | 100–5000 | R |
| 11 | rfid_seek_speed | 160 | Hub speed while locating the tag; stock 160.  | 1–255 | R |
| 12 | rfid_measure_speed | 120 | Hub speed while measuring the spool; stock 120.  | 1–255 | R |
| 13 | rfid_reposition_speed | 100 | Hub speed while repositioning for a read; stock 100.  | 1–255 | R |
| 14 | rfid_seek_move_ms | 800 | Tag locate move, ms; stock 800.  | 100–5000 | R |
| 15 | rfid_seek_settle_ms | 200 | Pause after a locate move, ms; stock 200.  | 10–2000 | R |
| 16 | rfid_post_auth_wait_ms | 1000 | Reverse between read attempts, ms; stock 1000.  | 100–5000 | R |
| 17 | rfid_pre_measure_settle_ms | 400 ms | Pause before reading the tag, ms; stock 400. Corrected true stock default: 400ms, not 10ms. | 1–2000 | R |
| 18 | rfid_neighbor_detect_delay_ms | 400 | Neighbour spool move, ms; stock 400.  | 50–2000 | R |
| 19 | rfid_neighbor_settle_ms | 100 | Pause after the neighbour move, ms; stock 100.  | 10–1000 | R |
| 20 | feed_total_timeout_ms | 1250 × 20ms = 25s | Stage-4 feed time limit, ms; stock 25000. Original stock raw count: 1250 ticks of 20ms equals 25000ms. | 5000–60000 | R |
| 21 | feed_recovery_timeout_ms | 3000 | Stage-4 recovery time limit, ms; stock 3000.  | 500–10000 | R |
| 22 | odometer_stall_timeout_ms | 25 × 20ms = 0.5s | Odometer stall limit, ms; stock 500. Original stock raw count: 25 ticks of 20ms equals 500ms. | 100–2000 | R |
| 23 | rfid_neighbor_retry_count | 3 | Tag locate attempts; stock 3.  | 1–10 | R |
| 24 | reverse_detooth_timeout_ms | 1000 | Reverse de-tooth delay, ms; stock 1000.  | 100–10000 | R |
| 25 | buffer_fill_timeout_ms | 30000 | Read-only: stock code never executed.  No writable hook in this build. | 1000–60000 | R |
| 26 | transition_detect_timeout_ms | 300 × 10ms = 3s | Read-only: stock code never executed. Original stock raw count: 300 ticks of 10ms equals 3000ms; independent retry sites remain. No writable hook in this build. | 50–5000 | R |
| 27 | load_retry_count | 3 | Pretension in/out cycles; stock 3.  | 1–10 | R |

## Firmware detection and startup flow

1. Query 0x7A after CFS enumeration. Require K2OH / format 1 / variant 4 / revision v323-cfg4 / version cfs0_000_153.
2. Also require 0x57 INFO API2, count 28, features 0xD7. v3.22 reports the same 0xD7: features alone are not proof of v3.23.
3. Apply only IDs 1, 2, 3, 5, 7 and 8 at the next completed CFS enumeration, verify with GET. Unsupported IDs are explicitly skipped.
4. The configuration is RAM-only, so it is lost on CFS power cycle.
5. If identity is OCFS, display its version and variant but never send K2OH CFG4 SET to OpenCFS.

## Configuration example

    [box_cfs_runtime]
    auto_apply: true
    hub_transition_speed: 220
    hub_insert_speed: 100
    hub_reverse_speed: 150
    #insert_sensor_timeout_ms: 7000

**Experimental image:** hardware/RS485 qualification incomplete; retain v3.22 rollback. Do not treat software BOX_STATE as independent motor-stop feedback.

[Guida italiana](CFS_V323_PARAMETER_GUIDE_IT.md) | [English compatibility](CFS_FIRMWARE_COMPATIBILITY.md) | [Compatibilità italiana](CFS_FIRMWARE_COMPATIBILITY_IT.md)

## Live type-4 filament remaining during printing

v3.23 CFG4 **inherits from v3.12/v3.22** the `remaining_gate_wrapper`, `remaining_init_wrapper` and `remaining_valid_wrapper` hooks. For supported third-party spools, these initialize the stock **type-4** runtime using the geometric percentage and a nominal 330,000 mm reference. Opcode `0x03` can read the initial value without writing to the RFID tag.

**This does not imply live consumption tracking during printing.** OpenCFS analysis of stock APP153 shows that the `rfid_mgr_fila_task`, which accumulates odometer millimeters and updates the percentage, is gated by the FM15L013 secure-element presence flag. On boards without that chip, the task is skipped even for type 4, so the CFS percentage can remain at its loading-time value while Kalico estimates G-code consumption.

v3.23 CFG4 **does not bypass this hardware gate** and does not add an independent odometer task. Live type-4 consumption tracking requires a later patch and dedicated hardware tests. IDs 20 and 22 are recognized and readable catalogue parameters, but have no effective SET hooks in the current CFG4 image.

[OpenCFS technical analysis](https://github.com/MzTechnology97/OpenCFS-Firmware/blob/main/docs/spec/05-preload-rfid.md) | [Italiano](CFS_V323_PARAMETER_GUIDE_IT.md)
