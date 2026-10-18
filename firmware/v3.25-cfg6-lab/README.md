# CFG6 v3.25 - Advanced parameters (English)

EXPERIMENTAL HARDWARE-TEST BUILD, NOT PRODUCTION-QUALIFIED. Flash only while the printer is idle and verified CFG5T/v3.22 rollback images are available.

Identita / Identity: K2OH v323-cfg6, API v2, features 0xE3, 28 ID; 23 SET effective, 5 GET-only.
15 new IDs: 6, 9, 11-19, 21, 23, 24, 27.

| ID | Parametro / Parameter | Stock | Range | SET |
|---:|---|---:|---|:---:|
| 0 | feeder_forward_speed | 255 | 1-255 raw | NO |
| 1 | hub_forward_speed | 100 | 1-255 raw | YES |
| 2 | hub_transition_speed | 200 | 1-255 raw | YES |
| 3 | hub_insert_speed | 155 | 1-255 raw | YES |
| 4 | feeder_reverse_speed | 255 | 1-255 raw | NO |
| 5 | hub_reverse_speed | 80 | 1-255 raw | YES |
| 6 | reverse_detooth_enable | 1 | 0-1 bool | YES |
| 7 | hub_transition_wait_ms | 3200 | 100-10000 ms | YES |
| 8 | insert_sensor_timeout_ms | 7000 | 1000-50000 ms | YES |
| 9 | hub_pullback_timeout_ms | 5000 | 500-15000 ms | YES |
| 10 | unload_sensor_timeout_ms | 1000 | 100-5000 ms | NO |
| 11 | rfid_seek_speed | 160 | 1-255 raw | YES |
| 12 | rfid_measure_speed | 120 | 1-255 raw | YES |
| 13 | rfid_reposition_speed | 100 | 1-255 raw | YES |
| 14 | rfid_seek_move_ms | 800 | 100-5000 ms | YES |
| 15 | rfid_seek_settle_ms | 200 | 10-2000 ms | YES |
| 16 | rfid_post_auth_wait_ms | 1000 | 100-5000 ms | YES |
| 17 | rfid_pre_measure_settle_ms | 400 | 1-2000 ms | YES |
| 18 | rfid_neighbor_detect_delay_ms | 400 | 50-2000 ms | YES |
| 19 | rfid_neighbor_settle_ms | 100 | 10-1000 ms | YES |
| 20 | feed_total_timeout_ms | 25000 | 5000-60000 ms | YES |
| 21 | feed_recovery_timeout_ms | 3000 | 500-10000 ms | YES |
| 22 | odometer_stall_timeout_ms | 500 | 100-2000 ms | YES |
| 23 | rfid_neighbor_retry_count | 3 | 1-10 raw | YES |
| 24 | reverse_detooth_timeout_ms | 1000 | 100-10000 ms | YES |
| 25 | buffer_fill_timeout_ms | 30000 | 1000-60000 ms | NO |
| 26 | transition_detect_timeout_ms | 300 | 50-5000 ms | NO |
| 27 | load_retry_count | 3 | 1-10 raw | YES |

## Dettagli / Details

- ID6: private RAM sidecar (byte50, bit21) gates the actual stock reverse de-tooth branch without touching unknown stock state.
- ID17: correct original 400ms RFID pre-read delay callsite 0x08012A60; a separate 10ms call is untouched.
- ID27: the actual pretension retry loop at 0x08012616, with original loop and exit targets preserved.
- IDs10/25/26: excluded because stock paths are unreachable. IDs0/4: on/off feeder motors, no proportional speed.
- All overrides are volatile RAM, written only from paired Klipper CFG on startup with deliberate auto_apply.
- This firmware is available from the Helper experimental CFS menu. Keep CFG5T and v3.22 for rollback.

## Validation / Verifiche

- All 32 patched stock sites, CRC, flash bounds and original bytes checked.
- Unicorn 0x57 SET/GET/RESET and read-only IDs tested.
- 15 new ARM callsites: exact default behaviour, ABI registers and CPU flags verified.
- ID6 disabled changes BLS condition to skip the actual stock de-tooth action.
- Type-4 regression passed with simulated odometer, stock print start/finish, percent setter and getter.
- Paired Kalico candidate is separate and passes 107 host tests.
- Real hardware, RFID tags, transport stability and rollback remain unqualified.

Experimental image: CFG6-ALL-ADVANCED-LAB-NOT-FOR-FLASH.bin
SHA-256: 6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6

## Installable experimental Helper image

- File: [`cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin`](cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin)
- SHA-256: `6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6`
- Identity: `K2OH / v323-cfg6`, API2 features `0xE3`.
- Same verified bytes as the laboratory image; the canonical filename above is preferred for installation.
- Keep `auto_apply` disabled until RS-485, motor and RFID smoke tests have passed following the flash.
