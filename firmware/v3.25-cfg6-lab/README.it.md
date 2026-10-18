# CFG6 v3.25 - Parametri avanzati (Italiano)

VERSIONE SPERIMENTALE PER TEST HARDWARE SUPERVISIONATI, NON QUALIFICATA PER PRODUZIONE. Flash solo con stampante inattiva e rollback CFG5T/v3.22 disponibile.

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

- ID6: flag sidecar RAM privato (byte50, bit21), blocca il ramo reale reverse de-tooth. Non scrive lo stato stock.
- ID17: aggancio all'attesa pre-lettura RFID di 400 ms al sito stock 0x08012A60. Il ritardo separato da 10 ms non viene toccato.
- ID27: ramo originale delle ripetizioni pretensione al sito 0x08012616, preservando i due target del loop.
- ID10/25/26: non sbloccati; codice stock non raggiungibile. ID0/4: feeder ON/OFF, nessuna velocita proporzionale.
- Gli override sono RAM-only e si applicano solo all'avvio di Klipper attraverso un extra abbinato e con auto_apply esplicitamente abilitato.
- Il firmware e' disponibile nel menu sperimentale dell'Helper. Conservare CFG5T e v3.22 per il rollback.

## Validation / Verifiche

- Byte originali dei 32 hook, immagine, CRC e limite flash verificati.
- API 0x57 SET/GET/RESET e rifiuto degli ID non operativi testati su Unicorn.
- 15 callsite ASM confrontati con lo stock; registri e flag CPU validati.
- ID6: flag off cambia il ramo BLS ed esclude l'azione reverse de-tooth.
- Regressioni residuo type 4: avvio/fine stampa, odometro simulato, setter e getter stock passano.
- Extra Kalico abbinato su ramo di sviluppo separato: 107 test host superati.
- Restano indispensabili prove con hardware e RFID reali, comunicazione prolungata e rollback.

Experimental image: CFG6-ALL-ADVANCED-LAB-NOT-FOR-FLASH.bin
SHA-256: 6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6

## BIN installabile tramite Helper (sperimentale)

- File: [`cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin`](cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin)
- SHA-256: `6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6`
- Identita': `K2OH / v323-cfg6`, API2, feature `0xE3`.
- L'immagine da laboratorio ha gli stessi byte e lo stesso SHA256; utilizzare preferibilmente il nome del file sopra.
- Non abilitare `auto_apply` finché il bus RS-485, motori e RFID non siano verificati dopo il flash.
