# CFG6 v3.25 - Parametri avanzati (Italiano)

VERSIONE SPERIMENTALE PER TEST HARDWARE SUPERVISIONATI, NON QUALIFICATA PER PRODUZIONE. Flash solo con stampante inattiva e rollback CFG5T/v3.22 disponibile.

Identita / Identity: K2OH v323-cfg6, API v2, features 0xE3, 28 ID; 23 SET effective, 5 GET-only.
15 new IDs: 6, 9, 11-19, 21, 23, 24, 27.

**[Guida dettagliata parametro per parametro: comportamento reale, valori, range e rischi](PARAMETERS_IT.md)** · [English](PARAMETERS_EN.md).

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
- ID10/25/26: GET-only perche' **CFG6 non installa hook su queste costanti**; alcune routine OEM (come il polling sensore di ID26) esistono, ma i rispettivi parametri non sono modificabili con questa build. ID0/4: feeder ON/OFF, nessuna velocita' proporzionale.
- Gli override sono RAM-only e si applicano solo all'avvio di Klipper attraverso un extra abbinato e con auto_apply esplicitamente abilitato.
- Il firmware e' disponibile nel menu sperimentale dell'Helper. Conservare CFG5T e v3.22 per il rollback.

## Validation / Verifiche

- Byte originali dei 32 hook, immagine, CRC e limite flash verificati.
- API 0x57 SET/GET/RESET e rifiuto degli ID non operativi testati su Unicorn.
- 15 callsite ASM confrontati con lo stock; registri e flag CPU validati.
- ID6: flag off cambia il ramo BLS ed esclude l'azione reverse de-tooth.
- Regressioni residuo type 4: avvio/fine stampa, odometro simulato, setter e getter stock passano.
- Extra Kalico CFG6 abbinato integrato sul ramo operativo `k2-pro-openhost`; test host passati.
- Restano indispensabili prove con hardware e RFID reali, comunicazione prolungata e rollback.

Experimental image: CFG6-ALL-ADVANCED-LAB-NOT-FOR-FLASH.bin
SHA-256: 6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6

## BIN installabile tramite Helper (sperimentale)

- File: [`cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin`](cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin)
- SHA-256: `6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6`
- Identita': `K2OH / v323-cfg6`, API2, feature `0xE3`.
- L'immagine da laboratorio ha gli stessi byte e lo stesso SHA256; utilizzare preferibilmente il nome del file sopra.
- Abilitare `auto_apply` soltanto dopo il controllo della firma CFG6 e della comunicazione a stampante inattiva. La prima prova SET/GET è passata; i cicli RFID e i movimenti reali restano da verificare.

## Primo flash fisico e applicazione — 18 ottobre 2026

La CFS è stata aggiornata dall'utente e identificata in lettura come **K2OH v323-cfg6, feature 0xE3**, API2 con 28 parametri. Il bus RS-485 e l'inizializzazione motori sono operativi, sebbene al primo avvio dopo il flash siano comparsi timeout e un errore CRC, recuperati automaticamente.

Con CFS `IDLE`, stampante `standby`, nessuna bobina caricata e nessun asse referenziato, l'extra Kalico CFG6 ha applicato **23 valori su 23** dal file `box.cfg` (`auto_apply: True`). Stato riportato: `applied 23 value(s)`, senza errori. La successiva diagnostica in sola lettura ha confermato **28 GET validi, 23/23 impostazioni corrispondenti al CFG**, con ID 0/4/10/25/26 non modificati.

**Non sono stati eseguiti homing Z, movimenti, caricamento filamento o prove di stampa.** L'attivazione e la lettura dei parametri non dimostrano ancora il comportamento fisico degli hook RFID/motori, il residuo live type 4 durante una stampa o l'affidabilità prolungata del bus. Conservare il firmware CFG5T per il rollback.
