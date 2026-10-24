# Audit cross-repository K2-OpenHost — 25 ottobre 2026

> **Solo revisione e documentazione della PR CFG6 #60.** Nessun flash, riavvio, richiesta RS-485 o modifica a Kalico, box.cfg, Helper, Mainsail o Home Assistant. Questa nota non approva un nuovo flash.

## Repository supplementari controllati

| Repository | Scopo e relazione con CFG6 |
| --- | --- |
| [K2-OpenHost](https://github.com/MzTechnology97/K2-OpenHost) | Wiki, test hardware, versioni e procedure CFS; evidenza storica di stampa e incidenti bus |
| [k2-openhost-firmware-tools](https://github.com/MzTechnology97/k2-openhost-firmware-tools) | Ricostruzione originale del protocollo aggiornamenti, loader probe, identità, preflight; **principale fonte aggiuntiva** |
| [K2-OpenHost-RFID](https://github.com/MzTechnology97/K2-OpenHost-RFID) | Riferimento di programmazione tag MIFARE/Creality, **non implementazione MCU firmware CFS** |
| [K2-OPENHOST-CM5](https://github.com/MzTechnology97/K2-OPENHOST-CM5) | Repository Klipper-Backup; non analizzarne eventuali dati di backup per diagnosi firmware |
| [kalico-k2pro](https://github.com/MzTechnology97/kalico-k2pro) | Host CFS, stima bobina, watchdog e motori, già presente sul CM5; **sola verifica PR, non modificare** |
| [mainsail-k2openhost](https://github.com/MzTechnology97/mainsail-k2openhost) | CFS UI alimentata da Moonraker `box`, non implementa bootloader/flash |
| [ha-k2-openhost](https://github.com/MzTechnology97/ha-k2-openhost) | Integrazione e sensori percentuale CFS, sempre a valle di `box` |
| [k2-improvements](https://github.com/MzTechnology97/k2-improvements) | Riferimento storico K2 e bootstrap, non firmware CFS corrente |
| [k2-pro-custom-firmware](https://github.com/MzTechnology97/k2-pro-custom-firmware) | Mirror **archiviato dal 4 ottobre**, extras trasferiti a Kalico |
| [cartographer3d-plugin-k2openhost](https://github.com/MzTechnology97/cartographer3d-plugin-k2openhost) | Fork **archiviato** a favore del plugin Cartographer3D ufficiale |

## Evidenza prioritaria: loader G32 misurato sulla stampante

La [prova live del loader del 4 ottobre](https://github.com/MzTechnology97/k2-openhost-firmware-tools/blob/main/docs/LIVE_LOADER_IDENTITY.md) non si limita alla descrizione del firmware pubblico storico:
- una CFS con hardware `cfs0_050_G32`, APP 113 all'epoca, ha risposto `F0/03` con token **`0xE0`**;
- il [protocollo updater ricostruito](https://github.com/MzTechnology97/k2-openhost-firmware-tools/blob/main/docs/RS485_UPDATE_PROTOCOL.md) interpreta tale token come `-32` parole da 4 byte = **128 byte per richiesta**, al netto dell'ultimo chunk;
- il probe era **non-flash** ma *state-changing* (ingresso nel loader/restore): non va ripetuto durante una stampa;
- la CFG6 v3.25 è 178.968 byte, la CFG6 candidata 178.980 byte: **1.399 blocchi da 128 byte in entrambi i casi**, finali 24 vs 36 byte; prime quattro richieste ipotetiche identiche e primo byte differente a `0x20C` (CRC16);
- il token è stato osservato sul dispositivo **prima di passare ad APP153/CFG6**: è un precedente forte per il G32, non una cattura delle richieste durante il flash fallito del 24 ottobre. Quel log **non indica l'indice della richiesta senza ACK**.

Il protocollo distingue ACK, FAIL/NACK e **DONE**. La trasmissione dell'APP è completata *soltanto* quando la risposta porta lo stato a `update_end` (DONE); dopo un timeout di `app_data` la procedura segna `fail` e **non esegue `start_app`** sul device. Questo è coerente con il log del 24 ottobre e rende non necessaria l'ipotesi che l'APP nuova sia stata eseguita e abbia causato il timeout.

**Altra evidenza della stessa prova:** `F0/02` può rispondere ACK pur lasciando A2 in `mode=loader`. La transizione `0B/01` è stata verificata come fallback; chi valida un flash deve testare il *modo applicazione* con A2 e la risposta runtime, non fidarsi dell'ACK.

## Evidenze fisiche del progetto principale

- [K2-OpenHost #17](https://github.com/MzTechnology97/K2-OpenHost/pull/17) e [#20](https://github.com/MzTechnology97/K2-OpenHost/pull/20): due stampe PETG-CF di circa 30 h con CFG `0xD7` / v3.22 e cambi bobina automatici riusciti; nella seconda 370.724 richieste/risposte RS-485, un timeout periodico non critico sul motore Y, nessun errore CRC. **Non qualifica CFG6 v3.26**.
- [K2-OpenHost #22](https://github.com/MzTechnology97/K2-OpenHost/pull/22): prova del guasto OpenCFS del 17 ottobre da MSP `0x20010000` a fine SRAM, con fault del salto loader e blocco bus; fix OpenCFS `932a818`. **Non corrisponde alla CFG6 candidata**, che mantiene MSP `0x20006EE8` come la CFG6 precedente.
- [K2-OpenHost / SERIAL_LINK_LOSS](https://github.com/MzTechnology97/K2-OpenHost/blob/main/docs/it/SERIAL_LINK_LOSS.md): interruzione reale del bus CFS+motori di circa 30 s il 5 ottobre, con 2 errori CRC e autoripristino, senza byte persi nei bridge; ipotesi del coinvolgimento di hub USB/webcam **non dimostrata**. Precedente utile a investigare separatamente la robustezza del trasporto, non prova della causa del flash 24 ottobre.
- [firmware-tools #12](https://github.com/MzTechnology97/k2-openhost-firmware-tools/pull/12): preflight fail-closed su stati ignoti, heater, serial owner; [#13](https://github.com/MzTechnology97/k2-openhost-firmware-tools/pull/13): identità *loader, runtime, package* tenute separate.
- [mainsail-k2openhost](https://github.com/MzTechnology97/mainsail-k2openhost) e [ha-k2-openhost](https://github.com/MzTechnology97/ha-k2-openhost): percentuale mostrata deriva da `box` via Moonraker; la UI non può correggere il contatore MCU CFG6 bloccato.

## Incongruenze documentali con priorità

1. **Alta — indirizzo APP errato nei testi datati:** `k2-openhost-firmware-tools/docs/CFS_RECOVERY_ANALYSIS.md` e parte di `docs/SAFETY.md` riportano ancora `0x08010000` come indirizzo *fisico* dell'applicazione. La successiva prova fisica sul loader storico e [T113 Bootstrap #13](https://github.com/MzTechnology97/k2-openhost-t113-bootstrap/pull/13) stabiliscono `0x08003000`; `0x08010000` è il sistema di coordinate *nominale* di taluni builder, non un indirizzo da usare per calcolare le pagine flash.
2. **Alta — procedura di flash interrotto:** la [wiki K2-OpenHost (IT)](https://github.com/MzTechnology97/K2-OpenHost/blob/main/docs/it/reference/troubleshooting.md) raccomanda per "Flash interrotto" di rieseguire lo stesso comando. Dopo il caso CFG6 del 24 ottobre questa raccomandazione è **troppo generica**: occorre prima distinguere loader raggiungibile, log, stato di stampa e immagine di rollback verificata; non riprovare automaticamente una build sperimentale che ha appena fallito.
3. **Media — validazione RFID sovrastimata:** [versioni CFS](https://github.com/MzTechnology97/K2-OpenHost/blob/main/docs/it/cfs-firmware/versions.md) e [residuo](https://github.com/MzTechnology97/K2-OpenHost/blob/main/docs/it/cfs-firmware/remaining.md) descrivono il conteggio CFG6 come supportato. È una funzione prevista dal firmware ma **non ancora qualificata nella stampa reale**; il report della percentuale ferma al 35% è in [issue #59](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/59).
4. **Media — docs storiche/release:** [stable.json](https://github.com/MzTechnology97/K2-OpenHost/blob/main/releases/stable.json) è *deliberatamente* un pin di release con data 9 ottobre, non va equiparato allo stato dell'ultimo firmware CFG6. Le note `TEST_STATUS.md` (18 ottobre) richiedono un aggiornamento esplicito se si vuole riflettere l'incidente del 24 ottobre.
5. **Media — compatibilità:** il file [CFS_FIRMWARE_COMPATIBILITY.md](https://github.com/MzTechnology97/k2-cfs-rfid-tools/blob/main/docs/CFS_FIRMWARE_COMPATIBILITY.md) si ferma alla CFG4 pur esistendo la CFG6 dopo [PR #58](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/58). Aggiornare separatamente senza modificare retroattivamente i fatti storici.

## Conseguenze per la PR #60

- Il codice ARM del fix Type4 rimane oggetto di test **solo offline**.
- Il mancato ACK durante `app_data` del 24 ottobre non prova né un crash del firmware nuovo né un difetto del bus: il punto esatto/risposta mancano nei log.
- L'evidenza del **token 0xE0 misurato dal vivo** rafforza la geometria 128-byte già modellata in `test_transport_contract.py`; il binario non va ricostruito solo per questo.
- Le correzioni proposte alla documentazione delle **altre repo** sono indicate qui ma **non applicate**; anche il firmware attualmente operativo, Kalico, Helper e box.cfg restano intatti.
