# CFG6 — ricognizione PR chiuse, lavoro precedente e documentazione (25 ottobre 2026)

**Scopo:** analisi documentale e offline. Nessun comando alla CFS, niente flash, reboot, GPIO, movimento, scritture Kalico o box.cfg. Sul CM5, alle 00:01 del 25 ottobre, Klipper risultava `ready`, con stampa in corso `PRINT` e identità CFS `K2OH v323-cfg6` (non sufficiente per distinguere fra BIN con medesima identità).

## 1. Status PR: *closed* non equivale a *merged*

| Repository | PR | Esito | Cosa è effettivamente disponibile |
| --- | --- | --- | --- |
| [k2-cfs-rfid-tools](https://github.com/MzTechnology97/k2-cfs-rfid-tools) | [#56](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/56) | **merged** | Confluenza di v3.20–v3.22 in main con precedenti audit RS-485, CPU e RAM; attesta stampa reale v3.22, non qualifica CFG6 |
| idem | [#57](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/57) | **merged** | CFG4 con identità K2OH, CONFIG v2 e guida compatibilità |
| idem | [#58](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/58) | **merged** | CFG6 v3.25, 15 hook avanzati aggiuntivi; 23 parametri effetto scrivibili; stessi limiti di qualifica hardware |
| idem | [#34](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/34), [#43](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/43), [#51](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/51), [#54](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/54) | **closed, non merged** | Studi e report; usare commit/doc come evidenza storica, non dichiarare queste PR integrate |
| [OpenCFS-Firmware](https://github.com/MzTechnology97/OpenCFS-Firmware) | [#5](https://github.com/MzTechnology97/OpenCFS-Firmware/pull/5), [#6](https://github.com/MzTechnology97/OpenCFS-Firmware/pull/6), [#7](https://github.com/MzTechnology97/OpenCFS-Firmware/pull/7) | **merged** | Specifica loader e app, correzione Type7 secure element, laboratorio immagine OpenCFS; prodotto distinto dalla CFG6 patched-stock |
| [T113 Bootstrap](https://github.com/MzTechnology97/k2-openhost-t113-bootstrap) | [#7](https://github.com/MzTechnology97/k2-openhost-t113-bootstrap/pull/7), [#9](https://github.com/MzTechnology97/k2-openhost-t113-bootstrap/pull/9), [#11](https://github.com/MzTechnology97/k2-openhost-t113-bootstrap/pull/11), [#13](https://github.com/MzTechnology97/k2-openhost-t113-bootstrap/pull/13) | **merged** | Staging custom CFS stesso numero versione, fix nome file + boot automatico, validazione fail-closed CRC/lunghezza/reset, base APP fisica 0x08003000 |
| idem | [#10](https://github.com/MzTechnology97/k2-openhost-t113-bootstrap/pull/10) | **closed, non merged** | Prima iterazione della validazione, sostituita dalla #11 |
| [Installer Helper](https://github.com/MzTechnology97/k2-openhost-installer-helper) | [#10](https://github.com/MzTechnology97/k2-openhost-installer-helper/pull/10), [#11](https://github.com/MzTechnology97/k2-openhost-installer-helper/pull/11), [#13](https://github.com/MzTechnology97/k2-openhost-installer-helper/pull/13), [#14](https://github.com/MzTechnology97/k2-openhost-installer-helper/pull/14) | **merged** | Percorso custom CFS con hash SHA256, menu sperimentale, registrazione e ritiro v2.1, nuova v2.2 corretta |

## 2. Incidenti precedenti realmente spiegati

**6 ottobre — CFS v2.1, `START_APP NACK`.** La #9 del T113 documentò che lo staging usava un filename `<boot>-<sha256>.bin`, generando una falsa versione *nei log*. La documentazione **successiva** della specifica OpenCFS chiarisce che **questa stringa NON viene trasmessa al loader**. La causa sostanziale di START_APP NACK fu un BIN con CRC16 e lunghezza dichiarata **obsoleti**, corretta dalle #11 T113 e #14 Helper. È un precedente confermato **diverso** dalla CFG6 v3.26, che ha CRC/lunghezza validi e fallisce **in fase send fw data**, senza arrivare a start-app.

**17 ottobre — immagini OpenCFS con MSP troppo alto.** Il documento `OpenCFS-Firmware/docs/spec/08-loader-and-recovery.md` riferisce che il loader stock, trasferendo MSP dall'APP, esegue ancora un pop della propria cornice, leggendo `MSP+0x0C`. Un OpenCFS con MSP esattamente `0x20010000` accede quindi a SRAM fuori range; il loader va in fault e PA2 può bloccare il bus. **La CFG6 originale e modificata hanno MSP identico `0x20006EE8`**, quindi quella causa specifica *non* si applica al candidato CFG6.

## 3. Riscontro: effettivo contratto T113 per APP e trasferimento

Documenti originali: [OpenCFS loader](https://github.com/MzTechnology97/OpenCFS-Firmware/blob/main/docs/spec/08-loader-and-recovery.md) e [T113 bootstrap #13](https://github.com/MzTechnology97/k2-openhost-t113-bootstrap/pull/13).

- Origine fisica APP **`0x08003000`**, pagina parametri `0x0807F800`. Il builder CFG6 usa **`0x08010000` solo nominalmente** per gli offset salvati; non correggerlo per sostituzione globale senza relinking.
- Il bootloader archiviato ritorna da `F0/03` il token **`0xE0`** (transfer token). L'updater T113 ARM Linux legge il token come `signed -32` e domanda `(-value)*4` → **128 byte** per richiesta. Il valore 255 in `__read_chk` è **la capacità del buffer**, non la dimensione di trasferimento.
- Questo token e la geometria da 128 byte sono autenticati contro **il loader storico**; il CFS operativo non è stato sottoposto a dump del loader. Se il bootloader installato con lo stesso ID risponde ugualmente, entrambe le immagini comportano **1399** richieste (ultima **24** vs **36** byte). La prima differenza fra BIN è al byte `0x20C` → **quinta richiesta**; i primi **512 byte** coincidono.
- La CFG6 v3.25 aveva 178968 byte, la CFG6 con fix 178980; entrambe terminano fisicamente nella stessa pagina Flash da 2 KiB: `0x0802EB17` e `0x0802EB23`. Restano sotto `0x0807F800` e preservano vettori, CRC e lunghezza validi.
- Il loader archiviato programma in RAM buffer da 256 B e cancella pagine Flash 2 KiB. Il loader storico F0/01 riceve 4 byte di lunghezza e invia risposte ACK per ciascun blocco. La stampa/contabilizzazione RFID dell'APP non deve essere chiamata durante queste fasi.
- **Il log del fallimento CFG6 alle 10:30 del 24 ottobre non include né il byte token/ACK né l'indice del blocco fallito**: non attribuire il guasto a quinto/ultimo pacchetto, a confine di pagina o a codice Type4 eseguito.

## 4. Ricerca type 4 precedente: cosa resta valido

Le PR chiuse ma non integrate della serie v3.23 e le documentazioni `CFS_V323_OEM_USAGE_TASK_RACE_REGRESSION_20261016.md`, `CFS_V323_LEGACY_TYPE4_LIVE_CONSUMPTION_20261016.md` forniscono emulatori ARM del task stock, prove di contatore e verifiche di race su FM15L013, modalità e record. Sono materiale d'analisi riutilizzabile ma *non* certificano la CFG6 in produzione.

La PR corrente [#60](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/60) rimane **draft**, con bug ARM di reinizializzazione Type4 riproducibile e fix software provato in laboratorio. **Non è ancora dimostrato che i reread siano la causa reale del 35% fermo né che il BIN sia in grado di completare il flash con questo setup.**

## 5. Documentazione non aggiornata e confini

- `docs/CFS_FIRMWARE_COMPATIBILITY.md` su main si ferma ancora alla **CFG4**, pur essendo già stato fatto merge della CFG6 #58. È una lacuna documentale da aggiornare in una successiva modifica autorizzata, indicando CFG5T/CFG6 API2, 23 ID writeable, identity e limiti del firmware; NON sostituire le guide CFG4 storiche in modo inconsapevole.
- `docs/CFS_V323_RELEASE_READINESS_20261012.md` è un rapporto *datato 12 ottobre*: conserva valore come fotografia dei gate iniziali, non come stato aggiornato della CFG6 installata.
- Il manifest/helper del CM5 presenta modifiche locali non committate, compresa l'opzione CFG6 Type4 sperimentale: non eseguire reset/fetch + merge automatico né sovrascrivere il manifesto. Al momento dell'audit la stampante era in stampa.
- **Non cambiare Kalico:** il commit locale ne conferma il merge della PR #90, ma questo audit non ne ha modificato file o configurazioni.

## 6. Prove eseguite e prossimo test NON distruttivo

`firmware/v3.26-cfg6-type4-fix/test_all_offline.py`: riproduzione bit-identica BIN e **10/10 suite offline PASS**, inclusa `test_transport_contract.py` che verifica l'ipotesi del token storico `E0` → 128 B, CRC, reset, dimensioni e doppia origine nominale/fisica. Hash BIN invariato `7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb`.

La **causa del `send fw data failed` rimane sconosciuta**, perché la traccia storico-host non registra progressione per trasferimento e ACK. Per test futuri distinguere protocollo loader installato vs archiviato e prevedere logging per ciascuna risposta, *senza inviare comandi al CFS durante la stampa*. Sconsigliato riflashare il candidato attuale sulla sola base di questi test.
