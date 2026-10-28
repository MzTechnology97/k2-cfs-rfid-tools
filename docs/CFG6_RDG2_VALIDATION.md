# CFG6 RDG2 — validazione del 28 ottobre 2026

[README IT](../README.it.md) · [English README](../README.md) · [Compatibilità](CFS_FIRMWARE_COMPATIBILITY_IT.md) · [Host Kalico](../host/kalico/README.md)

**Funzionamento verificato sul caso reale del 28 ottobre 2026**, con Bambu PETG HF nello slot fisico 4 di una Creality K2 Pro CFS G32 / APP153. La validazione riguarda l'immagine esatta indicata sotto e distingue prove fisiche, prove offline e punti ancora aperti.

## Identità e provenienza

| Artefatto | Identità |
| --- | --- |
| Firmware attuale | `firmware/cfg6-rdg2/cfs0_050_G32-cfs0_000_153-K2OH-CFG6-RDG2.bin`, 179.976 byte |
| SHA firmware | `7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f` |
| Lettore host | `host/kalico/box_rfid_diag.py` |
| SHA lettore host | `2b9810456f6bb7ae0f2ebbf82cdf1f293dab84867a9db2799fb3035cb7aef867` |
| Identità CONFIG conservata | `K2OH / v323-cfg6`, API2, feature `0xE3` |
| RFID conservato | API7, capability `0xE8` |
| Base intermedia | v3.13, 177.700 byte, SHA `9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff` |
| Provenienza della base | Commit `0ad22669248cc845a3c8d22dd613500c4b95feb3`, percorso storico `firmware/v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin` |
| Blob Git della base | `73284cf77e2e522248784832b78d5e690977955b` |

La base v3.13 è già modificata: non è una ROM OEM originale. `scripts/prepare_base.py` la recupera dal commit congelato, ne verifica dimensione e SHA e la conserva fuori dai file versionati, in `work/base-pinned.bin`. Le vecchie immagini non sono necessarie nel ramo corrente; restano recuperabili dalla cronologia Git.

I nomi dei sorgenti correnti sono `handler.S`, `build.py`, `preflight.py` e `link.ld` sotto `firmware/cfg6-rdg2/`. La ricostruzione offline deve produrre lo stesso SHA firmware; il riordino del repository non introduce ulteriori modifiche al BIN.

## Prove fisiche

L'utente ha confermato la lettura RFID manuale. Un messaggio di ripristino dalla cache host, da solo, non dimostrerebbe una lettura RF: questa conferma è distinta dall'interpretazione dei log.

Nel corso della stampa reale sullo **slot fisico 4, indice locale 3**, gli snapshot hanno mostrato:

| Grandezza | Osservazione |
| --- | --- |
| Filamento | Bambu PETG HF, identità host `BAMBU:PETG HF` |
| Backend CFS | Legacy, flag hardware 0 |
| Runtime | Valido, type 4, mode 1 durante il conteggio |
| Consumo MCU, mm | **0 → 51 → 202 → 6.293 → 17.113** |
| Percentuale CFS | **39 → 38 → 34** |
| Verifica finale `CMD 0x03` | Payload `FFFFFF22`, slot 4 = **34** |
| Lunghezza totale proxy MCU | **330.000 mm** |
| Lunghezza del profilo host | **327 m** |
| Maschera durante copia RDG2 | `PRIMASK=1` |
| Contesto acquisito | `CONTROL=6`, `IPSR=0` |

Nel campione finale il runtime aveva percentuale iniziale 39 e consumo 17.113 mm: la formula intera stock produce 34. Kalico esponeva `rfid_reported_percent=34` e una stima da encoder di circa `33.8126`. La discesa non era quindi soltanto un aggiornamento della stima software host: anche il contatore MCU e la risposta CFS cambiavano.

La sessione osservata comprendeva **31.548 frame TX e 31.548 frame RX**. I contatori di timeout, CRC, lunghezza non valida, risposte non associate/scadute, errori di invio/lettura, disconnessione e perdita del link risultavano tutti a zero. È una misura di quella sessione, non una garanzia universale di affidabilità.

## Modifiche al conteggio e atomicità

Le modifiche affrontano tre percorsi riprodotti sul codice ARM:

- **Inizializzazione legacy type-4:** il gate per i soli dati API7 poteva lasciare visibile la percentuale geometrica di un record Creality valido senza inizializzare il runtime di consumo. Il nuovo percorso controlla backend, tipo, metadati, lunghezza e corrispondenza del record prima dell'inizializzazione in RAM.
- **Rilettura geometrica durante il conteggio:** conservare il runtime non bastava se il chiamante aveva già sovrascritto la tabella delle percentuali. Scrittura geometrica e decisione di inizializzazione/conservazione avvengono nella stessa sezione critica. Una rilettura rifiutata conserva il conteggio attivo.
- **Pulizia dopo unload:** il percorso stock imposta mode 2 e richiede una scadenza superiore a 30.000 tick. Il vecchio gate type-4 limitato a mode 1 poteva impedire la pulizia. Il percorso attuale mantiene la soglia stock e la pulizia RAM senza il prologo di logging nella sezione critica.

Le sezioni critiche salvano e ripristinano PRIMASK. I percorsi legacy di conteggio e inizializzazione operano in RAM; non introducono chiamate RF, logging, RTOS o EEPROM sotto la maschera. Il percorso hardware secure conserva il comportamento stock. La conferma fisica di `PRIMASK=1` riguarda lo snapshot RDG2; non misura direttamente ogni esecuzione delle altre sezioni critiche.

## RDG2 e interpretazione del residuo

`BOX_CFS_DIAG2 ADDRESS=1 SLOT=3` usa la sessione condivisa di `serial_485` e invia una sola richiesta. `SLOT` è l'indice **locale 0–3**. Il comando legge lo stato esistente e non avvia letture RF, movimenti o inizializzazione del conteggio.

Il payload `RDG2` contiene 64 byte, con versione 2 al byte 63. Comprende runtime, contatore usato/totale, percentuale iniziale e tabella, odometro già in cache, stato del manager RF, marker stock, tick e registri di contesto. La copia avviene con gli interrupt configurabili mascherati; la risposta viene inviata dopo il ripristino della maschera precedente.

Il campo K2RL è un booleano, senza dump delle chiavi. Il lettore verifica formato, dimensione, versione e slot, registra `received_at_unix` al successo e azzera lo snapshot precedente se il comando fallisce. La consultazione dello stato host non provoca richieste aggiuntive.

Restano distinti tre casi del getter stock:

| Condizione | Esito possibile di `CMD 0x03` |
| --- | --- |
| Manager RF non idle e selezionato sullo stesso slot | `0xFF` prima del wrapper di validità, anche con runtime valido |
| Validità stock/runtime non soddisfatta | `0xFF` nel percorso di validazione |
| Runtime proxy valido, marker richiesto dal getter stock assente | Zero, nonostante il wrapper accetti il runtime |

Questi percorsi sono stati riprodotti offline. Il BIN attuale non corregge né aggira il getter stock. Il byte di slot attivo del conteggio non è da solo una prova di attività del worker RF. Gli indizi del decoder descrivono lo snapshot acquisito, non un contatore di esecuzioni; una richiesta successiva può osservare uno stato diverso.

## Regressioni offline da conservare

Le verifiche pertinenti alla build attuale comprendono:

- ricostruzione con SHA della base e dell'immagine, 33 hook, CRC/lunghezza, vettori, mappa e limiti dell'immagine;
- configurazione CFG6, ABI dei wrapper e conservazione di registri, flag, stack e maschera;
- consumo type-4 attraverso odometro e getter reali, inizializzazione nativa/API7, conservazione su rescan, input rifiutati e pulizia mode 2;
- confronto aritmetico con il codice stock e interleaving modellati delle transazioni;
- snapshot RDG2: otto casi, sette frame richiesta non validi e 157 punti di interleaving modellati; massimo osservato di 95 istruzioni sotto maschera e 96 byte di stack nel percorso snapshot;
- lettore host: una richiesta valida, otto casi di errore, singola sessione condivisa e nessun trasporto fisico nei test;
- sei casi del getter `CMD 0x03`, inclusi `0xFF`, marker assente e clamp stock.

I conteggi storici di test attestano le prove effettuate sul candidato. Dopo il riordino, il runner corrente è `python3 tests/run_offline.py`; il suo esito e lo SHA ricostruito sono il riferimento per una nuova esecuzione.

## Limiti e verifiche ancora aperte

**Da verificare su hardware:** unload seguito da rilettura e riavvio del conteggio; rescan completo durante una stampa; tag Creality nativi e altri formati/API7/backend; comportamento su altri slot e combinazioni di carico. Le prove offline su questi rami non sostituiscono la validazione fisica.

PRIMASK esclude gli interrupt configurabili, non NMI, fault o DMA. L'emulazione modella writer e interleaving selezionati; non dimostra tutti gli stati RTOS o accessi asincroni. Il conteggio di istruzioni non misura la latenza massima reale e non dimostra il rispetto di ogni scadenza del sistema.

Il proxy di 330 m non è una misura della lunghezza reale della bobina. La geometria e la percentuale intera sono stime; il profilo host da 327 m e la stima continua Kalico possono divergere. Gli snapshot e i contatori di comunicazione hanno il perimetro temporale indicato e non qualificano universalmente il firmware.

## English summary

The exact 179,976-byte image, SHA-256 `7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f`, was verified on 28 October 2026 with Bambu PETG HF in physical slot 4 on a K2 Pro CFS G32 / APP153. The operator confirmed the manual RF read. MCU consumption advanced from 0 to 17,113 mm and the actual CFS percentage moved from 39 to 34. The final normal remaining reply was `FFFFFF22`. The observed link session had 31,548 TX/RX frames and zero recorded errors.

RDG2 physically reported PRIMASK 1 during its copy, CONTROL 6 and IPSR 0. This supports the snapshot mask behavior in that context; it does not establish worst-case latency or exclude NMI, faults or DMA. The CFS proxy total is 330 m, while the Kalico profile uses 327 m.

Unload/reread, full rescan while printing, other formats/backends/slots and worst-case timing remain hardware qualification work. Stock getter filters that can return FF or zero are preserved. Historical firmware/tests are removed from the active branch but remain available in the [frozen Git history](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). No history rewrite is required.
