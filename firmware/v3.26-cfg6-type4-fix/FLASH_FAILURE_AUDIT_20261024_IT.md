# Analisi del flash CFG6 fallito — 24 ottobre 2026

**Ambito:** esclusivamente firmware CFS e updater Creality T113, analisi offline/in sola lettura. **Non sono stati eseguiti flash, movimenti o modifiche a Kalico e box.cfg.** La CFS è stata recuperata con la precedente CFG6 v3.25 dall'utente.

## Risultati hardware documentati

| Evento T113 del 24 ottobre | Esito |
|---|---|
| 10:30:19.519 — `state: erase_flash, get ACK` | Bootloader slave CFS 01 raggiungibile |
| 10:30:24.575 — `send fw data to slave [01] failed, 0` | Nessun ACK riconosciuto |
| 10:30:25.075 e 10:30:25.576 — retry 1/2 | Tre tentativi falliti |
| 10:30:25.576 — `update fw bin fail!` | Trasferimento firmware incompleto |
| 10:30:26–28 — startup motori 85/86 fallito | Anomalia RS-485 non limitata al solo startup CFS |
| 10:39:05 — rollback CFG6 v3.25, `addr [01] ... update: ok` | Ripristino riuscito, ~14 secondi |

**Limite dei log:** il firmware updater non stampa l'indice dell'ultimo blocco accettato, né il numero di byte trasferiti prima del timeout. Non è possibile attribuire il fallimento a un blocco specifico, né dimostrare che l'applicazione modificata sia stata eseguita o abbia causato un crash.

## Analisi statica dell'updater Creality originale — correzione del 24 ottobre

L'eseguibile originale T113 `/usr/bin/mcu_util_485` (ELF32 ARM EABI, 38.444 byte, analizzato localmente senza distribuirlo) **non usa blocchi di dimensione fissa da 255 byte**. La seconda analisi del flusso ARM ha permesso di identificare la vera richiesta di lettura:

- `0x00012278..0x0001227C`: salva nel campo `+40` della struttura del device il byte 9 di una risposta ricevuta;
- `0x00015208`: legge tale byte come valore **signed**, da cui dipende la quantità richiesta;
- `0x000154FC..0x00015508`: per valori negativi calcola `requested_bytes = (-signed_value) * 4` tramite aritmetica modulo 256;
- `0x0001521C..0x0001522C`: chiama `__read_chk(fd, buffer, requested_bytes, 255)`. Il quarto argomento **255 indica soltanto la capacità del buffer**, non il numero di byte da leggere;
- `0x00015244..0x00015260`: invio attraverso la routine protocollo, timeout **500 ms** e fino a tre tentativi, come visibile nel log;
- `0x000152CC`: riferimento al messaggio di errore `send fw data to slave`.

Per i valori ricevuti da -1 a -63 si ottengono **4–252 byte**, sempre multipli di quattro. **La lunghezza delle richieste è determinata dalle risposte del dispositivo, non soltanto dalla dimensione dell'immagine.** Il log storico non riporta tali byte di risposta né l'indice del blocco fallito; perciò il numero effettivo dei blocchi trasferiti non è ricostruibile.

La precedente interpretazione della capacità buffer 255 come dimensione fissa del payload, e il conseguente totale **702 blocchi**, erano **errati**: questa sezione li sostituisce esplicitamente.

## Confronto esatto delle due immagini

| Parametro | CFG6 v3.25 funzionante | Fix type 4 PR #60 |
|---|---|---|
| SHA256 | `6579eb55…0acc6cc6` | `7b45e515…88dbaceb` |
| Dimensione | 178.968 byte | 178.980 byte |
| Allineamento su parole a 4 byte | **Valido** | **Valido** |
| Numero reale di trasferimenti | **Non noto** | **Non noto** |
| CRC16 Creality | `0x571e`, valido | `0x2f88`, valido |
| Lunghezza dichiarata nel contenitore | Uguale al file | Uguale al file |
| Identificativo applicazione | `cfs0_000_153` | `cfs0_000_153` |
| Ultimo byte applicazione (indirizzo fisico) | `0x0802EB17` | `0x0802EB23` |

I due file sono identici nei primi **524 byte**. Il primo byte differente è a offset `0x20C`, nel CRC16. Se, *ipoteticamente*, il bootloader richiedesse sempre il massimo di 252 byte, entrambi richiederebbero 711 gruppi; ma questa **non è un'osservazione del trasferimento reale**. Per richieste piccole il numero di segmenti può variare. La differenza nel numero di parole a quattro byte è di tre.

### Chiarimento da audit precedenti degli altri agenti: APP fisica vs origine nominale

La ricerca del 15–16 ottobre sul loader Creality ha verificato il **vero APP_BASE fisico `0x08003000`** nel bootloader storico e nei controlli dell'updater T113; il builder CFG6 usa invece l'origine nominale `0x08010000` per gli offset dei simboli/callsite. Il delta è **`0xD000`**. **Non modificare direttamente l'origine del builder:** tutte le patch e i branch sono codificati relativamente a quel layout nominale, e cambiarla senza rilinkare integralmente romperebbe l'immagine.

Per entrambi i BIN, l'indirizzo fisico dell'ultimo byte è rispettivamente `0x0802EB17` e `0x0802EB23`, entro la **stessa pagina da 2 KiB**. Il precedente elenco con `0x0803BB17`/`0x0803BB23` rappresentava l'origine nominale, non il vero indirizzo fisico di flash. La validazione statica `test_transport_contract.py` ora applica il controllo del reset vector/limite fisico contro `0x08003000` e non contro `0x08010000`.

Fonti interne rilevanti: `docs/CFS_2025_PUBLIC_FULL_FLASH_LOADER_APP_SPLIT_20261015.md`, `docs/CFS_2025_PUBLIC_LOADER_UPDATE_FMC_AND_RECOVERY_20261015.md` dal ramo `docs/cfs-v323-stock-loader-recovery-20261016`, e `k2-openhost-t113-bootstrap/tests/test_k2oh_mcu_fw.py` già integrato nel ramo principale. I primi due audit sono basati su un dump pubblico storico: non certificano che il bootloader installato sia byte-identico.

Entrambe le immagini superano CRC16, integrità SHA256, length, identità applicazione, vettori Cortex-M e limite flash precedente alla pagina parametri. Questo elimina gli errori statici più immediati, **non** dimostra che il bootloader accetti ogni payload.

## Risultato tecnico e prossima evidenza necessaria

**Causa esatta non ancora identificata.** L'immagine modificata non risulta sovradimensionata, e il frammento ARM type 4 viene eseguito solo all'interno dell'applicazione: non può essere chiamato dal bootloader durante l'invio firmware. L'errore osservato è invece un mancato ACK sul canale di aggiornamento. Il fatto che siano falliti anche messaggi di startup a motori 85/86 è compatibile con un problema di ricezione/serializzazione RS-485, ma non lo dimostra.

Per discriminare un errore di trasporto da un rifiuto di uno specifico contenuto, un **eventuale** test hardware futuro, autorizzato separatamente, richiederebbe prima la registrazione dell'indice del blocco, del codice di risposta e degli ACK nel processo updater, senza alterare il protocollo né il firmware attivo. **Non ritentare il flash sperimentale sulla sola base dei test attuali.**

### Test riproducibili

```bash
python3 firmware/v3.26-cfg6-type4-fix/test_all_offline.py
```

Il runner ricompila l'immagine a partire dal BIN base verificato, controlla lo SHA, esegue 10 suite (incluso `test_transport_contract.py`) e rimuove gli artefatti temporanei di build creati. Eseguito e superato il 24 ottobre 2026 sul CM5.

[PR #60](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/60) · [Issue #59](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/59)
