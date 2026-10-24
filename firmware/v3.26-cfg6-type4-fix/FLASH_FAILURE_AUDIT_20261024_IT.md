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

## Analisi statica dell'updater Creality originale

L'eseguibile originale T113 `/usr/bin/mcu_util_485` (ELF32 ARM EABI, 38.444 byte, solo analizzato localmente, non distribuito) contiene:

- `0x0001521c..0x0001522c`: lettura di un massimo di **255 byte** dal file firmware (`__read_chk`);
- `0x00015244..0x00015260`: invio dati con timeout di **500 ms**, usando la routine interna del protocollo;
- `0x000152cc`: riferimento al messaggio di errore `send fw data to slave`;
- tre retry prima dell'abbandono, come nei log.

Il valore **240** osservato in alcuni registri è un parametro della routine di invio/ricezione, **non** la granularità di lettura dal file. I payload da 255 byte sono quindi il riferimento documentabile per il confronto offline. Le differenze tra dimensioni 16/32 byte erano ipotesi prima di analizzare l'ELF.

## Confronto esatto delle due immagini

| Parametro | CFG6 v3.25 installata e funzionante | Fix type 4 della PR #60 |
|---|---|---|
| SHA256 | `6579eb55…0acc6cc6` | `7b45e515…88dbaceb` |
| Dimensione | 178.968 byte | 178.980 byte |
| Pacchetti dati da massimo 255 byte | **702** | **702** |
| Ultimo pacchetto | 213 byte | 225 byte |
| CRC16 Creality | `0x571e`, verificato | `0x2f88`, verificato |
| Length nel contenitore | Uguale al file | Uguale al file |
| Identificativo applicazione | `cfs0_000_153` | `cfs0_000_153` |
| Fine applicazione | `0x0803BB17` | `0x0803BB23` |

I **primi due payload da 255 byte sono identici**. Il primo byte differente è l'offset `0x20C` (CRC16) nel terzo pacchetto. In totale 31 pacchetti hanno contenuti differenti, senza cambiare il numero di pacchetti.

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
