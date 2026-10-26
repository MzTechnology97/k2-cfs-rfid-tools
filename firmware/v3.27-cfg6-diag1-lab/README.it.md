# CFG6 DIAG1 — diagnostica RAM type 4 (solo laboratorio)

**NON FLASHARE AUTOMATICAMENTE. Variante non presente nel manifest Helper.**

Questo esperimento deriva dal firmware CFG6 v3.26. Mantiene invariati i 32 hook operativi, l'identità K2OH `v323-cfg6` e le feature `0xE3` per compatibilità con Kalico. Aggiunge soltanto la lettura di un'istantanea di 32 byte tramite RS-485: non richiama motori, RFID, odometro stock, scritture EEPROM o modifiche alla RAM globale. Nessuna modifica a Kalico, box.cfg, Helper o stampante.

## Motivazione

La CFG6 v3.26 ha gestito il cambio automatico reale, ma `rfid_reported_percent` dello slot attivo è rimasto al 60% mentre Kalico, mediante encoder, è sceso sotto il 58%. Le emulazioni mostrano che il firmware può calcolare 58% soltanto quando il runtime è valido, type 4, in mode PRINT (1), lo slot è attivo e il delta dell'odometro è positivo. Manca la verifica dei corrispondenti campi sulla MCU reale.

## Protocollo sperimentale

- Comando RS-485: `0x57`; sottocomando `0x15`.
- Richiesta: payload `[0x15, slot]`, lunghezza frame `5`; slot fisico interno `0..3`.
- Errore: status `1` per lunghezza diversa da 5 oppure slot non valido.
- Risposta: status `0`, payload fisso di **32 byte** little-endian; signature `RDG1`.

| Offset | Tipo | Dato |
|---|---|---|
| 0 | ASCII[4] | RDG1 |
| 4 | u8 | Slot MCU richiesto (0–3) |
| 5 | u8 | Slot attivo stock (RAM 0x200001F2) |
| 6 | u8 | Stato box stock (RAM 0x200037D2) |
| 7 | u8 | Flag secure-element stock |
| 8 | u8 | runtime.valid (offset +23) |
| 9 | u8 | runtime.type (+99) |
| 10 | u8 | runtime.mode (+22) |
| 11 | u8 | runtime.latch (+21) |
| 12 | u32 LE | used_mm (+0) |
| 16 | u32 LE | total_mm (+4) |
| 20 | f32 LE | last_odom normalizzato (+12) |
| 24 | f32 LE | odometro grezzo cached (RAM 0x200001AC) |
| 28 | u8 | percentuale geometrica iniziale (+20) |
| 29 | u8 | percentuale CFS tabella (0x20003974+slot) |
| 30 | u8 | marker di validità getter (0x2000391E+slot) |
| 31 | u8 | stato runtime (+40) |

Il valore cached raw **non ha scala e segno comparabili** con il checkpoint normalizzato: non sottrarli direttamente. Il decoder offline applica la conversione dello stock (`normalized = -raw * 0.0007886413368396461`, coefficiente ARM a `0x080188B8`) e presenta `odometer_normalized_current_approx_mm` e `odometer_delta_since_checkpoint_approx_mm` come **stime non atomiche**. La snapshot non è atomica rispetto all'RTOS. Il byte percentuale è quello della tabella firmware, non la stima interpolata di Kalico. Le condizioni del gate visibili nella risposta **non dimostrano che il task venga eseguito**; DIAG1 non aggiunge contatori di esecuzione per non alterare il runtime.

## Build e test offline

Dalla directory del modulo:

```sh
python3 test_all_diag1_offline.py
```

Il test ricompila l'immagine e ne confronta i byte con il BIN di riferimento, testa il parser, i quattro slot, rifiuto input errati, ABI, memoria scritta solo sullo stack e regressioni type 4/CFG6.

Decoder **solo offline**, nessuna connessione alla CFS:

```sh
python3 decode_diag1.py <payload_hex_32_byte>
```

Immagine di laboratorio: `CFG6-READONLY-DIAG1-NOT-FOR-FLASH.bin`

SHA-256: `6f07d792ad5fc6f402167a2aa1fe9c7b67df93dc558ac685176767a23b23a520`

### Diagnosi futura (solo dopo autorizzazione separata per il flash)

- Se `mode != 1`, indagare transizione stock `0x0801A8AC` e tracking.
- Se `mode = 1` ma `used_mm` resta fermo, indagare il gate `0x08013684` e l'odometro `0x0801B730`.
- Se `used_mm` cresce ma percentuale firmware resta fissa, indagare il setter `0x080123E4` e i suoi guard.
- La lettura in tempo reale della risposta DIAG1 richiederebbe un decoder host isolato/autorizzato, **non** installato in Kalico.

La variante non è qualificata su hardware, la sicurezza MCU e il bootloader reale non sono certificati dai test offline. Non eseguire test su una stampa in corso senza previa pianificazione di sicurezza.
