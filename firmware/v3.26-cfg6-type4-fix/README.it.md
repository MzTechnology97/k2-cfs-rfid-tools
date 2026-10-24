# CFG6 — correzione sperimentale della reinizializzazione RFID type 4

**Solo laboratorio. NON flashare durante la stampa, non qualificato su hardware.** Questo ramo modifica unicamente il firmware CFS, non Kalico e non box.cfg.

## Difetto riprodotto sul codice ARM originale

Quando la CFG6 rileva nuovamente un tag RFID type 4 mentre quel medesimo slot è in stato stampa, la funzione remaining_init_wrapper reinizializza il runtime: filamento usato da 8200 a 0 mm, checkpoint odometro da 497500 a 0, modalità stampa da 1 a 0 e percentuale riportata dal 33% al 35%.

Questo difetto è dimostrato in emulazione ARM usando il BIN originale. È un possibile motivo della percentuale che rimane fissa durante il lavoro, ma la presenza di effettive reinizializzazioni durante la stampa osservata NON è ancora dimostrata. Issue: https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/59.

## Correzione proposta

Per un runtime type 4 già valido e in modalità stampa, una nuova inizializzazione RFID restituisce successo senza modificare filamento consumato, odometro, modalità o percentuale. La normale reinizializzazione a stampante inattiva resta possibile e gli altri tipi di tag seguono il codice stock.

L'identità API2 rimane K2OH / v323-cfg6 / feature 0xE3: è compatibile con l'extra Kalico CFG6 corrente, che non richiede modifiche. La versione corretta si distingue dalla precedente per il nome del file e SHA-256.

**Non invertire nuovamente l'odometro:** la funzione stock a 0x0801B730 contiene già l'istruzione vneg.f32. I test eseguono questa istruzione originale e dimostrano che una lettura raw negativa viene presentata come progressione positiva.

## Test automatici offline

- Il BIN CFG6 originale è stato riprodotto byte per byte, stesso SHA-256.
- Riproduzione del reset dello stato in corso di stampa e verifica del suo blocco sui quattro slot.
- Reinizializzazione a stampante inattiva ancora operativa.
- Test completi stock per type 4: gate, avvio/fine stampa, percentuale, getter.
- Test dei 15 hook CFG6 e dei vecchi hook CFG5 con ABI, confronti dei registri.
- Test dedicato alla reale inversione di segno stock dell'odometro.

## BIN sperimentale (NON PER FLASH)

File: CFG6-TYPE4-RESCAN-FIX-NOT-FOR-FLASH.bin

SHA-256: 7b45e5152fdd124a50fd29877a1a9ed595769107ba9fc009b2ba7d7388dbaceb

**Cronologia aggiornata (25/10):** il BIN è stato rimosso dal manifest locale dopo il trasferimento fallito del 24/10 e **reinserito sul CM5 il 25/10 su esplicita richiesta dell'utente** per un'eventuale seconda prova manuale. La voce è la **n. 4** dell'Helper locale, **non** del manifest pubblico. La precedente CFG6 v3.25 resta funzionante e disponibile per il rollback. Non è stato effettuato un secondo flash durante il ripristino della voce. **Il re-staging non equivale a qualificazione hardware:** la causa del timeout sul bus RS-485 non è stata identificata. Usare esclusivamente Helper con stampante ferma e riscaldatori spenti; non aggirare controlli di sicurezza, mantenere il rollback verificato e non continuare con tentativi ripetuti se il trasferimento fallisce. Nessuna modifica a Kalico o `box.cfg`.

[Incidente 24/10](FLASH_INCIDENT_20261024.md) · [audit RS-485](FLASH_FAILURE_AUDIT_20261024_IT.md) · [PR #60 chiusa senza merge](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/60).

Importante: il comando diagnostico Kalico BOX_RFID_DIAG_REMAIN_STATE è per API7 e non può interrogare il runtime interno di CFG6/API2. Nessun comando è stato inviato alla CFS durante lo sviluppo.

[English](README.md) · [Test di regressione](test_type4_rescan_preserves_print.py)
