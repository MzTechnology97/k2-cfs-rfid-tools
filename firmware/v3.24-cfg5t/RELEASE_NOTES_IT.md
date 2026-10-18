# CFS CFG5 — Stato sperimentale (IT)

Non flashare ancora: le due immagini NON sono qualificate su hardware e NON
sono presenti nel menu dell'Helper. La CFS reale resta alla v3.23 CFG4.

## Variante CFG5: ID20 e ID22 modificabili

Percorso: separate CFG5 laboratory image
SHA256: c62d233355b8e7134687000ae63ffba5f62246fa374012933e5e740ca2812d01
Identità 0x7A: K2OH v323-cfg5; API v2, feature 0xE7.

- ID20 feed_total_timeout_ms, stock 25000 ms; 5000..60000, multipli di 20 ms.
  Callsite 0x08032C72, converte il valore in tick stock da 20 ms.
- ID22 odometer_stall_timeout_ms, stock 500 ms; 100..2000, multipli di 20 ms.
  Callsite 0x08032CEC, sostituisce adds r5,#1 / cmp r5,#25 mantenendo
  esattamente i flag della CPU con il default stock.
- Test superati: protocollo GET/SET/RESET, limiti, wrapper ABI, confronto
  dei flag stock e contenitore T113.

## Variante CFG5 Type4: gate consumo sperimentale

Percorso: cfs0_050_G32-cfs0_000_153-runtime-config-v3_24-K2OH-CFG5T-TYPE4-EXPERIMENTAL.bin
SHA256: 78c83416afaa4795de8a018533aea884f4def396f4829cc98c77fcce48155a55
Identità distinta: K2OH v323-cfg5t, feature 0xE5.

Include ID20/22, più una patch del SOLO gate del task del residuo
stock a 0x08013684: se manca FM15L013, consente il passaggio del task
solo quando lo slot attivo ha un runtime type 4 valido, è in modalità
stampa (modo 1) e contiene dati coerenti. Il type 7 senza chip rimane
escluso. Con chip presente, il percorso originale resta invariato.

La funzione stock di inizio stampa 0x0801A8AC può impostare modo 1;
il task stock dispone della logica di conteggio da odometro.

Sono passati 12 controlli Unicorn del gate: questi NON eseguono il task
completo e NON dimostrano che CMD 0x03 diminuisca durante una stampa.
Sono ancora indispensabili verifiche del consumo reale, multi-slot,
errori e modalità print/unload.

## Kalico
La controparte sperimentale è nella worktree:
~/cfs-v323-build/kalico-cfg5-lab/klippy/extras/box_cfs_runtime.py
Accetta entrambe le identità LAB, permette la scrittura dei soli
ID 1,2,3,5,7,8,20,22, e rifiuta valori ID20/22 non multipli di 20 ms.
Nessun extra attivo o CFG della stampante è stato modificato.

La v3.23 CFG4 installata, l'Helper e la v3.22 di recupero restano intatti.
