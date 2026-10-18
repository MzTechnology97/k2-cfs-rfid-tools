# CFG5T — Verifica sperimentale (italiano)

**Non qualificato su hardware reale.** Il firmware non è una release per produzione. Il BIN è destinato alla prima prova controllata sulla CFS G32/APP153.

## Novità rispetto alla CFG4

- ID 20: timeout totale feed, 25.000 ms stock, da 5.000 a 60.000 ms in multipli di 20 ms.
- ID 22: timeout stallo odometro, 500 ms stock, da 100 a 2.000 ms in multipli di 20 ms.
- Residuo type 4: il task stock di contabilizzazione viene raggiunto anche senza FM15L013 soltanto per lo slot attivo type 4, dati validi e modalità stampa. Il type 7 continua a richiedere la logica originale.
- Identificazione univoca: opcode 0x7A, K2OH, revisione v323-cfg5t, feature 0xE5.

## Verifiche concluse

L'immagine si ricompila byte per byte con lo stesso SHA256. I controlli preflight, contenitore T113, protocolli SET/GET/RESET, registri e flag CPU di ID 20/22 sono passati. Unicorn ha eseguito la logica ARM stock con odometro simulato: inizio e fine stampa, aggiornamento dei millimetri, setter della percentuale e getter usato da CMD 0x03. Sono stati provati quattro slot, esclusione del type 7 senza chip, divieto di doppio conteggio e minimo dell'1%. Una bobina dal 42% è passata al 41% dopo 4.100 mm simulati.

Queste prove **non sostituiscono** una stampa fisica: comunicazione RS-485 prolungata, guasti, RFID reali, riconnessione, cambio slot e odometro fisico non sono ancora qualificati.

## Installazione sperimentale

L'immagine è nel menu **experimental-cfs** dell'Helper. Non installare l'extra Kalico CFG5T prima di avere verificato il riavvio della CFS e la comunicazione dei motori X/Y. La vecchia versione di Kalico può identificare la nuova revisione senza inviare SET; per configurare ID20/22, usare poi l'extra abbinato e configurare auto_apply nel CFG. Il flash va eseguito solo con stampante inattiva e possibilità di ripristinare CFG4.

[English validation](VALIDATION_EN.md) | [Informazioni firmware](README.it.md)

## Prima osservazione hardware (18 ottobre 2026)

Dopo un flash eseguito dall'utente, il firmware ha risposto con identità K2OH / v323-cfg5t, API2, 28 ID e feature 0xE5. Klipper è arrivato in stato ready, CFS IDLE/OK, motori X/Y pronti. **La prima enumerazione del motore Y ha però avuto un timeout; il secondo tentativo è riuscito.** Questo evento impedisce di considerare la comunicazione RS-485 pienamente qualificata.

In sola lettura sono stati ottenuti i valori stock ID8 7000 ms, ID20 25000 ms, ID22 500 ms. auto_apply è rimasto disattivato e non sono stati eseguiti homing, movimenti o stampa per il test. Il residuo type 4 in stampa reale resta da verificare. L'extra abbinato è nella [PR Kalico #83 in bozza](https://github.com/MzTechnology97/kalico-k2pro/pull/83).
