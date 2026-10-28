# K2 CFS RFID — CFG6 RDG2

**CFG6 RDG2: funzionamento verificato sul caso reale del 28 ottobre 2026.** Questo ramo contiene una sola immagine firmware per **Creality K2 Pro CFS G32 / applicazione stock `cfs0_000_153`**, i sorgenti ricostruibili e il lettore diagnostico Kalico abbinato.

[English](README.md) · [Immagine firmware](firmware/cfg6-rdg2/cfs0_050_G32-cfs0_000_153-K2OH-CFG6-RDG2.bin) · [Validazione e limiti](docs/CFG6_RDG2_VALIDATION.md) · [Compatibilità](docs/CFS_FIRMWARE_COMPATIBILITY_IT.md) · [Integrazione Kalico](host/kalico/README.md)

## Artefatto esatto

| Voce | Valore |
| --- | --- |
| Immagine | `cfs0_050_G32-cfs0_000_153-K2OH-CFG6-RDG2.bin` |
| Dimensione | **179.976 byte** |
| SHA-256 | `7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f` |
| Identità runtime | `K2OH / v323-cfg6`, CONFIG API2, feature `0xE3` |
| Interfaccia RFID | API7, capability `0xE8` |
| Snapshot di sola lettura | Opcode `0x57`, sottocomando `0x15`, 64 byte `RDG2`, versione 2 |
| Lettore host abbinato | `host/kalico/box_rfid_diag.py`, SHA-256 `2b9810456f6bb7ae0f2ebbf82cdf1f293dab84867a9db2799fb3035cb7aef867` |

L'identità runtime e la versione OEM mostrata dalla stampante non identificano univocamente questa build: verificare lo SHA-256 completo. La feature CONFIG e la capability RFID appartengono a due interfacce distinte.

## Cosa è stato verificato

Durante una stampa reale con **Bambu PETG HF nello slot fisico 4** (indice locale 3), il contatore di consumo della MCU CFS è avanzato **0 → 51 → 202 → 6.293 → 17.113 mm**. La percentuale CFS è scesa **39 → 38 → 34** e una lettura del normale `CMD 0x03` ha restituito 34. L'utente ha confermato la lettura RFID manuale.

La sessione RS-485 osservata ha registrato **31.548 frame trasmessi e ricevuti**, senza errori registrati di timeout, CRC, lunghezza, associazione risposte, invio, lettura o connessione. Sulla MCU fisica RDG2 ha misurato `PRIMASK=1` durante lo snapshot, `CONTROL=6` e `IPSR=0`.

Le prove dimostrano questo caso operativo. **Scaricamento seguito da rilettura, altri formati di tag/backend e latenza massima degli interrupt restano da verificare su hardware.** L'emulazione copre altri percorsi, senza estendere a essi la validazione fisica. Dettagli nel [resoconto di validazione](docs/CFG6_RDG2_VALIDATION.md).

## Comportamento firmware e host

Il firmware conserva l'interfaccia dei parametri CFG6 e il percorso di cattura API7. Le modifiche al conteggio type-4 riguardano l'inizializzazione dei record legacy supportati, la conservazione del conteggio attivo durante le scansioni geometriche e la pulizia ritardata già prevista dopo lo scaricamento. Le transazioni in RAM e gli snapshot RDG2 salvano e ripristinano la maschera degli interrupt.

RDG2 legge la RAM e restituisce un singolo snapshot diagnostico: non avvia operazioni RFID e non inizializza il conteggio. Kalico continua a ricevere la percentuale CFS tramite il normale `CMD 0x03`. Nel caso verificato il proxy firmware usava **330 m**, mentre il profilo filamento Kalico usava **327 m**: le due stime possono differire.

Le modifiche diagnostiche e al conteggio non aggiungono scritture sui tag RFID o in EEPROM. Le scritture CONFIG esistenti restano volatili e richiedono il firmware corrispondente e una procedura di avvio controllata.

## Ricostruzione e test offline

Servono Python 3, assembler/linker `arm-none-eabi`, Unicorn e Capstone.

```sh
python3 scripts/prepare_base.py
python3 tests/run_offline.py
```

Lo script di preparazione recupera la **base intermedia v3.13, già modificata**, dal commit congelato `0ad22669248cc845a3c8d22dd613500c4b95feb3`, verifica lo SHA-256 `9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff` e la salva nel percorso ignorato `work/base-pinned.bin`. È un input di compilazione, non l'immagine attuale da installare né una ROM OEM originale.

I sorgenti attuali sono [handler.S](firmware/cfg6-rdg2/handler.S), [build.py](firmware/cfg6-rdg2/build.py), [preflight.py](firmware/cfg6-rdg2/preflight.py) e [link.ld](firmware/cfg6-rdg2/link.ld). Il runner offline deve riprodurre esattamente lo SHA dell'immagine indicato sopra. Questi comandi non comunicano con la stampante.

## Documentazione e storico

- [Validazione, interpretazione del residuo e limiti noti](docs/CFG6_RDG2_VALIDATION.md)
- [Compatibilità firmware](docs/CFS_FIRMWARE_COMPATIBILITY_IT.md)
- [Extra Kalico e comando RDG2](host/kalico/README.md)
- [Guida storica dei 28 parametri IT](docs/CFS_V323_PARAMETER_GUIDE_IT.md) ed [EN](docs/CFS_V323_PARAMETER_GUIDE_EN.md): riferimento ereditato; per gli ID scrivibili CFG6 usare il documento di compatibilità attuale.

Le vecchie immagini e i test delle singole versioni sono stati rimossi dal ramo corrente. Sorgenti, immagini e ricerca restano consultabili nell'[albero storico congelato](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). I documenti di ricerca datati descrivono le rispettive versioni e non costituiscono istruzioni di installazione attuali. La cronologia Git non è stata riscritta.

Lavoro indipendente di interoperabilità e reverse engineering, senza affiliazione con Creality, Bambu Lab o QIDI.
