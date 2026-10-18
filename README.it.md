# K2 CFS RFID — CFG6 v3.25 (firmware sperimentale)

**Ultima versione disponibile: K2OH CFG6 v3.25** per **Creality K2 Pro CFS G32** con applicazione stock `cfs0_000_153`. Il progetto conserva le versioni precedenti e il firmware API7 v3.12 con validazione hardware RFID.

[**English README**](README.md) · [**Firmware CFG6 e BIN**](firmware/v3.25-cfg6-lab/README.it.md) · [**Tutti i parametri**](firmware/v3.25-cfg6-lab/PARAMETERS_IT.md) · [**Helper per installazione**](https://github.com/MzTechnology97/k2-openhost-installer-helper)

## Versione attuale: CFG6 v3.25

| Voce | Dettaglio |
|---|---|
| CFS supportato | `cfs0_050_G32` e applicazione Creality `cfs0_000_153` |
| Identità rilevata | `K2OH`, revisione `v323-cfg6`, API v2, feature `0xE3` |
| Parametri leggibili | **28** |
| Parametri realmente scrivibili | **23** |
| Nuovi parametri rispetto a CFG5T | **6, 9, 11–19, 21, 23, 24, 27** |
| Parametri solo GET | **0, 4, 10, 25, 26** |
| Stato | **Flash e SET/GET verificati sulla CFS fisica**, ma firmware sperimentale non qualificato per l'uso in produzione |

**BIN per installazione:**

[`cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin`](firmware/v3.25-cfg6-lab/cfs0_050_G32-cfs0_000_153-runtime-config-v3_25-K2OH-CFG6-EXPERIMENTAL.bin)

SHA-256:

```text
6579eb552210d6b2b84fbbbdf2749bc8d310b324ffb095cf9662e7cd0acc6cc6
```

### Installazione tramite Helper

Sul CM5 che utilizza K2-OpenHost:

```bash
cd ~/k2-openhost-installer-helper
./helper.sh experimental-cfs
```

Selezionare **CFG6 v3.25** (voce **3** nel manifest verificato il 18 ottobre 2026). L'Helper controlla nome, compatibilità e SHA-256 e richiede una conferma esplicita. **Non esegue flash automatici.** La stampante deve essere inattiva; conservare una copia funzionante della CFG5T v3.24 e della v3.22 per il ripristino.

### Cosa modifica la CFG6

**Trasporto del filamento lato CFS.** Gli ID 1/2/3/5 configurano il motore hub per spinta iniziale, trasferimento verso la testina, inserimento e scarico. I valori di velocità sono comandi **grezzi 1–255, non mm/s**. I feeder delle bobine sono motori ON/OFF: gli ID 0/4 non permettono una regolazione proporzionale della velocità.

**Attese e rilevamento problemi.** Gli ID 7–9 e 20–22 modificano pause, timeout sensori, limiti della fase di alimentazione, recupero e rilevamento stallo dell'odometro. Il parametro di timeout non aumenta la velocità del motore. L'ID 8 opera su passi da 10 ms; gli ID 20/22 su passi da 20 ms.

**Identificazione RFID.** Gli ID 11–19 e 23 regolano velocità di ricerca, misura/riposizionamento della bobina, ritardi e tentativi di ricerca nello slot vicino. Queste modifiche devono essere testate con tag e materiali reali; una riduzione aggressiva delle attese può causare letture mancate.

**Pretensione e de-tooth.** L'ID 27 regola i cicli effettivi di pretensione avanti/indietro nella sequenza di carico, non tutti i tentativi generali di caricamento. Gli ID 6 e 24 controllano l'abilitazione e la soglia dell'azione reverse de-tooth. Disabilitarla può interferire con lo scarico.

**Residuo filamento type 4.** È mantenuta la logica basata sul contatore di consumo del firmware stock. La diminuzione effettiva della percentuale durante una stampa reale non è ancora qualificata sulla CFG6.

I valori GET-only **0, 4, 10, 25, 26** non hanno una scrittura operativa in questa immagine. Per tutti i dettagli, valori stock, limiti, hook ARM e rischi consultare la [guida completa dei 28 parametri](firmware/v3.25-cfg6-lab/PARAMETERS_IT.md).

### Integrazione Kalico

La versione abbinata dell'extra si trova nel ramo operativo [`kalico-k2pro/k2-pro-openhost`](https://github.com/MzTechnology97/kalico-k2pro/tree/k2-pro-openhost). La sezione `[box_cfs_runtime]` in `box.cfg` può applicare gli override **solo all'avvio di Kalico**, con firma firmware corrispondente:

```ini
[box_cfs_runtime]
auto_apply: True
# Seguire i 23 parametri del template CFG6.
# Gli ID 0/4/10/25/26 restano in sola lettura.
```

I valori sono **volatili in RAM CFS**: devono essere riapplicati dopo un riavvio. Abilitare `auto_apply` esclusivamente dopo aver verificato l'identità `K2OH/v323-cfg6/0xE3` e l'assenza di operazioni di stampa/caricamento. Non inviare SET/RESET durante movimenti. OpenCFS, CFG4, CFG5T e firmware Creality originale sono versioni distinte e non devono ricevere SET CFG6.

[Guida Kalico italiana](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_RUNTIME_CFG6_IT.md) · [Riferimento dei 28 ID lato Kalico](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_RUNTIME_CFG6_PARAMETERS_IT.md).

## Test hardware eseguiti il 18 ottobre 2026

Dopo il flash eseguito dall'utente, la CFS ha identificato correttamente **CFG6 v3.25, feature 0xE3**. Con stampante in standby, CFS in stato IDLE e nessun asse referenziato, Kalico ha applicato **23 parametri su 23**; una successiva lettura indipendente ha ricevuto **28/28 GET validi** e confermato tutti i **23 valori personalizzati**. Klipper e motori risultavano pronti.

**Durante queste verifiche non sono stati eseguiti G28, homing Z, movimenti degli assi, operazioni sul filamento o cicli RFID.** Nei primi avvii sono stati osservati timeout e un CRC RS-485, poi recuperati. Mancano ancora la prova del movimento dinamico con i nuovi parametri, il caricamento/scaricamento, la lettura dei diversi tag, il residuo type 4 in stampa e la stabilità del bus nel tempo.

**Problema di sicurezza aperto:** [issue #9 — `BOX_STATE` può indicare IDLE durante l'alimentazione](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9). Un semplice stato IDLE della MCU non prova che ogni motore sia fermo. L'interblocco MCU completamente atomico e indipendente non è ancora stato qualificato. **La CFG6 resta sperimentale e non è una release di produzione.**

## Versioni precedenti e rollback

| Versione | Identità / API | Evidenza |
|---|---|---|
| **CFG6 v3.25** | **`v323-cfg6 / 0xE3`** | Attualmente installata e verificata in SET/GET, 23 parametri |
| [CFG5T v3.24](firmware/v3.24-cfg5t/) | `v323-cfg5t / 0xE5` | 8 parametri operativi, task residuo type 4, rollback |
| [CFG4 v3.23](firmware/v3.23-k2oh/) | `v323-cfg4 / 0xD7` | 6 parametri operativi, storica |
| [v3.22](firmware/v3.22-readonly-state-probes/README.md) | `0xD7` | Caricamento/scaricamento e stampe fisiche precedenti; rollback |
| [v3.21](firmware/v3.21-busy-guard/README.md) | `0x97` | Prototipo di protezione busy, incompleto |
| [v3.20](firmware/v3.20-timing-hooks/README.md) | `0xB7` | Primi hook di temporizzazione |
| [v3.19](firmware/v3.19-volatile-ram/README.md) | `0xF7` | Esperimenti sulla RAM volatile |
| [v3.12](firmware/v3.12-remaining/) | API7 | Storica validazione hardware RFID Bambu e percentuale residua |

La vecchia **v3.12 API7** include la lettura di RFID di terze parti e il calcolo geometrico residuo verificato su Bambu; il fatto che quella versione sia stata provata non significa che la CFG6 abbia già superato le stesse prove.

## Documentazione

- [CFG6: sorgenti firmware, costruzione, test e guida IT](firmware/v3.25-cfg6-lab/README.it.md)
- [CFG6: descrizione dettagliata di ciascun ID](firmware/v3.25-cfg6-lab/PARAMETERS_IT.md)
- [Resoconto più recente e triage PR/issue](docs/CFG6_STATUS_PR_TRIAGE_20261018_IT.md)
- [Compatibilità firmware CFS](docs/CFS_FIRMWARE_COMPATIBILITY_IT.md)
- [Firmware API7 v3.12](docs/v3.12-remaining.md)
- [OpenCFS come progetto distinto](https://github.com/MzTechnology97/OpenCFS-Firmware)

Questo repository documenta attività indipendenti di interoperabilità e reverse engineering; non è affiliato a Creality, Bambu Lab o QIDI.
