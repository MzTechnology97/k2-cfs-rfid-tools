# Compatibilità dei firmware CFS — Italiano

Le scritture `CONFIG SET` sono supportate **solo dal firmware CFS K2-OpenHost patched-stock corrispondente**, dopo aver verificato **identità completa, API, feature e destinazione hardware**. Non sono comandi validi per qualunque firmware Creality, OpenCFS o di terze parti.

| Famiglia | Identità / capacità | ID realmente scrivibili | Regola |
| --- | --- | --- | --- |
| Creality stock `cfs0_000_153` | Nessuna estensione CONFIG K2OH | Nessuno | Solo lettura, nessun CONFIG SET K2OH |
| K2OH v3.13–v3.22 | Schema precedente; v3.22 usa `0xD7` | Solo ID previsti dal rispettivo schema storico | Non presumere compatibilità CFG4/CFG5T/CFG6 |
| **CFG4 v3.23** | `0x7A: K2OH`, `v323-cfg4`, API2, feature `0xD7`, G32/APP153 | 1, 2, 3, 5, 7, 8 (**6**) | Scrittura all'avvio soltanto con CFG4 |
| **CFG5T v3.24** | `0x7A: K2OH`, `v323-cfg5t`, API2, `0xE5`, G32/APP153 | 1, 2, 3, 5, 7, 8, 20, 22 (**8**) | Solo con CFG5T; residuo type-4 **sperimentale** |
| **CFG6 v3.25** | `0x7A: K2OH`, `v323-cfg6`, API2, `0xE3`, G32/APP153 | 1–3, 5–9, 11–24, 27 (**23**); 28 GET, 5 GET-only | Solo con CFG6; residuo type-4 **non qualificato su hardware** |
| **CFG6 candidata fix RFID** | Identità **identica** a CFG6 v3.25 | Gli stessi 23 ID | **[PR #60](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/60) in bozza: NON FLASHARE**; primo aggiornamento interrotto ([issue #59](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/59)) |
| OpenCFS | `0x7A: OCFS`, varianti RELEASE/INERT/BENCH | Nessuno della famiglia K2OH | Solo identificazione/lettura |
| Firmware ignoto o terze parti | Non verificato | Nessuno | Fail-closed, sola lettura |

Il **solo byte `0xD7` non distingue CFG4 da v3.22**, e la versione GUI Creality `1.5.3` non distingue i firmware modificati. La candidata CFG6 con fix RFID **ha volutamente la stessa identità della v3.25**: serve lo SHA-256 del pacchetto verificato per distinguerle. La versione visualizzata dopo un flash non dimostra che la programmazione sia riuscita.

Le scritture dei parametri CFG6 sono override in **RAM volatile**, applicati dal componente Kalico `box_cfs_runtime` solo all'avvio controllato, **mai dalla console durante una stampa**. Non applicare valori durante carico/scarico, alimentazione del filamento o letture RFID. Lo stato `BOX_STATE=IDLE` **non garantisce** che i motori CFS siano realmente fermi ([issue #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9)). SET/GET verificati a riposo non equivalgono a una qualifica funzionale meccanica o RFID.

Durante una stampa reale la CFG6 v3.25 ha mostrato una **percentuale type-4 ferma intorno al 35%**. La [issue #59](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/59) raccoglie le prove. La [PR #60](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/60) riproduce offline un reset del contatore durante una nuova inizializzazione RFID, ma non dimostra che sia avvenuto nella stampa e **non è una build pronta per il flash**.

Approfondimenti: [Guida parametri IT](CFS_V323_PARAMETER_GUIDE_IT.md) · [Compatibilità EN](CFS_FIRMWARE_COMPATIBILITY.md) · [Parametri CFG6 dettagliati](../firmware/v3.25-cfg6-lab/PARAMETERS_IT.md).
