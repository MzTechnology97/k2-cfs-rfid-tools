> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# Stato CFG6 e audit GitHub — 18 ottobre 2026 (IT)

## Firmware e configurazione attivi

- **Firmware CFS fisico:** `K2OH v323-cfg6`, feature `0xE3`, API2, 28 ID, 23 SET/GET e 5 GET-only (0/4/10/25/26).
- **Kalico CM5:** ramo `k2-pro-openhost` con extra CFG6 integrato; `box.cfg` attivo ha `auto_apply: True`. Con stampante `standby`, CFS `IDLE` e nessun asse referenziato, sono state confermate **23 scritture con readback 23/23**, 28/28 GET validi, nessuna opzione ignorata.
- **Valori personalizzati verificati:** `hub_transition_speed=220`, `hub_insert_speed=100`, `hub_reverse_speed=150`, `rfid_measure_speed=150`, `rfid_neighbor_retry_count=1`, `load_retry_count=1`.
- **Risultati limitati al controllo statico/configurazione**: durante la prova non sono stati inviati `G28`, homing Z, movimenti, caricamento/scaricamento o letture RFID con bobina in movimento. La prova fisica del residuo type 4 durante una stampa rimane aperta.
- **Bus RS-485**: il primo boot dopo flash ha richiesto un retry di enumerazione con alcuni timeout e un errore CRC; i motori sono poi risultati pronti. Al successivo riavvio solo Klipper, enumerazione al primo tentativo con un timeout broadcast. Stabilità nel tempo da confermare.
- **Rollback**: conservare CFG5T e v3.22; CFG6 è un firmware sperimentale, non una release completamente qualificata.

## Documentazione corrente

- [**28 parametri CFG6: effetto, range, default, limiti e valore CM5 (IT)**](https://github.com/MzTechnology97/k2-cfs-rfid-tools/blob/0ad22669248cc845a3c8d22dd613500c4b95feb3/firmware/v3.25-cfg6-lab/PARAMETERS_IT.md)
- [**Full 28-parameter documentation (EN)**](https://github.com/MzTechnology97/k2-cfs-rfid-tools/blob/0ad22669248cc845a3c8d22dd613500c4b95feb3/firmware/v3.25-cfg6-lab/PARAMETERS_EN.md)
- [Guida Kalico CFG6 IT](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_RUNTIME_CFG6_IT.md) · [EN](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_RUNTIME_CFG6_EN.md)
- [Immagine installabile e sorgenti CFG6](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3/firmware/v3.25-cfg6-lab)
- [Manifest Helper](https://github.com/MzTechnology97/k2-openhost-installer-helper/blob/main/firmware/custom-cfs/manifest.json)

## Pulizia PR/issue verificata

**Chiuse come storiche e superate dal flusso di rilascio CFG6** (nessun merge, branch conservati):
- [PR #34](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/34) — milestone compiler/byte-parity v3.22-v3.23. Non tutti i test storici sono stati trasferiti nella CFG6.
- [PR #43](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/43) — correzione documentale della readiness e del loader del vecchio ramo v3.23. I dettagli di analisi storica restano consultabili.
- [Kalico PR #83](https://github.com/MzTechnology97/kalico-k2pro/pull/83) — vecchia integrazione CFG5T, già chiusa prima dell'audit; sostituita dalla CFG6 integrata [PR #86](https://github.com/MzTechnology97/kalico-k2pro/pull/86).

**Restano aperte 19 PR di ricerca firmware**, non chiuse automaticamente perché hanno test, analisi o funzioni non equivalenti e non dimostrate nell'attuale CFG6:
- RFID, type4 e protezioni anti-race **#39, #40, #41, #44**; la valutazione dei due *secure sink guards* resta importante.
- Motor safety, GPIO/PWM, contatori, protocollo e fail-closed **#37, #45, #46, #47, #49, #50, #52**.
- Loader, provenienza OEM e verifiche crittografiche **#35, #36, #38, #42, #53, #55**.
- Event ring in MCU (proposte non integrate) **#11, #12**.

**Issue di sicurezza aperta:** [#9 — MCU BOX_STATE può indicare IDLE durante alimentazione](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9). La prova 23/23 a stampante ferma **non** certifica un interlock atomico che blocchi i SET durante movimento. Mantenere i guard host e non inviare SET/RESET raw durante azioni motore. L'issue resta intenzionalmente aperta.

**Altre repository verificate:** Kalico e Helper non presentano PR o issue aperte al momento di questo audit; OpenCFS-Firmware non ha PR aperte ma mantiene [issue #2](https://github.com/MzTechnology97/OpenCFS-Firmware/issues/2) (protocollo da completare) e [#3](https://github.com/MzTechnology97/OpenCFS-Firmware/issues/3) (safety/loader/recovery), ancora valide.

**Criterio di archiviazione:** una PR non diventa obsoleta soltanto perché è datata o punta a v3.23; si chiude solo se lo stesso risultato è stato integrato o il prototipo è effettivamente dismesso senza perdere la tracciabilità delle evidenze.