# CFS v3.23 CFG4 — Guida italiana dei 28 parametri

**Compatibilità esclusiva:** la scrittura di questi parametri è supportata soltanto dai firmware K2-OpenHost distribuiti nella repository k2-cfs-rfid-tools, nella build che presenta la stessa identità e lo stesso catalogo. Il firmware Creality originale e altri firmware modificati non sono compatibili con CFG4. OpenCFS viene identificato come una famiglia distinta (OCFS) ma non riceve questi SET.

**S = realmente scrivibile e operativo nella CFG4; R = sola lettura, non agganciato al codice stock o con comportamento di velocità non modulabile.** Le scritture avvengono solo dal CFG all'avvio di Klipper/Kalico. Tutti i valori CFG4 sono RAM-only.

| ID | Parametro CFG | Stock | Funzione | Range / unità | CFG4 |
|---:|---|---|---|---|:---:|
| 0 | feeder_forward_speed | 255 | Comando feeder avanti; le uscite stock sono GPIO ON/OFF, nessuna velocità PWM regolabile | 1–255 valore | R |
| 1 | hub_forward_speed | 100 | Velocità avanti del motore hub, nel registro RAM stock | 1–255 valore | S |
| 2 | hub_transition_speed | 200 | Velocità hub durante transizione del filamento | 1–255 valore | S |
| 3 | hub_insert_speed | 155 | Velocità hub durante inserimento del filamento | 1–255 valore | S |
| 4 | feeder_reverse_speed | 255 | Comando feeder reverse; stock ON/OFF, non regola velocità | 1–255 valore | R |
| 5 | hub_reverse_speed | 80 | Velocità hub in retrazione | 1–255 valore | S |
| 6 | reverse_detooth_enable | 1 | Flag reverse de-tooth rilevato nel firmware; non modificabile nella CFG4 | 0–1 valore | R |
| 7 | hub_transition_wait_ms | 3200 | Attesa temporale nella transizione hub→buffer | 100–10000 ms | S |
| 8 | insert_sensor_timeout_ms | 7000 ms | Timeout sensore di inserimento; 700 iterazioni di polling stock da 10ms; il firmware converte ms / 10 | 1000–50000 ms; multipli di 10 | S |
| 9 | hub_pullback_timeout_ms | 5000 | Timeout di rientro hub durante l'unload, hook non implementato | 500–15000 ms | R |
| 10 | unload_sensor_timeout_ms | 1000 tick da 10 ms | Timeout sensore unload nel ramo stock non raggiunto; Timeout di polling su ramo non eseguito; non promette 1000ms reali | 100–5000 tick OEM | R |
| 11 | rfid_seek_speed | 160 | Velocità hub per localizzazione RFID | 1–255 valore | R |
| 12 | rfid_measure_speed | 120 | Velocità hub durante misurazione bobina RFID | 1–255 valore | R |
| 13 | rfid_reposition_speed | 100 | Velocità hub di riposizionamento per RFID | 1–255 valore | R |
| 14 | rfid_seek_move_ms | 800 | Durata del movimento di ricerca tag | 100–5000 ms | R |
| 15 | rfid_seek_settle_ms | 200 | Attesa dopo movimento di ricerca tag | 10–2000 ms | R |
| 16 | rfid_post_auth_wait_ms | 1000 | Attesa dopo autenticazione e fra letture RFID | 100–5000 ms | R |
| 17 | rfid_pre_measure_settle_ms | 400 ms | Attesa precedente alla misurazione RFID; Pausa di assestamento prima della misurazione RFID: corretto stock 400, non 10 | 1–1000 ms | R |
| 18 | rfid_neighbor_detect_delay_ms | 400 | Ritardo ricerca bobina adiacente | 50–2000 ms | R |
| 19 | rfid_neighbor_settle_ms | 100 | Assestamento dopo arresto per ricerca bobina adiacente | 10–1000 ms | R |
| 20 | feed_total_timeout_ms | 1250 tick da 20ms = 25s | Timeout complessivo fase feed; Limite complessivo del feed, originariamente espresso in tick di 20ms | 250–3000 tick | R |
| 21 | feed_recovery_timeout_ms | 3000 | Timeout di recupero dopo anomalia feed | 500–10000 ms | R |
| 22 | odometer_stall_timeout_ms | 25 tick da 20ms = 500ms | Timeout odometro senza impulsi; Odometer stall: timeout senza impulsi, tick di 20ms | 5–100 tick | R |
| 23 | rfid_neighbor_retry_count | 3 | Numero ripetizioni ricerca RFID su bobina vicina | 1–10 valore | R |
| 24 | reverse_detooth_timeout_ms | 1000 | Timeout di rilascio ingranaggio (de-tooth) in reverse | 100–10000 ms | R |
| 25 | buffer_fill_timeout_ms | 30000 | Timeout riempimento buffer, codice OEM non raggiunto | 1000–60000 ms | R |
| 26 | transition_detect_timeout_ms | 300 tick da 10ms = 3s | Timeout transizione, codice OEM non raggiunto e percorsi indipendenti; Limite transizione in ramo stock non eseguito; l'altro percorso retry è indipendente | 50–5000 tick OEM | R |
| 27 | load_retry_count | 3 | Numero di tentativi di carico/pretensione filamento | 1–10 valore | R |

## Protocollo di identificazione

- 0x7A: identifica K2OH (format 1, variant 4, revision v323-cfg4) e versione Creality cfs0_000_153; non basta il numero GUI 1.5.3.
- 0x57 / CONFIG_V2_INFO: API v2, count 28 e features 0xD7. Anche v3.22 presenta 0xD7: senza identità e revisione esatta non è permessa la scrittura.
- Se 0x7A risponde OCFS, Kalico segnala OpenCFS con variante e revisione; non invia CONFIG_SET CFG4 finché non esiste un contratto di capacità OpenCFS verificato.
- SET: solo 1, 2, 3, 5, 7, 8; GET conferma l'accettazione del valore. Gli ID 0, 4, 6, 9–27 sono protetti da read-only nel firmware.

## Sequenza CFG-only all'avvio

1. La CFS viene enumerata con A1/A0 e identificata con 0x7A; Kalico verifica firma, versione e features.
2. Kalico legge la sezione box_cfs_runtime e applica solo le sei opzioni CFG4 realmente implementate; non registra i comandi G-code CONFIG_SET, CONFIG_RESET e CONFIG_APPLY.
3. Le opzioni non supportate sono riportate come ignorate. Un GET senza hook non prova la modifica di un comportamento.
4. I valori sono in RAM: al reset elettrico della CFS si perdono; alla nuova enumerazione Kalico rilegge il CFG.

## Esempio CFG (solo firmware abbinato)

    [box_cfs_runtime]
    auto_apply: true
    hub_transition_speed: 220
    hub_insert_speed: 100
    hub_reverse_speed: 150
    #hub_transition_wait_ms: 3200
    #insert_sensor_timeout_ms: 7000

**Attenzione:** l'immagine v3.23 CFG4 è sperimentale; la verifica con Unicorn non certifica i motori o la stabilità fisica RS-485. Tenere disponibile il firmware v3.22 per il recupero.

[English parameter guide](CFS_V323_PARAMETER_GUIDE_EN.md) | [Compatibilità IT](CFS_FIRMWARE_COMPATIBILITY_IT.md)

## Residuo type 4 durante la stampa

La v3.23 CFG4 **eredita dalla v3.12/v3.22** gli hook `remaining_gate_wrapper`, `remaining_init_wrapper` e `remaining_valid_wrapper`. Questi inizializzano, per le bobine di terze parti supportate, il runtime stock **type 4** dalla percentuale geometrica e da un riferimento nominale di 330.000 mm. Il comando `0x03` può leggere il residuo iniziale senza scrivere sul tag RFID.

**Non equivale al conteggio live durante la stampa.** L'analisi OpenCFS dello stock APP153 dimostra che il task `rfid_mgr_fila_task`, che accumula i millimetri dell'odometro e ricalcola la percentuale, è condizionato dal flag di presenza del chip FM15L013. Senza quel chip, il task stock viene saltato anche per type 4: il residuo CFS può restare fermo al caricamento, mentre Kalico stima il consumo da G-code.

La v3.23 CFG4 **non elimina questo gate hardware** e non aggiunge un task odometro alternativo. Il consumo live type 4 richiede una futura patch e test hardware specifici. Gli ID 20 e 22 sono riconosciuti da Kalico e leggibili, ma non modificabili nel firmware CFG4 attuale: mancano i relativi hook effettivi.

[Analisi OpenCFS](https://github.com/MzTechnology97/OpenCFS-Firmware/blob/main/docs/spec/05-preload-rfid.md) | [English](CFS_V323_PARAMETER_GUIDE_EN.md)
