# Current R3 reference

The current SGF1/RH1 R3 image is
[`a6dec25c…`](../firmware/cfg6-spool-profiles/README.md), 185900 bytes,
for CFS G32 / cfs0_000_153. It retains the CFG6/API7/RDG2 contracts below and
adds SGF1, SLOT_LENGTH and RH1. Use the complete matching
[Kalico branch](https://github.com/MzTechnology97/kalico-k2pro/tree/k2-pro-openhost),
including box_spool_profiles. Vendor geometry is host RAM configuration.
See [calibration](CFS_SPOOL_CALIBRATION.md) and [R3 hardware scope](../firmware/cfg6-spool-profiles/HARDWARE-R3.md).

The following dated RDG2 section describes the retained fallback image,
not the new R3 image or its per-UID nominal length.

# Compatibilità firmware CFS — CFG6 RDG2

[English](CFS_FIRMWARE_COMPATIBILITY.md) · [Validazione](CFG6_RDG2_VALIDATION.md) · [Firmware attuale](../firmware/cfg6-rdg2/cfs0_050_G32-cfs0_000_153-K2OH-CFG6-RDG2.bin)

Il ramo attivo distribuisce una sola immagine per **Creality K2 Pro CFS G32 / APP `cfs0_000_153`**. Il funzionamento è stato verificato il 28 ottobre 2026 con Bambu PETG HF nello slot fisico 4. Il risultato non qualifica altre schede, versioni applicative, formati di tag o tutte le transizioni operative.

| Interfaccia | Identità richiesta / ambito |
| --- | --- |
| Immagine esatta | 179.976 byte; SHA-256 `7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f` |
| CONFIG | `0x7A: K2OH`, variante `v323-cfg6`, API2, feature `0xE3`, G32/APP153 |
| CONFIG GET | 28 ID, da 0 a 27 |
| ID CONFIG scrivibili | 1–3, 5–9, 11–24, 27: **23 ID** |
| ID CONFIG di sola lettura | 0, 4, 10, 25, 26 |
| Diagnostica RFID | Opcode `0x57`, API7, capability `0xE8` |
| RDG2 | Opcode `0x57`, sottocomando `0x15`; payload di 64 byte, versione 2 |
| Lettore diagnostico Kalico abbinato | SHA-256 `2b9810456f6bb7ae0f2ebbf82cdf1f293dab84867a9db2799fb3035cb7aef867` |

L'identità CFG6 è ereditata dalle build precedenti e non identifica univocamente la release. Lo SHA dell'immagine distingue questa build RDG2; una risposta RDG2 dimostra il supporto del formato diagnostico, non l'identità di ogni byte del firmware. La sola versione OEM mostrata dalla GUI non basta.

CONFIG SET è specifico del firmware patched-stock corrispondente. Prima di abilitare le scritture occorre verificare identità completa, API, feature, variante e destinazione. Gli override volatili ereditati appartengono alla procedura controllata di avvio Kalico; questo documento non autorizza cambi di parametri durante stampa o caricamento/scaricamento.

La [guida storica italiana dei parametri](CFS_V323_PARAMETER_GUIDE_IT.md) descrive il catalogo ereditato e il precedente comportamento CFG4. La sua lista di sei ID scrivibili è storica; l'elenco **CFG6 attuale comprende i 23 ID indicati sopra**.

## Residuo e limiti diagnostici

Kalico riceve i valori CFS dal normale `CMD 0x03`; RDG2 espone lo stato RAM utile a interpretarli. La risposta `0xFF` significa che quella richiesta non ha restituito una percentuale utilizzabile per lo slot. Può essere emessa prima del wrapper di validità quando il manager RF stock seleziona lo stesso slot, oppure in seguito a controlli di validità falliti. Da sola non dimostra che il conteggio non sia inizializzato.

Un runtime proxy valido con il marker stock richiesto dal getter assente può ancora produrre zero. Questa build conserva il comportamento del getter originale e non ne aggira i filtri. Lo snapshot descrive l'istante di acquisizione e non garantisce lo stesso stato a una richiesta successiva.

Il proxy Bambu verificato usa 330 m, il profilo Kalico 327 m. La percentuale intera CFS e la stima Kalico da encoder possono quindi differire. Il [resoconto di validazione](CFG6_RDG2_VALIDATION.md) documenta consumo osservato, atomicità e verifiche hardware ancora aperte.

## Versioni precedenti

Le vecchie immagini installabili e i relativi test non sono presenti nel ramo corrente. L'[albero storico congelato](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3) ne conserva file e risultati datati. Le identità API/CFG storiche non sono intercambiabili con il contratto di scrittura attuale. L'immagine intermedia v3.13 recuperata nel percorso ignorato `work/base-pinned.bin` serve solo come input di compilazione verificato tramite SHA.
