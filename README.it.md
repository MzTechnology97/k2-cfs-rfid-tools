# K2 CFS RFID — CFG6 SGF1/RH1 R3

**R3 è la versione di riferimento attuale per CFS G32 / applicazione cfs0_000_153.**
Include lettura RFID con chiavi inviate da Kalico nello stesso ciclo OEM,
prova dei due UID e geometria vendor in RAM. Mantiene CFG6, API7 e RDG2.

[English](README.md) · [Firmware R3](firmware/cfg6-spool-profiles/cfs0_050_G32-cfs0_000_153-K2OH-CFG6-SGF1-RH1-R3-CANDIDATE.bin) · [SHA-256](firmware/cfg6-spool-profiles/SHA256SUMS.txt) · [Build](firmware/cfg6-spool-profiles/BUILD.md) · [Prove hardware](firmware/cfg6-spool-profiles/HARDWARE-R3.md) · [Come calibrare](docs/CFS_SPOOL_CALIBRATION.md)

Il BIN è185900byte, SHA-256
`a6dec25c74e7d259eec0387193548a0c3cc78ec9fc4ddc35824f0fe0965385b8`.
Conserva il suffisso CANDIDATE del file effettivamente collaudato e le stesse
identiche sequenze di byte. L'identità runtime v323-cfg6 non distingue R3 dalle
versioni precedenti; verificare lo SHA del file.

## Cosa è stato verificato

Le due PETG HF Bambu degli slot fisici2/4 sono state lette in24,60s/20,47s,
con una richiesta RH1 per bobina e flags0x13. I getter R3 copiano realmente i
due UID anche quando la lunghezza originale è0; byte75 resta invariato.

Il profilo host di riferimento è:
```ini
vendor_geometries:
    bambu = 1, 284.7, 508.3
```
I valori sono circonferenze in millimetri. Il nucleo effettivo 284,7 mm è
ricavato dal primo esaurimento reale: lo slot 4 ha consumato 19,655 m su
327 m nominali, ma mostrava ancora il 6% partendo dalla vecchia stima del 12%.
La correzione corrisponde al 6,005% per la misura iniziale; il pieno resta
508,3 mm e lo slot 2 nuovo resta al 100%. Il precedente nucleo 260,8 mm,
derivato dal diametro fisico circa 83 mm, resta documentato come prova
storica. Il nuovo coefficiente attende un altro ciclo fisico e la sua
attivazione a stampa terminata.

Il vendor viene dichiarato dal decoder RFID host; il solo nome commerciale
del filamento non seleziona una geometria. La lunghezza nominale resta per
UID/slot. Dopo perdita RAM del CFS, Kalico continua da cache e odometro fino
a una successiva misura valida, senza imporre una scansione al solo ripristino.

## Installazione e calibrazione

Il [Helper](https://github.com/MzTechnology97/k2-openhost-installer-helper),
menu40, presenta R3 come prima voce e mantiene RDG2 come fallback. Il flash è
supervisionato e richiede stampante/CFS inattivi. La
[configurazione Kalico pronta](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/config/k2/macros/box_spool_profiles.cfg)
contiene la geometria Bambu. Seguire la [procedura di calibrazione](docs/CFS_SPOOL_CALIBRATION.md)
per installarla, acquisire i riferimenti e verificare il ricalcolo.

I coefficienti sono modificabili nel file host e caricati in RAM; non richiedono
un nuovo firmware. Il diametro è approssimato e il riferimento pieno deriva
dalla bobina PETG HF da1kg provata. Per supporti o avvolgimenti diversi occorre
una nuova verifica. Consumo e cambio automatico al runout sono stati osservati.
Restano da provare inserimento/scollegamento fisico e margine reale di stack; le altre regressioni
sono coperte offline.

## Sorgenti e fallback

Per ricompilare e verificare l'immagine usare
[BUILD.md](firmware/cfg6-spool-profiles/BUILD.md) e `python tests/run_spool_family.py`.
La suite include il confronto byte per byte con il BIN pubblicato e controlli
negativi dei difetti precedenti. Il firmware RDG2 rimane disponibile come
[fallback precedente](firmware/cfg6-rdg2/README.md), con RFID e decremento39→34
verificati in stampa il28ottobre2026. Non contiene la geometria SGF1/RH1.
I vecchi candidati RH1 non sono proposti per il flash; i loro sorgenti rimangono
nella storia per le regressioni.

Lavoro indipendente di interoperabilità e reverse engineering, non affiliato
con Creality, Bambu Lab o QIDI.

## Candidato R4 per il residuo preciso

[R4-PRECISION1](firmware/cfg6-precise-remaining/README.md) aggiunge una lettura passiva in millimetri. La prova hardware e ancora da eseguire; R3 resta il riferimento. [Procedura](docs/CFS_PRECISE_REMAINING.md).
