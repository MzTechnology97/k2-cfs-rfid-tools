# Calibrazione CFS SGF1/RH1 R3

Configurazione e procedura completa sono mantenute con il codice host:
[guida Kalico in italiano](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_SPOOL_CALIBRATION.md)
e [file conf](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/config/k2/macros/box_spool_profiles.cfg).

Profilo Bambu di riferimento: `bambu = 1, 284.7, 508.3`.
I valori sono circonferenze in mm. Il nucleo effettivo284,7 deriva dal primo
esaurimento reale (19655/327000), che lasciava6% con il precedente260,8.
La bobina piena resta508,3. Il nuovo coefficiente attende un altro ciclo fisico.

Non confondere diametro fisico e coefficiente effettivo. La guida include
misura piena/nucleo, formule, comandi passivi, ID vendor, include, revisione RAM,
cache/odometro, vincolo BIND sul runtime consumato e limiti della verifica.
Non serve un nuovo firmware per modificare i coefficienti.
