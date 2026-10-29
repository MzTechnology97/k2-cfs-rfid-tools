# Precisione del residuo CFS — R4-PRECISION1

R4 e un candidato offline; R3 rimane il riferimento verificato su hardware.

La [procedura completa e il protocollo SGP1](https://github.com/MzTechnology97/kalico-k2pro/blob/feature/cfs-precise-remaining-20261029/docs/CFS_PRECISE_REMAINING.md)
sono mantenuti con l'integrazione Kalico. Il [manifest R4](../firmware/cfg6-precise-remaining/manifest.json)
identifica il BIN e i suoi limiti.

La geometria viene convertita in quantita iniziale in mm prima di sottrarre
il consumo protetto. La nuova lettura passiva distingue una stima valida di
zero da un valore non disponibile. Le percentuali legacy restano invariate;
nessuna nuova scansione o scrittura tag viene introdotta.
