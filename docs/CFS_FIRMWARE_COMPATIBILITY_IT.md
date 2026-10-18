# Compatibilità dei firmware CFS — Italiano

Le scritture dei parametri CFG4 sono supportate **solo dai firmware
K2-OpenHost modificati e corrispondenti, distribuiti in k2-cfs-rfid-tools**.

- **Creality originale**: nessuna estensione Runtime CFG4 compatibile.
- **K2-OpenHost v3.13–v3.22**: schema precedente, sola diagnostica CFG4.
- **v3.23 CFG4**: 0x7A = K2OH, formato 1, variante 4, revisione
  v323-cfg4, applicazione cfs0_000_153; 0x57 INFO con API2,
  28 parametri e feature 0xD7. Sono modificabili soltanto gli ID
  1/2/3/5/7/8, solo all'avvio dal file CFG.
- **OpenCFS**: 0x7A = OCFS, varianti RELEASE/INERT/BENCH.
  Kalico lo riconosce, ma non invia mai SET CFG4 della famiglia K2OH.
- **Firmware ignoto/terze parti**: nessuna scrittura CFG4.

Il byte 0xD7 non basta per distinguere v3.23 da v3.22:
occorre sempre verificare anche identità, revisione e versione.

[Guida completa IT](CFS_V323_PARAMETER_GUIDE_IT.md) |
[English parameters](CFS_V323_PARAMETER_GUIDE_EN.md) |
[English compatibility](CFS_FIRMWARE_COMPATIBILITY.md)
