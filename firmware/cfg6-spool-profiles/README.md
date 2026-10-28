# CFG6 SGF1 — family geometry firmware candidate

**Firmware-only candidate. Not a replacement for the hardware-verified [RDG2 release](../cfg6-rdg2/README.md).** Kalico integration and real Bambu geometry calibration are deferred. No live printer or Helper catalog is changed.

The exact candidate is described by [manifest.json](manifest.json). Its BIN is generated under `work/build/` and is not another installable image tracked in the release tree.

## Behavior

- Four boot-cleared RAM geometry profiles, selected by opaque IDs. Host convention may assign profile1 to an original Bambu spool.
- Raw rotation length captured **before** the OEM core clamp, with slot, UID, generation and quality.
- An explicit host declaration binds a decoded tag UID and measured generation to a profile/revision. The CFS cannot infer a manufacturer from UID, ATQA, SAK, keys or the mere fact that API7 succeeded.
- The first binding recalculates the cached measurement without another RF operation.
- Each subsequent trustworthy idle scan of that same UID recalculates the geometric anchor. A partly used spool stays partly used; no automatic “new spool =100%” action exists.
- Active printing/retracting counters remain protected. Unreliable scans do not replace an existing calibrated runtime.
- With no configured/bound profile, the existing geometry and type4 accounting remain the fallback.

Existing API7 authenticated reads, CFG6 API2 settings, ordinary remaining command0x03 and RDG2 snapshot0x15 remain available. A future host must declare the family after its decoder succeeds; loading the catalog alone does not classify tags.

## Identification and quality

The new BIND command checks current UID, measurement generation and catalog revision atomically. Generic API7 tags never become “Bambu” automatically. Different UIDs cannot inherit the prior slot's binding.

A usable rotation requires the original UID comparison to agree. Existing API7 may suppress a mismatch to finish tag identification; SGF1 exposes that discrepancy and refuses to use the measurement for calibration/binding. Fresh authenticated results are tracked per attempt. Old CAP masks or the K2RL latch alone do not establish a fresh successful read. Clearing keys after decoding preserves the completed measurement needed for BIND.

## Validation and limits

The ARM tests use synthetic geometry, deterministic RF replies, modeled IRQ interleavings and the actual message-validation-to-geometry tail. They cover stale UID/generation/revision, malformed requests, partial/stale authentication, UID mismatches, read retries, used-spool rereads, active-print protection, boot clearing and ABI preservation. They are not a physical Bambu calibration or a latency/stack qualification on the MCU.

RAM reservation adds320 bytes above the existing CFG6 sidecar and moves the heap start to0x20007068. No tag or nonvolatile write is added. Catalog values and bindings disappear on CFS restart.

See [build and checks](BUILD.md) and the [wire protocol](../../docs/SGF1_CANDIDATE_PROTOCOL.md).

## Stato in italiano

Questa versione prepara **solo il firmware CFS**: catalogo geometrie in RAM, misura grezza con qualità e associazione esplicita UID→profilo dopo la decodifica host. La lettura RFID non identifica autonomamente il produttore. Il collegamento Kalico verrà sviluppato nella fase successiva.

La bobina PETG HF nuova dello slot2 ha fornito il riferimento reale85%/0mm sulla RDG2, ma non abbiamo ancora misurato e validato i parametri fisici Bambu. I valori dei test sono simulati. Il firmware funzionante RDG2 e il manifest Helper restano invariati.
