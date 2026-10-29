# CFG6 SGF1 + RH1 — vendor geometry and single-cycle RFID R3

**R3 is reference-validated for RH1, UID quality and vendor RAM geometry in
physical slots2/4.** The current reference uses the operator's approximate
83mm bare cardboard diameter, not the earlier nearly-empty lower anchor.
The published BIN is beside [manifest.json](manifest.json) and
[SHA256SUMS.txt](SHA256SUMS.txt); its tested bytes are unchanged.

[Installation/calibration](../../docs/CFS_SPOOL_CALIBRATION.md) ·
[Hardware evidence](HARDWARE-R3.md) · [Build](BUILD.md).
The previous [RDG2 image](../cfg6-rdg2/README.md) remains a fallback.

## R2 correction and withdrawn image

The earlier RH1 image SHA `b7cd0ab36011af9cd5af8f1ae4932008110a8fbdd174086c1a0043f2f5010158` is withdrawn. Seven indirect calls in the handoff extension used nominal analysis addresses instead of physical flash addresses. R2 corrects each target by `-0xD000`, verifies all seven literal values statically, and runs the tests with one image mapped at `0x08003000`. RAM, UID bytes and register values are not automatically translated. The physical regression rejects the exact withdrawn BIN at its first incorrect indirect call. Earlier nominal-address test passes do not qualify that image for hardware use.

## R3 UID-pair measurement correction

The reference CM5 accepted R2 and completed one PETG HF RH1 read in24.54s, but
its raw measurement had flags0x02 rather than0x13. Passive metadata showed
record byte75=0. The original UID getter uses that byte as its length, so it
returned0 without copying either observed UID; a zero-length comparison could
not prove a consistent revolution. The earlier tests supplied byte75=4.

R3 wraps only the two getter calls in the original worker, both reached after
successful RF detection and descriptor copying. If the original getter returns
zero, recovery is limited to the legacy backend, ATQA0400/SAK08, a valid slot
and a nonzero four-byte UID. Each observation is copied into its actual caller
buffer and returns length4. Byte75, generic getter callers, the UID comparator
and BIND quality thresholds remain unchanged. Different UID observations still
invalidate geometry. Unsupported metadata retain the original behavior.

R3 has been tested on the reference machine: both slots returned flags0x13 and the host bound their retained measurements without another scan. See [hardware evidence and provisional calibration](HARDWARE-R3.md). The ready-to-include K2 macro contains the Bambu reference; the standalone example remains disabled until enabled.

## Behavior

- Four boot-cleared RAM geometry profiles selected by vendor, independently of material or color.
- A UID-keyed nominal length for each of four slots. The host uploads vendor geometries with total zero, then supplies the spool's nominal length before binding.
- Raw rotation length captured before the OEM core clamp, with UID, generation and measurement quality.
- After successful host decoding, BIND recalculates the saved measurement without another RF operation or motor movement.
- Later trustworthy idle scans of the same UID reuse the geometry and slot length. Partly used spools remain partly used; there is no automatic full-spool reset.
- Printing/retracting counters remain protected, and unreliable scans preserve an already calibrated runtime.
- RH1 lets the original RFID worker wait briefly for host keys after OEM authentication fails, while the spool is already stationary. It authenticates at the same measured position before OEM reposition/retry, avoiding a second complete scan on the successful handoff path.
- Manual START acknowledges immediately and enqueues the original preload worker. Automatic insertions use that same worker. All motion remains OEM-controlled.
- RH1 is disabled at boot and requires a configured session and live host lease. Missing or late host responses end the bounded wait and return control to OEM recovery.

The vendor is declared only after the host decoder accepts the tag data. UID or successful generic API7 authentication alone does not classify a spool as Bambu.

## Compatibility and mechanical preconditions

CFG6 identity remains K2OH/v323-cfg6, feature 0xE3, preserving the installed Kalico startup/runtime contract. SGF1 and RH1 are discovered separately. Existing API7, CFG6 API2, ordinary remaining command 0x03 and RDG2 snapshot 0x15 remain available.

RH1 targets the legacy MIFARE backend with four-byte UID and SAK 8. START requires idle state, no armed override, idle usage modes, a present target and an already empty hub. It does not silently free an occupied hub. Host operations must serialize scans against load/unload/printing; other clients must not issue stock force-read commands during an async job.

A first tag search may need a substantial rotation depending on the starting angle; a short movement cannot guarantee detection. The physical measurement still requires the next passage of the same UID. Geometry is needed for final arithmetic, not to acquire this measurement.

## Cache, quality and restart

Kalico can retain a spool's remaining amount and subtract odometer use after the CFS loses RAM, without forcing a new scan. The integration keeps that estimate until a trustworthy, correctly bound CFS anchor is available. Reloading the catalog alone does not restore a binding or prove a fresh measurement.

The original UID-pair comparison must match. Authenticated reads carry a fresh attempt epoch. Existing mismatch suppression may complete tag identification but cannot make a mismatched revolution calibratable. CLEAR after decoding preserves committed proof; handoff changes keys without discarding the current UID-pair proof.

## Validation boundary

ARM tests map the BIN once at its physical base `0x08003000`, without a second nominal mapping. The handoff tests execute the original message validator, three API7 wrappers and command handlers, with RF replies and RTOS scheduling modeled. They verify stale session/token/UID rejection, key retry, no motor entry inside handoff, timeout/decline, async cleanup, per-slot length, boot clearing and ABI/IRQ behavior. Inherited regressions remain part of the runner.

RAM reservation is 448 bytes above the existing CFG6 sidecar; heap starts at 0x200070E8. No tag or nonvolatile write is added. The nominal policy stop is 0x0803D800 (physical 0x08030800), a build bound rather than a newly certified limit of the installed loader.

See [build and checks](BUILD.md), [SGF1 protocol](../../docs/SGF1_CANDIDATE_PROTOCOL.md) and [RH1 contract and original-code evidence](RH1-CONTRACT.md).

## Stato in italiano

Il candidato separa la geometria per vendor dalla lunghezza nominale della bobina. RH1 permette di ricevere le chiavi da Kalico durante lo stesso ciclo, prima del recupero meccanico dopo un errore di autenticazione. La geometria può essere applicata alla misura già raccolta senza ripetere il giro.

La prova coordinata R3 ha verificato lettura RH1, misura valida e associazione della geometria in RAM sugli slot2/4. La calibrazione Bambu usa il cartone nudo di circa83mm e una bobina piena misurata; il valore è modificabile in Kalico e non è una costante del firmware. La prova di consumo durante una stampa R3 resta da eseguire.

## Runout refinement (29 October 2026)

Physical slot 4 ran out after 19655 mm counted from its retained measurement,
with total327000 mm, initial12% and current6%; automatic replacement by slot2
completed. The effective core was refined to **284.7 mm circumference**, while
full508.3 stays unchanged. It predicts about6.005% at the old measurement.
This is a single-runout host coefficient, not a newly measured cardboard
diameter. It was saved for the next idle host restart; no live profile change,
scan or firmware flash was performed. Another physical cycle must validate it.
BIND rejects replacement of a protected consumed runtime; do not clear usage.
See the [calibration guide](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_SPOOL_CALIBRATION.md).
