# R3 host integration

Use the complete matching
[Kalico k2-pro-openhost](https://github.com/MzTechnology97/kalico-k2pro/tree/k2-pro-openhost)
for SGF1/RH1 R3, including box_spool_profiles, its Box coordinator integration,
[configuration](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/config/k2/macros/box_spool_profiles.cfg)
and [calibration guide](https://github.com/MzTechnology97/kalico-k2pro/blob/k2-pro-openhost/docs/CFS_SPOOL_CALIBRATION.md).
Copying only the legacy extras below does not supply the R3 integration.
The diagnostic reader below remains shared. The following section documents
the retained RDG2 fallback and its dated consumption example.

# Kalico host extras — CFG6 RDG2

[Current firmware](../../README.md) · [Validation and limitations](../../docs/CFG6_RDG2_VALIDATION.md) · [Compatibility](../../docs/CFS_FIRMWARE_COMPATIBILITY.md)

These extras integrate the K2-OpenHost/Kalico RFID path with the stock CFS worker:

| File | Role |
| --- | --- |
| `box_rfid_diag.py` | Opcode `0x57` transport, API7 records/key-arm operations and the read-only RDG2 snapshot |
| `box_rfid_bambu.py` | Bambu Key A derivation, API7 stock-worker orchestration and material/colour parsing |
| `box_rfid_mifare.py` | MIFARE Classic provider registry and vendor-specific decoding |

The diagnostic reader paired with the current image has SHA-256 **`2b9810456f6bb7ae0f2ebbf82cdf1f293dab84867a9db2799fb3035cb7aef867`**. The firmware SHA is **`7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f`**.

## Dependencies and configuration

The extras require the integrated K2 branch's `extras.box_protocol`, `extras.serial_485.build_485_body`, shared request queue/session and Box driver's `force_rfid_read(mask)`. They are not a standalone replacement for those components. The existing printer transport owns the RS-485 device.

```ini
[box_rfid_diag]
serial: serial485
address: 1
allow_active_rf: false
require_idle: true

[box_rfid_bambu]
serial: serial485
address: 1

[box_rfid_mifare]
serial: serial485
address: 1
```

The integrated Box driver can additionally expose `auto_bambu_rfid_fallback` and `auto_mifare_rfid_fallback`. Automatic fallback is restricted to API7. RF operations retain their existing confirmation, idle and session ownership rules. Updating source files takes effect at the next normal Klipper/Kalico restart; do not reload the printer service during a print.

## Read-only RDG2 snapshot

With the matching firmware and host reader:

```text
BOX_CFS_DIAG2 ADDRESS=1 SLOT=3
```

`ADDRESS` selects the CFS address. `SLOT` is its **local zero-based index 0–3**: `SLOT=3` means physical slot 4. It is not the global slot numbering used by integrated tag-read commands.

This command makes one request through `serial_485.request_session`, using opcode `0x57`, payload `15 <slot>` and the shared transport. It reads a 64-byte `RDG2` version-2 snapshot. It does not start RF activity, perform a tag read, change configuration, initialize accounting or move hardware. It is outside the active RF command list.

The response includes runtime validity/type/mode, used and total millimetres, initial/current CFS percentages, cached odometer, stock RF-manager flags/markers, tick count and PRIMASK/CONTROL/IPSR context. It exposes a boolean K2RL latch indicator, not key material. The firmware copies RAM with configurable interrupts masked and restores the incoming mask before sending the response.

The host validates payload length, magic, version, reserved byte and requested slot. Non-finite odometer values remain identifiable through their raw bits. On success it records `received_at_unix`; on error it clears `last_diag2_snapshot` and records the error. Reading the extra's status returns cached diagnostic data without another wire request. Check the timestamp before interpreting it.

PRIMASK does not exclude NMI, faults or DMA. Snapshot hints describe that instant, not a guarantee that a subsequent remaining query sees the same state.

## RFID reads, cache and profiles

API7 temporarily supplies keys at the stock authentication callsites and captures successful stock reads for host decoding. Normal tag operations remain in the CFS worker. The host profile association continues to supply temperatures, pressure advance and flow settings; live RFID can supply identity and colour.

A restored profile or a log saying a tag is known from the RFID cache does not prove a new physical RF read or reinitialization of MCU accounting. Use the command outcome and acquisition context to distinguish them. The manual RF read in the 28 October validation was confirmed by the operator; the cache observation does not contradict that confirmation.

The integrated commands `_BOX_RFID_READ_SLOT`, `_BOX_RFID_ASSOCIATE` and `BOX_RFID_MIFARE_READ` use their existing global-slot interface. They have different purposes and numbering from the local `BOX_CFS_DIAG2` snapshot.

## Remaining percentage

Kalico continues to receive the CFS percentage through normal `CMD_RFID_REMAINING (0x03)`. RDG2 is a diagnostic view of MCU RAM; it does not replace that protocol or force a percentage refresh.

On the verified Bambu PETG HF print, the MCU counter advanced **0 → 51 → 202 → 6,293 → 17,113 mm**, the CFS percentage moved **39 → 38 → 34**, and the final normal reply was `FFFFFF22`. The firmware proxy uses **330 m**, while the Kalico profile uses **327 m**, so the integer `rfid_reported_percent` and continuous `rfid_estimated_percent` can differ.

A returned `0xFF` alone does not prove invalid runtime: the stock RF-manager prefilter can suppress the selected slot before its runtime is checked. A valid proxy runtime with a missing stock getter marker can still return zero. The current BIN preserves those stock filters. The accounting active-slot byte alone does not identify RF-worker activity.

## Validation scope and history

The current physical validation covers Bambu PETG HF, physical slot 4 and the observed print/link session. Unload/reread, full rescan, other formats/backends/slots and worst-case timing remain hardware checks. Provider support and older QIDI/Bambu evidence are recorded in the [frozen historical tree](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3); they do not extend qualification of this exact image.

See the [current validation record](../../docs/CFG6_RDG2_VALIDATION.md) for offline regressions and physical snapshot evidence.
