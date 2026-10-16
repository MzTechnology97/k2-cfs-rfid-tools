# CFS v3.23 — first hardware-test candidate, binary/header and loader-range preflight

*16 October 2026. This is a reproducible offline qualification gate, not release approval.*

## Current hardware-test scope (firmware ONLY)

The latest source-stacked v3.23 app (draft
[#49](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/49)) includes:

- OEM v3.22-based RFID reader and manufacturer tag functions;
- experimental volatile type-4 live usage/Creality length and guarded
  idle-only spool-removal cleanup;
- dual defensive FM15L013 secure-element paths under the original
  OEM usage task;
- read-only `0x57/0x15` BOX_STATE snapshot,
  `0x57/0x16` raw timer PWM-enable register snapshot,
  and `0x57/0x17` raw hub commanded-duty and FG IRQ counter snapshot;
- legacy runtime CONFIG INFO/GET; **CONFIG SET `0x57/0x12`
  and RESET `0x57/0x13` always return busy (status 7)**.

This deliberately excludes configurable motor speeds,
RFID speed, active buffer timeout, advanced runtime RAM
tuning and remote-set profile application. The extra already
installed on CM5 (`box_cfs_runtime.py`) remains untouched;
the existing `0xD7` experimental signature gates auto-apply.

## Offline reproducibility / preflight

New script
`firmware/v3.22-readonly-state-probes/cfs_v323_first_test_image_preflight.py`
loads only pinned v3.13/v3.22 original APP files,
fully assembles the current v3.23 in **transient Python memory**,
checks canonical header/CRC16, MCU vectors, unchanged
manufacturer RFID reader/secure functions, known complete
RFID+diagnostic handler symbols and disassembles the
fail-closed CONFIG SET/RESET branches. It *also executes*
12 original ARM CONFIG write attempts under Unicorn across all
six BOX_STATE values to prove no sidecar mutation.

Expected audited candidate:

| Property | Source-checked value |
| --- | --- |
| Physical APP base | `0x08003000` |
| Length | **178,520 bytes** |
| APP end exclusive | **`0x0802E958`** |
| Trial-only SHA-256 | `0439c780e75ef78de50e09d11070efecac62e11c0a77f442c601e01be7cdacd0` |
| Stored/recomputed CRC16/0x8005 | `0xF956` |
| OEM bootloader pages | 0–5; **not covered** |
| APP page coverage | **6–93 inclusive (88 × 2KiB)** |
| Last page start | `0x0802E800` |
| APP write buffering | 128-byte host chunks, 256-byte FMC buffers |
| Estimated host chunks | **1,395** |
| Buffered FMC chunks | **698** |
| Conservative padded end | **`0x0802EA00`** |
| Reserved manufacturer calibration/params | starts `0x0807F800`, page 255, **not reached** |

These are physical layout **facts** from the archived loader's
documented writer and our own bounded source images, not proof
that the *installed* loader has already accepted this binary.

The checked, hardware-used v3.22 rollback APP is still pinned
SHA-256 `40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`,
178,140 bytes.

The script fails closed if code generation changes the expected
SHA, CRC, header, reset/stack vectors, unchanged OEM RFID/secure
functions or either protected CONFIG entry. It additionally
rejects **8 mutated/bad images**: altered application base,
reserved-page overflow, zero image length, corrupted header
length or CRC, changed reset vector, truncated image and changed
manufacturer RFID reader.

No BIN, HEX, ELF, G-code, UART message or Flash programming is
produced. CI now uses this source-only preflight for every
subsequent candidate change.

## How far from the first physical test?

The **minimal first-test firmware feature set is already
implemented and rebuilt offline.** We can now focus on a small
test-entry procedure without completing the entire original
highly-configurable parameter roadmap.

Still required before an irreversible decision to flash the
user's only CFS:

1. **Non-destructive loader/recovery handshake:** verify the
   installed boot revision/enumeration using a known-safe read-
   only RS485 path and an independent power-cycle route. The
   archived bootloader design is documented; equivalence to
   the user's installed firmware is not yet proven by test.
2. **Recovery/rollback readiness:** preserve the latest known
   working v3.22 APP and user-specific parameter/calibration
   page, establish reliable old-image restore procedure, and
   refuse any update crossing its original geometry.
3. **Functional safety test acceptance:** separate normal OEM
   feeder behavior from experimental RFID (Creality/third-party,
   in-flight unload/removal/runout) and partial non-atomic
   motor telemetry. The new experimental task transitions have
   no complete physical RT-Thread/ISR interleaving coverage;
   no new MCU motor writer is enabled.

Not required for this intentionally read-only/limited prototype:
Kalico edits, user speed profiles, applying ID9–27 parameters,
new event ring or a full OpenCFS firmware port. They remain
future development after the first controlled physical test.

**Status**: Image-format preflight PASSED offline; installed-CFS
Flash permission **DENIED** until outstanding test-entry gates
are explicitly qualified. Neither the only CFS, the CM5
Kalico installation nor the proprietary full firmware binary
has been modified/published.
