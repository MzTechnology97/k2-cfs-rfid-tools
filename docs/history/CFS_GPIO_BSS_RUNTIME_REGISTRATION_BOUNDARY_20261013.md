> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS GPIO dispatcher: ROM provenance vs runtime registration
*13 October 2026 — PR #24 · SHA-pinned v3.13/v3.22 saved images · offline only*

## Why the static GPIO callgraph could not identify M1/M2

The original RT-Thread GPIO write helper at physical Thumb PC
`0x08018EEC` receives a logical pin ID in `r0` and a desired
value in `r1`. The original helper loads a registered GPIO
device through `[r4 + 0x40]`, then dispatches through
`[device + 0x04]` with `BX r3`.

The saved original firmware's LDR literal at `0x0801916C`
contains the global object address `0x20004C44`.
Therefore the actual GPIO device pointer field is
**`0x20004C84`**.

The OEM scatter descriptors initialize data SRAM
`0x20000000..0x20000BC4`, followed by zero-initialized
SRAM `0x20000BC4..0x20006EE8`. The entire
`0x20004C84` field lies in the **zero-init BSS** region.
The saved application cannot supply its *post-initialization*
runtime callback value. It is populated later by device
registration; consequently no source-only tool may claim
to have recovered that callback from the decompressed 3012-byte
initial RAM image.

This distinction is verified by the
`cfs_gpio_dispatch_runtime_boundary_audit.py` test
on both pinned firmware versions. The test also reuses the
independently scanned **122 possible direct BL** sites
and isolates only those where two literal `MOVS` instructions
assign `r0` and `r1` in the four bytes immediately
preceding the `BL` instruction. The known PE4 brake
command at `0x0801119E` must resolve to
**logical pin 0x44, value 1**. Even such a contiguous
original ROM instruction sequence is not by itself a complete
reachability proof: a binary can contain data or alternative
control-flow entries.

No indirect dynamic callsite is declared recovered by a
ROM halfword scan. Other pin IDs may be loaded by table,
register transfer or conditional flow, so absence of
`MOVS r0,#0x30..0x33` immediately before a BL does not
prove that M1/M2 are not controlled by this helper.

## Next discriminating evidence

1. Identify the GPIO driver registration function and the
   assignment to `[0x20004C44 + 0x40]`, then reconstruct
   the driver's **actual** callback from original code,
   with verified call/return and branch reachability.
2. Trace PD0–PD3 pin arguments in source-accurate
   **caller dataflow**, rather than merely looking for
   nearby immediate constants.
3. For current-sense PC5/PC0/PA1/PA0, prove *reachable*
   ADC setup, channel selection and result consumption.
   A generic ADC0 result helper exists, but known saved-ROM
   scans found zero direct callers and zero aligned
   pointers to its Thumb entry.
4. Do not poll live `ADC_RDATA` just to discover values:
   such a read may clear EOC status. A verified non-invasive
   telemetry mechanism is required.

**No actual CFS/CM5 register reads or writes, no motion, no
firmware flash, no Kalico changes.** The v3.23 independent
motor-stop / atomic SET-RESET safety gate remains blocked.

## Verified CI result: original BLDC GPIO argument assignments

GitHub Actions passed the SHA-pinned v3.13/v3.22 audit.
Among **122 halfword-scanned BL encodings**, **58** sites have
the *strict* adjacent two-instruction `MOVS r0,#pin` /
`MOVS r1,#value` pattern (including reverse order).
Exactly **nine** of those sites target the already-proven
BLDC direction (PE3 / RT pin `0x43`) or brake
(PE4 / RT pin `0x44`).

| Source physical Thumb BL PC | Original pin | Literal value |
| --- | --- | ---: |
| `0x08011004` | PE3 direction | 0 |
| `0x08011014` | PE4 brake | 1 |
| `0x080110C0` | PE3 direction | 1 |
| `0x0801116C` | PE4 brake | 0 |
| `0x08011186` | PE4 brake | 0 |
| `0x0801119E` | PE4 brake | 1 |
| `0x0801135A` | PE4 brake | 0 |
| `0x0801139E` | PE4 brake | 1 |
| `0x0801153E` | PE4 brake | 1 |

All nine are now exact CI regression assertions. These are
byte-accurate Thumb sequences immediately before the call;
they do *not* constitute execution traces, timing evidence
or a measured peripheral state. The scan found no strict
adjacent-pair M1/M2 pins PD0–PD3 among these nine
motor-labelled pairs. Other callsites may calculate or
load the pin identifier in other ways, and
`B/BLX` indirect dispatch is not ruled out.

The practical next step is to trace **source-accurate
register dataflow** for the wider 122 candidates and the
actual RT GPIO device-registration callback. We must not
treat unclassified callsites as proof that M1 or M2 lacks
GPIO control.
