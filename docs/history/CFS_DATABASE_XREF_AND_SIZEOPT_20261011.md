> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# Creality CFS v1.5.3 → v3.22: database path and safe-size audit

**2026-10-11 | STATIC / OFFLINE ONLY | no flash or serial access.**

Sources are SHA256-pinned original Creality CFS 1.5.3 application,
the currently validated v3.22 image, and the original assembler
`handler-v3_22.S`. The firmware files are **not committed**.

- Original 1.5.3: SHA256
  `5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea`
- v3.22: SHA256
  `40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`
- Read-only scanner:
  `firmware/v3.22-readonly-state-probes/database_path_and_sizeopt_audit.py`.
  Requires Capstone 5.x and GNU ARM assembler/objcopy/nm only if the optional
  disposable handler-size test is requested.

## 1. Real ROM database callgraph

The following original, byte-matched Thumb `BL` instructions were
verified in **both** original stock and v3.22:

| ROM callsite | ROM destination | Observation |
| --- | --- | --- |
| `0x080102EE` | `0x0801EEBA` | application startup calls database initialization |
| `0x0801EEBE` | `0x0801ED40` | database initialization dispatches setup |
| `0x0801ED50` | `0x0801EC72` | setup calls registry lookup |
| `0x0801C69C` | `0x0801ED82` | stock command handling calls database read helper |
| `0x0801C6D2` | `0x0801EDB4` | stock command handling calls database write helper |
| `0x08017066` | `0x0801EDB4` | separate stock caller of database write helper |
| `0x0801EEFA` | `0x0801EDB4` | database initialization/repair invokes write helper |
| `0x0801EA86` | `0x080318BE` | higher-level firmware Flash write wrapper → FMC word program |
| `0x0801EAEC` | `0x0803175A` | higher-level Flash erase wrapper → FMC 2KiB page erase |
| `0x0801EBB6`, `0x0801EBCC` | `0x0801EA78` | chunk writer → low-level Flash programming wrapper |

Associated exact, unchanged original ROM strings include:

- `rfid_mgr_fila_save` at `0x08036CB6`
- `rfid_mgr_fila_task` at `0x08036CC9`
- `database_get_value` at `0x08036D7C`
- `database_set_value` at `0x08036D8F`

The original high-Flash descriptor contains **one** exact pointer
`0x0807F800` at `0x08036D2C` and the nearby size word `0x800`
at `0x08036D38`. Other table entries reference `0x20004A20`
and preserved ROM procedures; the original and v3.22 descriptor SHA256
match.

### What is and is NOT proven

The original application genuinely initializes a database and has
executable read/write callsites. Independently it contains real GD32 FMC
erase/program routines with application-level wrappers. The descriptor
and adjacent RFID/database strings are strong evidence for a
non-volatile storage path.

**We have NOT established a complete direct or indirect control-flow
path** from a specific database/RFID key or the descriptor's
`0x0807F800` value all the way to an actual FMC hardware write of
page 255. The callback registry uses indirection, and original firmware
sometimes contains debug and static-table sections without a simple
direct branch. No runtime usage, sectors beyond `0x0803B800`, or
Creality bootloader max-app-length is certified by these crossrefs.

Accordingly: **do not erase, write, repurpose or probe**
`0x0807F800` on the only working CFS. A higher-risk live test would not
be warranted simply to close a static-analysis gap.

## 2. Correction: `config_v2_ensure` is NOT dead

The prior Phase-2 report identified `config_v2_ensure` as a candidate
~20-byte removal based on a one-occurrence name count.
That statement was **wrong**.

```asm
config_v2_ensure:
config_ptr:
    ldr r0, config_root_ptr
    ...
```

Both labels resolve to the **same address** `0x0803AF72` and
`config_v2_get_value` contains a **direct `bl config_ptr`**.
The routine is live via its alias; deleting it or its dependent
`config_expected_ptr` / `config_root_ptr` is unsafe. The Phase-2
documentation and source audit were corrected to explicitly report
alias reachability. A review that uses just grep counts to classify
firmware as dead code is not sufficient.

## 3. Actual offline size experiment (no release)

A separate source copy of the original v3.22 handler was used to
remove **only** this six-byte historical data table:

```asm
config_defaults: .byte 255, 100, 200, 155, 255, 80
```

The assembler's `.balign 4` resulted in just **4 bytes** of real
reduction.

| Item | Verified result |
| --- | ---: |
| Original complete v3.22 image | 178,140 B |
| Isolated test image after removing table | 178,136 B |
| Reduction | **4 B** |
| Candidate SHA256 | `a743f747a11528a1cc4f3b6d31296560946723db7ac9eb5769974a421ad3c1d0` |
| v3.22 handler compiled size | 2,468 B |
| Trimmed temporary handler compiled size | 2,464 B |
| Historical `0x0803B800` bound | Still within, but UNVERIFIED by loader |
| Live device flashed | **No** |

The full candidate was compiled in an isolated CM5 workspace using
existing preflight checks, and Unicorn emulator tests completed:
28 GET defaults, 21 SET/GET/RESET advanced parameters, invalid-bounds
rejection, busy-state rejection and actual default/patched behavior for
the effective ID7/ID8 timing hooks. It is **not** proof of physical
firmware equivalence or safe release; in particular no real MCU stack,
IRQ/RFID race, NVM persistence or bootloader erase map was exercised.
The candidate BIN remains private and is **not included in the PR**.

The public `database_path_and_sizeopt_audit.py` compiles **only
disposable handler fragments** in a temporary directory, verifies
both live aliases, reports the 4-byte size saving, and deletes these
fragments. It **cannot** be used to emit a flashable application.

Five CRC-corrected deliberate mutations are rejected by the read-only
stock/v3.22 xref test. The public CI runs the v3.22-only assertions,
without uploading vendor proprietary binaries.

## 4. Implication for v3.23

The event ring's already-prototyped core (~320 B ARM code) plus
trampoline, state guards and readback protocol cannot fit into a
four-byte saving. It would be unsafe to expand the deployed v3.22
image merely by assuming physical Flash beyond the old
`0x0803B800` policy is writable through the undumped loader.
Consider either more substantial proven-safe source compression or
alternative host-side telemetry on existing Kalico CFS messages,
without modifying the MCU Flash.

The **production v3.22 remains byte-identical** and unchanged.
Neither a firmware flash nor automatic advanced parameter writes
are authorised by this audit.
