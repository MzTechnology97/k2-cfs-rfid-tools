> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.22 — table-fed GPIO caller provenance (2026-10-15)

Read-only analysis of the saved v3.13 and v3.22 OEM application. The original application is linked at physical Flash address `0x08003000`. No live MCU access was performed.

The previous candidate census found 122 potential direct Thumb calls into the manufacturer GPIO write service at `0x08018EEC`. The existing bounded argument audit classified 58 calls using literal register assignments.

## Newly recovered source data

The original Keil scatter source at `0x0802DB6C..0x0802DE38` decompresses 716 source bytes in 251 tokens into 3012 SRAM bytes. Its initialized memory at `0x20000594` and `0x20000598` contains the logical pin numbers **0x1A** and **0x1B**. Six OEM literal loads in the `0x080144xx` and `0x08015Bxx` areas point to that pair; 29 separately pinned GPIO-call instructions obtain their pin ID from `[r4]` or `[r4,#4]`.

The function at `0x0801B7E4` reads the ROM descriptor at `0x0802B4CC`, whose first two pin bytes are **0x2B** and **0x2C**. Four further source-checked GPIO calls read those IDs through `LDRB`. The loop uses one 8-byte descriptor.

## Combined coverage

| Candidate type | Count |
|---|---:|
| Previously checked immediate argument pairs | 58 |
| RAM table-fed calls | 29 |
| ROM table-fed calls | 4 |
| Unclassified candidates | **31** |
| Original direct branch candidates | **122** |

The two audits explicitly verify that their classified callsite sets are disjoint. No source-classified group maps to the M1/M2 logical pin identifiers 0x30..0x33 under its static initialization assumptions. This is **not** a proof that M1/M2 cannot be commanded indirectly or that the listed code paths are reachable, or that initialized SRAM stays unchanged after boot.

The new reproducible offline script is `firmware/v3.22-readonly-state-probes/cfs_gpio_table_fed_callsite_provenance_audit.py`. It checks pinned original binaries, ROM instructions and table values; all ten deliberate corruption fixtures are rejected. GitHub Actions regenerates the exact v3.22 image and reruns this test.

**Release status: blocked.** The remaining 31 candidate branches, indirect and tail branches, runtime motor activity, ISR/task serialization, Flash layout and recovery remain unresolved. Firmware deployment and motor-active MCU SET/RESET have not been authorized.
