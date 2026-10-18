# CFS v3.22: 118 of 122 OEM direct GPIO calls source-classified

Offline audit, 15 October 2026. Pinned original v3.13 and exact SHA-identical rebuilt v3.22 MCU APP, physically linked at `0x08003000`. No live serial, CFS flash, motor activity or Kalico changes.

The original executable yields 122 **candidate** direct Thumb `BL` encodings to OEM RT-Thread GPIO dispatcher `0x08018EEC`. Prior source audits classified 94 candidates. This audit identifies **24 additional** calls by provenance of their pin ID:

| Provenance | New direct BL sites |
| --- | ---: |
| Two halfword pin pairs initially at RAM `0x200001D0`: 0x18/19 and 0x1A/1B | 15 |
| Ten-word initialized GPIO list at `0x20000218` | 1 |
| Four pin pairs initially at RAM `0x20000528` | 2 |
| Parameter-indexed command using the same table | 1 |
| Consecutive source immediate pin IDs 0x21..0x24 | 4 |
| Conditional fall-through at `0x0800A5C8`, where `CMP r0,#0x10` plus `BNE` constrains pin r0 to 0x10 | 1 |
| **Added** | **24** |

**118/122** direct branch-pattern candidates are now classified by source. Four are still driven by a *runtime argument* rather than a pinned initial table: `0x0800727C`, `0x08007298`, `0x080072E8`, `0x08007302`. The source shows argument-fed pins in OEM functions `0x08007264` and `0x080072D0`. Some direct callers to these functions supply constant pin pairs, but their complete indirect/reachable caller set is **not** yet proven.

The new script `firmware/v3.22-readonly-state-probes/cfs_oem_gpio_deeper_indirect_tables_audit.py` checks original opcode addresses, ROM literal targets, bounded Keil scatter decompress, exact initialized RAM hash, loop bounds, static table contents, set disjointness and four explicitly unresolved sites across both saved firmware generations. **20 synthetic mutated ROM/RAM cases are rejected.** The extended GitHub Actions workflow rebuilds v3.22 and runs the same fail-closed audit.

**Important limitations:** initialized RAM values can change in service; 122 branch patterns do not enumerate `BLX` callback dispatch or `B.W` tailcalls, and none of these software GPIO values proves a motor electrically stopped. The motor-active false-IDLE defect (issue #9), interrupt/task atomicity, Flash/RAM ownership and loader recovery remain unverified. **Motor-active MCU SET/RESET and v3.23 flashing remain prohibited.**
