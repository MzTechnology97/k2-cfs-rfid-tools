> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.22 STOCK branch relocation — source and saved-image audit
*15 October 2026 · offline-only continuation, stacked on draft PR #24.*

## Finding: all 11 current external `STOCK_*` branches preserve the OEM target

The v3.22 assembly/linker nominally locate the appended handler at
`0x0803AE38`, using an obsolete assumed APP origin `0x08010000`.
The saved source APP is actually linked at `0x08003000`, so the
handler executes at physical `0x0802DE38`. Both callsite and target
move by `-0xD000`.

The new `cfs_v322_stock_branch_relocation_audit.py` compiles the
**unchanged** handler into a temporary ELF/BIN, byte-compares the raw
handler against the exact SHA-pinned v3.22 saved APP tail, parses the
assembler's symbol-aware disassembly, then *independently* decodes each
real physical branch from those same raw bytes.

All **11/11** manufacturer `STOCK_*` references in this handler are
32-bit **PC-relative** `BL` or `B.W`; their translated destinations
lie inside the preserved vendor-app portion of the saved image, and
the first target instructions agree across the saved v3.13 and v3.22.

| OEM reference | Count | Verified actual MCU destination |
| --- | ---: | --- |
| `STOCK_MEMCMP` | 3 | `0x0802693C` |
| `STOCK_MSG_VALIDATE` | 1 | `0x0800D670` |
| `STOCK_REMAIN_INIT` | 1 | `0x0800DA14` |
| `STOCK_REMAIN_VALID` | 1 | `0x0800545C` |
| `STOCK_REMAIN_GATE` | 1 | `0x080032E2` |
| `STOCK_51` | 1 | `0x0800F704` |
| `STOCK_INVALID` | 1 | `0x0800F7F8` |
| `STOCK_DONE` | 1 | `0x0800F808` |
| `STOCK_HEAP_INIT` | 1 | `0x0801A8D4` |

Thus the earlier warning that `STOCK_MEMCMP=0x0803393C` is outside
the *physical* saved-app image is **not by itself an erroneous runtime
call**: `0x0803393C` is the old nominal assembly address, and the
existing relative branch bytes execute at `0x0802693C`.

The source audit rejects four synthetic negatives: altered saved
handler bytes, wrong OEM branch target, introduction of an indirect
`BLX` in place of an authenticated `BL`, and a new unaudited absolute
`STOCK_*` symbol. GitHub CI and local CM5 saved-image replay both
use pinned immutable inputs.

## Strict limits

The conclusion covers **only these 11 instruction-relative external
ROM branches in the exact v3.22 handler**. It does *not* prove that any
other literal-pool addresses, in-memory absolute function pointers,
direct data references, future v3.23 extensions or separately patched
call sites are correctly mapped. No update-loader app length/erase
ownership, NVM safety, spare RAM, physical motor idle or MCU atomicity
has been authenticated.

The v3.23 release and motor-active MCU SET/RESET remain blocked by
issue #9 and the nine release criteria. No new flashable BIN, firmware
modification, serial command, movement or CFS hardware access occurred.
