# CFS v3.23 — legacy/Creality RFID type-4 LIVE remaining (offline firmware candidate)

*16 October 2026 · built on the v3.23 read-only GET snapshot in draft PR #35,
historical-loader audit #38 and the other agent's OpenCFS type-4 analysis.*

## User requirement and outcome

On a CFS board **without** the FM15L013 secure element (hardware flag
`0x20000000 == 0`), the OEM firmware currently skips its remaining-filament
usage manager, including for runtime type-4 records. This leaves percentage
`0x03` static throughout printing, even though the original type-4 usage
math and odometer are implemented.

The first **strictly offline** v3.23 candidate changes that behavior:
existing initialized **valid type-4 printing** records may run the original
`rfid_mgr_fila_task`, which updates `used_mm` at 10 mm increments and
recalculates remaining percentage in RAM. It **does not write tag EEPROM,
MIFARE sectors or FM15L013 data**. For Creality-origin tags on legacy boards,
the stock initialization retains the tag's actual nominal length instead
of imposing the 330,000 mm third-party fallback, then converts only the
in-memory usage record to type 4.

This is source-/emulator-verified new code, **not a release**. The use of
the original usage task is not proved safe against concurrent task/ISR
changes while printing.

## Source provenance and ABI

Evidence: [OpenCFS PR #6](https://github.com/MzTechnology97/OpenCFS-Firmware/pull/6)
(corrected type-7 secure-element behavior), plus the independently
reconstructed OEM function at `0x0800DC94`, and the other agent's local
`cfs-firmware-re/docs/09-live-remaining-legacy-patch.md`.

| Physical ROM PC | Existing/experimental behavior |
| --- | --- |
| `0x08006380` | **existing** `remaining_gate_wrapper`; unchanged inbound hook location |
| `0x08006388` | original `cmp.w sb, #0` checks Creality tag-read register `r9` |
| `0x08006394` | **existing** `remaining_init_wrapper`; unchanged inbound hook location |
| **`0x08006684`** | **one added BL** replacing the stock `STOCK_REMAIN_GATE` call **only in the preload loop** |
| `0x08006688..0x0800668C` | stock `cmp r0,#1` / skip / call `rfid_mgr_fila_task` stays unchanged |
| `0x080032E2` | original secure-chip hardware-flag gate; still used by the new wrapper |
| `0x0800DC94` | original, unchanged OEM per-slot usage manager |

The new wrapper `live_type4_usage_gate` returns the stock result on a
secure-element board. With no chip, it returns 1 **only** when the
current physical slot `[0x200001F0+2]` is in range 0..3 and
the existing runtime record at `0x20004590 + slot*100` has:

- `valid(+0x17) == 1`
- `mode(+0x16) == 1` (printing)
- `type(+0x63) == 4`
- `total_mm(+0x04) >= 10000`
- `initial_percent(+0x14)` within 1..100.

With no valid record or in idle/unload mode (including **mode 2 after
filament unloading**), the task is **not invoked**. This avoids the
known unsafe no-record/dirty and unloading/dirty routes into
`FUN_0800D83E` (secure `rfid_detect_tag`) on legacy hardware.
It also means the old 30-second mode-2 reset may be delayed until a
later command `0x04` changes the mode.

The existing `remaining_gate_wrapper` keeps its original third-party
capture acceptance, and additionally returns 1 on a legacy board when
`r9 != 0`, as the original Creality caller already checks.
The existing `remaining_init_wrapper` keeps the original third-party
proxy code **unchanged**. For a legacy Creality record, it calls the
**original stock `STOCK_REMAIN_INIT`**, checks that the initialized
record is valid and has a plausible total and starting percentage,
and changes **only the RAM runtime type at +0x63 to 4**.

All original readers, chip initialization, `0x0800D624`,
`0x0800D694`, and all other `STOCK_REMAIN_GATE` callsites
remain as before. **No device registers are written by the new gate.**

## Offline compiler / Flash checks

Source-only command:
`firmware/v3.22-readonly-state-probes/cfs_v323_legacy_type4_live_usage_candidate.py`.

This script first reconstructs the **exact SHA-pinned saved v3.22 APP**
and the first, read-only v3.23 snapshot in memory. It then applies
anchored transformations to copies of existing assembly text, relinks
at the physical `0x0802DE38` handler origin, and checks all
existing **14 inbound OEM hook targets** and **15 outgoing original OEM
code references**, plus the additional one stock gate call:

- v3.22 original: **178,140 bytes**.
- v3.23 GET-only snapshot: **178,176 bytes**.
- new type-4 experiment: **178,320 bytes**, exactly **+144 bytes**
  over the GET-only snapshot.
- End-exclusive `0x0802E890`, **physical Flash page 93**
  (crosses the old GET snapshot's end at page 92).
- Historical reserved parameter page `0x0807F800` is untouched
  by this image length. **This arithmetic does not verify actual loader
  erase ownership, image-size checks or rollback**.
- No new static SRAM/heap/event ring. The only added nonstack write
  is to the OEM `REMAIN_RUNTIME[slot].type` of an existing record.
- **15 total inbound OEM BL hooks**, unchanged 14 plus
  `0x08006684`; 16 outgoing OEM references, preserved old 15
  plus OEM hardware-flag gate.
- All changed original APP-prefix bytes are restricted to the 15 hook
  sites and the recalculated CRC/length metadata.
- No persistent firmware BIN/ELF/HEX is created.

## Emulator and negative checks

Unicorn exercises:

- **17 guard cases:** valid type4 printing on legacy boards, invalid/
  missing record, mode idle/unload, type 7, out-of-range slot,
  malformed total/percentage, unchanged secure board behavior.
- **17 existing-wrapper cases:** Creality tag-read flag r9, no tag,
  invalid slot, secure board, stock init with original tag lengths,
  invalid stock runtime, invalid nominal length/percentage. The stock
  initializer in these wrapper tests is an **explicit synthetic stub**:
  its real physical execution and record parsing are **not** validated
  by these cases.
- **13 OEM instruction sites** pinned on both saved generations,
  including `sb == r9`, and the old hook target addresses.
- **4 fail-closed source/reference mutations**, verified locally.

Original OEM `rfid_mgr_fila_task` itself is **not** executed in
these tests; only the new gate and existing wrapper paths are
emulated. A real filament-consumption regression on hardware remains
essential.

## Open issues: NOT flash-qualified

1. **Task race:** record `valid/mode/type` can change **between**
   `live_type4_usage_gate` returning 1 and the OEM task inspecting
   the record. That is not an atomic, independently qualified guard
   against a secure-chip call, even though static cases pass.
2. Need verify all reachable OEM usage-task branches and interrupts
   through unloading, print start/end, spool removal, reset and
   reloading; including paths to the FM15L013 `FUN_08015A42`
   and `FUN_0800D83E`. Currently those functions remain in the
   unmodified OEM ROM.
3. **Host integration not yet implemented.** The new INFO capability
   flag should only be advertised after hardware and atomic guard
   qualification. Kalico/CM5 persistence/fallback/reset semantics
   require a separate tested PR.
4. Bootloader installed identity, page-93 erase/write acceptance,
   physical backup and interrupted-upgrade recovery remain unproven.
5. Existing motor-idle and other v3.23 release gates remain false.

The prototype is **source only**, not delivered as a flashable
firmware; no live CM5 Kalico config, CFS MCU, serial/SWD or motors
were changed. Do not flash this experiment.
