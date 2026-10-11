# CFS G32 / application 153: offline bootloader address/length audit

**Status (2026-10-11): evidence collected, loader maximum NOT recovered.**

The exact Creality v1.5.3 application, tested-equivalent v3.22 application
and original Creality `mcu_util_485` ARM ELF were independently SHA-pinned
and inspected *only as files*. No MCU state, serial line, RS-485, Flash or
EEPROM was accessed or altered.

This is stacked on [Phase 2 Flash/RAM audit](CFS_FLASH_RAM_PHASE2_20261011.md)
and original-firmware [v3.22 static audit](../firmware/v3.22-readonly-state-probes/README.md).
Machine-generated sanitized
[BOOTLOADER_STATIC_EVIDENCE.json](../firmware/v3.22-readonly-state-probes/BOOTLOADER_STATIC_EVIDENCE.json)
is reproducible using
`firmware/v3.22-readonly-state-probes/bootloader_static_audit.py`.

## A. Three boundaries that must NOT be confused

| Address | Meaning | Certainty |
| --- | --- | --- |
| `0x08000000` | Beginning of main MCU Flash (if GD32F303VET6 marking is correct) | silicon specification, hardware marking NOT independently verified |
| `0x08010000` | Link base of shipped CFS app image; first 64 KiB below may contain a custom Creality RS-485 loader | **application address verified**, actual loader content NOT dumped |
| `0x0803B800` | Historical manually imposed **build-policy** stop | **NOT** found in original application as 32-bit literal; NOT a proven loader limit |
| `0x08040000` | End of first 256 KiB region with fast instruction fetch | latency/performance boundary, NOT a prohibition on instruction fetching beyond |
| `0x0807F800` | Start of final 2 KiB physical main Flash page (page 255) | original CFS application contains this exact pointer |
| `0x08080000` | End-exclusive of 512 KiB physical main Flash | silicon specification, NOT necessarily free application space |

GigaDevice GD32F30x User Manual §2.1-2.3
(https://www.gd32mcu.com/data/documents/userManual/GD32F30x_User_Manual_Rev2.9.pdf)
states main Flash bank0 erase pages are **2 KiB** for the 512 KiB
high-density parts and explicitly describes instruction fetch beyond the
first **256 KiB**, with extra latency. Treat the datasheet's CODE/DATA
split as a **performance classification** rather than a hardware execute
permission. Moving timing-sensitive CFS routines beyond `0x08040000`
would require proof that the bootloader supports that region and new
latency, IRQ, motor and RFID regression tests.

The chip vendor's factory System Memory loader (separate information
block) must not be confused with the **undumped custom Creality RS-485
loader** suggested by the application's `0x08010000` relocation.

## B. Exact application/Flash page map

The v3.22 application (178,140 bytes; SHA256
`40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`)
ends at `0x0803B7DC` exclusive. The last written byte is on **page 118**.

| Pages (0-based, 2048 bytes each) | Address range | Interpretation |
| --- | --- | --- |
| 0–31 | `0x08000000..0x0800FFFF` | separate 64 KiB region; custom loader candidate, NOT dumped |
| 32–118 | `0x08010000..0x0803B7FF` | v3.22 app bytes; 36 bytes remain unused inside final page |
| 119–127 | `0x0803B800..0x0803FFFF` | **nine unknown pages = 18,432 bytes** below fast-fetch boundary |
| 128–254 | `0x08040000..0x0807F7FF` | slower-fetch Flash, ownership UNKNOWN |
| 255 | `0x0807F800..0x0807FFFF` | **address explicitly present in original Creality app**; role NOT verified |

The old bound `0x0803B800` happens to align precisely to page 119;
this **does not** prove the loader owns that page or that it is free.
Neither an aligned address nor the omission of an address from compiled
application constants can certify absence of loader use.

## C. Original application has a high-Flash pointer table

An exact 56-byte table at `0x08036D10..0x08036D47` contains
the following **unaltered in both original Creality 1.5.3 and v3.22**:

| Table address | 32-bit little-endian word |
| --- | --- |
| `0x08036D2C` | `0x0807F800` — final physical main Flash erase-page start |
| `0x08036D30` | `0x00000001` |
| `0x08036D34` | `0x0802C598` — within original app ROM |
| `0x08036D38` | `0x00000800` — precisely one 2-KiB page |
| `0x08036D3C` | `0x20004A20` — SRAM-region address |

The table also contains several original ROM references near
`0x0802C53C..0x0802C57C`, and the table's SHA256 is checked byte-for-byte
against the v3.22 variant. The grouping is **strong evidence worth
investigating** for an original high-Flash persistence/configuration path,
but is **NOT proof of runtime reads/writes** to the last page. A direct
live flash-write claim would require a full function/xref/control-flow
analysis or a validated non-invasive physical trace. We have not made one.

Accordingly **do not allocate code or ring persistence anywhere in the
second 256 KiB simply because it exists physically**; this would risk
colliding with original persistent use and with a higher flash-fetch cost.

## D. Creality host updater vs MCU loader

Original ARM userspace updater ELF SHA256:
`dcf3a63136d5ef5766812c22ac243640e26b5600400ef951091ff72fcc0784d8`.

Read-only disassembly confirms a `lseek(fd, 0, SEEK_END)` near ELF VA
`0x000135F0` and storing the length in updater state near `0x000135FC`.
The previously reconstructed firmware-update state machine sends:

`F0/00` identity → `F0/03` token → `F0/06` erase →
`F0/01` update request → raw 32-bit little-endian image size →
streamed app-data chunks → `F0/02` application start.

The exact `G32` token `0xE0` observed during an **earlier authorised
physical probe** decodes to **128-byte RS-485 transport chunks**:
`(-32 × 252) mod 256 = 128`. It does **NOT** specify physical Flash
erase-page size or maximum allowed application length. The host
does not supply a destination Flash address with app-data chunks; the
loader must select where to write. That protects against arbitrary host
address selection but **does not prove erase/write safety**.

Crucially, analysing the host updater is **not analysing the loader
itself**. This static work does NOT establish whether the host or the
loader checks an application size, whether tail pages 119–127 are protected,
which pages `F0/06` erases, nor how the device behaves after interrupted
programming. An apparent absence of a checked bound in one disassembly
path must NOT be used as permission to test larger images.

## E. Missing evidence and non-invasive next step

No authenticated raw image of the custom CFS bootloader was found among
the available original firmware packages or saved local artifacts;
the original app image begins at `0x08010000` and does not contain
that region. We cannot deduce arbitrary loader branch conditions from
application code or a 128-byte packet token.

To close this gate without modifying a production CFS, obtain one of:

1. Creality's original G32 bootloader binary + matching linker script
   or authenticated maximum-app/Flash page layout.
2. A **read-only acquisition from a spare, recoverable CFS** with
   verified SWD read permissions and a backup plan. Do NOT alter RDP
   protection, mass-erase, request option-byte unprotection or turn
   on the debug probe's automatic reset/flash actions.
3. Equivalent trusted dump gathered previously by an authorised operator.

If a 65,536-byte lower-Flash dump becomes available, the auditor accepts
`--bootloader-dump /private/path/creality-cfs-loader-64k.bin`
and reports its SHA and candidate boundary address literals. That scan
is intentionally **not considered proof** until the loader's call
graph, erase policy, address-range arithmetic and max-size guard have
been independently reviewed.

## F. Reproducible offline checks

```bash
python3 firmware/v3.22-readonly-state-probes/bootloader_static_audit.py \
  --stock /private/unmodified-cfs153.bin \
  --v322 /private/pinned-v322.bin \
  --stock-updater-elf /private/mcu_util_485 \
  --self-test \
  --json-out /tmp/BOOTLOADER_STATIC_EVIDENCE.json
```

**Observed:** stock table equals v3.22 table, original address `0x0807F800`
and adjacent `0x800` verified, exact ARM host ELF fingerprints verified,
page numbering passes, **4 intentional corruptions are rejected**,
and no loader image available. No binary, passwords, hardware identifiers
or serial logs are committed. CI also runs the v3.22-only check after
reconstructing the SHA-pinned firmware image.

**Conclusion:** no new address range beyond the currently constrained
v3.22 firmware is certified for a v3.23 image. `safe_to_expand_CFS_binary`
remains `false`; leave motor activity protections, host mutex and
`flash_allowed` disabled until proven otherwise.
