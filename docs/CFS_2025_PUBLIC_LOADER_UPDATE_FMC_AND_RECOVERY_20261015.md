# CFS loader `0xF0/0x01` update path: original 2025 ROM evidence

*15 October 2026. Supplemental offline audit, stacked on PR #37.*

## Why this audit was added

OpenCFS draft
[PR #5](https://github.com/MzTechnology97/OpenCFS-Firmware/pull/5),
commit
[`6b0b511`](https://github.com/MzTechnology97/OpenCFS-Firmware/commit/6b0b51143261022dc7bacfba7c690d6e73f13887),
now includes a detailed specification at
`docs/spec/08-loader-and-recovery.md`. This describes the public
historical loader's **30-second boot window**, RS485 `0xF0`
subcommands, image upgrade and recovery.

Instead of treating that document as a verified description of the
user's installed bootloader, this audit **independently inspects
original Thumb machine code** from the exact SHA-256-pinned public
2025 512-KiB Flash dump. It only reproduces bounded program-address
facts; it does **not** attempt an update.

## Recovered OEM path (all physical Flash addresses)

| ROM address | Source-verified meaning |
| --- | --- |
| `0x08001A32..0x08001A38` | Loader eight-way `0xF0` dispatch table |
| `0x08001A40` | Original 32-bit slot 1 points to **`0x08001E0D`**, update entry |
| `0x08001E26` / `0x08001E2A` | Reads **4-byte** image length through OEM serial helper `0x0800136C` |
| `0x08001E80` / `0x08001E84` | Reads **128 bytes** at a time from the host |
| `0x08001E94` / `0x08001EF4` | Both write/flush paths invoke the shared buffered writer `0x080003B0` |
| `0x080003B0..0x080003DC` | Builds up to **256 bytes** in SRAM, then enters FMC programming |
| `0x080003EA..0x080003EE` | Tests destination address `mod 0x800` (2 KiB) to decide whether to erase a page |
| `0x08000426` | Invokes original page erase helper `0x080002B8` |
| `0x080002DE` | Page erase command loads the physical destination into FMC page-address register |
| `0x08000466..0x08000468` | Writes/checks a 256-byte buffered block |
| `0x08001A88` | Original APP start literal **`0x08003000`**, loaded by update dispatcher |
| `0x08001A54` / `0x08001D66..0x08001D6C` | Separate `0xF0/0x06` command erases final Flash page **`0x0807F800`** |

There are **33 exact OEM Thumb instructions, 8 dispatch
slots and 8 original literals** pinned against the published Flash
image. They are not derived from the C++ reimplementation.

The FMC erase helper also has a silicon density-dependent branch
that references `0x0807FFFF`. This is **not a dedicated
application-vs-parameter-page guard**. The observed application
update writer route contains no separately pinned compare against
`0x0807F800`. However, **this is not a full negative proof about
every loader path or every installed-loader revision**.

## Comparison with our saved images

- Original APP start: **`0x08003000`**.
- Known v3.22 APP length: **178,140 bytes**, last byte before
  `0x0802E7DC`; occupies Flash page index 92.
- Our **offline-only** v3.23 GET snapshot APP: **178,176 bytes**,
  exclusive end **`0x0802E800`**, also ending in page 92.
- Parameter page reserved by historic loader: **`0x0807F800`**
  (Flash page 255). These known-size images do **not** touch it.

**Critical safety boundary:** a hypothetical image ending exactly at
`0x0807F800` does not cover the reserved page; one more byte would.
The entire theoretical region to that last page is **NOT certified
available** for application code and must not be treated as a
recommended build size. The old arbitrary policy `0x0803B800`
is likewise not an authenticated loader limit.

## Automated proof

`firmware/v3.22-readonly-state-probes/cfs_public_2025_loader_update_page_geometry_audit.py`
verifies the public Flash hash and original Thumb/data references,
then runs **seven in-memory page-address boundary scenarios**,
including the exact v3.13, v3.22 and current v3.23 sizes, an image
ending on the parameter-page boundary, and images extending one byte
into the reserved page or past the 512-KiB physical Flash. It rejects
**14 synthetic mutations** to command routing, writer, page erase and
FMC target instructions/ROM constants.

This tool is **not an uploader** and cannot issue RS485 commands.
No installable BIN/ELF, write operation, SWD call, GPIO change or
Kalico access is performed.

## Recovery is a documented stock-loader feature — exact qualification limit

The independent OpenCFS loader specification (PR #5) documents
the existing manufacturer boot-window and recovery protocol; this
audit pins its `F0/01` writer path, APP base and parameter erase
behavior against the archived full Flash. **We no longer need to
invent a recovery protocol for v3.23.** The two outstanding
uncertainties are the installed loader's byte identity and a safe
hardware recovery check, neither of which invalidates the
*archived loader design*.

The APP begins at `0x08003000` and must have exclusive end no
later than `0x0807F800`, so the purely arithmetic image span is
`0x7C800` = **509,952 bytes**. This is NOT a vendor-approved
maximum length and the old `0x0803B800` build-policy address
is not a loader enforcement limit. The experimental #40 type4
candidate ends at `0x0802E8B0`, inside the observed geometry.

## Recovery assumptions still unverified on the installed MCU

The OpenCFS PR #5 historical specification says enumeration within
the initial ~30-second window can keep the old loader running,
and an invalid app CRC keeps it in loader mode. Those are valuable
recovery leads, but **we have not tested them on the real CFS**.

More importantly, a validly CRC-signed firmware that reprograms
the loader, option bytes, or protected Flash can defeat ordinary
recovery. An interrupted upgrade could leave system metadata or
other Flash data in an unexpected state even if its APP CRC fails.

Before saying "ready to flash" we require all of:

- independently establish installed-loader version/identity and
  address/erase coverage or qualify a recoverable spare unit;
- verify power-cycle/boot-window/enumeration and command `0xF0`
  access from a separate host without sending any write/erase command;
- preserve/recover the last page containing calibration/parameters;
- verify all motor, preload, stage4 direct UART and RFID
  operations are safely excluded at the MCU task/ISR level;
- exact image diff, bootloader-compliant CRC/header/length, and
  a tested rollback route.

**No new v3.23 firmware has been flashed or approved.**
