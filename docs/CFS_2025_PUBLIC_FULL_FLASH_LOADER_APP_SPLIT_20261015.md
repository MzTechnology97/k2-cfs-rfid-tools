# CFS full public 2025 Flash: bootloader and application split

*15 October 2026 — offline comparison. No CFS MCU, serial, GPIO, motor or flash I/O.*

## Source recovered (not missing)

The historical full-flash dump is already published in
[fake-name/cfs-reverse-engineering](https://github.com/fake-name/cfs-reverse-engineering)
at `reversing/live_dumps/0x0800_0000.bin`.
The source repository commit inspected locally is
`d9453317d7649b28b87771c63255551293b07aaf`, and the public
Flash has **524,288 bytes** and SHA-256
`58b8b90890c08aae81235dd4625fc75ff955e09e82f6c47ee2d74276498bc125`.
Exact public Git blob SHA-1 is
`44e2d48a144356c1ae2b3fe0b4e23175c050e28e`.
The public RAM snapshot is separate and is **not needed** for this audit.

**Do not copy the public full binary or proprietary Creality loader code
into the project repository.** The source-only test transiently reads
the independently published binary after checking its fingerprint.

## Proven geometry in this archived historical CFS instance

| Physical Flash address | Historical dump evidence |
| --- | --- |
| **`0x08000000`** | Initial valid ARM vector table: MSP **`0x20010000`**, Thumb reset **`0x080005B9`** |
| `0x080005B8` | Initial loader code disables interrupts, sets its stack and branches to `0x08001F29` |
| `0x08002270` | Last nonzero byte in lower 12-KiB region; the entire `0x08002400..0x08002FFF` tail contains zeros |
| **`0x08003000`** | Independent **application** vector: MSP **`0x20005420`**, Thumb reset **`0x08015B21`** |
| `0x08000AA4`, `0x08001360`, `0x08001A88` | Three exact 32-bit original loader literals equal to **`0x08003000`**, loaded by authenticated Thumb PC-relative instructions |

The historical loader handoff sequence at
**`0x0800134C..0x0800135E`** reads the destination
application's reset vector from `[APP_BASE+4]`, reads its initial
MSP from `[APP_BASE]`, loads the CPU MSP with the original ARM
`MSR MSP, r2` encoding and transfers to the application's reset
address with `BX r3`. The setup source obtains
`APP_BASE=0x08003000` at `0x08001306`.

This establishes a **bootloader/application split in the historical
2025 unit**, with an original loader starting at `0x08000000` and
an application beginning at **`0x08003000`**. It does not prove that
the loader occupies every byte before that address, or that the
currently deployed CFS shares the exact same loader revision.

**The older `0x08010000` application address in historical internal
reports was an incorrect, nominal tooling origin** used to examine
our later, separately saved Creality v3.13/v3.22 application. The
correct physical base of those saved APP bytes is also `0x08003000`.
The complete public 2025 firmware is a **different manufacturer
generation** and its application content differs from v3.22.

## Bootloader checksum compatibility confirmed

The historical boot ROM checksum routine at **`0x08000A08`**
is an MSB-first 16-bit CRC with polynomial **`0x8005`**.
Original code reads the saved application header near
`0x0800320C` and calculates the checksum over the
documented two ranges that omit the six metadata bytes at
APP offsets `0x20C..0x211`.

From the archived APP header:

- Declared APP length **150,312 bytes** (`0x24B28`).
- Historical APP end **`0x08027B28`**.
- Stored CRC16 **`0x172F`**.
- Independently recomputed CRC16 **`0x172F`** (exact match).

The separately saved current v3.13 and v3.22 application images
use the same header/checksum convention. The known-good
v3.22 ends at **`0x0802E7DC`**, with CRC16 **`0xC36F`**.

Our first v3.23 *offline* prototype ends at **`0x0802E800`**:
the end of page 92, **not** a demonstrated loader maximum.
The old hypothetical physical source-build limit is
`0x0803B800`, leaving **53,248 arithmetic bytes** to that
arbitrary point. No part of that gap is certified free or loader
accepted. The fact that the old loader checks a CRC does **not**
prove it has a safe larger-image acceptance/erase policy.

## Additional original loader update command finding

The historical 8-way receive dispatcher at
`0x08001A32..0x08001A38` uses ROM Thumb pointers.
Its **slot 6** points to `0x08001D5D`. The code at
`0x08001D60..0x08001D70` disables interrupts, initializes
Flash programming, loads an original literal
**`0x0807F800`** at `0x08001DD8`, calls the
manufacturer FMC Flash page-erase helper
**`0x080002B8`** and then locks Flash and
reenables interrupts.

This establishes that **one historical loader dispatch path
explicitly requests an erase of the final 2-KiB Flash page**.
It does **not** establish where all application firmware update
pages are erased, which pages the current loader uses, or
whether this slot can be invoked from a specific unauthenticated
external connection. Do not run this operation on the user's
production device.

## Automated test

`firmware/v3.22-readonly-state-probes/cfs_public_2025_loader_app_split_crc_audit.py`:

- authenticates the full public Flash SHA and Git blob;
- pins both source vector tables and three independent
  loader-to-application `0x08003000` literal references;
- pins Thumb load/branch/handoff code and the historic CRC16;
- proves historic APP metadata and modern v3.13/v3.22 checksums;
- checks corrected 2-KiB page numbers;
- rejects **18 synthetic corruptions** covering loader vectors,
  app vectors, the CRC polynomial, handoff and header;
- **never** accesses a physical CFS or publishes a BIN/HEX/ELF.

## Unresolved release blockers

The public 2025 dump is a strong analysis reference, **not a
confirmed dump of the user's currently deployed bootloader**.
We still must authenticate current-loader version/bytes,
max application length, exact FMC erase ranges and page
ownership, watchdog/reset and interrupted-update recovery,
and independent motor-stop evidence plus atomic task/ISR
exclusion. All nine mandatory release gates remain open.

**The v3.23 experimental image must NOT be flashed yet.**
