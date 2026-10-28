> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# Creality CFS G32 — original application FMC / Flash persistence audit

**Date: 2026-10-11. Scope: offline static reverse engineering, not a live MCU operation.**

This investigation examines exact local copies of the original Creality CFS
v1.5.3 application (175,672 bytes, SHA256
`5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea`)
and the verified v3.22 application (178,140 bytes, SHA256
`40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`).

## Bottom line

**Original Creality application code contains a real GD32 Flash erase/program
driver and caller wrappers.** The application also contains a descriptor
word naming the MCU's last main-Flash page (`0x0807F800`).
Both the driver and the descriptor have been preserved without modification
in the tested v3.22 image.

This **does not** show that the last page is actually erased or programmed
during normal CFS operations: a proven caller-to-descriptor-to-hardware
runtime path is still missing. It also does **not** reveal the custom RS-485
bootloader's application size/erase restrictions.

## Recovered stock firmware calls and hardware evidence

Using Capstone Thumb-2 disassembly at pinned original ROM addresses:

| Stock ROM address | Observation | Significance |
| --- | --- | --- |
| `0x080319FC` | load register base `0x40022000` | GD32 FMC register bank |
| `0x08031A04`, `0x08031A08` | `0x45670123` then `0xCDEF89AB` | FMC unlock sequence |
| `0x0803175A` | page-erase routine entry | stock ROM routine |
| `0x0803175E` – `0x08031766` | reads MCU Flash-size halfword at `0x1FFFF7E0`, compares 512 KiB | generic driver selects bank |
| `0x0803177E` | set `FMC_CTL0.PER` bit 1 | begin page erase |
| `0x08031784` | write caller-supplied page address to `FMC_ADDR0` offset `0x14` | **page address is NOT fixed in driver** |
| `0x08031788` – `0x0803178C` | set `FMC_CTL0.START` bit 6, write control | launch erase |
| `0x080318BE` | program-word routine entry | stock ROM routine |
| `0x080318E4`, `0x080318EA` | set `FMC_CTL0.PG` bit 0; write word to caller address | Flash programming primitive |
| `0x0801EA86` | Thumb `BL 0x080318BE` | **higher-level program wrapper exists** |
| `0x0801EAE8` | `r0 = r6 + (r5 << 11)` | step through **2KiB** pages |
| `0x0801EAEC` | Thumb `BL 0x0803175A` | **higher-level page-erase wrapper exists** |

The driver reads the Flash-size field and includes branches for devices
with different Flash sizes. Those branches do not prove the actual physical
part number; the firmware/recovery protocol's `G32` classification remains
to be correlated with physical silicon marking.

The FMC operations are executable routines in the original application, not
merely unused address literals. Static cross-references prove higher-level
`BL` instructions call both the page-erase and word-programming functions.
They **do not** prove which user-visible CFS operation triggers the wrappers.

## Original end-of-Flash descriptor

A stock structure at `0x08036D10..0x08036D47` contains:

| Word at | Value |
| --- | --- |
| `0x08036D2C` | `0x0807F800`, **last physical 2-KiB page** of 512-KiB main Flash |
| `0x08036D30` | `0x00000001` |
| `0x08036D34` | `0x0802C598`, original ROM |
| `0x08036D38` | `0x00000800` (2048 bytes) |
| `0x08036D3C` | `0x20004A20`, RAM |
| `0x08036D40` | `0x08011AA3`, original ROM |
| `0x08036D44` | `0x08011B13`, original ROM |

The descriptor's SHA256 is
`f76a5776dfef2396ef90c16d5e5edc2abd03053afd9d5d7e6bd216ac39187248`
in **both** the original vendor image and v3.22.
The `0x0807F800` value occurs **exactly once** in each ROM file.

The descriptor strongly warrants investigation as a nonvolatile
storage/configuration backend, but the direct relation to the detected
erase/program wrappers is currently a **hypothesis**.

## Why this still does not certify application expansion

On the hypothesised GD32F303VET6, physical main Flash covers
`0x08000000..0x0807FFFF`, and the 512-KiB HD controller erases
2-KiB pages (see
[GigaDevice GD32F30x User Manual, Flash memory controller, §2](https://www.gd32mcu.com/data/documents/userManual/GD32F30x_User_Manual_Rev2.9.pdf)).
The first 256KiB has faster instruction-fetch latency; that 256KiB split
is **not** an executable/non-executable boundary.

The custom Creality RS-485 bootloader is **not contained** in the
application image and has not been dumped. The app starts at
`0x08010000`, **consistent with**, but not proof of, a 64KiB custom
Katapult-like loader at `0x08000000`.

The old `0x0803B800` build guard is a conservative **unverified policy**,
not a recovered bootloader constant. The application currently finishes at
`0x0803B7DC` exclusive, with **36 bytes remaining** before that policy
boundary. The code beyond that limit may or may not be accepted by the
loader, irrespective of the silicon capacity. Therefore:

- DO NOT write, erase, relocate code to, or probe `0x0807F800` on the live CFS;
- DO NOT use `0x0803B800..` as app code or new scratch pages by assumption;
- DO NOT flash a larger v3.23 image without a verified loader/partition map;
- DO NOT replace the original loader with Katapult on the only working CFS;
- DO NOT misinterpret a bootloader *transport* chunk of 128 bytes as
  Flash page geometry or as a firmware-size limit.

The existing CFS v3.22 runtime, RFID and remaining-filament functionality
has **not been modified** by this investigation.

## Reproducible audit

```bash
python -m pip install "capstone>=5,<6"
python3 firmware/v3.22-readonly-state-probes/stock_fmc_driver_audit.py \
  --stock /private/Creality-cfs153-original.bin \
  --v322 /private/CFS-v322-verified.bin \
  --self-test \
  --json-out /tmp/STOCK_FMC_DRIVER_AUDIT.json
```

The script pins both source hashes, checks firmware CRC/header, resolves
PC-relative literal loads, and validates **23 exact original Thumb
instruction encodings** on both ROM images including erase/program
callers. Five deliberately altered in-memory images with **valid
recomputed CRCs** are rejected (high-page pointer, page size, erase PER
bit, caller program `BL`, FMC unlock key). It does not open any device or
create flashable output.

The CI path also validates the exact v3.22 application without needing to
redistribute Creality's original proprietary binary.

**Outcome:** original application Flash program/erase capability and its
higher-level wrappers are established; high-page ownership and Creality
loader maximum application size are **not** established. The release gate
`safe_to_flash_a_larger_app` stays **false**.
