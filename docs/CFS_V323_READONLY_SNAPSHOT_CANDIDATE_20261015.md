# CFS v3.23 — First read-only firmware code delta (OFFLINE CANDIDATE)

*15 October 2026 · stacked on exact physical-link v3.22 compiler baseline.*

## What was implemented

A **new original-handler subcommand `0x57 / 0x15`**, not previously
dispatched by the v3.22 command router, returns a fixed **two-byte
read-only snapshot**. The existing reserved **`0x14` DESCRIBE**
opcode is deliberately kept unavailable, so no already documented
future ABI slot is reassigned.

| Request | Format |
| --- | --- |
| Outer opcode | `0x57` |
| Inner opcode at request offset 4 | **`0x15`** |
| Expected declared request length | **4** |
| Response status | **0** on success, **1** on invalid length |
| Response payload byte 0 | **`0x23`**: experimental v3.23 candidate marker |
| Response payload byte 1 | **raw `[0x200037D0 + 2]`** OEM BOX_OPER_STATE |

The state is an **uninterpreted, sequentially sampled byte**, shared
with the OEM box-state response already read by the v3.22 handler.
Values 0–5 and `0xFF` were independently simulated, but **0/IDLE
can occur while the feeder is moving**. No API consumer may use this
value to authorize motor/RFID writes, and the response is not a
timestamped or atomic snapshot of all device motion.

The command only reads from existing OEM RAM and writes **two bytes
to the previously reserved 8-byte response scratch on the caller's
stack**. It reads no new peripheral registers, allocates no SRAM,
does not touch the existing 64-byte v3.22 sidecar and adds
**no extra task, timer, interrupt, PWM/GPIO action or RFID SET/RESET**.

The existing `0x57/0x14` reservation remains invalid. No original
Creality task, legacy wrappers or existing 0x57 subcommands change
their intended behavior.

## Physical build and ABI checks

`firmware/v3.22-readonly-state-probes/cfs_v323_readonly_snapshot_candidate.py`
starts by proving exact saved SHA-pinned **v3.13 → v3.22 full-image
parity**, then generates a strictly anchored, localized source
transformation in memory. The original `handler-v3_22.S` is
**not modified**.

After relinking at the physical `0x0802DE38` origin:

- Existing handler: **2,468 bytes**.
- Trial handler: **2,504 bytes**, **+36 bytes**.
- Reconstructed complete APP: **178,176 bytes**, in memory only.
- All **13 external OEM Flash symbols** remain source pinned.
- All **15 original handler→OEM external Thumb branches** retain their
  exact OEM destinations; all **14 OEM→handler BL hooks** decode and
  target the corresponding relocated wrapper in the expanded handler.
- The OEM APP prefix is unchanged outside those existing hook
  relocations and the image checksum/length metadata.
- The original v3.22 64-byte sidecar heap-root change remains
  exactly as before.
- Experimental candidate checksum and SHA-256 are reported solely
  in the offline JSON report; no BIN/ELF/HEX is saved or uploaded.

**Corrected Flash interpretation (historical dump reviewed):**
the +36-byte candidate ends at `0x0802E800`, exactly a **2-KiB
page boundary**, immediately after page 92. **This is NOT an
application-size or bootloader limit.** The older study's hypothetical,
non-loader-authenticated code-policy stop is the *absolute physical
address* `0x0803B800`; the candidate has **53,248 arithmetic
bytes** to that policy boundary, but these bytes are **NOT certified
free or safe to flash**. The public 2025 archived CFS Flash has
bootloader/vector code at `0x08000000` and a separate application
vector at `0x08003000`; its own loader's max size and erase policy
must be independently proven and cannot be transferred to the installed
CFS without matching the loader bytes. See the subsequent historical
bootloader provenance audit.

## Offline dynamic tests

The script emulates the candidate MCU handler in **Unicorn ARM Thumb
mode** using mapped *synthetic* Flash/SRAM. The emulator intercepts
the OEM `SEND_RESPONSE` entry before executing any OEM transport code
and fails if a new code path writes SRAM anywhere outside the
existing response-call stack.

- Seven valid requests for raw OEM state `0,1,2,3,4,5,255`:
  exactly `[0x23, state]`, success status 0.
- Invalid length `3`, invalid length `5`, and reserved
  `0x14`: rejected with status 1 and empty payload.
- Four source mutation fixtures for a deleted opcode router,
  changed OEM Flash call reference, wrong linker origin and
  tampered saved v3.22 image must all fail closed.
- Builds are memory-only and verified against the original
  branch/heap/metadata budgets; **no target CFS hardware access**.

## Reproduce (offline only)

```sh
cd firmware/v3.22-readonly-state-probes
python cfs_v323_readonly_snapshot_candidate.py \
  --v313 ../v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin \
  --v322 /private/exact-v322-saved.bin \
  --asm handler-v3_22.S --linker link.ld --builder build-v3_22.py \
  --self-test
```

Requires the Python Capstone and Unicorn packages plus the existing
cross assembler/linker; the reference firmware stays local and
is never copied into the public repository.

## Qualification and next steps

This is **the first actual trial v3.23 behavior implemented**, NOT a
flashable or hardware-proven release. It does not disable/repair
the preexisting v3.22 write behavior or establish motor quiescence.
The current candidate ends on a 2 KiB page boundary, but the loader's
real erase-page ownership, update/recovery and backup behavior remain
unknown. Never interpret the arithmetic headroom as an authorization. A proper motor-active RFID interlock is likewise unproven.

Before considering even a spare-CFS test, independently confirm
the bootloader Flash erase/install boundaries, documented rescue
path, full motor/ISR coordination, safe memory mapping, and
detailed protocol/host compatibility. Keep OpenCFS paused until
these firmware objectives are more advanced.
