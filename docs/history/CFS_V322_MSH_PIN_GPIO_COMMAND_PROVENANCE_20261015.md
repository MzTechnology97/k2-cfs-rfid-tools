> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.22 — RT-Thread MSH pin command registration and GPIO write path

*Original SHA-pinned v3.13 and rebuilt saved-equivalent v3.22 · 2026-10-15 · source-only.*

## New, source-proven command registration

The saved original manufacturer ROM has a run of 16-byte MSH-compatible
command records. **The actual layout is NOT the superficially apparent
[previous function, command name, description, zero]**. Instead the
original entries start with **[name pointer, description pointer,
zero, Thumb-handler pointer]**:

| ROM record start | OEM command | Exact Thumb entry |
| --- | --- | --- |
| 0x0802D970 | box_aging_mode_test | 0x08012BF9 |
| 0x0802D980 | adc | 0x080188DB |
| **0x0802D990** | **pin** | **0x08019029** |
| 0x0802D9A0 | pwm | 0x08019629 |
| 0x0802D9B0 | help | 0x0801C2D9 |
| 0x0802D9C0 | ps | 0x0801C305 |

For the **pin** entry:
- Name pointer at **0x0802D990** contains **0x0802D66F**, which
  references the string \`pin\`.
- Description pointer at **0x0802D994** contains **0x0802D673**,
  which references \`pin [option]\`.
- The zero/reserved word at **0x0802D998** is zero.
- Thumb handler at **0x0802D99C** contains **0x08019029**.
  This is code at physical 0x08019028 plus the Thumb state bit.

**The adjacent \`pwm\` entry is independent**: ROM 0x0802D9A0
contains the name, and 0x0802D9AC points to Thumb handler 0x08019629.
Confusing the handler in the previous record with the name in the
following record would misidentify these two command implementations.

## Source call chain to OEM physical GPIO dispatcher

The OEM handler at **0x08019028** checks the software command
argument and compares it to ROM words:

\`num\` · \`mode\` · \`read\` · **\`write\`**

The recognized \`write\` path ends in original instruction
**0x0801909C \`B.W 0x080190F0\`**.

The OEM routine at **0x080190F0** checks command argc, obtains
the supplied logical pin argument from argv at **0x080190F8**,
runs numeric conversion at **0x08019104**, saves the result in
\`r5\` at **0x08019108**, and parses the last software
argument using original ROM choices:

\`high\` · \`on\` · \`low\` · \`off\`

The source then loads the software pin number to r0 at
**0x08019150** and tail-branches at
**0x08019156 \`B 0x08018EEC\`**.

The OEM RT-Thread pin_write dispatcher at **0x08018EEC**
fetches registered \`pin_ops.write\` from device BSS,
calls its callback indirectly through \`BX r3\` at
**0x08018F12**, and the callback ultimately writes to
hardware GPIO BOP/BC. That source chain was authenticated
by earlier stacked audits.

Manufacturer ROM help text includes
\`MSH >pin mode GPIO output\`,
\`MSH >pin read GPIO\`, and
\`MSH >pin write GPIO high\`.
These demonstrate an **MSH-style software command surface in
the original firmware code**, not verified console availability
from the CM5, USB, T113, CFS RS485, network or any external
connection. **No active hardware was queried or operated.**

## Consequence for RFID motor-safety interlock

The \`pin write\` implementation accepts a **runtime-supplied
logical pin number** and routes it to GPIO handling.
The bounded source audit does **not** prove a safe pin whitelist,
caller authorization, external accessibility, task/IRQ exclusivity,
or motor electrical standstill.

Therefore any proposed RFID interlock must account for the
possibility of **non-RFID GPIO commands changing motor driver
signals independently of a box state enum**. This is a reason
not to treat \`BOX_STATE=IDLE\` as evidence of stopped motors.
It does not by itself establish an exploitable network interface
or a current vulnerability.

## Automated CI

New source-only audit script
\`firmware/v3.22-readonly-state-probes/cfs_oem_msh_pin_gpio_command_registration_audit.py\`:
- checks six adjacent \`[name,desc,0,Thumb handler]\` descriptors,
  with pin vs pwm explicitly different;
- verifies 4 \`pin\` subcommands and 4 write value tokens by ROM
  address and PC-relative opcode;
- checks command-to-write routine and write-to-GPIO \`B.W\`/\`B\` instructions,
  including dynamic software pin origin;
- uses the existing tail/callback pinning from the original APP;
- verifies both SHA-pinned saved generations; and
- rejects **18 synthetic mutated ROM or instruction cases**.

This is a code/ROM evidence audit, not an end-to-end shell trace.
The v3.23 firmware has **no flash authorization**; MCU SET/RESET
must remain disabled for potentially moving motors. Additional
work is required on motor physical feedback, command authorization,
ISR/task atomicity, RAM ownership and loader recovery.
