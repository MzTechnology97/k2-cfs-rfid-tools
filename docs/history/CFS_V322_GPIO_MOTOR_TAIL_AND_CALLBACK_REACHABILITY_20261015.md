> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.22 — GPIO/motor tail branches and indirect registered pin callback

*15 October 2026 · saved SHA-pinned v3.13 and v3.22 · physical source-only audit · continuation of draft #30.*

## New source-level branch inventory

The existing **122 candidate direct `BL` instructions** to the OEM
RT-Thread GPIO write service `0x08018EEC` are **not** all the
manufacturer's direct control transfers.

A separate halfword-aligned scan of the original APP at its real
`0x08003000` link base identifies precisely **18** candidate
`B`/`B.W` tail branches to `0x08018EEC`. It also finds
**two** `B`/`B.W` tail branches to the original
four-brushed-motor control function `0x08010054`.

These are distinct from the prior 122 `BL` patterns; like any
binary opcode-pattern census, counts alone are not complete
execution reachability or proof of live physical behavior.

### Eighteen OEM GPIO tail branches

| Original physical PC | Source-proven GPIO pin category |
| --- | --- |
| `0x0800A1B6` | immediate `0x10` |
| `0x0800A264`, `0x0800A2AA`, `0x0800A2D2` | immediate `0x21` |
| `0x0800A362` | immediate `0x10` |
| `0x0800ADBA`, `0x0800ADF4`, `0x0800AEBE` | immediate `0x45` |
| `0x0800B5D8` | immediate `0x1C` |
| `0x0800B5A6` | indexed load from RAM-based GPIO table |
| `0x0800BC0A`, `0x0800BCA8`, `0x0800BD44`, `0x0800BDCC` | halfword value from original OEM RAM pin table |
| `0x080106C2` | pin loaded from pair-record table based on a runtime index |
| **`0x08019156`** | **software-provided pin parameter**, dynamic |
| `0x0801B7AE`, `0x0801B7B8` | runtime byte loads; final pin provenance unknown |

The nine **immediate** cases require original source opcode pairs
(`MOVS r0, #pin` and a pinned `r1` software value), not a
search for random nearby constants.

The dynamic `0x08019156` path is particularly important:
at `0x08019104`, the original firmware calls OEM value parser
`0x080268B8`; at `0x08019108`, it saves the converted
value in `r5`. A second recognized value path at
`0x08019134` calls `0x080190A0` and saves its value at
`0x08019138`. Both feed `MOV r0,r5` at
`0x08019150`, followed by the tail branch
`0x08019156 B 0x08018EEC`.
The original four null-terminated GPIO choice strings are **`high`,
`on`, `low`, `off`**. They are stored at original ROM locations
`0x08019388`, `0x08019390`, `0x08019394`, and
`0x08019398`, and referenced by the command parser's PC-relative
`ADR` instructions. This is evidence of a software command
parser, **not** evidence that its interface is exposed via a
network, serial bus, user shell, or other external connection.

The preceding source selects a software value for `r1`,
but the audit **does not authenticate a complete parameter
whitelist, authorization condition or motor-pin exclusion**.
It does not attempt to send or synthesize an actual command.

### Two original motor-controller tail branches

- `0x0800D24A B.W 0x08010054`: original code at
  `0x0800D226` saves the input motor argument in `r4`,
  and just before the tail branch converts it with `SXTB r0,r4`
  and assigns `r1=0`. This source command is **not**
  independent mechanical stop evidence.
- `0x080102C0 B 0x08010054`: original code at
  `0x080102AC` computes the `0xAC`-stride motor record,
  stores the input value at `[record+0xAA]`, reads a motor
  record byte at `[record+0xA8]` to `r1`, then branches to
  the shared controller. The record may be mutable at runtime;
  no task/ISR exclusivity has been established.

This reinforces the earlier conclusion: the firmware contains
multiple entry points into motor-control hardware, not just
the direct `BL` callsites.

## Original RT-Thread indirect callback route

The pinned OEM ROM operation table at `0x0802B49C` contains
the Thumb function pointer **`0x0801AB91`** in the
`pin_ops.write` slot `0x0802B4A0`. The earlier
registration audit proves the original startup initializer
will install that operations table into BSS field
`0x20004C84` *if the startup path executes*.

The RT-Thread dispatch source loads the write function with
`LDR r3,[r0,#4]` at `0x08018F0A` and invokes it using
**`BX r3` at `0x08018F12`**. The callback
`0x0801AB90` resolves the physical pin through the
manufacturer's lookup table and writes to GD32 GPIOD BOP/BC.

Therefore there is a verified **function-pointer-based
indirect call path**, even though a static ROM word census
finds no direct Thumb function pointers to the GPIO
*dispatcher*, shared motor controller, or two parameter
helpers. The callback pointer is unique among those
searched in the original aligned ROM words. The original
3,012-byte scatter-initialized RAM contains no aligned
pointers to these five exact targets.

**Absence of an initial ROM/RAM pointer is not proof that
runtime code cannot construct a pointer dynamically** or
call through a different table/slot.

## Automated checks and safety boundary

`firmware/v3.22-readonly-state-probes/cfs_oem_gpio_motor_tail_and_callback_audit.py`
pins the exact original physical branches; checks
9 immediate and 9 non-immediate GPIO source sites, 2
motor-controller tail paths, parser value production,
the original OEM callback table/dispatch instructions and
the bounded initial ROM/RAM pointer census against both
saved SHA-pinned firmware generations. It includes
**18 synthetic corruption fixtures** that must all fail closed.

This is **not** a full program-level `BLX` reachability,
interrupt ownership or motor-stop proof. `BOX_STATE=IDLE`
has already been observed while motors were moving;
nor is a zero software duty register a physical stop signal.
No live serial/MCU read was attempted. The CFS, printer,
Kalico and operating firmware remain unmodified.

**v3.23 flashing and motor-active MCU SET/RESET are blocked.**
