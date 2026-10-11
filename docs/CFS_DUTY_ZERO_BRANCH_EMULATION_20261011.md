# Constrained ARM duty-controller emulation — stock 1.5.3 vs v3.22

**2026-10-11. Not a real-motor test. No firmware flashing, CFS reset,
serial command, GPIO access, UART transaction or MCU reads/writes.**

This study extends [CFS_MOTOR_COMMAND_COVERAGE_20261011.md](CFS_MOTOR_COMMAND_COVERAGE_20261011.md)
using the exact original CFS APP and the currently validated v3.22
image (pinned SHA256). The entry `0x0801E0CC` is the shared motor
command/duty controller reached by the forward, reverse, zero-command
and two direct callers.

The new script
[`motor_duty_zero_branch_emulate.py`](../firmware/v3.22-readonly-state-probes/motor_duty_zero_branch_emulate.py)
executes actual, unchanged ARM Thumb instructions in Unicorn from a
simulated `0x0801E0CC` entry, with 64 KiB simulated SRAM. **All calls
to hardware-dependent procedures are explicitly intercepted and
mock-returned**. The experiment stops before the final hardware branch
or the zero-path VFP status update. This is *constrained differential
execution* of the original binary, not execution of the complete
motor controller.

## Observed branch and RAM effects

The shared function saves callee registers, clamps duty requests greater
than 255, computes intermediate scaled values, stores a previous
requested duty and calls two low-level hardware routines. After that,
the duty=0 and duty!=0 paths diverge.

| Static original ROM address | Evidence |
| --- | --- |
| `0x0801E0CC` | `push.w {r4,r5,r6,r7,r8,lr}` |
| `0x0801E0D2..0x0801E0D6` | Clamp duty to 255 |
| `0x0801E0F4` | `cbz r5,0x0801E10E` bypasses a **nonzero-only** state update |
| `0x0801E10A`, `0x0801E10C` | Nonzero request clears SRAM words at `0x20004990`/`0x20004994` |
| `0x0801E116`, `0x0801E11E` | Both branches invoke `0x08026516`/`0x08026488` (mocked) |
| `0x0801E126` | Write the current requested duty at `0x20004A1A` |
| `0x0801E128` | Branch to `0x0801E13C` on zero duty |
| `0x0801E12A`, `0x0801E12E` | Nonzero branch updates `0x20003778` and `0x200037A1` |
| `0x0801E138` | Nonzero path tail-branches to `0x0802F190` (mock stop) |
| `0x0801E13E`, `0x0801E146` | Zero path calls `0x0802F270` then `0x08013CD6` (both mocked) |
| `0x0801E14A`, `0x0801E14C` | Original zero path next loads 0x14 and stores to `0x2000499C` (static verification only) |
| `0x0801E154`, `0x0801E158`, `0x0801E15C` | Original zero path contains VFP and byte writes to other SRAM fields (static verification only) |

The emulated state was initialized with previous duty=72 and a
distinctive SRAM canary pattern. Five requests were tested:

| Requested value | Effective stored duty | Executed branch | Mocked low-level calls |
| ---: | ---: | --- | ---: |
| 0 | 0 | zero | 4 |
| 1 | 1 | nonzero | 2 |
| 127 | 127 | nonzero | 2 |
| 255 | 255 | nonzero | 2 |
| 300 | 255 (clamped) | nonzero | 2 |

The zero path retains the two nonzero-only SRAM words' initial
canaries; the nonzero path clears them. In both cases the old
requested duty (72) is copied to the previous-value field. **Each
case produced byte-identical simulated results from the exact
stock APP and the tested v3.22 image**.

The emulator deliberately pauses the zero path at `0x0801E14A`,
*before* the original status byte and VFP stores execute. It pauses
the nonzero path on entry to the external finalizer
`0x0802F190`. It does not claim that the original functions
`0x08026516`, `0x08026488`, `0x0802F270`,
`0x08013CD6` or `0x0802F190` behaved identically to mocks
on the real board. The external functions are hardware-dependent.

## Additional original software-status helper at `0x0801E1AA`

The original ROM has **three direct Thumb BL callers** of this
function, at `0x080108AE`, `0x08010932` and
`0x08010C8A`. The code loads a static pointer to
`0x20004960`, reads a single **software RAM byte**
`[0x20004960 + 0x3C] = [0x2000499C]`, then returns `1`
for a zero byte and `0` for any nonzero byte. It performs
**no direct peripheral, encoder, current-sense or motor-driver
register read** in that function.

Four isolated executions using actual original machine code
and the v3.22 code matched exactly:

| Forced software RAM byte | Returned status |
| ---: | ---: |
| `0x00` | `1` |
| `0x01` | `0` |
| `0x14` | `0` |
| `0xFF` | `0` |

The emulator read hook observed **only**
`0x0801E244` (pointer literal) and `0x2000499C`
(single RAM byte). No mocked hardware routine is required for
this status-helper test. The original common duty setter contains
a separate **statically verified** instruction writing the
literal `0x14` to this same RAM byte on its zero-command path;
that write is past the duty-path emulator's deliberate stop point.

**Safety conclusion:** this function exposes a **software-derived
condition**, not independent physical `motor_idle` evidence.
Treat its value as an opaque stock state. It MUST NOT be used
alone as an MCU motor-active interlock to permit runtime
parameter SET/RESET. A real feedback correlation would require
separately controlled instrumentation.
## Safety implications

The zero-command path is now distinguishable from the nonzero
command path both **structurally** and by constrained ARM execution.
It is a reasonable target for capturing **requests** to zero duty
in a future instrumented MCU, but:

- Zero requested duty does **not** prove immediate physical rotor stop,
  motor driver disable, spool inertia, lack of other motor motion, or
  safe permission to write MCU configuration.
- No status flag examined here has been proven to be an independent
  feedback signal for all CFS motors.
- Indirect calls, IRQs, DMA, additional motor control sources and the
  real hardware execution of mocked procedures remain outside coverage.
- The `0x0803B800` flash limit remains unverified; v3.22 still
  ends at `0x0803B7DC` with 36B of conservative headroom. The
  v3.23 ring/trampoline needs hundreds of extra bytes plus validated
  SRAM/stack and real tick/IRQ synchronization.
- Do **not** reuse `0x0807F800` (candidate NVM), swap bootloaders, or
  install a new MCU binary merely because the static branches are known.

The independent MCU motor-active protection issue #9 stays OPEN.
The proposed v3.23 ring remains offline-only.

## Reproduction

```sh
python -m pip install "unicorn>=2,<3" "capstone>=5,<6"
python3 firmware/v3.22-readonly-state-probes/motor_duty_zero_branch_emulate.py \
  --stock /private/original-cfs-153.bin \
  --v322 /private/working-v322.bin \
  --json-out /tmp/CFS_MOTOR_ZERO_DIFFERENTIAL_PRIVATE.json
```

CI runs the same **five constrained cases** on SHA-pinned rebuilt
v3.22, without distributing any vendor firmware. It also verifies the
21 exact original instructions that delimit these paths and denies
any release or physical-idle claim.

The offline self-test also corrupts **nine** Thumb instruction bytes
in-memory, each with a correctly recalculated firmware CRC. All
mutants are rejected by the disassembly guards; these include
branch logic, a zero-path SRAM state store, two RAM-status helper
instructions and a direct helper caller.

**All results are offline-only. No change to the running Creality CFS.**
