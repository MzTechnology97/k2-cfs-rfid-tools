> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS original vs v3.22 — motor-command static path coverage

**2026-10-11 — completely offline. No RS-485 or physical CFS accesses.**

Exact SHA256-pinned binary inputs:

- Original Creality 1.5.3 APP (base `0x08010000`): `5b076563f474da1e8741ee88a9b019c2dcb1b7de6c1c651f201f1be61c345dea`;
- Currently validated experimental v3.22: `40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7`.

The public `firmware/v3.22-readonly-state-probes/motor_command_callgraph_audit.py`
validates 102 exact Thumb BL encodings, direction/zero constants,
three unconditional tail branches, the common function prologue and
two original RAM pointer literals in **both** applications. A complete
two-byte-aligned Thumb encoding scan independently checked the
enumerated callsite counts and locations. SHA256 of the canonical
address/target/encoding inventory:
`d66b17e67f80af1a8e9eb89ac435fadb4250a8c5c441a5580468e94b45617081`.

## New confirmed callgraph

| Original entry point | Static role based on code | Direct `BL` callsites |
| --- | --- | ---: |
| `0x0801E164` | Select one direction, forward-like wrapper | **33** |
| `0x0801E17E` | Select the other direction, reverse-like wrapper | **17** |
| `0x0801E198` | Set a **zero** command, potential stop wrapper | **50** |
| `0x0801E0CC` | Shared duty/command controller | **2** |
| **Total** | Stock and v3.22 byte-identical calls | **102** |

Verified flow at the three wrapper tails:

```text
      0x0801E164  direction 0 (via 0x0801E0B2)
                  restore original wrapper registers
      0x0801E17C  branch  ─────────────┐
                                       │
      0x0801E17E  direction 1 (via 0x0801E0B2)
      0x0801E196  branch  ─────────────┤
                                       │
      0x0801E198  setup via 0x08025EEC
      0x0801E1A6  movs r0,#0          │
      0x0801E1A8  branch  ─────────────┤
                                       ▼
                        0x0801E0CC  shared duty/command controller
                                       ▲
                        2 additional direct calls
```

The shared controller's original prologue is
`2D E9 F0 41`, `push.w {r4,r5,r6,r7,r8,lr}`.
Next it copies `r0`, compares against 255 and bounds larger values.
The function reads the `0x20004960` original RAM root, controls
additional RAM fields and invokes other original hardware routines.
The zero-command wrapper performs `movs r0,#0` before tail-branching
to this controller. That establishes **command zero**, not measured
rotational speed zero. There are no physically verified encoder,
current or drive-enable semantics here.

The three wrapper tails are **unconditional Thumb branches**, not
`BL` callsites; simply counting calls to `0x0801E0CC` would miss
them. This explains why the static entry directly shows only two
`BL` calls while the wrapper group has 100.

## Practical impact on the v3.23 event ring

This resolves one missing path from
[draft PR #12](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/12):
the zero-command wrapper has 50 additional static callers, preserved
alongside the previously mapped 33/17 directional callers.

**But a central entry hook would capture commands, not necessarily
the actual start/stop events of every feeder/hub motor.** Unknown
indirect calls, other control primitives, ISR/DMA activity and async
completion can bypass or outlive these calls. The shared controller
must **not** be used as the independent MCU `motor_active` guard
without a separately validated physical state source. No motor commands
have been sent by this audit.

Further live-readiness gates remain:

1. Determine the actual Creality loader app write boundary. The
   inferred `0x0803B800` safety cutoff is **not hardware-authenticated**.
   The verified v3.22 image ends at `0x0803B7DC` (**36 B** earlier).
2. Validate the 512-B ring reservation against real RTOS heap/stack,
   IRQ contexts and DMA, and prove bounded/single-writer event logging.
3. Show preserved AAPCS/Thumb registers/FPU flags and real task stack
   high-water during the actual logging callback, not just the
   30-case synthetic ABI simulator.
4. Verify motor coverage with a genuine, independently observable
   state signal; a zero PWM *command* is not physical motor idle.
5. Add frozen, GET-only ring readback after movement with no
   SET/RESET permission and no interference with RFID reads.

No code relocation, app binary generation, flash writes, runtime
motor-modification, new serial protocol or movement test occurs
in this work. Existing v3.22 behavior is unchanged.

## Reproducibility

For full offline SHA, direct callsite and CRC-corrected tamper review:

```sh
python -m pip install "capstone>=5,<6"
python3 firmware/v3.22-readonly-state-probes/motor_command_callgraph_audit.py \
  --stock /private/original-Creality-CFS-1.5.3.bin \
  --v322 /private/verified-CFS-v3.22.bin \
  --scan-all --self-test \
  --json-out /tmp/MOTOR_COMMAND_EVIDENCE.json
```

The `--scan-all` mode scans **all halfword aligned Thumb BL
encodings**. It is more thorough than verifying only the pinned
102 sites, though it is not a true full execution CFG and cannot
prove runtime reachability.

**Nine in-memory mutants with a valid recalculated APP CRC** are
rejected: original prologue, forward/reverse direction, zero-command,
zero-to-setter tail, one callsite each from forward/reverse/zero
and the original motor RAM pointer literal. The script never opens
the serial bus or writes a firmware image.

Without the proprietary original APP, the public CI runs identical
validations against the exact expected v3.22 hash; it also verifies
`safe_to_install_trace_hook=false` and `safe_to_flash_expanded_app=false`.

**Conclusion:** 102 preserved ROM callsites and three common
controller tails are established. No physical stop signal, full motor
coverage or deployable v3.23 firmware is established.
