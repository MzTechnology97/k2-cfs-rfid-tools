> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS extended PWM request shim: 0x1E04 / 0x1E05 (offline)

**11 October 2026 — no live MCU access, no serial, no flash.**

This study is stacked on
[PR #20](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/20)
and compares SHA-pinned original Creality CFS APP 1.5.3 with the
verified, operational v3.22. The objective is to understand original
commands `0x1E04`/`0x1E05` **without asserting that any particular
function is the actual runtime `pwm1` device callback**.

## A second, extended command decoder exists in the stock application

Function `0x0802639C` interprets the request number separately from
the generic PWM decoder at `0x08028394`:

- `0x080263A0`: computes `r1 - 0x1E00`;
- `0x080263A4`: subtracts 4;
- `0x080263A6`: branches on request `0x1E04`;
- `0x080263AA`: branches on request `0x1E05`;
- `0x080263BA`: produces `1` for `0x1E04`;
- `0x080263BE`: produces `0` for `0x1E05`;
- `0x080263C0`: stores that value at **`[r2+0x14]`**, i.e.
  in the request structure provided by the caller;
- `0x080263B6`: returns result `0` for those special cases.

The special commands do **not** invoke the backend callback within
this function. Other requests follow a separate path:
`[r0+0x40] -> [interface+0x00] -> BLX r4`; the return value of
the downstream function is propagated. With no callback pointer,
the shim returns `0`.

A successful request-code match is **not an indication that a physical
PWM motor changed direction, started or completed movement**.

## Important relationship to prior generic-PWM audit

The generic PWM routine `0x08028394` studied in PR #20
accepts `0x1E00..0x1E03` but rejects `0x1E04` and
`0x1E05` with result `5`. The separately identified
`0x0802639C` handles the latter pair by updating a
*caller-provided request struct field*.

This resolves the semantics of the two special command codes
**inside the candidate extended shim**, but does **not** prove
that the real CFS named device `pwm1` ever routes through
`0x0802639C`.

In fact, an exhaustive 2-byte-aligned original Thumb **direct BL
scan** found **zero** sites targeting `0x0802639C` in both
stock and v3.22 APPs. A separate raw-byte search found **zero**
little-endian address literals for `0x0802639C` and
`0x0802639D` in either image. That is a narrow, reproducible
negative finding, **not proof the routine is dead**: possible
indirect dispatch, computed addresses, bootloader initialization
and runtime registration have not been ruled out.

It would be unsafe to install an MCU hook at this address
merely because its behavior fits the missing opcodes.

## Executable offline tests using actual stock Thumb

`firmware/v3.22-readonly-state-probes/extended_pwm_1e04_1e05_audit.py`
runs exact original instructions with Unicorn in isolated
emulated SRAM. The callback at `0x08050000` is **synthetic**
and never executes real firmware driver code.

| Request | Mock backend installed | Original data write | Return |
| --- | --- | --- | --- |
| `0x1E04` | No | `[request+0x14]=1` | `0` |
| `0x1E04` | Yes | `[request+0x14]=1` | `0` |
| `0x1E05` | No | `[request+0x14]=0` | `0` |
| `0x1E05` | Yes | `[request+0x14]=0` | `0` |
| `0x1E00` | No | none | `0` |
| `0x1E00` | Yes (returns `0x5A`) | none | `0x5A` |
| `0x1E02` | Yes (returns `0x5A`) | none | `0x5A` |
| `0x1E03` | Yes (returns `0`) | none | `0` |
| `0x1E06` | Yes (returns `0x5A`) | none | `0x5A` |

All **nine** cases produced identical results using the
original stock and v3.22 ROMs. The test also checks **23
exact Thumb instruction locations**, including both
high-level request builders `0x08026488` and
`0x080264D0` that contain `0x1E04/0x1E05`.
**Eleven valid-CRC in-memory mutation cases** are
rejected by the original instruction checker.

The emulated request RAM was initialized to sentinel value
`0xA5A5A5A5`; the non-special commands leave that field
untouched. The code's ordinary push/pop stack activity
is excluded from the **persistent request-field write** audit.

Run the comparison without distributing the original firmware:

```sh
python3 firmware/v3.22-readonly-state-probes/extended_pwm_1e04_1e05_audit.py \
    --stock /private/original-stock-153.bin \
    --v322 /private/validated-v322.bin \
    --self-test --json-out /tmp/EXTENDED_PWM_PRIVATE.json
```

The CI re-runs the same tests using the checksum- and
SHA256-pinned v3.22 only. The proprietary stock image
is never uploaded or committed.

## Outstanding safety gate

To advance firmware v3.23, identify the actual type-9
`pwm1` registry instance and prove which callback is
stored at `[object+0x38]`. Neither this candidate extended
shim nor the generic PWM driver is connected to that
concrete live registry instance by verified control/data
flow yet.

Even after identifying a callback, request acceptance,
`[request+0x14]` state, driver-enable and timer PWM
register reads are **not independent evidence of rotor
stopped/encoder stationary**. A real MCU safety interlock
needs stronger feedback and validation under normal
task/IRQ scheduling. Flash headroom and SRAM/stack
ownership constraints from earlier audits still apply.

**No flashable BIN, device command, NVM write, reboot
or motor movement was generated during this investigation.**
