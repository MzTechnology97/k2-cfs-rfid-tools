# CFS M1/M2 GPIO candidate argument dataflow — 14 October 2026

The [PR #24](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/24) baseline CI was green at commit `adf85463a271785da702b95d7f274fd6ca048d84`. The previously validated source facts are: 122 halfword-scanned candidate direct BL calls to OEM GPIO helper `0x08018EEC`, 58 strict immediately adjacent two-MOVS argument patterns, nine verified PE3/PE4 direction/brake argument pairs, and original runtime GPIO callback pointer `0x20004C84` in zero-initialized BSS. The stored APP bytes **cannot disclose** that runtime field's populated value.

The new `cfs_gpio_bounded_argument_provenance.py` attempts a **strict, deliberately incomplete** backward argument analysis for the 122 saved ROM BL candidates. It accepts only contiguous, unambiguous short original Thumb instruction sequences consisting of immediate `MOVS r0,#pin`, `MOVS r1,#value` (plus NOPs). Any branch, stack operation, indirect control transfer, unknown operation, or ambiguously decoded instruction sequence makes the callsite ineligible rather than extrapolating across unknown register or memory state.

Compared to the four-byte immediate window, this offers additional *potential* argument provenance if a bounded basic-block candidate contains harmless spacing or more than two instructions. It is **not a full control-flow graph**, does not verify an instruction is reachable executable code, and cannot identify pin values held in registers, loaded indirectly or computed by another function. A missing M1/M2 match is not evidence the pin is unused.

The physical M1/M2 pins are operator-confirmed PD0/PD1 (RT IDs `0x30/0x31`) and PD2/PD3 (IDs `0x32/0x33`). Any source candidate remains classified as **unqualified**, until original GPIO device registration, task/ISR execution and actual motor driver behavior are authenticated.

Parallel research needs to trace the original ADC channel selection/conversion to actual motor current consumers. The existing `ADC0_RDATA` helper at `0x08022BBC` has no proven direct callers; a direct unsynchronized read of ADC conversion data could alter EOC state and is not an approved diagnostic.

**Never treat GPIO state, zero-duty PWM, absent tach pulses or a zero current sample as independent proof of physical motor standstill.** Host motion protections and the existing nine release gates remain in force. No CFS/CM5 commands, movement, firmware binary edits or flash were performed by this update.
