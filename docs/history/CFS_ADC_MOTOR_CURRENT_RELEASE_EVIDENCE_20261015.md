> Historical research for earlier firmware. This is not the current installation guide. Removed firmware and tests are recoverable from [the frozen pre-cleanup commit](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3). Use [the current documentation](../../README.md) for CFG6 RDG2.

# CFS v3.23 — ADC current-feedback qualification gate
*15 October 2026 · Saved OEM v3.13/v3.22 offline source audits only.*

## What is verified

On the user-confirmed CFS wiring, brushed motor current amplifier
outputs connect to **PC5, PC0, PA1, PA0** (hardware-capable ADC
channels 15, 10, 1, 0). The saved firmware has an authentic original
ADC0 conversion-result helper at physical PC `0x08022BBC` which
reads `ADC0_RDATA` at `0x4001244C` when called.

Other bounded original Thumb source audits discovered nine local
ADC0 CTL0/CTL1/RDATA reads or writes; four known ADC helper
entries have no direct BL/aligned ROM function-pointer candidates;
adjacent and bounded non-adjacent MOVW/MOVT immediate address
scans found no ADC register address construction matches.
These are **syntax-bounded observations**, not whole-program
reachability or claims that motor-current sensing is unused.

## New audit and regression

The new `cfs_adc_motor_current_evidence_gate.py` combines the
existing original-ADC source dataflow and MOVW/MOVT result for
both SHA-pinned saved versions. It requires a real
`ADC0_RDATA` source instruction to be found while continuing
to mark these critical properties **unverified**:

- ADC channel ranks and sampling for the four brushed motors;
- a reachable conversion call chain and motor-task consumer;
- sample calibration, units, fault behavior and freshness;
- a non-interfering live observation path (ADC RDATA reads may
  affect EOC state);
- motor shaft stop and independent driver deenergization.

Its ten synthetic negative fixtures reject attempts to infer
idle or authorize a firmware write from an isolated ADC helper,
zero current, a potential pin-to-channel mapping, missing/aged
conversion data, or absence of BLDC FG pulses.

**A passing CI means no unsafe release inference was made.**
It does not mean physical current feedback is implemented.
All MCU SET/RESET safety and v3.23 flash release gates remain
**closed**.

## Additional bounded rank/sample register regression

The source analysis now explicitly pins the nine original local ADC0
register operations in both saved firmware versions: two CTL0 reads,
two CTL0 writes, two CTL1 reads, two CTL1 writes, and a single RDATA
read at `0x08022BC0`. The bounded straight-line scanner finds **no
RSQ0/RSQ1/RSQ2 or SAMPT0/SAMPT1 access** within the same verified
windows. GitHub CI asserts that this remains true and rejects changed
evidence.

**This is a scope-limited negative result, not a claim that the
application never configures ADC channel ranks.** In particular,
indirect addressing, DMA, library calls, computed registers, unscanned
code or ISR-driven conversion remain outside this local analysis.
No current-channel ownership, electrical calibration, sampling
freshness or safe EOC-preserving observation has been established.

## Next evidence required

Recover a source-accurate ADC channel configuration-to-result
consumer path if one exists, including any indirect callbacks,
ADC sequence registers, DMA transfers or runtime table.
Then prove the hardware revision and establish a read-only
observation mechanism that cannot clear EOC or affect timing.
Only then could real current data complement independent
BLDC FG, drive outputs and atomic motor-start exclusion.

The CFS, CM5 and Kalico were not accessed; no production
firmware was modified, flashed or executed.
