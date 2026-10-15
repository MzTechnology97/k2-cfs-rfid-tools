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
