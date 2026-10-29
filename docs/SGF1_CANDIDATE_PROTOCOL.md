# SGF1 vendor-geometry candidate protocol

Status: candidate source and offline evidence; coordinated Kalico integration is prepared separately, and real geometry calibration is pending. [Overview](../firmware/cfg6-spool-profiles/README.md) · [Manifest](../firmware/cfg6-spool-profiles/manifest.json).

SGF1 extends the existing0x57 envelope. Integers are little-endian. Old API7, CFG6 API2 and RDG2 are retained. The0x7A identity remains K2OH/v323-cfg6 with CFG6 feature0xE3, because installed Kalico uses that exact contract for startup settings and live remaining. SGF1 is discovered independently through sub0x16; filename and SHA identify the build. Exact body length is checked; invalid/unsupported/stale requests return status1, busy requests return7, success0. SGF1 geometry commands do not initiate RF or motion, or write tags/EEPROM. The separate [RH1 extension](../firmware/cfg6-spool-profiles/RH1-CONTRACT.md) adds asynchronous scheduling of the original RFID worker.

## Boot catalog and classification

The host loads up to4 geometry profiles into volatile RAM at CFS startup. IDs1..4 are numeric host conventions; ID1 may denote Bambu original spools. The firmware does not decode a vendor. After a host decoder succeeds, the host sends BIND with UID, measurement generation, profileID and expected catalog revision.

The first BIND can use the already completed raw measurement. Later same-UID idle scans use the binding automatically. Different UIDs invalidate it. Printing/retracting keeps the active counter; a normal idle rescan obtains a new geometric anchor for a new or used spool. Neither a new UID nor a new scan automatically means100%.

The applied full reference must match the intended spool/content calibration; matching RFID manufacturer alone does not prove a refill is on its original physical support. Geometry is selected by vendor. Nominal length belongs to the individual spool/slot; a nonzero catalog total is retained only as a legacy fallback.

## Commands

| Subcommand | Payload including subcommand | Reply |
|---|---|---|
|0x16 INFO|sub|12 bytes: SGF1, version1, slots4, profiles4, features31, snapshot_size u16=64, catalog_size u16=20|
|0x17 READ|sub, local_slot0..3|64-byte SGD1 snapshot|
|0x18 SET_CATALOG|sub,id,reserved0,reserved0,revision u32,core_c10 u16,full_c10 u16,total_mm u32|20-byte SGC1 catalog entry|
|0x19 GET_CATALOG|sub,id1..4|20-byte SGC1 catalog entry|
|0x1A BIND|sub,slot,id0..4,reserved0,expectedUID4,expected_generation u32,expected_revision u32|64-byte SGD1 snapshot|
|0x1B GET_LENGTH|sub,slot0..3|16-byte SGL1 slot-length reply|
|0x1C SET_LENGTH|sub,slot,reserved0,reserved0,expectedUID4,total_mm u32|16-byte SGL1 slot-length reply|

SET_CATALOG and BIND both have16 payload bytes (body length19). INFO body length4, READ/GET_CATALOG/GET_LENGTH5, SET_LENGTH15. The normal frame/CRC remains the existing one.

Core/full are circumferences in tenths of a millimeter: core500..10000, full at least core+100 and at most15000. A catalog total may be zero (vendor geometry without shared length) or10000..2000000mm. The effective slot total must be10000..2000000mm. Geometry uses `round(100*(C²-core²)/(full²-core²))`, clamped1..100. The raw C must be finite, positive and50..2000mm.

A new enabled catalog revision must be greater than that entry's previously accepted revision. Exact replays of the current enabled revision and values are idempotent. Revision0 with zero parameters disables an entry but retains its revision high-water mark. This prevents disable/re-enable ABA reuse within the boot session.

BIND ID0 removes the binding only (expected_revision0), without immediately changing the current counter. Nonzero BIND requires an enabled matching revision, current UID, measured UID, generation, fresh complete API7 proof and trustworthy same-UID rotation. It also requires a valid legacy type4 runtime. Same binding/generation/revision/effective total is idempotent even when consumption has advanced; a stale re-anchor with nonzero consumption is refused.

Mutations require BOX_STATE=IDLE, RFID manager idle, no armed override and all four runtime modes idle. The host must also serialize against its own load/unload workflow; BOX_STATE alone does not prove that no early motion is pending.

## Slot nominal length

INFO feature bit4 advertises the slot-length extension. SET_LENGTH checks the current four-byte UID and stores a separate UID/total pair for that slot; total0 clears it. It does not reset runtime or apply a geometric anchor. While used_mm is nonzero, a different total is refused. Normal idle/override/mode guards apply. A newly measured different UID invalidates the prior override.

The SGL1 reply has magic[4], slot u8, configured u8, reserved u16=0, currentUID[4], configured_total_mm u32. An absent or nonmatching UID override returns configured0 and total0.

BIND and future idle scans select the matching slot override first, then a nonzero legacy catalog total. If neither exists, a new geometric anchor cannot be applied. PLA/PETG and other materials can share one vendor geometry while retaining different nominal lengths.

## SGC1 catalog reply20

| Offset | Field |
|---|---|
|0|magic SGC1[4]|
|4|profileID u8|
|5|enabled u8|
|6|core_c10 u16|
|8|full_c10 u16|
|10|reserved u16=0|
|12|default_total_mm u32|
|16|last accepted nonzero revision u32, retained while disabled|

## SGD1 snapshot64

| Offset | Field |
|---|---|
|0|magic SGD1[4]|
|4|local slot u8|
|5|measurement flags u8|
|6|bound profileID u8 (0 unknown/unbound)|
|7|reserved u8=0|
|8|measurement generation u32|
|12|measured UID[4]|
|16|raw rotation length binary32, before OEM minimum-radius clamp|
|20|measurement tick u32|
|24|current conservative UID[4]|
|28|revision applied to the current anchor u32|
|32|runtime total_mm u32|
|36|runtime used_mm since anchor u32|
|40|initial percent u8|
|41|percent table u8|
|42|runtime valid u8|
|43|runtime type u8|
|44|bound catalog core_c10 u16|
|46|bound catalog full_c10 u16|
|48|bound catalog default_total_mm u32|
|52|bound catalog enabled u8|
|53|binding matches current cached UID u8|
|54|reserved u16=0|
|56|current tick u32|
|60|format1 u8|
|61|hardware backend flag u8|
|62|RFID manager flag u8|
|63|box state u8|

Flag bits:0 numeric/successful/same-UID usable measure;1 fresh complete API7 authentication/capture proof;2 original UID comparison mismatched;3 stock read failed;4 actual matching UID pair verified. Normal eligible API7 flags=19. Bits0 and1 must both be present for a profile.

R9 is **not** a vendor/provenance flag: the existing API7 message validator can report success and the OEM caller sets R9=1. Proof therefore uses per-attempt authenticated results, matching UID, full hit/ok/fail masks and capture markers. K2RL or old CAP masks alone are insufficient.

The OEM terminal logger retains its original area value for ABI compatibility; SGD1 and command0x03 report the applied calibrated value.

The cache is invalidated on measurement begin; auth results carry the attempt epoch sampled before the RF call. ARM/CLEAR invalidates transient auth/compare state, while CLEAR after decoding retains a completed measurement. A non-four-byte comparison invalidates a prior matching comparison without reading beyond the buffers.

Generation is boot-local. The protocol asserts consistency with current cached data, not physical occupancy, tag uniqueness across clones or manufacturer authenticity independent of the trusted host decoder. Empty/changed slots, connection resets and session changes must be reconciled by the host.

## Memory and validation boundary

The unchanged CFG6 sidecar occupies0x20006EE8..0x20006F28. New4×64 slot records occupy0x20006F28..0x20007028;4×16 catalog entries occupy0x20007028..0x20007068. UID-keyed nominal lengths occupy0x20007068..0x20007088; RH1 state occupies0x20007088..0x200070E8. The heap lower-bound literal is relocated to0x200070E8. All448 new bytes are explicitly zeroed after original heap initialization; they are not assumed to be BSS.

Raw/auth/UID hooks use integer operations only. The geometry hook preserves general registers, S0..S31/FPSCR expectations and PRIMASK around bounded computation. IRQ tests are modeled; they do not establish wall-clock latency, NMI/DMA behavior or actual RTOS stack margins.

Background research: [OpenCFS preload/RFID specification](https://github.com/MzTechnology97/OpenCFS-Firmware/blob/main/docs/spec/05-preload-rfid.md) and [multi-vendor decoder design](https://github.com/MzTechnology97/OpenCFS-Firmware/blob/main/docs/spec/11-multi-vendor-tags.md). OpenCFS is a separate reconstruction; this candidate retains the patched OEM API7 reader.

## Candidate R2 artifact status

The SGF1/RH1 R2 BIN SHA is `27cd264f36a217a98552351578f37fb4060e3d631793cc801242c0deaa6ec046`. It supersedes the withdrawn RH1 BIN SHA `b7cd0ab36011af9cd5af8f1ae4932008110a8fbdd174086c1a0043f2f5010158`, whose C handoff helpers used nominal rather than physical flash addresses. The wire protocol is unchanged. The source manifest identifies the exact R2 filename and offline validation boundary; hardware validation and vendor calibration remain pending.

## Candidate R3 artifact status

R3 SHA is `a6dec25c74e7d259eec0387193548a0c3cc78ec9fc4ddc35824f0fe0965385b8`, size185900. It preserves the wire contract and wraps the two original UID-getter observations when legacy metadata has a missing length. R2 could decode Bambu via RH1 but its real flags0x02 did not permit geometry binding; R3 retains the strict same-UID proof and BIND requirements. The previous R2 status above records historical evidence, not the current artifact.
