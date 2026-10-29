# RH1 single mechanical RFID cycle

This is a build-time candidate contract, not a flashed or hardware-qualified release. RH1 extends the existing opcode 0x57. No RF or motor operation runs in its command handler. All integers are little endian. The subcommand is payload byte 0 (frame byte 4); frame byte 1 is payload size + 3. Invalid or stale input returns existing wire status 1; busy returns status 7. Successful replies have status 0.

## Commands

| Subcommand | Payload bytes | Layout | Reply |
|---|---:|---|---|
| 0x20 INFO | 1 | sub | info12 |
| 0x21 CONFIG | 12 | sub, enable:u8, zero:u16, session:u32, wait_ms:u16, lease_ms:u16 | state40 |
| 0x22 START | 12 | sub, slot:u8, zero:u16, session:u32, request_id:u32 | state40 |
| 0x23 POLL | 8 | sub, zero:u24, session:u32 | state40 |
| 0x24 KEYS | 34 | sub, slot:u8, zero:u16, session:u32, token:u32, uid[4], key0[6], key1[6], key2[6] | state40 |
| 0x25 DECLINE | 16 | sub, slot:u8, zero:u16, session:u32, token:u32, uid[4] | state40 |

INFO bytes: `RHI1` at 0; version 1 at 4; state size 40 at 5; slot count 4 at 6; feature mask 7 at 7; maximum wait 5000:u16 at 8; maximum lease 10000:u16 at 10. Feature bits 0/1/2 mean bounded in-cycle key handoff / asynchronous manual START / host polling lease.

CONFIG is accepted only while idle with every runtime mode zero and no armed override. Enabling CONFIG and new START require legacy HW_FLAG zero; the secure path does not support this handoff. The host must generate a fresh nonzero session for each firmware connection/bootstrap. Wait is 500..5000 ms, lease is 1000..10000 ms. CONFIG does not activate a lease; POLL does. Boot disables RH1 and clears all of its reserved SRAM. A host that does not CONFIG/POLL adds no waiting to ordinary CFS operation.

POLL with the configured session activates or renews its lease, including while the RF thread waits. KEYS and DECLINE require an active lease and exact session, token, slot and current UID equality. KEYS are copied once into API7 scratch in the RF thread, then removed from RH SRAM. No vendor is inferred from UID or API7 success; the host still classifies the complete decoded capture.

START only enqueues the existing OEM preload worker. Its guard is atomic: BOX idle, manager idle, no other RH job, every runtime mode zero, no armed override, all four hub sensors empty, requested entry sensor present. It requires a nonzero request ID. The most recent request ID is idempotent within the configured session; reuse with a different slot is invalid. Automatic insertion uses request ID zero. The host must serialize manual requests and use a new request ID for each intentional scan.

## State reply, 40 bytes

| Offset | Type | Meaning |
|---:|---|---|
| 0 | 4 bytes | `RHO1` |
| 4 | u8 | version 1 |
| 5 | u8 | state: 0 IDLE, 1 RUNNING, 2 WAIT_KEYS, 3 KEYS_READY, 4 DONE |
| 6 | u8 | slot 0..3, 255 when unassigned |
| 7 | u8 | result: 0 NONE, 1 NATIVE_OK, 2 API7_OK, 3 DECLINED, 4 TIMED_OUT, 5 RF_FAILED; 6 reserved CANCELED |
| 8 | u32 | session |
| 12 | u32 | monotonically advancing nonzero handoff token within boot |
| 16 | u32 | request ID, zero for automatic insertion |
| 20 | 4 bytes | measured scan UID, nonzero only once handoff is offered |
| 24 | u32 | remaining key wait, milliseconds; zero outside WAIT_KEYS |
| 28 | u32 | flags: enabled=1, current lease valid=2, async START job awaiting cleanup=4 |
| 32 | u32 | SGF1 current measurement generation for slot |
| 36 | u32 | current RTOS tick (1000 Hz), modulo 2^32 |

DONE is published only by the existing preload thread's periodic hook after manager state 1 and BOX state 0. For asynchronous START it calls stock 0x08012358 exactly once to restore the saved read-on-insert setting. Reading POLL has no RF or completion side effect. Geometry BIND and per-UID total length are applied afterward while idle from the cached raw measurement; they require no second revolution.

## Original-code evidence and guards

All addresses below are the pinned image's nominal disassembly addresses (APP_BASE 0x08010000), not a new hardware memory-map claim.

* Existing hook 0x08012E62 calls message validator 0x0801A670 after motor stop 0x0801E198 and 500 ms delay. On failure the OEM branches at 0x08012E6A into reverse/reposition and retry. RH1 offers host keys before that branch and retries only authentication in the same RF thread.
* S16 at that call is the final odometer and S17 the first odometer. The absolute circumference is formed later at 0x08012FA4..0x08012FB8. RH1 preserves these FP registers; cached raw SGF capture remains at 0x08013112 before the OEM clamp.
* Validator disables the reader at 0x0801A6C0 after legacy reads. Its new first attempt does not reselect the tag; RH1 explicitly calls 0x0801959E(reader, reader_slot) before its second validator call, without a motor command.
* 0x0801233C is enqueue-only: if manager is idle it sets manager=0 and forced slot 0x20000027. It saves the current flag from 0x20000025 to 0x20000026 and sets the requested flag. RH1 checks idle atomically before calling it.
* 0x08012358 restores that flag and can forcibly set idle when used too early. RH1 calls it only once, from worker completion, after manager=1 and BOX=0. No synchronous 0x08011EC4 / 0x08011E80 path is used.
* Pure input helpers 0x0801B78C (entry) and 0x0801B79C (hub) call GPIO read 0x08025F14 with no delay. Zero is occupied; one is empty. The debounce helper 0x080124C4 includes sleep and is deliberately unused in START.
* Delay 0x0802EE28 yields through RT-Thread 0x0802EC60. The wait loop restores interrupts before every delay and refuses handoff if entered with PRIMASK set.
* Authentication arm clears the four scratch ranges bytes 4..19 but calls sgf_prepare_handoff instead of sgf_cancel_transients, retaining this scan's UID-pair comparison while advancing its auth epoch.
* Success conversion requires fresh SGF auth UID, mask7/fail0 and epoch, current record UID, API7 hit/ok masks7/fail0, CAP1/CAP2 markers and K2RL latch. A legacy ARM already present in any of the four records on validator entry is never replaced by a new handoff.

## SRAM and linker policy

Existing family bank 0x20006F28..0x20007068; per-slot length bank 0x20007068..0x20007088; RH1 bank 0x20007088..0x200070E8 (96 bytes). Heap start is moved to 0x200070E8 and the boot hook clears all 448 bytes from 0x20006F28. No hypothetical free SRAM, heap tail, or stack region is used. Original MSP and heap end are unchanged. Firmware sources and emulation must be reviewed before any release or flash.

The RH1 build-policy end is nominal 0x0803D800 (physical 0x08030800), approved after checking local cfs-firmware-re docs/01-hardware-overview.md lines 19..25,50..54 and docs/08-loader-and-recovery.md lines 69..95. This stays below the silicon fast-fetch boundary and parameter page; no flash-data region is moved. It is a build ceiling, not certification/readback of the installed loader. KEYS retries are idempotent only while KEYS_READY and with identical bytes; after RUNNING/DONE the host recovers a lost acknowledgement through POLL.

## R2 native-call correction (29 October 2026)

The application vector table and reset entry establish a physical load base of `0x08003000`, while the disassembly and linker use `0x08010000`. The C `FN` adapter now subtracts `0xD000` before setting the Thumb bit. The seven native calls (validator, enqueue, cleanup, RFID reader selection, delay, hub and inlet sensors) are checked as physical literal values by preflight. Relative assembly branches are unchanged. A single-image physical-base test executes original validator, enqueue, worker finalizer, cleanup and heap initialization; only hardware/RTOS boundaries are modeled. The exact earlier BIN SHA `b7cd0ab36011af9cd5af8f1ae4932008110a8fbdd174086c1a0043f2f5010158` fails the same physical regression and is withdrawn.

## R3 UID-pair evidence (29 October 2026)

The original first/second UID-getter callsites are nominal0x08012B78 and
0x08012DD2 (physical0x08005B78 and0x08005DD2). Both follow successful RF
presence confirmation and the descriptor copier0x0801A608. A nonzero RF result
branches back to polling at0x08012B4E. Descriptor copying itself requires the
reader selector0x0801959E to return0. The first call records the first passage;
the second follows the subsequent confirmed passage via12BAC/12C0C/12DCC.

The original getter0x0801A70C uses INTERNAL[slot]+75 as length. Hardware R2
showed0, and executing copier/getter/comparator with this descriptor reproduced
flags0x02 despite successful API7 authentication. R3 recovers a four-byte UID
only at those two worker calls and under strict legacy metadata checks. It
copies both observations rather than substituting a comparison length over
unwritten buffers. It does not change byte75 globally, force equality, weaken
quality flags or identify the manufacturer from a generic UID.
