# K2OH CFS v3.23 CFG4 — EXPERIMENTAL

Hardware: G32, Creality APP 153; **hardware qualification still open**.

The firmware is only compatible with the matching K2-OpenHost runtime
integration, and the original stock Creality/third-party images are NOT
compatible with these CFG4 parameter-write operations.

- Firmware image: cfs0_050_G32-cfs0_000_153-runtime-config-v3_23-K2OH-CFG4-EXPERIMENTAL.bin
- Size: 178340 bytes; SHA256: 118f34118edeb1e3d4ac018445b3fb839f8762b9d762bbfc011e62861fe8f71b
- Identity on 0x7A: K2OH, format 1, variant 4, revision v323-cfg4.
- API 0x57/0x10: 28 entries, feature 0xD7. That feature by itself
  cannot distinguish v3.23 from v3.22.
- Effective writable IDs: 1,2,3,5 hub stock speed table; 7 and 8
  timing callsites. All other IDs must remain read-only.
- ID8 is real milliseconds in the host, with exact /10 conversion to
  original 10ms stock polling units. ID17 has corrected 400ms default.
- Console CONFIG SET/RESET/APPLY is not exposed by the paired Kalico;
  values come only from the CFG at Klipper startup.
- OpenCFS has a separate OCFS identity/firmware family. Detection does
  not imply support for this patched-stock CFG4 write protocol.
- Keep v3.22 available as the tested rollback path.

# CFS Runtime Config v3.23 CFG4 — EXPERIMENTAL

Built 18 October 2026. Not hardware-qualified. No flash or printer motion performed.

## Image
- Filename: cfs0_050_G32-cfs0_000_153-runtime-config-v3_23-K2OH-CFG4-EXPERIMENTAL.bin
- Size: 178340 bytes
- SHA256: 118f34118edeb1e3d4ac018445b3fb839f8762b9d762bbfc011e62861fe8f71b
- Identity command 0x7A: K2OH format 1, variant 4, revision v323-cfg4.
- Runtime 0x57/0x10: API v2, 28 parameters, features 0xD7 (shared with v3.22; 0x7A distinguishes v3.23).
- T113 PR13 offline container validator PASS; 0 unexpected source patch bytes.

## Supported CONFIG-at-startup writes
- ID1 hub_forward_speed, ID2 hub_transition_speed, ID3 hub_insert_speed, ID5 hub_reverse_speed (stock RAM table, 1–255).
- ID7 hub_transition_wait_ms: 3200ms stock, 100–10000ms accepted.
- ID8 insert_sensor_timeout_ms: 7000ms stock, 1000–50000ms in multiples of 10; MCU converts to 10ms stock polls.
- Feeder IDs 0/4 have no speed effect. IDs 6 and 9–27 are GET-only, including dead-code 10/25/26. ID17 default is corrected to 400ms.
- Existing stock BOX_STATE write guard remains; no independent motor-idle guard added.
- Does not add type-4 live remaining tracking; original v3.22 RFID/remaining behavior retained.

## Kalico staged changes
- Worktree: ~/cfs-v323-build/kalico-v323-integration
- Local commit: b1b6a8c8 (feat/cfs-v323-startup-cfg-only).
- Exact 0x7A identification required before writes, then enum/operation lock, write, GET readback.
- G-code CONFIG_SET / CONFIG_RESET / CONFIG_APPLY not registered; INFO/DIAG/SNAPSHOT remain read-only.
- Unimplemented parameter differences appear under skipped_overrides in status.
- Existing active Kalico source and running CFG were NOT changed. Deploy tested staging only after the first firmware RS-485 hardware check.

## Validation and recovery
- 61 Kalico unit tests PASS (existing and v3.23 startup test suite).
- Unicorn PASS for 0x7A, hub speeds 1/2/3/5, ID7/8, bad limits and read-only IDs.
- Original stock callsite defaults, all caller-visible registers and APSR pass ID7/8 differential emulation.
- T113 loader validator PASS. The image is not certified on real CFS hardware.
- v3.22 fallback SHA256: 40dbaad88de7b6f9435592fa03b081e9b96663a9e84896b1ad8021a8f13cf8c7.
- Helper candidate 17 for v3.23; fallback v3.22 candidate 3 at time of registration. Other sessions may reorder items.

## Intended test flow
1. Choose the v3.23 experimental candidate explicitly in the helper, and test only RS-485, CFS discovery, stepper discovery and 0x7A identity.
2. Do not home/move the printer during initial bus validation.
3. If bus fails, restore v3.22 through the custom image path, not a normal version-comparison upgrade.
4. Once bus works, deploy the Kalico worktree module, enable auto_apply in box.cfg for supported values, restart Klipper at a controlled time, then read back values.
5. There is no production release approval; no full RFID regressions or motor fault qualification yet.
