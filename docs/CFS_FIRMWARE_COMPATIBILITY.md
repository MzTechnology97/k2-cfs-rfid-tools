# CFS firmware compatibility policy

Runtime CONFIG SET is supported **only** on the matching K2-OpenHost patched-stock CFS firmware and **only after checking its complete runtime identity**. It is not a generic Creality, OpenCFS or third-party protocol.

| Firmware family | Runtime identity / capabilities | Effective writable IDs | Policy |
| --- | --- | --- | --- |
| Creality stock `cfs0_000_153` | No K2OH CONFIG extension | None | Read-only; do not issue K2OH CONFIG SET |
| K2OH v3.13–v3.22 | Historical API/diagnostic schemas; v3.22 reports feature `0xD7` | Legacy-specific only | Do not assume CFG4/CFG5T/CFG6 support |
| **CFG4 v3.23** | `0x7A: K2OH`, `v323-cfg4`, CONFIG API2, feature `0xD7`, G32/APP153 | 1, 2, 3, 5, 7, 8 (6 IDs) | CFG4-only startup writes |
| **CFG5T v3.24** | `0x7A: K2OH`, `v323-cfg5t`, API2, feature `0xE5`, G32/APP153 | 1, 2, 3, 5, 7, 8, 20, 22 (8 IDs) | CFG5T-only startup writes; type-4 live remaining **experimental** |
| **CFG6 v3.25** | `0x7A: K2OH`, `v323-cfg6`, API2, feature `0xE3`, G32/APP153 | 1–3, 5–9, 11–24, 27 (**23 IDs**); 28 readable, 5 GET-only | CFG6-only startup writes; type-4 live remaining **not hardware-qualified** |
| **CFG6 type-4 rescan candidate** | Same `v323-cfg6 / 0xE3` identity as v3.25 | Same 23 IDs | **Draft [PR #60](https://github.com/MzTechnology97/k2-cfs-rfid-tools/pull/60), NOT for flash**: one attempted update failed before completion; see [issue #59](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/59) |
| OpenCFS | `0x7A: OCFS`; distinct RELEASE/INERT/BENCH variants | None from the K2OH CFG tables | Identify/read only; never send K2OH CONFIG SET |
| Unknown identity or third-party firmware | Not verified | None | Fail closed (read-only) |

Firmware identification must match the **complete** runtime identity, API, feature, variant and expected target, not only the feature byte. In particular, **`0xD7` is not enough to distinguish v3.22 from CFG4**, and the Creality GUI version `1.5.3` identifies neither patch family nor build. The CFG6 rescan candidate **deliberately reuses the CFG6 v3.25 identity**; only an independently validated package SHA-256 distinguishes the two images. Runtime identity alone cannot prove that an attempted flash completed successfully.

CFG6 write settings are volatile RAM overrides, normally applied from the paired Kalico `box_cfs_runtime` configuration at controlled startup, **not from a live console SET**. They should never be applied during printing, feeding, loading, unloading, or an active RFID operation. `BOX_STATE=IDLE` by itself is not a proven motor-idle interlock ([issue #9](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/9)). GET/SET readback at idle does **not** qualify the type-4 accounting or mechanical behavior under load.

The real-print type-4 remaining percentage was observed staying around **35%** on CFG6 v3.25; [issue #59](https://github.com/MzTechnology97/k2-cfs-rfid-tools/issues/59) tracks it. A code-level reset on RFID reinitialization is reproduced offline in PR #60, but the cause of the physical symptom and a hardware-safe candidate are **not yet established**. Do not advertise CFG6 live remaining as verified.

Further reading: [28-parameter guide (EN)](CFS_V323_PARAMETER_GUIDE_EN.md) · [Italiano](CFS_FIRMWARE_COMPATIBILITY_IT.md) · [Parameter guide (IT)](CFS_V323_PARAMETER_GUIDE_IT.md) · [CFG6 detailed parameters (EN)](../firmware/v3.25-cfg6-lab/PARAMETERS_EN.md).
