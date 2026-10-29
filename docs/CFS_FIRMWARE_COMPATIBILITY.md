# Current R3 reference

The current SGF1/RH1 R3 image is
[`a6dec25c…`](../firmware/cfg6-spool-profiles/README.md), 185900 bytes,
for CFS G32 / cfs0_000_153. It retains the CFG6/API7/RDG2 contracts below and
adds SGF1, SLOT_LENGTH and RH1. Use the complete matching
[Kalico branch](https://github.com/MzTechnology97/kalico-k2pro/tree/k2-pro-openhost),
including box_spool_profiles. Vendor geometry is host RAM configuration.
See [calibration](CFS_SPOOL_CALIBRATION.md) and [R3 hardware scope](../firmware/cfg6-spool-profiles/HARDWARE-R3.md).

The following dated RDG2 section describes the retained fallback image,
not the new R3 image or its per-UID nominal length.

# CFS firmware compatibility — CFG6 RDG2

[Italiano](CFS_FIRMWARE_COMPATIBILITY_IT.md) · [Validation](CFG6_RDG2_VALIDATION.md) · [Current firmware](../firmware/cfg6-rdg2/cfs0_050_G32-cfs0_000_153-K2OH-CFG6-RDG2.bin)

The active branch supplies one image for **Creality K2 Pro CFS G32 / APP `cfs0_000_153`**. Operation was verified with Bambu PETG HF in physical slot 4 on 28 October 2026. That result does not qualify other boards, application versions, tag formats or every lifecycle transition.

| Interface | Required identity / scope |
| --- | --- |
| Exact image | 179,976 bytes; SHA-256 `7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f` |
| CONFIG | `0x7A: K2OH`, variant `v323-cfg6`, API2, features `0xE3`, G32/APP153 |
| CONFIG GET | 28 IDs, 0 through 27 |
| CONFIG writable IDs | 1–3, 5–9, 11–24, 27: **23 IDs** |
| CONFIG GET-only IDs | 0, 4, 10, 25, 26 |
| RFID diagnostics | Opcode `0x57`, API7, capabilities `0xE8` |
| RDG2 | Opcode `0x57`, subcommand `0x15`; 64-byte payload, version 2 |
| Matching Kalico diagnostic reader | SHA-256 `2b9810456f6bb7ae0f2ebbf82cdf1f293dab84867a9db2799fb3035cb7aef867` |

The CFG6 identity is inherited from earlier builds. It is not a unique release identifier. The image SHA distinguishes this RDG2 build; an RDG2 response proves support for that diagnostic format, not the identity of every firmware byte. The printer's OEM GUI version alone is insufficient.

CONFIG SET is specific to the matching patched-stock firmware. Full identity, API, feature byte, variant and target must be checked before enabling writes. The inherited volatile overrides belong to the controlled Kalico startup workflow; this documentation does not authorize live parameter changes during printing or loading/unloading.

The [historical English parameter guide](CFS_V323_PARAMETER_GUIDE_EN.md) explains the inherited catalogue and its earlier CFG4 behavior. Its six-ID write list is historical; the **23-ID CFG6 list above** is current.

## Remaining percentage and diagnostic limits

Kalico receives CFS values through normal `CMD 0x03`; RDG2 exposes the RAM state used to explain them. A reply of `0xFF` means no usable percentage was returned for that slot in that request. It can occur before the runtime-validity wrapper when the stock RF manager selects the same slot, or after validity checks fail. It alone does not prove uninitialized accounting.

A valid proxy runtime with a missing stock getter marker can still yield zero. This build retains the stock getter behavior; it does not bypass those filters. A snapshot describes its acquisition time and cannot guarantee a later reply sees the same state.

The verified Bambu proxy uses 330 m, while its Kalico profile uses 327 m. The CFS integer percentage and Kalico's encoder estimate can differ. See [the validation record](CFG6_RDG2_VALIDATION.md) for observed consumption, atomicity evidence and pending hardware checks.

## Previous versions

Older installable images and their tests are absent from the current branch. The [frozen historical tree](https://github.com/MzTechnology97/k2-cfs-rfid-tools/tree/0ad22669248cc845a3c8d22dd613500c4b95feb3) preserves their files and dated results. Historical API/CFG identities are not interchangeable with the current write contract. The intermediate v3.13 image retrieved into ignored `work/base-pinned.bin` is only a SHA-pinned build input.
