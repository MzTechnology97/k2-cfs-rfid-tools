# CFS Firmware compatibility policy

Runtime CONFIG SET for the v3.23 CFG4 parameters is **only supported with
the matching K2-OpenHost modified firmware distributed by this repository**.
It is not compatible with stock Creality or arbitrary third-party firmware.

- Creality original G32/APP153: no matching CONFIG extension.
- K2-OpenHost patched-stock v3.13–v3.22: older schemas; not CFG4-capable.
- **v3.23 CFG4**: identity 0x7A = K2OH, format 1, variant 4, revision
  v323-cfg4, application cfs0_000_153, CONFIG_V2 features 0xD7.
  Only IDs 1/2/3/5/7/8 have effective write hooks in this candidate.
- **OpenCFS**: 0x7A = OCFS, variant RELEASE/INERT/BENCH; it can be
  identified and reported, but it is a separate firmware family and
  K2OH stock-patch CONFIG_SET must not be sent to it.
- Unknown firmware: fail closed, read-only.

The legacy v3.22 image shares feature 0xD7; a feature byte by itself is
not sufficient identification. The stock GUI's 1.5.3 version also cannot
distinguish the builds.

[Guida completa ai 28 parametri in italiano](CFS_V323_PARAMETER_GUIDE_IT.md).
