# CFG6 DIAG1 — experimental type-4 read-only RAM snapshot

**LAB ONLY. NOT FOR AUTOMATIC FLASHING OR HELPER MANIFEST.** DIAG1 derives from v3.26 with the same operational hooks, K2OH revision `v323-cfg6` and feature bitset `0xE3` for current Kalico compatibility. It adds a read-only diagnostic subcommand, without modifying Kalico, box.cfg, updater manifest, printer, or live CFS.

The original v3.26 returned a frozen 60% while Kalico's encoder-based estimate fell below 58%. DIAG1 tests whether the stock runtime is actually valid, type 4, in printing mode, has advanced its consumed-millimetres counter, and is linked to the correct active slot.

Request: opcode `0x57`, subcommand `0x15`, frame length `5`, payload `[0x15, MCU_slot_0_to_3]`. Invalid length or slot returns status 1. Successful response is exactly 32 little-endian bytes beginning with `RDG1`. Refer to [Italian protocol table](README.it.md) or `decode_diag1.py` for the full offset-by-offset format.

DIAG1 performs no motor/RFID/tag commands, no global RAM writes and no calls to stock odometer helpers; it reads the cached raw position, which is not directly comparable to the normalized checkpoint without stock sign/scale conversion. The offline decoder applies the unchanged ROM coefficient from nominal `0x080188B8` (`normalized = -raw * 0.0007886413368396461`) and reports a non-atomic approximate delta. The frame is not RTOS-atomic; it is not proof the accounting task executes.

Offline suite:

```sh
python3 test_all_diag1_offline.py
```

Offline decoder: `python3 decode_diag1.py <32_byte_hex_payload>`.

Experimental file: `CFG6-READONLY-DIAG1-NOT-FOR-FLASH.bin`

SHA-256: `6f07d792ad5fc6f402167a2aa1fe9c7b67df93dc558ac685176767a23b23a520`

**No CFS flash, printer movement, or hardware testing was performed.** Real MCU and bootloader safety remain unqualified. Any future installation requires separate explicit authorization.
