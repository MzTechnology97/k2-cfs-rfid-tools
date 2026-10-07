# Kalico host extras

These are the exact host-side extras used by the K2-OpenHost/Kalico API7 implementation:

- `box_rfid_diag.py` — opcode `0x57` transport, API7 decoding, internal-record access and key-arm/clear operations.
- `box_rfid_bambu.py` — Bambu HKDF Key-A derivation, API7 stock-task orchestration and material/colour parsing.

They are published here for reference and for porting to other Kalico/Klipper trees.

## Dependencies

The files expect the K2 branch's existing:

- `extras.serial_485.build_485_body`;
- `extras.box_protocol`;
- shared `serial_485` request queue/session;
- Box driver with `force_rfid_read(mask)`.

Do not open the RS-485 device independently while the printer stack owns it. Use the existing transport owner/queue.

## Configuration

```ini
[box_rfid_diag]
serial: serial485
address: 1
allow_active_rf: false
require_idle: true

[box_rfid_bambu]
serial: serial485
address: 1
```

For the integrated K2 branch, `[box]` also enables:

```ini
auto_bambu_rfid_fallback: true
```

Automatic fallback is deliberately restricted to API7. Older direct-auth diagnostic APIs are not used automatically.
