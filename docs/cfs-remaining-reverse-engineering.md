# CFS 1.5.3 remaining-filament reverse engineering

I started this analysis after confirming on hardware that `CMD_RFID_REMAINING (0x03)` returns `0xFF` for Bambu API7 tags even when material/colour decoding succeeds. The same limitation applies to the current QIDI path.

My goal is to determine whether I can initialize the **stock CFS odometer in RAM only**, without writing anything to a Bambu/QIDI RFID tag.

## Confirmed command path

The stock command dispatcher handles `0x03` at:

```text
0x0801C3C0
```

It passes the requested slot mask to:

```text
0x0801BF66(mask)
```

The reply builder initializes all four result bytes to `0xFF`. For each requested slot it only replaces that sentinel when the stock validity checks succeed.

The final byte returned for a valid slot comes from:

```text
0x080123CE(slot)
```

## Stock remaining table

The stock per-slot database base is:

```text
0x2000391C
```

The state byte is:

```text
0x2000391C + 2 + slot
```

The current remaining percentage is:

```text
0x2000391C + 0x58 + slot
```

so the four percentage bytes are:

```text
slot 0  0x20003974
slot 1  0x20003975
slot 2  0x20003976
slot 3  0x20003977
```

The stock setter is:

```text
0x080123E4(slot, percent)
```

It clamps zero to one before storing the byte. Therefore `CMD 0x03` is not reading a percentage directly from the RFID tag; it is returning a value maintained in CFS RAM.

## Stock 40-byte RFID record

The stock 40-byte ASCII record starts at:

```text
0x2000391C + 0x5C + 40 * slot
```

The stock record setter is:

```text
0x08012444(slot, record40)
```

The validity path through `0x0801245C(slot)` checks that:

- the per-slot state byte is nonzero;
- the first record character is in the accepted stock range;
- the associated runtime structure is in a valid state.

This explains the observed `0xFF` for Bambu/QIDI: API7 intentionally leaves the Creality stock record untouched, so the stock `CMD 0x03` gate never considers that slot a normal Creality spool.

## Real Creality reference record

From my historical K2 Pro log I recovered a real stock Creality record for UID `0203DFC6`:

```text
AB1240276A21056280B1BEC60330000001000000
```

The host parser maps its fields as:

```text
month       offset 0   len 1
day         offset 1   len 2
year        offset 3   len 2
supplier    offset 5   len 4
batch       offset 9   len 2
mat_id      offset 11  len 6
color       offset 17  len 7
len         offset 24  len 4
number      offset 28  len 6
reserve     offset 34  len 6
```

For this real tag the length field is:

```text
0330
```

meaning 330 metres.

The same 40-byte record is present at `INTERNAL_RECORD[20:60]`; the length field is therefore at `INTERNAL_RECORD[44:48]`.

## Runtime odometer structure

The stock odometer/runtime base is:

```text
0x20004590
```

with a stride of exactly 100 bytes per slot:

```text
runtime(slot) = 0x20004590 + 100 * slot
```

The stock validity function at `0x0801ABA0(slot)` uses, among other fields:

```text
+23  active/valid flag
+40  status/error word
+99  runtime type
```

The path is considered valid when the required flag/state conditions are satisfied.

## Stock initializer

The key stock initializer is:

```text
0x0801AA14(slot, initial_percent)
```

I traced the following behavior:

1. locate the 100-byte runtime structure;
2. locate that slot's 76-byte `INTERNAL_RECORD`;
3. copy all 76 bytes into runtime offset `+24`;
4. store the initial percentage at runtime `+20`;
5. clear the usage counter at runtime `+0`;
6. set runtime flag `+23`;
7. parse the final three ASCII digits of the four-character stock length field;
8. multiply the resulting metres by 1000;
9. store the nominal filament length in millimetres in the runtime structure.

With a stock record containing `len="0330"`, the initializer obtains:

```text
330 m -> 330000 mm
```

This is strong evidence that the stock remaining mechanism can be initialized entirely from RAM metadata.

## Update paths: type 4 and type 7

I found only three callsites to the stock remaining setter `0x080123E4`.

### Runtime type 4

The type-4 path computes a remaining percentage from the runtime counters and nominal total. In simplified form:

```text
used_percent = used * 100 / total
remaining = initial_percent - used_percent
```

The result is stored with `0x080123E4`.

I have not found an RFID tag-write call in this type-4 path. This is therefore the most promising mode for Bambu/QIDI.

### Runtime type 7

The type-7 path includes explicit RFID update logic. The stock binary contains the diagnostic string:

```text
rfid write used=%dmm,percent=%d: find=%d,write=%d,error=%d
```

I do not want to use that path for Bambu/QIDI because the design requirement is to keep third-party tags read-only.

## Important unresolved field

The runtime byte at `+99` selects behavior such as type 4 versus type 7.

A cached `INTERNAL_RECORD[75]` can be zero after a normal RFID read, so I do not yet assume that copying the record alone is enough to select the correct runtime mode. I will not create a RAM-writing shim until I have observed the stock runtime fields directly on hardware.

## v3.4 read-only diagnostic candidate

To make that comparison safe and repeatable I created a separate v3.4 diagnostic candidate. It does **not** initialize or modify the stock odometer.

It adds API7 subcommand `0x0A REMAIN_STATE` and returns a fixed 40-byte snapshot containing:

- stock state byte;
- stock remaining byte;
- `INTERNAL_RECORD[75]`;
- runtime type `+99`;
- initial percent `+20`;
- runtime flags `+21/+22/+23`;
- secondary percent `+32`;
- stock/runtime first record byte;
- counters at runtime `+0/+4/+28/+36/+40`;
- runtime and stock four-byte ASCII length fields.

I intentionally did not expose an arbitrary RAM reader.

The matching Kalico command is:

```text
BOX_RFID_DIAG_REMAIN_STATE SLOT=<0..3>
```

## Candidate validation

The v3.4 candidate:

```text
size        176952 bytes
handler     1280 bytes at 0x0803AE38
CRC16       0x915D
SHA-256     6da931b20ce8e54f5a4e4b7c5b59999507d9eaefae5afcb9066da4a0acda26cc
INFO        07 02 02 F8 03 10
```

Static validation confirms:

- app id remains `cfs0_000_153`;
- declared length matches file size;
- CRC-16/BUYPASS verifies;
- the six patched RFID read callsites point to the new wrappers;
- the only image changes outside the handler tail are container metadata and those six read callsites;
- the new handler contains no calls to the known MIFARE write or EEPROM write routines;
- a clean rebuild reproduces the exact SHA-256 byte-for-byte.

Hardware validation is still pending. The K2-OpenHost flash helper correctly requires a fresh root host-evidence proof with Klipper stopped and the gadget ports free. The current remote session cannot complete `sudo`, so I did not bypass that safety gate.

## Next hardware comparison

Once the normal host-evidence preflight can run, I will capture `REMAIN_STATE` for:

1. a genuine Creality RFID spool;
2. a Bambu spool after API7 recognition;
3. the hardware-validated QIDI PET-CF spool.

That comparison should tell me which stock runtime fields need RAM-only initialization and whether type 4 can be used as the no-tag-write remaining path.