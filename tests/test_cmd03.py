"""Explain CMD03 255 using the exact candidate instructions, without hardware."""
from arm_addresses import code, physical_symbols, ACTUAL_BASE, RETURN
from pathlib import Path
import hashlib
import json
import struct
import test_accounting as t

from paths import ROOT, BUILD, CANDIDATE_IMAGE, RESULTS
D = BUILD
IMAGE = CANDIDATE_IMAGE.read_bytes()
SYMS = physical_symbols(json.loads((D / 'symbols.json').read_text()))
RF_MANAGER = 0x2000391C
MARKERS = RF_MANAGER + 2


def initialized():
    a = t.AuditArm(IMAGE, 3)
    a.geometry(60)
    a.position(495145.0)
    a.call(t.old.START, 3)
    a.position(505514.0)
    a.call(t.old.GATE_CALLSITE)
    assert a.state()['used_mm'] == 10368
    assert a.state()['runtime_valid'] == 1
    assert a.state()['table_percent'] == 57
    a.clear_audit()
    return a


def scenario(name, change, expected_value, expect_valid_wrapper):
    a = initialized()
    change(a)
    before = a.state()
    payload = a.response()
    after = a.state()
    visited = any(pc == SYMS['remaining_valid_wrapper'] for pc, _, _ in a.trace)
    assert payload['slot_value'] == expected_value, (name, payload, before)
    assert visited == expect_valid_wrapper, (name, visited)
    assert after == before, (name, 'getter modified accounting')
    return {'case': name, 'passed': True,
            'rf_manager_first_byte': a.u.mem_read(RF_MANAGER, 1)[0],
            'rf_manager_selected_slot': a.u.mem_read(RF_MANAGER + 1, 1)[0],
            'stock_marker': a.u.mem_read(MARKERS + a.slot, 1)[0],
            'accounting_before': before, 'cmd03': payload,
            'remaining_valid_wrapper_visited': visited,
            'accounting_unchanged': True}


def busy_same(a):
    a.u.mem_write(RF_MANAGER, b'\x00\x03')


def busy_other(a):
    a.u.mem_write(RF_MANAGER, b'\x00\x02')


def no_runtime(a):
    a.u.mem_write(MARKERS + a.slot, b'\x00')
    a.u.mem_write(a.row + 23, b'\x00')
    a.u.mem_write(t.rem.INTERNAL + a.slot * 76 + 75, b'\x00')


def proxy_without_native_record(a):
    # This models the Bambu proxy after a successful init, not observed RAM.
    a.u.mem_write(MARKERS + a.slot, b'\x00')
    a.u.mem_write(t.rem.INTERNAL + a.slot * 76 + 20, bytes(40))
    a.u.mem_write(t.rem.INTERNAL + a.slot * 76 + 75, b'\x00')


def exhausted(a):
    a.u.mem_write(a.row, struct.pack('<I', 250000))
    a.u.mem_write(a.row + 21, b'\x01')
    a.call(t.old.GATE_CALLSITE)
    assert a.state()['table_percent'] == 1
    a.clear_audit()


def main():
    rows = [
        scenario('valid tracking, RF manager idle', lambda a: None, 57, True),
        scenario('valid tracking, RF manager non-idle for the same slot', busy_same, 255, False),
        scenario('valid tracking, RF manager non-idle for another slot', busy_other, 57, True),
        scenario('missing stock record and missing accounting validity', no_runtime, 255, True),
        scenario('valid proxy accounting but missing stock getter marker', proxy_without_native_record, 0, True),
        scenario('exhausted initialized spool uses stock clamp', exhausted, 1, True),
    ]
    result = {'passed': True, 'candidate_sha256': hashlib.sha256(IMAGE).hexdigest(),
              'cases': rows,
              'conclusions': [
                  '255 can be emitted before reading the valid runtime or percent table.',
                  'The early condition reads 0x2000391C/+1, not API stock_state 0x200001F0.',
                  '255 can also result from failed stock/runtime validity checks.',
                  'The valid-wrapper override alone does not bypass the later stock getter marker check.',
              ],
              'limits': [
                  'RAM inputs are constructed offline; the live RF-manager bytes were not acquired.',
                  'The live 100-byte accounting runtime was not acquired.',
                  'No live printer command, RF read or memory write is performed.',
              ]}
    (RESULTS / 'cmd03.json').write_text(json.dumps(result))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
