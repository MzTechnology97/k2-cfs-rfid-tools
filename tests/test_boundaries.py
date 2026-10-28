"""Additional candidate ABI, RAM-init, unload and container checks; no hardware."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
from unicorn.arm_const import *
import test_accounting as t

from paths import ROOT, BUILD, BASE_IMAGE, CANDIDATE_IMAGE, RESULTS
D = BUILD
IMAGE = CANDIDATE_IMAGE.read_bytes()
REF = BASE_IMAGE.read_bytes()
SYMS = json.loads((D / 'symbols.json').read_text())


def view(a):
    return (bytes(a.u.mem_read(a.row, 100)),
            bytes(a.u.mem_read(t.old.STATE, 64)),
            bytes(a.u.mem_read(t.rem.PERCENT, 4)))


def init_equivalence():
    count = 0
    for slot in range(4):
        for length in [b'0010', b'0327', b'0330', b'0999']:
            for mode in [0, 2]:
                arms = []
                for image, secure in [(REF, 1), (IMAGE, 0)]:
                    a = t.AuditArm(image, slot, length=length, secure=secure)
                    # Stock native init preserves lifecycle fields and copies 76 bytes.
                    a.u.mem_write(a.row + 8, struct.pack('<I', 321))
                    a.u.mem_write(a.row + 12, struct.pack('<f', 1234.5))
                    a.u.mem_write(a.row + 16, struct.pack('<I', 17))
                    a.u.mem_write(a.row + 21, bytes((1, mode)))
                    a.geometry(35)
                    arms.append(a)
                assert view(arms[0]) == view(arms[1]), (slot, length, mode)
                count += 1
    return count


def unload_equivalence():
    count = 0
    for slot in range(4):
        for start, now in [(1000, 1000), (1000, 30999), (1000, 31000),
                           (1000, 31001), (0xfffff000, 0x7000)]:
            expired = ((now - start) & 0xffffffff) > 30000
            arms = []
            for image, gate in [(REF, t.DIRECT_TASK), (IMAGE, t.old.GATE_CALLSITE)]:
                # Initialize reference through its enabled native stock path.
                a = t.AuditArm(image, slot, secure=int(image is REF))
                a.geometry()
                a.u.mem_write(0x20000000, b'\x00')
                a.position(500000)
                a.call(t.old.START, slot)
                a.now = start
                a.call(t.old.UNLOAD, slot)
                a.now = now
                a.position(500225)
                # Legacy does not authorize the original pre-timeout RF write.
                # Only expired mode2 is compared with its stock END behavior.
                if expired or image is IMAGE:
                    a.call(gate)
                arms.append(a)
            assert view(arms[0]) == view(arms[1]), (slot, start, now, arms[0].state(), arms[1].state())
            count += 1
    return count


def abi():
    count = 0
    min_sp = 0x2000ee00
    for vendor, secure in [('native', 0), ('thirdparty', 0), ('native', 1), ('native', 2)]:
        for mask in [0, 1]:
            for flags in [0, 0x20000000, 0x98000000, 0xf8000000]:
                a = t.AuditArm(IMAGE, 2, vendor=vendor, secure=secure)
                if vendor == 'thirdparty':
                    a.u.mem_write(t.rem.INTERNAL + 2 * 76 + 12, struct.pack('<I', t.rem.LATCH))
                expected = {}
                for i in range(13):
                    reg = getattr(t, 'UC_ARM_REG_R' + str(i))
                    expected[reg] = 0x12340000 + i
                expected[UC_ARM_REG_R4] = 60
                expected[UC_ARM_REG_R8] = 2
                expected[UC_ARM_REG_R9] = 1 if vendor == 'native' else 0
                expected[UC_ARM_REG_R11] = 0x2000391c + 2
                for reg, value in expected.items():
                    a.u.reg_write(reg, value)
                a.u.reg_write(UC_ARM_REG_APSR, flags)
                a.u.reg_write(UC_ARM_REG_PRIMASK, mask)
                a.call(SYMS['geometry_percent_store_wrapper'])
                for reg, value in expected.items():
                    assert a.u.reg_read(reg) == value, (vendor, secure, mask, flags, reg)
                assert a.u.reg_read(UC_ARM_REG_APSR) & 0xf8000000 == flags
                assert a.u.reg_read(UC_ARM_REG_PRIMASK) == mask
                assert a.u.reg_read(UC_ARM_REG_SP) == 0x2000ee00
                min_sp = min(min_sp, *(r[2] for r in a.trace))
                # Public calls made under the mask must enter with an aligned stack.
                public = {t.old.ODOMETER, t.old.CLOCK, 0x0803393c, 0x0801245c, 0x080123e4}
                assert all(sp % 8 == 0 for pc, _, sp in a.trace if pc in public)
                count += 1
    return {'cases': count, 'maximum_observed_stack_bytes_geometry': 0x2000ee00 - min_sp}


def container():
    from test_container import inspect
    static = json.loads((BUILD / 'static-validation.json').read_text())
    assert len(static['patches']) == 33
    return {'container': inspect(CANDIDATE_IMAGE), 'patch_sites': 33}


def failed_rescans():
    results = []
    for slot in range(4):
        for failure in ['OEM invalid', 'marker absent', 'record mismatch', 'type7']:
            a = t.AuditArm(IMAGE, slot)
            a.geometry()
            a.position(495145.0)
            a.call(t.old.START, slot)
            a.position(505514.0)
            a.call(t.old.GATE_CALLSITE)
            before = view(a)
            if failure == 'OEM invalid':
                a.native_valid = 0
            elif failure == 'marker absent':
                a.u.mem_write(0x2000391e + slot, b'\x00')
            elif failure == 'record mismatch':
                a.u.mem_write(t.rem.RECORD_TABLE + slot * 40, b'Z')
            else:
                a.u.mem_write(t.rem.INTERNAL + slot * 76 + 75, b'\x07')
            a.geometry(60)
            assert view(a) == before, (slot, failure, a.state())
            response = a.response()
            # An invalid stock marker can suppress the response percentage.
            # Compare the actual stock getter on identical post-rescan RAM.
            reference = t.AuditArm(REF, slot)
            reference.u.mem_write(0x20000000, bytes(a.u.mem_read(0x20000000, 0xe000)))
            assert response == reference.response(), (slot, failure, response)
            results.append({'slot': slot, 'failure': failure, 'preserved_percent': 57,
                            'actual_cmd03': response})
    return results


def main():
    result = {'passed': True, 'native_init_stock_equivalent_cases': init_equivalence(),
              'unload_stock_equivalent_cases': unload_equivalence(), 'abi': abi(),
              'container': container(), 'rejected_rescans': failed_rescans()}
    (RESULTS / 'boundaries.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
