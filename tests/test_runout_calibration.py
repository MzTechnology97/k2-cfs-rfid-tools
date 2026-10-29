"""Execute the first Bambu runout calibration against the actual R3 ARM image."""
import json, math
from test_spool_family import FamilyArm, START, END, GATE_CALLSITE

def main():
    raw, full, used, total = 302.823, 508.3, 19655, 327000
    fraction = used / total
    core = math.sqrt((raw * raw - fraction * full * full) / (1 - fraction))
    assert round(core, 1) == 284.7
    rows = []
    for core_c10, initial, remaining in [(2608, 12, 6), (2847, 6, 1)]:
        a = FamilyArm()
        assert a.catalog(core=core_c10, full=5083)[0] == 0
        a.scan(c=raw)
        assert a.bind()[0] == 0
        before = a.query()
        assert before['initial'] == initial
        a.position(495145)
        a.call(START, a.slot)
        a.position(495145 + used)
        a.call(GATE_CALLSITE)
        a.call(END, a.slot)
        after = a.query()
        assert abs(after['used'] - used) <= 1  # float encoder quantization
        assert after['percent'] == remaining
        assert after['generation'] == before['generation']
        assert a.catalog(core=2847, full=5083, rev=3)[0] == 0
        protected = a.protected_ram()
        assert a.bind(rev=3)[0] == 7
        assert protected == a.protected_ram(), 'Calibration reset protected usage'
        rows.append({'core_c10': core_c10, 'initial': initial,
                     'used_mm': after['used'], 'current': remaining})
    a = FamilyArm()
    assert a.catalog(core=2847, full=5083)[0] == 0
    a.scan(c=508.253)
    assert a.bind()[0] == 0 and a.query()['percent'] == 100
    print(json.dumps({'passed': True, 'effective_core_mm': round(core, 1),
                      'rows': rows, 'full_still_100': True,
                      'protected_rebind_rejected': True, 'no_hardware': True}))

if __name__ == '__main__':
    main()
