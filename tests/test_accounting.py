"""Cortex-M4/M-class functional, differential and mask-aware interleaving tests.

Interrupt writers/readers are modeled and deferred while PRIMASK is set.
This does not model DMA, NMI, HardFault or real interrupt latency.
"""
from pathlib import Path
import argparse
import copy
import itertools
import json
import random
import struct
import sys

from unicorn import Uc as RealUc, UC_MODE_MCLASS
from unicorn.arm_const import *

from paths import ROOT, BUILD, BASE_IMAGE, CANDIDATE_IMAGE, RESULTS
sys.path.insert(0, str(ROOT))
import arm_base as old
import arm_geometry as rem


def factory(arch, mode):
    u = RealUc(arch, mode | UC_MODE_MCLASS)
    u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)
    u.mem_map(0xE000E000, 0x2000)
    u.mem_write(0xE000ED88, struct.pack('<I', 0x00F00000))
    u.reg_write(UC_ARM_REG_CONTROL, 0)
    u.reg_write(UC_ARM_REG_XPSR, 0x01000000)
    return u


old.Uc = factory
DIRECT_TASK = 0x0801AC94
FORBIDDEN_LOCKED = {0x0802D074, 0x0802EE28, 0x0801A940,
                    0x0801A83E, 0x0801A878, 0x0801A39E,
                    0x08022082, 0x08022A42, 0x0801C814, 0x0801BAF2}


class AuditArm(rem.NativeArm):
    def __init__(self, *args, **kwargs):
        self.trace = []
        self.injection_at = None
        self.injection = None
        self.delivered = None
        self.observation = None
        super().__init__(*args, **kwargs)

    def clear_audit(self):
        self.trace = []
        self.delivered = None

    def on_code(self, cpu, address, size, user):
        mask = cpu.reg_read(UC_ARM_REG_PRIMASK)
        self.trace.append((address, mask, cpu.reg_read(UC_ARM_REG_SP)))
        if mask and address in FORBIDDEN_LOCKED:
            raise AssertionError(('blocking/backend entry under new IRQ mask', hex(address)))
        if (self.injection is not None and self.delivered is None
                and len(self.trace) >= self.injection_at and not mask):
            self.delivered = len(self.trace)
            self.injection(self)
        super().on_code(cpu, address, size, user)


def setup(image, operation):
    a = AuditArm(image, 2)
    if operation != 'native_init':
        a.geometry()
        a.position(495145.0)
        a.call(old.START, 2)
        if operation == 'rescan':
            a.position(505514.0)
            a.call(old.GATE_CALLSITE)
        else:
            a.position(505514.0)
    a.clear_audit()
    return a


def perform(a, operation):
    if operation == 'count':
        a.call(old.GATE_CALLSITE)
    else:
        a.geometry(60)


def ram(a):
    return bytes(a.u.mem_read(0x20000000, 0xE000))


def stop_writer(a):
    a.u.mem_write(a.row + 22, b'\x00')
    a.u.mem_write(old.STATE + 2, b'\x04')


def unload_writer(a):
    used = struct.unpack('<I', a.u.mem_read(a.row, 4))[0]
    a.u.mem_write(a.row, struct.pack('<I', used + 15))
    a.u.mem_write(a.row + 21, b'\x01\x02')
    a.u.mem_write(a.row + 8, struct.pack('<I', a.now))
    a.u.mem_write(old.STATE + 2, bytes((a.slot,)))


def record_writer(a):
    a.u.mem_write(rem.INTERNAL + a.slot * 76 + 75, b'\x07')
    a.u.mem_write(a.row + 99, b'\x07')


def reader(a):
    a.observation = a.state()
    if (a.observation['runtime_valid'] == 1
            and a.observation['runtime_type'] == 4
            and a.observation['runtime_mode'] == 1):
        s = a.observation
        wanted = max(1, s['initial_percent'] - s['used_mm'] * 100 // s['total_mm'])
        assert s['table_percent'] == wanted, ('mixed published state', s, wanted)


def max_masked_run(trace):
    longest = current = 0
    for _, mask, _ in trace:
        current = current + 1 if mask else 0
        longest = max(longest, current)
    return longest


def interleavings(image):
    records = []
    count = 0
    largest = 0
    for operation in ['count', 'rescan', 'native_init']:
        base = setup(image, operation)
        perform(base, operation)
        steps = len(base.trace)
        largest = max(largest, max_masked_run(base.trace))
        for label, writer in [('stop', stop_writer), ('unload', unload_writer),
                              ('record_type_change', record_writer), ('reader', reader)]:
            if label == 'reader':
                serial_before = serial_after = None
            else:
                before = setup(image, operation)
                writer(before)
                perform(before, operation)
                serial_before = ram(before)
                after = setup(image, operation)
                perform(after, operation)
                writer(after)
                serial_after = ram(after)
            for index in range(1, steps + 1):
                a = setup(image, operation)
                a.injection_at = index
                a.injection = writer
                perform(a, operation)
                assert a.delivered is not None, (operation, label, index, steps)
                assert a.u.reg_read(UC_ARM_REG_PRIMASK) == 0
                if label != 'reader':
                    assert ram(a) in (serial_before, serial_after), (
                        'not a serial-equivalent result', operation, label, index, a.state())
                largest = max(largest, max_masked_run(a.trace))
                count += 1
            records.append({'operation': operation, 'modeled_irq': label,
                            'instruction_boundaries': steps, 'passed': True})
        print('PASS interleavings', operation, steps, flush=True)
    return {'passed': True, 'modeled_interleavings': count, 'cases': records,
            'maximum_observed_contiguous_masked_instructions': largest}


def differential(reference_image, atomic_image, cases=420):
    rng = random.Random(20261027)
    results = []
    samples = list(itertools.product([0, 1], [0.0, 5.0, 9.9, 10.1, 25.0, 3400.0,
                                                   6800.0, -5.0, -100.0]))
    for i in range(cases):
        dirty, delta = samples[i % len(samples)]
        slot = i % 4
        total = rng.choice([10000, 327000, 330000, 999000, 2000000])
        initial = rng.choice([1, 35, 60, 100])
        used = rng.choice([0, 15, total // 4, total - 1, total + 100])
        outputs = []
        for image, address in [(reference_image, DIRECT_TASK),
                               (atomic_image, old.GATE_CALLSITE)]:
            a = AuditArm(image, slot)
            a.u.mem_write(a.row, struct.pack('<II', used, total))
            a.u.mem_write(a.row + 20, bytes((initial, dirty, 1, 1)))
            a.u.mem_write(a.row + 99, b'\x04')
            a.u.mem_write(old.STATE + 2, bytes((slot, initial)))
            a.u.mem_write(rem.PERCENT + slot, bytes((initial,)))
            a.u.mem_write(a.row + 12, struct.pack('<f', 495145.0))
            a.position(495145.0 + delta)
            a.call(address)
            outputs.append((bytes(a.u.mem_read(a.row, 100)),
                            bytes(a.u.mem_read(old.STATE, 64)),
                            bytes(a.u.mem_read(rem.PERCENT, 4))))
        assert outputs[0] == outputs[1], ('stock arithmetic mismatch', i, dirty, delta,
                                          slot, total, initial, used)
        results.append({'slot': slot, 'dirty': dirty, 'delta_input_mm': delta,
                        'total_mm': total, 'initial': initial, 'old_used_mm': used})
    return {'passed': True, 'stock_equivalent_cases': cases, 'inputs': results}


def primitive_checks(image, symbols):
    output = []
    for mask in [0, 1]:
        for slot in range(4):
            a = AuditArm(image, slot)
            a.u.reg_write(UC_ARM_REG_PRIMASK, mask)
            a.geometry()
            assert a.u.reg_read(UC_ARM_REG_PRIMASK) == mask
            a.position(495145.0)
            # Stock START contains logging; execute setup with normal IRQs.
            a.u.reg_write(UC_ARM_REG_PRIMASK, 0)
            a.call(old.START, slot)
            a.u.reg_write(UC_ARM_REG_PRIMASK, mask)
            a.position(505514.0)
            a.call(old.GATE_CALLSITE)
            assert a.u.reg_read(UC_ARM_REG_PRIMASK) == mask
            assert a.state()['table_percent'] == 57
            a.geometry(60)
            assert a.u.reg_read(UC_ARM_REG_PRIMASK) == mask
            assert a.state()['table_percent'] == 57
            # Stock END/UNLOAD are setup, not the critical section under test.
            a.u.reg_write(UC_ARM_REG_PRIMASK, 0)
            a.call(old.END, slot)
            a.call(old.UNLOAD, slot)
            a.u.reg_write(UC_ARM_REG_PRIMASK, mask)
            a.now = 32001
            a.call(old.GATE_CALLSITE)
            assert a.u.reg_read(UC_ARM_REG_PRIMASK) == mask
            assert a.state()['runtime_mode'] == 0
            assert a.state()['active_slot_raw'] == 4
            output.append({'incoming_primask': mask, 'slot': slot, 'passed': True})
    return output


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--skip-interleavings', action='store_true')
    args = ap.parse_args()
    folder = BUILD
    image = CANDIDATE_IMAGE.read_bytes()
    reference = BASE_IMAGE.read_bytes()
    symbols = json.loads((folder / 'symbols.json').read_text())
    functional = [rem.scenario(image, slot, vendor, secure, True, 'atomic')
                  for slot in range(4)
                  for vendor, secure in [('native', 0), ('native', 1), ('thirdparty', 0)]]
    print('PASS 12 format/backend scenarios', flush=True)
    negatives = rem.helper_negative_cases(image, symbols)
    print('PASS 48 native rejection cases', flush=True)
    arithmetic = differential(reference, image)
    print('PASS 420 stock arithmetic comparisons', flush=True)
    primitives = primitive_checks(image, symbols)
    print('PASS saved/restored masks and cleanup', flush=True)
    races = interleavings(image) if not args.skip_interleavings else None
    report = {'passed': True, 'cpu': 'Cortex-M4, Unicorn MCLASS, CPACR FPU enabled',
              'functional': functional, 'native_negative_cases': negatives,
              'differential_arithmetic': arithmetic, 'mask_and_cleanup_cases': primitives,
              'interleavings': races,
              'limits': ['IRQs and serial writers are modeled; RTOS/DMA/NMI/fault timing is not.',
                         'Instruction counts do not establish wall-clock interrupt latency.',
                         'No physical MCU, RFID read, printer operation or flash is executed.']}
    args.out.write_text(json.dumps(report, indent=2))
    print(json.dumps({'passed': True, 'interleavings': races,
                      'out': str(args.out)}, indent=2), flush=True)

if __name__ == '__main__':
    main()
