"""Read-only SGP1 against actual R4 ARM; no printer or RF access."""
import json, math, random, struct
from test_spool_family import (
    FamilyArm, START, GATE_CALLSITE, END, SLOT_RAM, CAT, UID,
    expect_readonly_rejection, ROOT, SYMS, u32,
)
from unicorn.arm_const import (
    UC_ARM_REG_PRIMASK, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_S16, UC_ARM_REG_S31,
)

def read(a):
    before = a.protected_ram()
    status, p = a.command(bytes((0x1d, a.slot)))
    assert status == 0 and len(p) == 72 and p[:4] == b'SGP1'
    assert a.protected_ram() == before, 'Read-only SGP1 changed retained RAM'
    initial, remaining = struct.unpack_from('<II', p, 64)
    used = struct.unpack_from('<I', p, 36)[0]
    assert p[7] in (0, 1)
    if p[7]:
        assert remaining == max(0, initial - used)
    else:
        assert initial == remaining == 0
    return p, initial, remaining

def prepared(raw=302.823, core=2847, full=5083, total=327000):
    a = FamilyArm()
    assert a.catalog(core=core, full=full, total=total)[0] == 0
    a.scan(c=raw)
    assert a.bind()[0] == 0
    return a

def reference(a, core, full, total):
    q = a.query()
    raw = struct.unpack('<f', bytes.fromhex(q['raw_bits']))[0]
    fraction = max(0.0, min(1.0, ((raw-core/10.0)*(raw+core/10.0))
                           / ((full/10.0-core/10.0)*(full/10.0+core/10.0))))
    return math.floor(fraction * total + 0.5)

def main():
    cases = 0
    a = prepared()
    p, initial, remaining = read(a)
    assert p[7] == 1 and initial == remaining == 19636
    assert a.query()['initial'] == a.query()['percent'] == 6
    a.position(495145)
    a.call(START, a.slot)
    a.position(514800)
    a.call(GATE_CALLSITE)
    p, _, remaining = read(a)
    assert p[7] == 1 and remaining == 0 and p[41] == 1
    a.call(END, a.slot)
    assert read(a)[0][7] == 1
    cases += 3

    a = prepared(core=2608)
    assert read(a)[1] == 40688
    assert a.query()['initial'] == 12  # old legacy packet stays compatible
    cases += 1

    # Millimetre resolution is numerical; the physical estimate is calibrated separately.
    rng = random.Random(0x53475031)
    largest_mm_error = 0
    for core, full, total in [(2847,5083,327000),(3000,5100,330000),
                              (500,600,10000),(10000,10100,2000000),(9999,10099,2000000),
                              (10000,15000,2000000)]:
        values = [50.0, core/10.0, full/10.0, 2000.0]
        values += [rng.uniform(core/10.0, full/10.0) for _ in range(14)]
        for raw in values:
            a = prepared(raw, core, full, total)
            p, initial, remaining = read(a)
            assert p[7] == 1
            expected = reference(a, core, full, total)
            error = abs(expected - initial)
            largest_mm_error = max(largest_mm_error, error)
            # Includes worst accepted 1000/1010 mm geometry and IEEE32 coefficients.
            assert error <= max(1, math.ceil(total * 0.00001)), (raw, expected, initial)
            assert 0 <= initial == remaining <= total
            cases += 1

    # Current UID/geometry/generation/runtime must all still identify this anchor.
    corruptions = [
        lambda a: a.set_uid(b'\x11\x22\x33\x44'),
        lambda a: a.u.mem_write(SLOT_RAM+a.slot*64, u32(99)),
        lambda a: a.u.mem_write(SLOT_RAM+a.slot*64+16, u32(0)),
        lambda a: a.u.mem_write(SLOT_RAM+a.slot*64+8, u32(0x7fc00000)),
        lambda a: a.u.mem_write(CAT, u32(2)),
        lambda a: a.u.mem_write(CAT, u32(0)),
        lambda a: a.u.mem_write(a.row+4, u32(330000)),
        lambda a: a.u.mem_write(a.row+20, b'\x32'),
        lambda a: a.u.mem_write(a.row+23, b'\0'),
        lambda a: a.u.mem_write(a.row+99, b'\x07'),
        lambda a: a.u.mem_write(0x20000000, b'\x01'),
    ]
    for corrupt in corruptions:
        a = prepared()
        corrupt(a)
        assert read(a)[0][7] == 0
        cases += 1
    a = FamilyArm()
    assert read(a)[0][7] == 0
    for raw in [float('nan'), float('inf'), -1.0, 49.0, 2001.0]:
        a = FamilyArm()
        a.catalog()
        a.scan(c=raw)
        assert read(a)[0][7] == 0
        cases += 1

    # A failed scan or a new scan while printing preserves counters, but cannot
    # mislabel its different raw measurement as the existing precise anchor.
    for failed in [True, False]:
        a = prepared()
        a.position(495145)
        a.call(START, a.slot)
        a.position(499145)
        a.call(GATE_CALLSITE)
        before = a.state()
        a.scan(c=460, mismatch=failed)
        assert a.state() == before
        assert read(a)[0][7] == 0
        cases += 1

    a = prepared()
    for payload in [b'\x1d',b'\x1d\x04',b'\x1d\xff',
                    b'\x1d\x01\0',b'\x1e\x01']:
        expect_readonly_rejection(a, payload)
        cases += 1

    # Model an interrupt writer at every executed read boundary: the pair
    # used/remaining must always describe one atomic snapshot.
    a = prepared()
    a.clear_audit()
    read(a)
    boundaries = len(a.trace)
    for at in range(1, boundaries+1):
        a = prepared()
        a.clear_audit()
        a.injection_at = at
        a.injection = lambda x: x.u.mem_write(x.row, u32(1234))
        p, initial, remaining = read_atomic_writer(a)
        used = struct.unpack_from('<I', p, 36)[0]
        assert used in (0,1234) and remaining == max(0,initial-used)
        assert a.delivered is not None

    a = prepared()
    for i, reg in enumerate(range(UC_ARM_REG_S16, UC_ARM_REG_S31+1)):
        a.u.reg_write(reg, 0x3f000000+i)
    read(a)
    for i, reg in enumerate(range(UC_ARM_REG_S16, UC_ARM_REG_S31+1)):
        assert a.u.reg_read(reg) == 0x3f000000+i

    # Direct C entry must preserve an incoming interrupt mask, including 1.
    for mask in (0,1):
        a = prepared()
        frame = 0x2000d000
        data = bytearray(16);data[1]=5;data[4:6]=bytes((0x1d,a.slot))
        a.u.mem_write(frame, bytes(data))
        a.u.reg_write(UC_ARM_REG_R1, 0x2000d100)
        a.u.reg_write(UC_ARM_REG_PRIMASK, mask)
        a.call(SYMS['sgf_command'], frame)
        assert a.u.reg_read(UC_ARM_REG_PRIMASK) == mask

    result = {'passed':True,'cases':cases,'irq_boundaries':boundaries,
              'max_numerical_error_mm':largest_mm_error,
              'reference_initial_mm':19636,'legacy_packets_unchanged':True,
              'retained_ram_writes':False,'no_hardware_access':True}
    (ROOT/'work/test-results/precision-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

def read_atomic_writer(a):
    status,p=a.command(bytes((0x1d,a.slot)))
    assert status==0 and len(p)==72 and p[7]==1
    return p,*struct.unpack_from('<II',p,64)

if __name__=='__main__':
    main()
