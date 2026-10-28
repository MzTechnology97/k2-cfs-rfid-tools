"""RDG2 ARM read-only/ABI, coherent snapshot and payload decoder verification."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
import test_accounting as t

from paths import ROOT, BUILD, CANDIDATE_IMAGE, HOST_MODULE, RESULTS
D = BUILD
IMAGE = CANDIDATE_IMAGE.read_bytes()
STACK = 0x2000E000
ENTRY = 0x0803AE38
SEND = 0x0801BAF2
DONE = 0x0801C808


class Snapshot(t.rem.NativeArm):
    def __init__(self, slot=3, mask=0):
        self.trace = []
        self.message = None
        self.inject_at = None
        self.inject = None
        self.delivered = False
        self.incoming_mask = mask
        super().__init__(IMAGE, slot)
        self.u.mem_write(0x200001f0, bytes.fromhex('40000339'))
        self.u.mem_write(0x200001f0 + 28, struct.pack('<I', 123456))
        self.u.mem_write(0x2000391c, bytes((0, 3, 1, 0, 1, 1)))
        self.u.mem_write(0x200037d2, b'\x02')
        self.u.mem_write(0x200009e4, struct.pack('<I', 0xf0010203))
        self.u.mem_write(0x200001ac, struct.pack('<f', -640000000.0))
        for i in range(4):
            row = t.old.ROWS + i * 100
            self.u.mem_write(row, struct.pack('<III', 7500 + i, 330000, 123400 + i))
            self.u.mem_write(row + 12, struct.pack('<f', 500000.0 + i))
            self.u.mem_write(row + 20, bytes((60, 1, 1, 1)))
            self.u.mem_write(row + 99, b'\x04')
            self.u.mem_write(row + 44, bytes((65 + i,)))
            self.u.mem_write(t.rem.PERCENT + i, bytes((57 - i,)))
            self.u.mem_write(t.rem.INTERNAL + i * 76 + 20, bytes((70 + i,)))
            self.u.mem_write(t.rem.INTERNAL + i * 76 + 75, bytes((i,)))
            self.u.mem_write(t.rem.INTERNAL + i * 76 + 12,
                             struct.pack('<I', t.rem.LATCH if i % 2 else 0xdeadbeef))
        self.u.mem_write(STACK - 512, b'\xa5' * 512)
        self.writes = []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.on_write)

    def on_write(self, cpu, access, addr, size, value, unused):
        assert STACK - 512 <= addr and addr + size <= STACK, (hex(addr), size)
        self.writes.append((addr, size))

    def on_code(self, cpu, address, size, unused):
        mask = cpu.reg_read(UC_ARM_REG_PRIMASK)
        self.trace.append((address, mask, cpu.reg_read(UC_ARM_REG_SP)))
        if (self.inject is not None and not self.delivered
                and len(self.trace) >= self.inject_at and mask == 0):
            self.delivered = True
            self.inject(self)
        if address == SEND:
            assert mask == self.incoming_mask, 'transport inside a newly held mask'
            assert cpu.reg_read(UC_ARM_REG_SP) % 8 == 0
            n = cpu.reg_read(UC_ARM_REG_R3)
            ptr = cpu.reg_read(UC_ARM_REG_R2)
            self.message = (cpu.reg_read(UC_ARM_REG_R0), cpu.reg_read(UC_ARM_REG_R1),
                            bytes(cpu.mem_read(ptr, n)))
            self.ret(cpu)
        elif address == DONE:
            self.returned = True
            cpu.emu_stop()
        elif address in t.FORBIDDEN_LOCKED or address in (0x0801AA14, 0x0801B730):
            raise AssertionError(('unexpected backend/helper entry', hex(address)))

    def request(self, requested=None, frame_len=5, sub=0x15, check_ram=True):
        requested = self.slot if requested is None else requested
        request = bytearray(16)
        request[1] = frame_len
        request[4:6] = bytes((sub, requested))
        self.u.mem_write(0x20008000, bytes(request))
        regs = [getattr(t, 'UC_ARM_REG_R' + str(i)) for i in range(4, 12)]
        values = [0x20008000] + [0x57000000 + i for i in range(5, 12)]
        for reg, value in zip(regs, values):
            self.u.reg_write(reg, value)
        self.u.reg_write(UC_ARM_REG_R0, 0x57)
        self.u.reg_write(UC_ARM_REG_SP, STACK)
        self.u.reg_write(UC_ARM_REG_LR, t.old.RETURN)
        self.u.reg_write(UC_ARM_REG_PRIMASK, self.incoming_mask)
        before = bytes(self.u.mem_read(0x20000000, STACK - 512 - 0x20000000))
        self.u.emu_start(ENTRY | 1, t.old.RETURN, count=2000)
        assert self.returned and self.message is not None
        assert self.u.reg_read(UC_ARM_REG_SP) == STACK
        assert self.u.reg_read(UC_ARM_REG_PRIMASK) == self.incoming_mask
        assert [self.u.reg_read(reg) for reg in regs] == values
        if check_ram:
            assert bytes(self.u.mem_read(0x20000000, len(before))) == before
        return self.message

    def expected(self):
        p = bytearray(64)
        p[:4] = b'RDG2'
        p[4] = self.slot
        p[5] = self.u.mem_read(0x200001f2, 1)[0]
        p[6] = self.u.mem_read(0x200037d2, 1)[0]
        p[7] = self.u.mem_read(0x20000000, 1)[0]
        for dst, off in [(8, 23), (9, 99), (10, 22), (11, 21), (28, 20), (58, 44)]:
            p[dst] = self.u.mem_read(self.row + off, 1)[0]
        for dst, off in [(12, 0), (16, 4), (20, 12), (48, 8)]:
            p[dst:dst+4] = self.u.mem_read(self.row + off, 4)
        p[24:28] = self.u.mem_read(0x200001ac, 4)
        p[29] = self.u.mem_read(t.rem.PERCENT + self.slot, 1)[0]
        p[30] = self.u.mem_read(0x2000391e + self.slot, 1)[0]
        p[31] = self.u.mem_read(t.rem.INTERNAL + self.slot * 76 + 75, 1)[0]
        p[32:38] = self.u.mem_read(0x2000391c, 6)
        p[38] = self.incoming_mask
        p[39] = self.u.reg_read(UC_ARM_REG_CONTROL)
        p[40:44] = self.u.mem_read(0x200001f0, 4)
        p[44:48] = self.u.mem_read(0x200009e4, 4)
        p[52:56] = self.u.mem_read(0x200001f0 + 28, 4)
        p[56] = int(bytes(self.u.mem_read(t.rem.INTERNAL + self.slot * 76 + 12, 4))
                    == struct.pack('<I', t.rem.LATCH))
        p[57] = self.u.mem_read(t.rem.INTERNAL + self.slot * 76 + 20, 1)[0]
        struct.pack_into('<H', p, 60, self.u.reg_read(UC_ARM_REG_IPSR))
        p[62] = 1
        p[63] = 2
        return bytes(p)


def writer(a):
    a.u.mem_write(a.row, struct.pack('<II', 111111, 555555))
    a.u.mem_write(a.row + 20, bytes((81, 0, 2, 0)))
    a.u.mem_write(t.rem.PERCENT + a.slot, b'\x2d')
    a.u.mem_write(0x2000391c, bytes((1, 2, 0, 1, 0, 1)))
    a.u.mem_write(0x200001f0, bytes.fromhex('41000229'))
    a.u.mem_write(0x200001f0 + 28, struct.pack('<I', 222222))
    a.u.mem_write(0x200009e4, struct.pack('<I', 42))


def decoder():
    # Execute the actual pure decoder without loading the printer stack.
    import ast, math
    from types import SimpleNamespace
    source = HOST_MODULE.read_text(); tree = ast.parse(source)
    nodes = [n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef))
             and n.name in ('RfidDiagError', 'decode_cfs_diag2_payload')]
    namespace = {'math': math, 'struct': struct}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(HOST_MODULE), 'exec'), namespace)
    return SimpleNamespace(**namespace)


def main():
    mod = decoder()
    outputs = []
    for mask in [0, 1]:
        for slot in range(4):
            a = Snapshot(slot, mask)
            expected = a.expected()
            cmd, status, payload = a.request()
            assert (cmd, status, payload) == (0x57, 0, expected)
            decoded = mod.decode_cfs_diag2_payload(payload, slot)
            assert decoded['snapshot_mask_validated']
            outputs.append({'slot': slot, 'mask': mask, 'payload_hex': payload.hex(),
                            'decoded': decoded})
    invalid = 0
    for slot, length, sub in [(4, 5, 0x15), (255, 5, 0x15), (3, 0, 0x15),
                              (3, 4, 0x15), (3, 6, 0x15), (3, 255, 0x15),
                              (3, 5, 0x16)]:
        assert Snapshot().request(slot, length, sub) == (0x57, 1, b'')
        invalid += 1
    base = Snapshot()
    before = base.request()[2]
    steps = len(base.trace)
    after = Snapshot()
    writer(after)
    after_payload = after.request()[2]
    for step in range(1, steps + 1):
        a = Snapshot()
        a.inject_at, a.inject = step, writer
        payload = a.request(check_ram=False)[2]
        assert a.delivered
        assert payload in (before, after_payload), ('mixed snapshot', step, payload.hex())
    # Decoder negatives reject old format, malformed version/slot/length/padding.
    bad = [before[:32], b'RDG1' + before[4:], before[:-1] + b'\x03',
           before[:4] + b'\x04' + before[5:], before[:59] + b'\x01' + before[60:]]
    for p in bad:
        try:mod.decode_cfs_diag2_payload(p, 3)
        except mod.RfidDiagError:pass
        else:raise AssertionError('malformed payload accepted')
    try:mod.decode_cfs_diag2_payload(before, 2)
    except mod.RfidDiagError:pass
    else:raise AssertionError('wrong requested slot accepted')
    p = bytearray(before)
    struct.pack_into('<ff', p, 20, float('nan'), float('inf'))
    q = mod.decode_cfs_diag2_payload(p, 3)
    assert q['checkpoint_mm'] is None and q['current_odometer_approx_mm'] is None
    p = bytearray(before)
    p[39], p[62] = 1, 0
    q = mod.decode_cfs_diag2_payload(p, 3)
    assert not q['snapshot_mask_validated']
    longest = current = 0
    for _, mask, _ in base.trace:
        current = current + 1 if mask else 0
        longest = max(longest, current)
    result = {'passed': True, 'sha256': hashlib.sha256(IMAGE).hexdigest(),
              'snapshot_cases': outputs, 'invalid_frames': invalid,
              'modeled_interrupt_boundaries': steps,
              'maximum_observed_masked_instructions': longest,
              'maximum_observed_stack_bytes': STACK - min(x[2] for x in base.trace),
              'decoder_negative_cases': len(bad) + 3,
              'scope': 'Only stack writes observed; configurable-IRQ writers modeled; no hardware.'}
    (RESULTS / 'snapshot.json').write_text(json.dumps(result))
    print(json.dumps({k:v for k,v in result.items() if k != 'snapshot_cases'}, indent=2))


if __name__ == '__main__':
    main()
