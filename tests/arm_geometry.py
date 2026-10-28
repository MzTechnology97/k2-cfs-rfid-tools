"""Geometry, actual OEM odometer and CMD03 harness."""
import struct
from unicorn.arm_const import *
from arm_base import Arm, START, GATE_CALLSITE, ODOMETER

GEOMETRY_STORE = 0x0801337C
GEOMETRY_DONE = 0x080133A8
CMD03 = 0x0801BF66
SEND = 0x0801BAF2
INTERNAL = 0x20004460
RECORD_TABLE = 0x20003978
PERCENT = 0x20003974
LATCH = 0x4C52324B


def record(length=b"0330"):
    data = (b"A" + b"26" + b"26" + b"9999" + b"01" + b"105628"
            + b"0FF0000" + length + b"000123" + b"000000")
    assert len(data) == 40
    return data

class NativeArm(Arm):
    def __init__(self, image, slot, *, vendor="native", secure=0,
                 length=b"0330", kind=4, marker=1, native_valid=1):
        super().__init__(image, slot)
        self.scale = struct.unpack_from("<f", image, 0x080188B8 - 0x08010000)[0]
        self.vendor = vendor
        self.native_valid = native_valid
        self.record = record(length)
        self.packet = None
        self.u.mem_write(self.row, bytes(100))
        self.u.mem_write(0x20000000, bytes((secure,)))
        self.u.mem_write(0x2000391C, b"\x01")
        self.u.mem_write(0x2000391E + slot, bytes((marker,)))
        data = bytearray(76)
        if vendor == "native":
            self.u.mem_write(RECORD_TABLE + slot * 40, self.record)
            data[20:60] = self.record
        data[60:62] = b"\x04\x00"
        data[62:66] = b"\x01\x02\x03\x04"
        data[74] = 8
        data[75] = kind
        self.u.mem_write(INTERNAL + slot * 76, bytes(data))

    def on_code(self, cpu, address, size, user):
        if address == ODOMETER:
            self.events.append({"actual_odometer": hex(address)})
            return  # Execute the actual raw-cache read, scale and vneg.f32.
        if address == GEOMETRY_DONE:
            self.returned = True
            cpu.emu_stop()
            return
        if address == 0x0801B890:
            cpu.reg_write(UC_ARM_REG_R0, 0)  # No physical slot-error response.
            self.ret(cpu)
            return
        if address == SEND:
            assert cpu.reg_read(UC_ARM_REG_R0) == 3
            assert cpu.reg_read(UC_ARM_REG_R1) == 0
            assert cpu.reg_read(UC_ARM_REG_R3) == 4
            self.packet = bytes(cpu.mem_read(cpu.reg_read(UC_ARM_REG_R2), 4))
            self.ret(cpu)
            return
        super().on_code(cpu, address, size, user)

    def position(self, normalized_mm):
        self.u.mem_write(0x200001AC, struct.pack("<f", -normalized_mm / self.scale))

    def geometry(self, percent=60):
        if self.vendor == "thirdparty":
            self.u.mem_write(INTERNAL + self.slot * 76 + 12, struct.pack("<I", LATCH))
        self.u.reg_write(UC_ARM_REG_R4, percent)
        self.u.reg_write(UC_ARM_REG_R8, self.slot)
        self.u.reg_write(UC_ARM_REG_R9,
                         self.native_valid if self.vendor == "native" else 0)
        self.u.reg_write(UC_ARM_REG_R11, 0x2000391C + self.slot)
        self.call(GEOMETRY_STORE)

    def response(self):
        self.packet = None
        self.call(CMD03, 1 << self.slot)
        assert self.packet is not None
        assert all(v == 255 for i, v in enumerate(self.packet) if i != self.slot)
        return {"payload_hex": self.packet.hex(), "slot_value": self.packet[self.slot]}

    def state(self):
        return {**self.snapshot(),
                "total_mm": struct.unpack("<I", self.u.mem_read(self.row + 4, 4))[0],
                "checkpoint_mm": struct.unpack("<f", self.u.mem_read(self.row + 12, 4))[0],
                "initial_percent": self.u.mem_read(self.row + 20, 1)[0],
                "table_percent": self.u.mem_read(PERCENT + self.slot, 1)[0]}

def helper_negative_cases(image, symbols):
    changes = [
        {"name": "OEM validation absent", "native_valid": 0},
        {"name": "native record marker absent", "marker": 0},
        {"name": "type7 excluded", "kind": 7},
        {"name": "unknown hardware flag", "secure": 2},
        {"name": "unsupported length prefix", "length": b"1330"},
        {"name": "invalid length digit", "length": b"03X0"},
        {"name": "length below ten metres", "length": b"0009"},
        {"name": "different cached metadata", "mismatch": True},
        {"name": "zero geometry", "percent": 0},
        {"name": "geometry over 100", "percent": 101},
        {"name": "geometry unavailable", "percent": 255},
        {"name": "invalid slot", "bad_slot": True},
    ]
    results = []
    for slot in range(4):
        for case in changes:
            kwargs = {k: case[k] for k in ("native_valid", "marker", "kind", "secure", "length") if k in case}
            arm = NativeArm(image, slot, **kwargs)
            arm.u.mem_write(PERCENT + slot, bytes((case.get("percent", 60),)))
            if case.get("mismatch"):
                arm.u.mem_write(INTERNAL + slot * 76 + 20, b"B")
            arm.u.reg_write(UC_ARM_REG_R9, arm.native_valid)
            before = bytes(arm.u.mem_read(0x20000000, 0xE000))
            arm.call(symbols["native_legacy_type4_ready_slot"], 4 if case.get("bad_slot") else slot)
            assert arm.u.reg_read(UC_ARM_REG_R0) == 0, case
            assert bytes(arm.u.mem_read(0x20000000, 0xE000)) == before, case
            results.append({"slot": slot, "case": case["name"], "rejected_without_global_writes": True})
    return results

def scenario(image, slot, vendor, secure, corrected=True, version='current'):
    arm = NativeArm(image, slot, vendor=vendor, secure=secure)
    arm.geometry()
    initialized = arm.state()
    assert initialized['runtime_valid'] == 1
    assert initialized['runtime_type'] == 4 and initialized['total_mm'] == 330000
    arm.position(495145.0)
    arm.call(START, slot)
    samples = []
    for delta in (3400, 6800, 10369):
        arm.position(495145.0 + delta)
        arm.call(GATE_CALLSITE)
        state = arm.state(); response = arm.response()
        assert response['slot_value'] == max(1, 60 - state['used_mm'] * 100 // 330000)
        assert delta - 2 <= state['used_mm'] <= delta + 2
        samples.append({'forward_delta_mm_input': delta, 'state': state, 'actual_cmd03': response})
    rescan = None
    if vendor == 'thirdparty' or not secure:
        before = arm.state(); arm.geometry(60); after = arm.state()
        assert after == before
        assert arm.response()['slot_value'] == 57
        rescan = {'before': before, 'after_full_geometry_callsite': after}
    return {'slot': slot, 'vendor_input': vendor, 'secure_input': secure,
            'after_geometry': initialized, 'samples': samples, 'rescan': rescan}
