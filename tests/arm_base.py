"""Shared ARM harness; no hardware transport."""
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import *

BASE = 0x08010000
RETURN = 0x0803F001
START = 0x0801A8AC
END = 0x0801A940
UNLOAD = 0x0801A9B8
TASK = 0x0801AC94
GATE_CALLSITE = 0x08013684
STATE = 0x200001F0
ROWS = 0x20004590
BOX_STATE = 0x200037D2
LOG = 0x0802D074
ODOMETER = 0x0801B730
CLOCK = 0x0802A4D2


class Arm:
    def __init__(self, image, slot):
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.u.mem_map(0x08000000, 0x40000)
        self.u.mem_write(BASE, image)
        self.u.mem_map(0x20000000, 0x10000)
        self.u.reg_write(UC_ARM_REG_CPSR, 0x33)
        self.u.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        self.u.reg_write(UC_ARM_REG_FPSCR, 0)
        self.slot = slot
        self.row = ROWS + 100 * slot
        self.now = 1000
        self.odo = 100.0
        self.events = []
        self.returned = False
        self.u.mem_write(STATE, b"\x40\x00\x04\x00")
        self.u.mem_write(BOX_STATE, b"\x00")
        self.u.mem_write(self.row, struct.pack("<II", 8200, 330000))
        self.u.mem_write(self.row + 12, struct.pack("<f", 100.0))
        self.u.mem_write(self.row + 20, bytes((35, 0, 0, 1)))
        self.u.mem_write(self.row + 99, b"\x04")
        for i in range(4):
            self.u.mem_write(0x20003974 + i, bytes((33,)))
        self.u.hook_add(UC_HOOK_CODE, self.on_code)

    def ret(self, cpu):
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))

    def on_code(self, cpu, address, _size, _user):
        if address in (RETURN & ~1, 0x0801367A, 0x08013690):
            self.events.append({"stop": hex(address)})
            self.returned = True
            cpu.emu_stop()
        elif address == LOG:
            self.ret(cpu)
        elif address == ODOMETER:
            cpu.reg_write(UC_ARM_REG_S0, struct.unpack("<I", struct.pack("<f", self.odo))[0])
            self.events.append({"modeled_odometer": self.odo})
            self.ret(cpu)
        elif address == CLOCK:
            cpu.reg_write(UC_ARM_REG_R0, self.now)
            self.events.append({"modeled_rtos_ticks": self.now})
            self.ret(cpu)
        elif address == TASK:
            self.events.append({"actual_stock_task": hex(address)})
        elif address == END:
            self.events.append({"actual_stock_end": hex(address)})
        elif address in (0x0801A83E, 0x0801A878, 0x0801A39E,
                         0x08022082, 0x0801A4A0):
            raise AssertionError("Unexpected entry to RFID backend: %s" % hex(address))

    def call(self, address, r0=None):
        if r0 is not None:
            self.u.reg_write(UC_ARM_REG_R0, r0)
        self.u.reg_write(UC_ARM_REG_SP, 0x2000EE00)
        self.u.reg_write(UC_ARM_REG_LR, RETURN)
        self.returned = False
        self.u.emu_start(address | 1, RETURN, count=12000)
        assert self.returned, (hex(address), hex(self.u.reg_read(UC_ARM_REG_PC)))

    def snapshot(self):
        return {
            "stock_state_hex": bytes(self.u.mem_read(STATE, 4)).hex(),
            "active_slot_raw": self.u.mem_read(STATE + 2, 1)[0],
            "box_state_input": self.u.mem_read(BOX_STATE, 1)[0],
            "runtime_mode": self.u.mem_read(self.row + 22, 1)[0],
            "used_mm": struct.unpack("<I", self.u.mem_read(self.row, 4))[0],
            "runtime_valid": self.u.mem_read(self.row + 23, 1)[0],
            "runtime_type": self.u.mem_read(self.row + 99, 1)[0],
        }
