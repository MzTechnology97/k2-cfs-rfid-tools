"""Regression cases for a future CFS v3.21 *host preflight*.

This code models the decision logic only; it does not talk to the printer.
It is NOT a substitute for an independent MCU-side movement guard.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Snapshot:
    box_state: str | None
    operation_active: bool | None
    loaded_slot: int | None
    printhead_sensor: bool | None
    rfid_transaction_active: bool | None
    fresh: bool
    stock_rfid_active_slot: int | None


def old_firmware_guard(snapshot: Snapshot) -> bool:
    """The defective v3.20 firmware guard (for regression evidence only)."""
    return snapshot.stock_rfid_active_slot is not None and snapshot.stock_rfid_active_slot >= 4


def prospective_host_preflight(snapshot: Snapshot) -> bool:
    """Conservative *host-side* precondition, never a firmware authorisation.

    This gate permits only an EMPTY idle box. Unknown sensors, stale data,
    a live RFID transaction, and every moving/loaded state fail closed.
    Firmware must STILL independently verify real physical activity.
    """
    return (
        snapshot.fresh is True
        and snapshot.box_state == "IDLE"
        and snapshot.operation_active is False
        and snapshot.loaded_slot == -1
        and snapshot.printhead_sensor is False
        and snapshot.rfid_transaction_active is False
    )


class BusyGuardRegression(unittest.TestCase):
    def test_fresh_boot(self):
        state = Snapshot("IDLE", False, -1, False, False, True, 4)
        self.assertTrue(old_firmware_guard(state))
        self.assertTrue(prospective_host_preflight(state))

    def test_real_unload_keeps_rfid_slot_one(self):
        state = Snapshot("IDLE", False, -1, False, False, True, 1)
        # The v3.20 guard incorrectly rejects idle CFS with a remembered RFID slot.
        self.assertFalse(old_firmware_guard(state))
        self.assertTrue(prospective_host_preflight(state))

    def test_during_load(self):
        state = Snapshot("PRELOAD", True, -1, False, False, True, 1)
        self.assertFalse(prospective_host_preflight(state))

    def test_loaded_print_state(self):
        state = Snapshot("PRINT", False, 1, True, False, True, 1)
        self.assertFalse(prospective_host_preflight(state))

    def test_unload_in_progress(self):
        state = Snapshot("RELOAD", True, 1, True, False, True, 1)
        self.assertFalse(prospective_host_preflight(state))

    def test_rfid_task_actively_running(self):
        state = Snapshot("IDLE", False, -1, False, True, True, 1)
        self.assertFalse(prospective_host_preflight(state))

    def test_stale_snapshot(self):
        state = Snapshot("IDLE", False, -1, False, False, False, 1)
        self.assertFalse(prospective_host_preflight(state))

    def test_unknown_sensor_or_rfid_task(self):
        self.assertFalse(prospective_host_preflight(Snapshot("IDLE", False, -1, None, False, True, 1)))
        self.assertFalse(prospective_host_preflight(Snapshot("IDLE", False, -1, False, None, True, 1)))

    def test_unexpected_cfs_state(self):
        for state in ("ERROR", "TEST", None, "NO_RESPONSE"):
            self.assertFalse(prospective_host_preflight(Snapshot(state, False, -1, False, False, True, 4)))


if __name__ == "__main__":
    unittest.main()
