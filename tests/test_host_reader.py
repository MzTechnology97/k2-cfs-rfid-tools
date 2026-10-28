"""Host framing, error handling and session ownership. No physical transport."""
from contextlib import contextmanager
from pathlib import Path
import importlib.util
import json
import sys

from paths import ROOT, KALICO, HOST_MODULE, RESULTS
sys.path.insert(0, str(KALICO / "klippy"))
from extras.serial_485 import crc8

spec = importlib.util.spec_from_file_location('extras.box_rfid_diag2_host_test', HOST_MODULE)
diag = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = diag
spec.loader.exec_module(diag)
VALIDATION = json.loads((RESULTS / 'snapshot.json').read_text())
PAYLOAD = bytes.fromhex(next(x['payload_hex'] for x in VALIDATION['snapshot_cases']
                            if x['slot'] == 3 and x['mask'] == 0))


def frame(payload=PAYLOAD, address=1, command=0x57, status=0):
    data = bytes((0xf7, address, len(payload) + 3, status, command)) + payload
    return data + bytes((crc8(data[2:]),))


class Serial:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.entries = self.exits = self.depth = 0

    @contextmanager
    def request_session(self):
        self.entries += 1
        self.depth += 1
        try:yield self
        finally:
            self.exits += 1
            self.depth -= 1

    def cmd_send_data_with_response(self, body, timeout):
        assert self.depth == 1, 'missing serial request-session ownership'
        self.requests.append((bytes(body), timeout))
        return self.response


class Gcmd:
    def __init__(self):
        self.messages = []

    def get_int(self, name, default=None, minval=None, maxval=None):
        value = {'SLOT': 3, 'ADDRESS': 1}.get(name, default)
        assert value is not None
        assert (minval is None or value >= minval) and (maxval is None or value <= maxval)
        return value

    def respond_info(self, text):self.messages.append(text)
    def error(self, text):return RuntimeError(text)


def command(response):
    serial = Serial(response)
    obj = diag.BoxRfidDiag.__new__(diag.BoxRfidDiag)
    obj.default_address = 1
    obj.last_diag2_snapshot = {'stale': True}
    obj._transport = lambda: serial
    obj.allow_active_rf = False
    obj.require_idle = True
    def forbidden(*args, **kwargs):
        raise AssertionError('read-only command entered active-RF/idle permission path')
    obj._ensure_active_allowed = forbidden
    obj._claim_rfid_read = forbidden
    gcmd = Gcmd()
    try:
        obj.cmd_diag2_snapshot(gcmd)
        error = None
    except RuntimeError as exc:
        error = str(exc)
    assert serial.entries == serial.exits == 1 and serial.depth == 0
    assert len(serial.requests) == 1
    assert serial.requests[0][0] == bytes.fromhex('0105ff571503')
    return obj, gcmd, error


def main():
    obj, gcmd, error = command(frame())
    assert error is None and len(gcmd.messages) == 1
    result = json.loads(gcmd.messages[0].removeprefix('CFS RDG2 '))
    assert result['physical_slot'] == 4 and result['address'] == 1
    assert result['cmd03_early_filter_would_skip']
    assert result['snapshot_mask_validated']
    assert result['received_at_unix'] > 0
    bad_crc = bytearray(frame())
    bad_crc[-1] ^= 0x01
    wrong_slot = bytearray(PAYLOAD)
    wrong_slot[4] = 2
    cases = [
        ('unsupported firmware', frame(b'', status=1)),
        ('timeout', None),
        ('old RDG1 payload', frame(b'RDG1' + bytes(28))),
        ('wrong response address', frame(address=2)),
        ('wrong response command', frame(command=3)),
        ('CRC mismatch', bad_crc),
        ('wrong payload slot', frame(wrong_slot)),
        ('error with payload', frame(b'\x00', status=1)),
    ]
    outcomes = []
    for label, response in cases:
        obj, gcmd, error = command(response)
        assert error and 'RDG2' in error and not gcmd.messages, label
        assert obj.last_error
        assert obj.last_diag2_snapshot is None
        outcomes.append({'case': label, 'error': error})
    assert 'BOX_CFS_DIAG2' not in diag.RF_TASK_COMMANDS
    data = {'passed': True, 'valid_command_cases': 1, 'error_cases': outcomes,
            'one_request_session_per_command': True, 'one_wire_request_per_command': True,
            'physical_transport_used': False}
    (RESULTS / 'host-reader.json').write_text(json.dumps(data))
    print(json.dumps(data, indent=2))


if __name__ == '__main__':
    main()
