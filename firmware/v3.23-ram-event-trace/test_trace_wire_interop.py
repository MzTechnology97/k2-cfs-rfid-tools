"""End-to-end offline v3.23 C wire writer -> Python fail-closed reader test."""
import subprocess
import sys

from trace_readback_host import (
    HEADER, EVENT, TraceDecodeError, read_frozen_snapshot,
)

def run(binary_path):
    output = subprocess.check_output([binary_path])
    assert len(output) == HEADER.size * 2 + 30 * EVENT.size
    calls = []
    def reader(selector):
        calls.append(selector)
        if selector == 0xFF:
            # First call returns the original header, second the after header.
            start = 0 if calls.count(0xFF) == 1 else len(output) - HEADER.size
            return output[start : start + HEADER.size]
        assert 0 <= selector < 30
        offset = HEADER.size + selector * EVENT.size
        return output[offset : offset + EVENT.size]

    header, events = read_frozen_snapshot(reader)
    assert len(events) == 30
    assert header.magic == 0x33544643
    assert header.generation == 42
    assert (header.head, header.count, header.overwritten, header.frozen) == (9,30,9,1)
    assert header.last_tick == 100 + 38 * 17
    assert [e.sequence for e in events] == list(range(9,39))
    assert [e.tick for e in events] == [100+i*17 for i in range(9,39)]
    assert [e.motor0 for e in events] == [3*i for i in range(9,39)]
    assert all(e.flags == 0xA5 and e.task0 == 0x5678
               and e.task1 == 0x9ABC for e in events)
    assert calls == [0xFF] + list(range(30)) + [0xFF]

    # Simulate a torn read: mutate the "post" header without changing any
    # event data. The decoder MUST reject snapshots that changed mid-dump.
    altered = bytearray(output)
    altered[-HEADER.size+4] ^= 1
    changed_calls = []
    def torn(selector):
        changed_calls.append(selector)
        if selector == 0xFF:
            start = 0 if changed_calls.count(0xFF) == 1 else len(altered)-HEADER.size
            return bytes(altered[start:start+HEADER.size])
        return bytes(altered[HEADER.size+selector*EVENT.size:
                             HEADER.size+(selector+1)*EVENT.size])
    try:
        read_frozen_snapshot(torn)
    except TraceDecodeError:
        pass
    else:
        raise AssertionError("Torn wire snapshot was accepted")
    print("PASS C -> Python 30 event wire roundtrip and changed-header rejection")

if __name__ == "__main__":
    run(sys.argv[1])
