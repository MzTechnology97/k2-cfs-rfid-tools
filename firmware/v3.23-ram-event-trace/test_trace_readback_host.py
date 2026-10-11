"""Tests for the proposed v3.23 post-movement trace decoder (offline)."""
import struct
from trace_readback_host import (
    MAGIC, HEADER, EVENT, TraceDecodeError, read_frozen_snapshot
)


def fail(callable_):
    try:
        callable_()
    except TraceDecodeError:
        return
    raise AssertionError("Unsafe trace decoder did not fail closed")


def stable_reader(count=30, generation=123, altered_second=False,
                  corrupt_event=None):
    start = 100
    # Return 30 chronological records from a wrapped ring, idx 0..29.
    def read(index):
        if index == 0xFF:
            if altered_second and reads and reads[-1] == count - 1:
                g = generation + 1
            else:
                g = generation
            reads.append(index)
            return HEADER.pack(MAGIC, g, 13 if count == 30 else count,
                               count, 13 if count == 30 else 0, 1,
                               1000+(start+count-1)*7)
        assert 0 <= index < count
        reads.append(index)
        seq = (start+index) & 0xFFFF
        payload = EVENT.pack(1000+(start+index)*7, seq, 1, 0,
                             index, 0x1234, 0x5678, 0x9ABC)
        if corrupt_event == index:
            return payload[:3]  # truncated UART/event response
        return payload
    reads = []
    return read, reads


def test_successful_frozen_snapshot():
    read, calls = stable_reader()
    h, rows = read_frozen_snapshot(read)
    assert h.count == 30 and h.overwritten == 13
    assert len(rows) == 30
    assert rows[0].sequence == 100
    assert rows[-1].sequence == 129
    assert rows[-1].tick == h.last_tick
    assert calls == [0xFF] + list(range(30)) + [0xFF]


def test_torn_generation_fails():
    read, _ = stable_reader(altered_second=True)
    fail(lambda: read_frozen_snapshot(read))


def test_short_record_fails():
    read, _ = stable_reader(corrupt_event=11)
    fail(lambda: read_frozen_snapshot(read))


def test_bad_header_fails():
    for blob in (b"", b"X"*20,
                 HEADER.pack(MAGIC, 1, 0, 31, 0, 1, 0),
                 HEADER.pack(MAGIC, 1, 0, 30, 0, 0, 0),
                 HEADER.pack(MAGIC, 1, 30, 30, 0, 1, 0),
                 HEADER.pack(MAGIC, 1, 4, 2, 0, 1, 0),
                 HEADER.pack(MAGIC, 1, 2, 2, 1, 1, 0)):
        fail(lambda b=blob: read_frozen_snapshot(lambda _: b))


def test_sequence_gap_fails():
    read, _ = stable_reader()
    def broken(index):
        val=read(index)
        if index==3:
            words=list(EVENT.unpack(val))
            words[1] = 777
            return EVENT.pack(*words)
        return val
    fail(lambda: read_frozen_snapshot(broken))


def test_no_mutation_side_effects():
    # Decoder requests header exactly twice and each record at most once.
    read, calls = stable_reader(count=2)
    header, rows = read_frozen_snapshot(read)
    assert calls == [0xFF, 0, 1, 0xFF]
    assert header.count == len(rows) == 2


if __name__ == "__main__":
    test_successful_frozen_snapshot()
    test_torn_generation_fails()
    test_short_record_fails()
    test_bad_header_fails()
    test_sequence_gap_fails()
    test_no_mutation_side_effects()
    print("PASS: frozen v3.23 trace decode, torn read reject, lengths, sequencing")