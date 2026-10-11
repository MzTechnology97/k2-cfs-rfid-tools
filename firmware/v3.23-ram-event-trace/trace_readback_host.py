"""OFFLINE decoder for *proposed*, unflashed CFS v3.23 0x57/0x15 GET.

Do NOT register this as a live Klipper command until MCU format, version,
freeze semantics, and motion/RFID exclusion have been tested on hardware.
No serial port, MCU, G-code, or filesystem mutations are performed here.
"""
from dataclasses import dataclass
import struct

MAGIC = 0x33544643
CAPACITY = 30
HEADER_SELECTOR = 0xFF
HEADER = struct.Struct("<IIHHHHI")
EVENT = struct.Struct("<IHBBHHHH")


class TraceDecodeError(ValueError):
    """Corrupt, stale, torn or otherwise unsafe trace response."""


@dataclass(frozen=True)
class TraceHeader:
    magic: int
    generation: int
    head: int
    count: int
    overwritten: int
    frozen: int
    last_tick: int


@dataclass(frozen=True)
class TraceEvent:
    tick: int
    sequence: int
    event: int
    flags: int
    motor0: int
    motor1: int
    task0: int
    task1: int


def decode_header(payload: bytes) -> TraceHeader:
    if len(payload) != HEADER.size:
        raise TraceDecodeError("Trace header must be exactly 20 bytes")
    header = TraceHeader(*HEADER.unpack(payload))
    if (header.magic != MAGIC or header.frozen != 1
            or header.head >= CAPACITY or header.count > CAPACITY
            or (header.count < CAPACITY
                and (header.head != header.count
                     or header.overwritten != 0))):
        raise TraceDecodeError("Invalid/unfinished trace header")
    return header


def decode_event(payload: bytes) -> TraceEvent:
    if len(payload) != EVENT.size:
        raise TraceDecodeError("Trace event must be exactly 16 bytes")
    return TraceEvent(*EVENT.unpack(payload))


def read_frozen_snapshot(read_selector):
    """Read one immutable frozen trace, *after* the motor session is over.

    read_selector is a supplied mock or future safe transport callable;
    only selectors 0xff and 0..29 are ever requested. It must separately
    enforce v3.23 firmware feature signature, standby/box-idle, transport
    CRC, RFID exclusion and any required device ownership checks.
    """
    first = decode_header(read_selector(HEADER_SELECTOR))
    result = []
    for index in range(first.count):
        result.append(decode_event(read_selector(index)))
    second = decode_header(read_selector(HEADER_SELECTOR))
    if first != second:
        raise TraceDecodeError("Trace changed during readout")

    # A wrapped 16-bit sequence is valid only if the chronological entries
    # are consecutive; sequence needn't start at zero after overwritten data.
    for left, right in zip(result, result[1:]):
        if (left.sequence + 1) & 0xFFFF != right.sequence:
            raise TraceDecodeError("Trace records skipped or reordered")
    if result and result[-1].tick != first.last_tick:
        raise TraceDecodeError("Final event tick differs from frozen header")
    return first, result