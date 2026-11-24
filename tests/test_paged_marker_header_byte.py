"""FST/Gen3 BMS paged walk: a 0xb2 followed directly by the page marker is
the surviving first byte of an entry whose length, type and time the marker
overwrote. When the gap after it is recovered as that entry (header
destroyed), the 0xb2 is not reported as an entry of its own, and its entry
number is left unused so the entries after it keep theirs. Invented values
only."""
import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

MARK = b'\x00\xf0\xff\x00'
LOGGER = logging.getLogger('test_paged_marker_header_byte')


def _entry(message_type, timestamp, payload):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def _fill(n, start=1):
    return bytes(((start + i) % 100) + 1 for i in range(n))


def _walk(buf):
    return Gen2.collect_paged_bms_entries(bytes(buf), LOGGER)


def test_header_byte_before_the_marker_is_not_an_entry():
    entry0 = _entry(0x01, 1_700_000_000, _fill(5))
    damaged = b'\xb2' + MARK + b'Sending first contactor close command\x00'
    entry1 = _entry(0x01, 1_700_000_100, _fill(5, start=50))
    collected = _walk(entry0 + bytearray(damaged) + entry1)
    events = [e['event'] for _ts, e, _n in collected]
    assert events == ['BMS Reset', 'Corrupted Entry (header destroyed)', 'BMS Reset']
    # the recovered entry is the same as before: the marker and what follows it
    gap_entry = collected[1][1]
    assert gap_entry['structured_data']['corrupted_byte_count'] == 4
    assert bytes.fromhex(gap_entry['structured_data']['raw_hex']) == damaged[5:]
    # the skipped 0xb2's number stays unused; the entries after it keep theirs
    assert [n for _ts, _e, n in collected] == [0, 2, 3]


def test_header_byte_is_kept_when_the_gap_is_not_recovered():
    # Fill after the marker: no header-destroyed entry is recovered, so the
    # 0xb2 stays as the walk reports it today.
    entry0 = _entry(0x01, 1_700_000_000, _fill(5))
    damaged = b'\xb2' + MARK + b'\xff' * 8
    entry1 = _entry(0x01, 1_700_000_100, _fill(5, start=50))
    events = [e['event'] for _ts, e, _n in _walk(entry0 + bytearray(damaged) + entry1)]
    assert events == ['BMS Reset', 'Board Status', 'BMS Reset']


def test_zero_length_entry_without_the_marker_is_unchanged():
    buf = bytearray([0xb2, 0x00]) + _entry(0x01, 1_700_000_000, _fill(5))
    events = [e['event'] for _ts, e, _n in _walk(buf)]
    assert events == ['Board Status', 'BMS Reset']


def test_marker_two_bytes_after_the_header_byte_is_unchanged():
    # Only a marker directly after the 0xb2 is taken as the overwritten header.
    entry0 = _entry(0x01, 1_700_000_000, _fill(5))
    damaged = b'\xb2\x00\x00' + MARK + b'Sending first contactor close command\x00'
    entry1 = _entry(0x01, 1_700_000_100, _fill(5, start=50))
    events = [e['event'] for _ts, e, _n in _walk(entry0 + bytearray(damaged) + entry1)]
    assert events == ['BMS Reset', 'Board Status', 'Corrupted Entry (header destroyed)', 'BMS Reset']
