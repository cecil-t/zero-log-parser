"""FST/Gen3 BMS page format: clock values whose top bytes the 00 f0 ff 00 page
marker overwrote (raw 0xF000xxxx or 0xFFF000xx) are rebuilt from the surviving
low bits and the neighbouring clock values (Gen2.marker_clock_low_bits,
Gen2.rebuild_marker_clock, assign_legacy_times(marker_clock=...)).
Synthetic buffers only."""
import logging
import os
import struct
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

MARK = b'\x00\xf0\xff\x00'
NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
A, TRUE_B, C = 0x6a02b71b, 0x6a02b71d, 0x6a02b757


def _entry(message_type, timestamp, payload):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def _paged(entries):
    """A 384-byte paged buffer with each (offset, bytes) placed, then the page
    marker written over offsets 128 and 256, as the BMS does."""
    buf = bytearray(384)
    for off, data in entries:
        buf[off:off + len(data)] = data
    buf[128:132] = MARK
    buf[256:260] = MARK
    return buf


def _collect(buf, now=NOW):
    spans = []
    collected = Gen2.collect_paged_bms_entries(buf, logging.getLogger('t'), entry_spans=spans)
    marker = {}
    for k, ((_ts, p, _n), span) in enumerate(zip(collected, spans)):
        low = Gen2.marker_clock_low_bits(buf, span, p.get('original_timestamp'))
        if low is not None:
            marker[k] = low
    return Gen2.assign_legacy_times(collected, 0, now=now, marker_clock=marker), marker


def test_rebuild_16_bits():
    assert Gen2.rebuild_marker_clock(0xb71d, 16, A, C) == TRUE_B


def test_rebuild_8_bits_across_a_low_byte_wrap():
    before, after = 0x6a02b7f0, 0x6a02b830
    assert Gen2.rebuild_marker_clock(0x05, 8, before, after) == 0x6a02b805


def test_rebuild_needs_both_neighbours_in_order():
    assert Gen2.rebuild_marker_clock(0xb71d, 16, None, C) is None
    assert Gen2.rebuild_marker_clock(0xb71d, 16, A, None) is None
    assert Gen2.rebuild_marker_clock(0xb71d, 16, C, A) is None


def test_rebuild_must_lie_between_the_neighbours():
    # low bits that put the nearest candidate after the later neighbour
    assert Gen2.rebuild_marker_clock(0xb760, 16, A, C) is None


def test_rebuild_must_lie_within_half_the_low_bit_range():
    before, after = 0x6a020000, 0x6a040000
    # nearest candidate 0x8001 s from both neighbours: more than 32,768 s
    assert Gen2.rebuild_marker_clock(0x8001, 16, before, after) is None
    assert Gen2.rebuild_marker_clock(0x7fff, 16, before, after) == 0x6a027fff


def _three(b_offset, b_raw_bytes):
    """Entry A, then entry B at b_offset whose time bytes are b_raw_bytes
    before the marker lands on them, then entry C."""
    a = _entry(0x60, A, bytes(range(1, 11)))
    b = bytearray([0xb2, 0]) + bytes([0x61]) + b_raw_bytes + bytes(range(20, 32))
    b[1] = len(b)
    c = _entry(0x62, C, bytes(range(40, 50)))
    end_b = b_offset + len(b)
    return _paged([(100, a), (b_offset, b), (end_b, c)])


def test_marker_from_time_byte_2_rebuilds_16_bits():
    buf = _three(123, struct.pack('<I', TRUE_B))
    out, marker = _collect(buf)
    assert list(marker.values()) == [(0xb71d, 16)]
    p = out[1][1]
    assert p['original_timestamp'] == 0xf000b71d
    assert p['time_source'] == 'clock' and p['time_repair'] == 'page_marker'
    assert p['raw_timestamp'] == 0xf000b71d
    assert p['time'] == '2026-05-12 05:14:05'
    assert 'time_repair' not in out[0][1] and 'time_repair' not in out[2][1]


def test_marker_from_time_byte_1_rebuilds_8_bits():
    buf = _three(124, struct.pack('<I', TRUE_B))
    out, marker = _collect(buf)
    assert out[1][1]['original_timestamp'] == 0xfff0001d
    assert list(marker.values()) == [(0x1d, 8)]
    assert out[1][1]['time_source'] == 'clock' and out[1][1]['time'] == '2026-05-12 05:14:05'


def test_escape_byte_before_the_marker():
    # time byte 0 is 0xfe, stored escaped as fe 01: the marker sits one byte later
    raw = (TRUE_B & 0xffffff00) | 0xfe
    b_time = b'\xfe\x01' + struct.pack('<I', raw)[1:]
    buf = _three(122, b_time)
    out, marker = _collect(buf)
    assert out[1][1]['original_timestamp'] == 0xf000b7fe
    assert list(marker.values()) == [(0xb7fe, 16)]
    assert out[1][1]['time_source'] == 'invalid'      # 0x6a02b7fe is after C: not between
    assert 'time_repair' not in out[1][1]


def test_value_form_without_the_marker_is_not_rebuilt():
    buf = bytearray(_three(123, struct.pack('<I', TRUE_B)))
    buf[128:132] = b'\x00\xf0\x11\x22'                 # top bytes as the form, but no marker there
    span = (123, buf[124])
    assert Gen2.marker_clock_low_bits(bytes(buf), span, 0xf000b71d) is None
    assert Gen2.marker_clock_low_bits(bytes(buf), span, 0x6a02b71d) is None
    assert Gen2.marker_clock_low_bits(bytes(buf), None, 0xf000b71d) is None


def test_uptime_entry_between_means_another_power_cycle():
    collected = [(0, {'original_timestamp': A, 'event': 'a'}, 0),
                 (0, {'original_timestamp': 0xf000b71d, 'event': 'b'}, 1),
                 (0, {'original_timestamp': 5, 'event': 'u'}, 2),
                 (0, {'original_timestamp': C, 'event': 'c'}, 3)]
    out = Gen2.assign_legacy_times(collected, 0, now=NOW, marker_clock={1: (0xb71d, 16)})
    assert out[1][1]['time_source'] == 'invalid' and 'time_repair' not in out[1][1]


def test_other_entries_unchanged():
    def run(marker):
        collected = [(0, {'original_timestamp': r, 'event': str(i)}, i)
                     for i, r in enumerate((3, A, 0xf000b71d, 7, C, 0xfff0001d))]
        return Gen2.assign_legacy_times(collected, 0, now=NOW, marker_clock=marker)
    plain = run(None)
    repaired = run({2: (0xb71d, 16), 5: (0x1d, 8)})
    for i in (0, 1, 3, 4):
        assert {k: v for k, v in plain[i][1].items() if k != '_order'} == \
               {k: v for k, v in repaired[i][1].items() if k != '_order'}
    # entry 2 lies between 1 and 4, but entry 3 (uptime) starts another cycle
    assert repaired[2][1]['time_source'] == 'invalid'
    assert repaired[5][1]['time_source'] == 'invalid'   # no clock value after it
