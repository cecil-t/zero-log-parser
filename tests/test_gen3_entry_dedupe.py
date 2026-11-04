"""
Tests for dropping duplicate FST/Gen3 entries (Gen2.find_duplicate_entries,
Gen2.drop_duplicate_entries, wired into both walkers by
LogData._collect_and_process_entries).

An entry is a duplicate when its whole unescaped content (type, seconds,
sub-second, sequence, marker and payload) equals an earlier entry's in the
same file; the first occurrence is kept. An isolated copy (fewer than 64
matching context bytes around the two copies) is kept when its sub-second is
999,999. Only files that start with the FST/Gen3 system information entry
(type 0xfb) are changed; legacy files, including legacy-platform ring-buffer
files the parser also reads as log_version REV3, are never changed.

Plain test_* functions, stdlib only, synthetic bytes and invented values.
"""

import logging
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2, LogFile, LogData, REV3

logging.disable(logging.CRITICAL)

MARK = b'\x00\xf0\xff\x00'
T0 = 1_700_000_000


def _entry(text, ts=T0, subsecond=250000, seq=7, marker=1, message_type=0xfd):
    """One framed Gen3 entry: 0xb2, length, type, seconds, sub-second, sequence, marker, payload."""
    body = (bytes([message_type]) + struct.pack('<I', ts) + struct.pack('<I', subsecond)
            + bytes([seq, marker]) + text.encode('ascii'))
    return bytes([0xb2, len(body) + 2]) + body


def _filler(n, start):
    """n bytes that are never 0xb2 or 0xfe, varied by start so two fillers differ."""
    return bytes(((start * 7 + i * 13) % 97) + 1 for i in range(n))


def _header_entry():
    """A type 0xfb first entry with an invented, too-short payload: enough for
    is_fst_platform_file, decoded as an unknown entry."""
    body = bytes([0xfb]) + struct.pack('<I', T0) + b'\x01\x02\x03'
    return bytes([0xb2, len(body) + 2]) + body


def _parse(data, name):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, name)
        with open(path, 'wb') as f:
            f.write(data + b'\xff' * 64)
        ld = LogData(LogFile(path), timezone_offset=0)
    assert ld.log_version == REV3
    return ld._processed_entries


def _gen3_mbb(data):
    """Parse data as an unpaged FST/Gen3 file; the 0xfb header entry is left out of the result."""
    return [e for e in _parse(_header_entry() + data, 'synthetic_MBB.bin') if e.message_type != '0xFB']


def _events(entries):
    return sorted(e.event for e in entries)


def _block(entries, size=128):
    """A 128-byte block holding the given entries, padded with 0xff."""
    data = b''.join(entries)
    assert len(data) <= size
    return data + b'\xff' * (size - len(data))


def test_adjacent_repeated_block_is_dropped_once_each():
    first = _block([_entry('alpha one', subsecond=1000, seq=1), _entry('alpha two', subsecond=2000, seq=2)])
    after = _block([_entry('alpha three', ts=T0 + 5, subsecond=3000, seq=3)])
    out = _gen3_mbb(first + first + first + after)
    assert _events(out) == ['alpha one', 'alpha three', 'alpha two']


def test_non_adjacent_repeated_region_is_dropped():
    region = _entry('beta one', subsecond=1000, seq=1) + _filler(40, 1) + _entry('beta two', subsecond=2000, seq=2) \
        + _filler(80, 2)
    middle = _entry('beta middle', ts=T0 + 9, subsecond=5000, seq=9) + _filler(300, 3)
    out = _gen3_mbb(region + middle + region)
    assert _events(out) == ['beta middle', 'beta one', 'beta two']


def test_isolated_copy_with_an_ordinary_subsecond_is_dropped():
    copy = _entry('gamma copy', subsecond=431000, seq=4)
    data = copy + _filler(100, 1) + _entry('gamma other', ts=T0 + 3, subsecond=1000, seq=5) + _filler(100, 2) + copy \
        + _filler(100, 3)
    found = Gen2.find_duplicate_entries(data, _spans(data))
    assert len(found) == 1 and found[0]['context'] < 64 and not found[0]['keep']
    assert _events(_gen3_mbb(data)) == ['gamma copy', 'gamma other']


def test_isolated_copy_with_subsecond_999999_is_kept():
    copy = _entry('delta clamp', subsecond=999999, seq=4)
    data = copy + _filler(100, 1) + _entry('delta other', ts=T0 + 3, subsecond=1000, seq=5) + _filler(100, 2) + copy \
        + _filler(100, 3)
    found = Gen2.find_duplicate_entries(data, _spans(data))
    assert len(found) == 1 and found[0]['subsecond'] == 999999 and found[0]['keep']
    assert _events(_gen3_mbb(data)) == ['delta clamp', 'delta clamp', 'delta other']


def test_subsecond_999999_inside_a_repeated_region_is_still_dropped():
    region = _entry('epsilon clamp', subsecond=999999, seq=4) + _filler(100, 1)
    data = region + _entry('epsilon other', ts=T0 + 3, subsecond=1000, seq=5) + _filler(50, 2) + region
    found = Gen2.find_duplicate_entries(data, _spans(data))
    assert len(found) == 1 and found[0]['context'] >= 64 and not found[0]['keep']
    assert _events(_gen3_mbb(data)) == ['epsilon clamp', 'epsilon other']


def test_entries_differing_only_in_subsecond_are_both_kept():
    data = _entry('zeta same', subsecond=100000, seq=4) + _filler(30, 1) + _entry('zeta same', subsecond=101000, seq=4)
    assert Gen2.find_duplicate_entries(data, _spans(data)) == []
    assert _events(_gen3_mbb(data)) == ['zeta same', 'zeta same']


def test_entries_differing_only_in_sequence_are_both_kept():
    data = _entry('eta same', seq=4) + _filler(30, 1) + _entry('eta same', seq=5)
    assert _events(_gen3_mbb(data)) == ['eta same', 'eta same']


def test_kept_entries_keep_their_order_and_are_numbered_without_gaps():
    a, b, c = (_entry('theta %s' % k, ts=T0 + i, subsecond=1000 * i, seq=i) for i, k in enumerate('abc', 1))
    region = a + b + _filler(90, 1)
    data = region + c + _filler(200, 2) + region
    out = sorted(_gen3_mbb(data), key=lambda e: e.entry_number)
    assert [e.event for e in out] == ['theta a', 'theta b', 'theta c']
    assert [e.entry_number for e in out] == [2, 3, 4]   # 1 is the 0xfb header entry


def test_drop_duplicate_entries_renumbers_in_walk_order():
    collected = [(10, {'n': 'a'}, 0), (11, {'n': 'b'}, 1), (12, {'n': 'c'}, 2)]
    a = _entry('iota a', subsecond=1000, seq=1)
    buf = a + _filler(10, 1) + _entry('iota b', subsecond=2000, seq=2) + a
    spans = _spans(buf)
    out = Gen2.drop_duplicate_entries(buf, collected, spans)
    assert [(ts, p['n'], n) for ts, p, n in out] == [(10, 'a', 0), (11, 'b', 1)]


def test_entries_without_their_own_bytes_are_never_compared():
    a = _entry('kappa a')
    buf = a + _filler(10, 1) + a
    spans = [None] + _spans(buf)[1:]
    assert Gen2.find_duplicate_entries(buf, spans) == []


def test_paged_bms_walker_drops_duplicates_too():
    first = _entry('lambda one', subsecond=1000, seq=1, message_type=0x01)
    page0 = _block([_header_entry(), first, _entry('lambda two', subsecond=2000, seq=2, message_type=0x01)])
    page1 = bytearray(_block([b'\xff' * 4 + first]))
    page1[0:4] = MARK
    page2 = bytearray(_block([b'\xff' * 4 + _entry('lambda three', ts=T0 + 5, subsecond=3000, seq=3,
                                                      message_type=0x01)]))
    page2[0:4] = MARK
    buf = bytes(page0 + page1 + page2)
    assert Gen2.is_paged_bms_format(buf)
    spans = []
    collected = Gen2.collect_paged_bms_entries(buf, logging.getLogger('t'), entry_spans=spans)
    assert len(spans) == len(collected) == 5
    out = Gen2.drop_duplicate_entries(buf, collected, spans)
    assert len(out) == 4
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'synthetic_BMS0.bin')
        with open(path, 'wb') as f:
            f.write(buf)
        ld = LogData(LogFile(path), timezone_offset=0)
    assert len(ld._processed_entries) == 4


def test_legacy_platform_ring_buffer_file_is_untouched():
    # starts with 0xb2 (read as log_version REV3) but not with a type 0xfb entry
    a = _entry('mu repeated', subsecond=431000, seq=4, message_type=0x01)
    data = a + _filler(100, 1) + _entry('mu other', ts=T0 + 3, message_type=0x01) + _filler(100, 2) + a
    assert not Gen2.is_fst_platform_file(data)
    assert len(_parse(data, 'synthetic_MBB.bin')) == 3


def test_is_fst_platform_file():
    assert Gen2.is_fst_platform_file(_header_entry() + b'\x00' * 10)
    assert not Gen2.is_fst_platform_file(b'\xb2\x0b\x01' + b'\x00' * 10)
    assert not Gen2.is_fst_platform_file(b'MBB\x00' + b'\x00' * 10)
    assert not Gen2.is_fst_platform_file(b'\xb2')


def test_legacy_file_with_identical_entries_is_untouched():
    body = bytes([0x01]) + struct.pack('<I', T0) + b'\x10\x20\x30\x40\x50\x60'
    entry = bytes([0xb2, len(body) + 2]) + body
    entries_bytes = entry + entry + entry
    header = bytearray(0x600)
    header[0:4] = b'MBB\x00'
    header[0x26:0x2a] = b'\xa1\xa1\xa1\xa1'
    header[0x2a:0x2a + 20] = b'Jan  1 2020 00:00:00'
    start = 0x610
    header += b'\xa2\xa2\xa2\xa2'
    header += struct.pack('<III', start + len(entries_bytes), start, 3)
    header += b'\x00' * (start - len(header))
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'synthetic.bin')
        with open(path, 'wb') as f:
            f.write(bytes(header) + entries_bytes)
        ld = LogData(LogFile(path), timezone_offset=0)
    assert ld.log_version != REV3
    assert len(ld._processed_entries) == 3


def _spans(buf):
    """(start, length) of every framed entry, walking 0xb2 headers the way the main loop does."""
    spans, pos = [], 0
    while True:
        pos = buf.find(b'\xb2', pos)
        if pos < 0:
            return spans
        length = buf[pos + 1]
        spans.append((pos, length))
        pos += max(length, 1)
