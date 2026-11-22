"""Legacy logs: later copies of whole blocks of entries are dropped
(Gen2.drop_legacy_copies), real byte-identical repeats are kept, and the
remaining entries keep their entry numbers. Synthetic logs only."""
import json
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import LogFile, LogData, Gen2

T = 1_700_000_000


def _write_minimal_rev0_file(path, entries_bytes):
    header = bytearray(0x600)
    header[0:4] = b'MBB\x00'
    header[0x26:0x2a] = b'\xa1\xa1\xa1\xa1'
    header[0x2a:0x2a + 20] = b'Jan  1 2020 00:00:00'
    entries_start = 0x610
    entries_end = entries_start + len(entries_bytes)
    header += b'\xa2\xa2\xa2\xa2'
    header += struct.pack('<III', entries_end, entries_start, len(entries_bytes))
    header += b'\x00' * (entries_start - len(header))
    with open(path, 'wb') as f:
        f.write(bytes(header) + bytes(entries_bytes))


def _entry(raw, tag, message_type=0x77):
    """An entry of an undecoded type with a 12-byte payload made from tag."""
    body = bytes([message_type]) + struct.pack('<I', raw) + bytes((tag + i) % 90 + 1 for i in range(12))
    assert b'\xb2' not in body and b'\xfe' not in body
    return bytes([0xb2, len(body) + 2]) + body


def _numbers(entries_bytes):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'test.bin')
        _write_minimal_rev0_file(path, entries_bytes)
        ld = LogData(LogFile(path), timezone_offset=0)
        out = os.path.join(d, 'test.json')
        ld.emit_json_decoding(out)
        return {e['entry_number']: e for e in json.load(open(out))['entries']}


def _block(raws, tag):
    return b''.join(_entry(r, tag + k) for k, r in enumerate(raws))


def test_later_copy_of_a_wall_clock_block_is_dropped_and_numbers_kept():
    block = _block([T + k for k in range(6)], 10)            # 6 entries, 114 bytes
    filler = _block([T + 100 + k for k in range(8)], 40)     # 8 other entries, 152 bytes
    log = block + filler + block + _entry(T + 200, 70)
    entries = _numbers(log)
    # entries 1-6, 7-14 and 21 kept; 15-20 (the copy, 266 bytes after the first) dropped
    assert sorted(entries) == list(range(1, 15)) + [21]
    assert entries[21]['raw_timestamp'] == T + 200


def test_uptime_block_repeated_at_a_later_key_on_is_kept():
    boot = _block([0, 0, 1, 1, 2, 2], 10)                    # identical uptime records at every key-on
    between = _block([T + k for k in range(8)], 40)
    entries = _numbers(boot + between + boot + _entry(T + 50, 70))
    assert len(entries) == 21


def test_flood_within_128_bytes_is_kept():
    one = _entry(T, 10)
    flood = one * 6                                          # the same message logged six times in a row
    entries = _numbers(_block([T - 10 + k for k in range(4)], 30) + flood + _block([T + 10 + k for k in range(4)], 50))
    assert len(entries) == 14


def test_isolated_repeat_without_matching_context_is_kept():
    a = _entry(T, 10)
    log = a + _block([T + 1 + k for k in range(10)], 20) + a + _block([T + 50 + k for k in range(3)], 60)
    assert len(_numbers(log)) == 15


def test_status_rows_a_minute_apart_are_kept():
    rows = b''.join(_entry(T + 60 * k, 10) for k in range(12))   # same payload, a minute apart
    assert len(_numbers(rows)) == 12


def test_drop_legacy_copies_directly():
    blk = _block([T + k for k in range(6)], 10)
    other = _block([T + 100 + k for k in range(8)], 40)
    buf = blk + other + blk
    spans, collected = [], []
    pos = 0
    while pos < len(buf):
        spans.append((pos, buf[pos + 1]))
        collected.append((0, {'raw_timestamp': struct.unpack_from('<I', buf, pos + 3)[0]}, len(collected)))
        pos += buf[pos + 1]
    kept = Gen2.drop_legacy_copies(buf, collected, spans)
    assert [n for _ts, _p, n in kept] == list(range(14))
    # the same copy with uptime values is kept
    for _ts, p, _n in collected:
        p['raw_timestamp'] = 5
    assert len(Gen2.drop_legacy_copies(buf, collected, spans)) == 20


def test_not_a_zero_log_is_judged_on_the_entries_as_walked():
    import types
    import pytest
    from zero_log_parser import UnreadableLogError
    # 100 entries kept: 30 unknown with impossible dates (under the 40% line);
    # 50 dropped copies, all unknown with impossible dates: 80 of 150 as walked
    ents = [types.SimpleNamespace(event='Unknown Type 211' if i < 30 else 'Board Status',
                                  time_source='invalid' if i < 30 else 'clock') for i in range(100)]
    ld = object.__new__(LogData)
    ld.log_file = types.SimpleNamespace(log_type=LogFile.log_type_unknown, file_path='x.bin')
    ld.header_json_fields = {'platform': None}
    ld.vin_source = None
    ld._get_processed_entries = lambda: ents
    ld.legacy_copies_dropped = []
    ld.require_zero_log()
    ld.legacy_copies_dropped = [{'event': 'Unknown Type 211', 'time_source': 'invalid'}] * 50
    with pytest.raises(UnreadableLogError, match='80 of its 150 entries'):
        ld.require_zero_log()
