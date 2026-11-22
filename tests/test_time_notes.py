"""time_note on entries without a usable date (Gen2.label_time_notes). The
dates are not changed. Synthetic logs only."""
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
    body = bytes([message_type]) + struct.pack('<I', raw) + bytes((tag + i) % 90 + 1 for i in range(12))
    assert b'\xb2' not in body and b'\xfe' not in body
    return bytes([0xb2, len(body) + 2]) + body


def _entries(raws):
    log = b''.join(_entry(r, 3 * k) for k, r in enumerate(raws))
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'test.bin')
        _write_minimal_rev0_file(path, log)
        ld = LogData(LogFile(path), timezone_offset=0)
        out = os.path.join(d, 'test.json')
        ld.emit_json_decoding(out)
        return {e['entry_number']: e for e in json.load(open(out))['entries']}


def test_seam_time_bytes_are_labelled():
    e = _entries([T, 0xa2a2a2a2, T + 5, 0xa2a2a201, 0x04a2a2a2, T + 9])
    assert e[2]['time_source'] == 'invalid' and e[2]['time_note'] == 'seam'
    assert e[2]['timestamp'] is None and e[2]['raw_timestamp'] == 0xa2a2a2a2
    assert e[4]['time_note'] == 'seam'
    # 0x04a2a2a2 is an uptime longer than the backfill window: still invalid, still from the marker
    assert e[5]['time_source'] == 'invalid' and e[5]['time_note'] == 'seam'
    for n in (1, 3, 6):
        assert 'time_note' not in e[n]


def test_dated_entry_with_marker_bytes_is_not_labelled():
    e = _entries([T, 0x6550a2a2, T + 0x500000])
    assert e[2]['time_source'] == 'clock' and 'time_note' not in e[2]


def test_other_invalid_values_are_not_labelled_seam():
    e = _entries([T, 0xc0000000, T + 5])
    assert e[2]['time_source'] == 'invalid' and 'time_note' not in e[2]


def test_label_time_notes_directly():
    collected = [(0, {'time_source': 'invalid', 'raw_timestamp': 0xa2a2a2a2}, 0),
                 (0, {'time_source': 'clock', 'raw_timestamp': 0x6550a2a2}, 1),
                 (0, {'time_source': None, 'raw_timestamp': None}, 2)]
    Gen2.label_time_notes(collected)
    assert [p.get('time_note') for _t, p, _n in collected] == ['seam', None, None]
