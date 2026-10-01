"""
Tests for legacy (Gen2) timestamps: the raw uint32 is seconds since power-on
below 2010-01-01 UTC and wall-clock epoch above it. Entries before the first
dated entry of a power cycle are backfilled from it; cycles that never get a
date keep their uptime and no time of day; sort_timestamp is a true UTC epoch
whatever the host timezone is; the order never mixes undated entries into
other cycles.

Same conventions as the other files in this directory: plain test_* functions,
stdlib only, synthetic in-process files, no dataset files checked in.
"""

import json
import os
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import LogFile, LogData


def _write_minimal_rev0_file(path, entries_bytes):
    """Same minimal REV0 builder test_undecoded_and_corrupted_rendering.py
    uses: MBB magic, an a1a1a1a1 fencepost, an a2a2a2a2 event-log header
    pointing at the given already-framed entry bytes."""
    header = bytearray(0x600)
    header[0:4] = b'MBB\x00'
    header[0x26:0x2a] = b'\xa1\xa1\xa1\xa1'
    header[0x2a:0x2a + 20] = b'Jan  1 2020 00:00:00'
    entries_start = 0x610
    entries_end = entries_start + len(entries_bytes)
    header += b'\xa2\xa2\xa2\xa2'
    header += struct.pack('<III', entries_end, entries_start, len(entries_bytes))
    header += b'\x00' * (entries_start - len(header))
    buf = bytes(header) + bytes(entries_bytes)
    with open(path, 'wb') as f:
        f.write(buf)


def _entry(message_type, timestamp, payload):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def _battery_status_payload(event):
    """battery_status() (type 0x33): precharge_percent is None whenever
    event != 1 (event 1 is "Closing Contractor")."""
    payload = bytearray(0x14)
    payload[0x0] = event
    payload[0x1] = 3  # module_num
    struct.pack_into('<I', payload, 0x2, 350_000)   # mod_volt (mV)
    struct.pack_into('<I', payload, 0x6, 400_000)   # sys_max
    struct.pack_into('<I', payload, 0xa, 300_000)   # sys_min
    struct.pack_into('<I', payload, 0xe, 340_000)   # capacitor_volt
    struct.pack_into('<h', payload, 0x12, 50)       # battery_current (int16)
    payload += b'SN123\x00'
    return payload



T1 = 1_700_000_000
T2 = 1_700_100_000
OPEN, CLOSE, REG = 0, 1, 2   # battery_status events: Opening, Closing, Registered


def _log(*raw_and_event):
    out = bytearray()
    for raw, ev in raw_and_event:
        out += _entry(0x33, raw, _battery_status_payload(ev))
    return out


def _entries(entries_bytes, tz=None):
    """JSON entries (as emitted), in output order."""
    old = os.environ.get('TZ')
    try:
        if tz is not None:
            os.environ['TZ'] = tz
            time.tzset()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'test.bin')
            _write_minimal_rev0_file(path, entries_bytes)
            ld = LogData(LogFile(path), timezone_offset=0)
            out = os.path.join(d, 'test.json')
            ld.emit_json_decoding(out)
            return json.load(open(out))['entries']
    finally:
        if tz is not None:
            if old is None:
                os.environ.pop('TZ', None)
            else:
                os.environ['TZ'] = old
            time.tzset()


def _txt(entries_bytes):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'test.bin')
        _write_minimal_rev0_file(path, entries_bytes)
        ld = LogData(LogFile(path), timezone_offset=0)
        out = os.path.join(d, 'test.txt')
        ld.emit_zero_compatible_decoding(out)
        return open(out, encoding='utf-8-sig').read()


def _by_number(entries):
    return {e['entry_number']: e for e in entries}


def test_backfill_from_first_dated_entry_of_the_cycle():
    es = _by_number(_entries(_log((0, OPEN), (2, CLOSE), (5, REG), (T1, OPEN), (T1 + 10, CLOSE))))
    # last uptime before the date is 5 -> that entry is at T1, the others earlier by their gap to it
    assert es[3]['sort_timestamp'] == T1 and es[3]['time_source'] == 'backfilled'
    assert es[2]['sort_timestamp'] == T1 - 3 and es[2]['time_source'] == 'backfilled'
    assert es[1]['sort_timestamp'] == T1 - 5 and es[1]['time_source'] == 'backfilled'
    assert es[1]['raw_timestamp'] == 0 and es[1]['uptime_s'] == 5 - 5 and es[2]['uptime_s'] == 2
    assert es[4]['time_source'] == 'clock' and es[4]['sort_timestamp'] == T1 and 'uptime_s' not in es[4]
    assert es[1]['timestamp'] == time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(T1 - 5))


def test_undated_cycle_keeps_uptime_and_has_no_time_of_day():
    es = _by_number(_entries(_log((T1, OPEN), (T1 + 5, CLOSE), (0, OPEN), (7, REG), (3, CLOSE), (9, OPEN))))
    # entries 3,4 are one cycle (0 -> 7), 5,6 another (drop to 3): neither ever gets a date
    for n, up in ((3, 0), (4, 7), (5, 3), (6, 9)):
        e = es[n]
        assert e['time_source'] == 'uptime' and e['timestamp'] is None and e['sort_timestamp'] is None
        assert e['uptime_s'] == up and e['raw_timestamp'] == up
    assert '1970' not in json.dumps([e['timestamp'] for e in es.values()])


def test_wall_clock_followed_by_uptime_starts_a_new_cycle():
    # date, then uptime 1000 (>0 but a new cycle): must not be backfilled from the earlier date
    es = _by_number(_entries(_log((T1, OPEN), (1000, CLOSE), (1010, REG))))
    assert es[2]['time_source'] == 'uptime' and es[3]['time_source'] == 'uptime'


def test_uptime_drop_starts_a_new_cycle_and_each_cycle_backfills_on_its_own():
    es = _by_number(_entries(_log((0, OPEN), (50, CLOSE), (T1, REG), (0, OPEN), (20, CLOSE), (T2, REG))))
    assert es[2]['sort_timestamp'] == T1 and es[2]['time_source'] == 'backfilled'
    assert es[1]['sort_timestamp'] == T1 - 50
    assert es[5]['sort_timestamp'] == T2 and es[4]['sort_timestamp'] == T2 - 20


def test_large_uptime_over_0xfff_is_not_a_1970_date():
    es = _by_number(_entries(_log((0, OPEN), (5000, CLOSE), (72_821, REG))))
    assert es[3]['time_source'] == 'uptime' and es[3]['uptime_s'] == 72_821
    assert es[3]['sort_timestamp'] is None and es[3]['timestamp'] is None


def test_fully_undated_file_note_and_reverse_log_order_in_text():
    text = _txt(_log((0, OPEN), (3, CLOSE), (4, REG)))
    assert 'This log has no dates or times of day. Times are shown as time since the bike was switched on.' in text
    assert 'clock not set' not in text and '1970' not in text
    lines = [l for l in text.splitlines() if l.startswith(' 0000')]
    assert [l.split()[0] for l in lines] == ['00003', '00002', '00001']
    assert '+0:00:04' in lines[0] and '+0:00:00' in lines[2]


def test_dated_file_has_no_undated_note():
    assert 'no dates or times of day' not in _txt(_log((T1, OPEN), (T1 + 1, CLOSE)))


def test_undated_cycle_between_dated_ones_keeps_log_position():
    es = _entries(_log((T1, OPEN), (T1 + 1, CLOSE), (0, OPEN), (4, REG), (T2, OPEN), (T2 + 1, CLOSE)))
    # 0 and 4 are in the cycle that gets T2 at entry 5, so 3 and 4 are backfilled (T2-4, T2);
    # entries 4 and 5 tie at T2 and keep log order, as ties always have
    order = [e['entry_number'] for e in es]
    assert order == [6, 4, 5, 3, 2, 1]
    es = _entries(_log((T1, OPEN), (T1 + 1, CLOSE), (0, OPEN), (4, REG), (2, CLOSE), (T2, OPEN)))
    order = [e['entry_number'] for e in es]
    # entries 3,4 are one cycle (0->4) that never gets a date; 5 starts another (drop to 2) dated at 6.
    # The undated pair sits just after (newer than) entry 2, reverse log order, below the dated cycle
    assert order == [5, 6, 4, 3, 2, 1]


def test_undated_tail_after_dated_entries_sorts_newest_first_above_them():
    es = _entries(_log((T1, OPEN), (T1 + 1, CLOSE), (0, OPEN), (4, REG)))
    assert [e['entry_number'] for e in es] == [4, 3, 2, 1]
    assert es[0]['time_source'] == 'uptime' and es[2]['time_source'] == 'clock'


def test_sort_timestamp_is_utc_epoch_whatever_the_host_timezone():
    data = _log((0, OPEN), (2, CLOSE), (T1, REG), (T1 + 60, OPEN), (0, OPEN), (9, CLOSE))
    a = _entries(data, tz='UTC')
    b = _entries(data, tz='America/New_York')
    c = _entries(data, tz='Asia/Kolkata')
    assert a == b == c
    assert {e['entry_number']: e['sort_timestamp'] for e in a}[3] == T1
