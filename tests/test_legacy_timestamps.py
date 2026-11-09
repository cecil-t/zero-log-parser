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

from datetime import datetime, timezone

from zero_log_parser import LogFile, LogData, Gen2


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
    # no escaping here, so the test values must not contain 0xb2 or 0xfe
    assert b'\xb2' not in body and b'\xfe' not in body, hex(timestamp)
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


# --- rolling future limit: UTC date at parse time plus 30 months, end of that day ---

FIXED_NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
LIMIT_2026 = 1_869_782_399        # 2029-04-01 23:59:59 UTC


def _with_now(now, fn):
    old = Gen2.utc_now
    Gen2.utc_now = staticmethod(lambda: now)
    try:
        return fn()
    finally:
        Gen2.utc_now = old


def test_clock_max_is_end_of_utc_day_thirty_months_on():
    assert Gen2.clock_max(FIXED_NOW) == LIMIT_2026
    assert Gen2.clock_max(datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)) == LIMIT_2026
    assert Gen2.clock_max(datetime(2026, 10, 1, 23, 59, 59, tzinfo=timezone.utc)) == LIMIT_2026
    # the next UTC day moves the window by a day
    assert Gen2.clock_max(datetime(2026, 10, 2, 0, 0, 0, tzinfo=timezone.utc)) == LIMIT_2026 + 86400
    # a non-UTC "now" is measured by its UTC date
    from datetime import timedelta
    ny = timezone(timedelta(hours=-5))
    assert Gen2.clock_max(datetime(2026, 9, 30, 22, 0, 0, tzinfo=ny)) == LIMIT_2026
    # a day missing in the target month becomes that month's last day
    assert Gen2.clock_max(datetime(2026, 8, 31, 5, 0, 0, tzinfo=timezone.utc)) == \
        int(datetime(2029, 2, 28, 23, 59, 59, tzinfo=timezone.utc).timestamp())
    assert Gen2.clock_max(datetime(2028, 2, 29, 5, 0, 0, tzinfo=timezone.utc)) == \
        int(datetime(2030, 8, 29, 23, 59, 59, tzinfo=timezone.utc).timestamp())


def test_default_now_is_the_real_clock():
    lim = Gen2.clock_max()
    now = int(datetime.now(timezone.utc).timestamp())
    assert now + 29 * 30 * 86400 < lim < now + 31 * 31 * 86400


def _sources(raws, now):
    data = _log(*[(r, OPEN) for r in raws])
    es = _with_now(now, lambda: _by_number(_entries(data)))
    return [es[i + 1]['time_source'] for i in range(len(raws))]


def test_boundary_just_inside_and_just_outside_the_window():
    inside, outside = LIMIT_2026, LIMIT_2026 + 1
    assert _sources([inside], FIXED_NOW) == ['clock']
    assert _sources([outside], FIXED_NOW) == ['invalid']
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(_log((inside, OPEN)))))
    assert es[1]['sort_timestamp'] == inside
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(_log((outside, OPEN)))))
    assert es[1]['sort_timestamp'] is None


def test_far_future_is_invalid_and_the_window_moves_with_the_calendar():
    jun_2031 = 1_938_902_400     # 2031-06-01: beyond FIXED_NOW's window
    assert _sources([jun_2031], FIXED_NOW) == ['invalid']
    # the same value is an ordinary date when parsed in mid-2029
    later = datetime(2029, 6, 15, tzinfo=timezone.utc)
    assert _sources([jun_2031], later) == ['clock']


def test_value_between_the_window_and_2030_is_invalid_now():
    # 2030-06-01 is before the old fixed limit but about 3.7 years past FIXED_NOW
    assert _sources([1_906_502_400], FIXED_NOW) == ['invalid']


def test_lower_bound_is_unchanged():
    # 2010-01-01 is a date; one below it is read as uptime, here 40 years of it,
    # which cannot fit the file's window, so it is invalid rather than backfilled
    assert _sources([1_262_304_000 - 1, 1_262_304_000], FIXED_NOW) == ['invalid', 'clock']
    assert _sources([1_262_304_000 + 100, 1_262_304_000 + 200], FIXED_NOW) == ['clock', 'clock']


# --- backfill anchor rule: A is rejected only when its neighbours agree with each other and disagree with it ---

def _times(raws, now=FIXED_NOW):
    es = _with_now(now, lambda: _by_number(_entries(_log(*[(r, OPEN) for r in raws]))))
    return {n: (e['time_source'], e['sort_timestamp']) for n, e in es.items()}


def test_long_forward_gap_does_not_reject_the_anchor():
    d30 = 30 * 86400
    t = _times([0, 7, T1, T1 + d30, T1 + d30 + 5])
    assert t[1] == ('backfilled', T1 - 7) and t[2] == ('backfilled', T1)


def test_future_outlier_with_agreeing_neighbours_is_rejected():
    # P=T1, boot entries 0 and 4, A far ahead, N and N2 agree with each other and with P
    t = _times([T1, 0, 4, T1 + 500, T1 + 100, T1 + 105])
    assert t[4] == ('clock', T1 + 500)                    # A is untouched
    # same arithmetic, on N: boot entries (raw 0 and 4) land at N - 4 and N
    assert t[2] == ('backfilled', T1 + 96) and t[3] == ('backfilled', T1 + 100)


def test_garbage_n_far_before_p_does_not_reject_a():
    # N is an old garbage date (before P): A is kept even though it is later than N
    t = _times([T1, 0, 4, T1 + 500, T1 - 100_000, T1 - 99_995])
    assert t[3] == ('backfilled', T1 + 500) and t[2] == ('backfilled', T1 + 496)


def test_garbage_n_between_p_and_a_after_parking_does_not_reject_a():
    # parked for ten days: N is a garbage value between P and the correct A, N2 does not follow N
    d10, d5 = 10 * 86400, 5 * 86400
    t = _times([T1, 0, 4, T1 + d10, T1 + d5, T1 + d10 + 5])
    assert t[3] == ('backfilled', T1 + d10)


def test_rejection_needs_n_to_agree_with_n2():
    # A later than N, N after P, but N2 is earlier than N: no vote, A kept
    t = _times([T1, 0, 4, T1 + 500, T1 + 100, T1 + 50])
    assert t[3] == ('backfilled', T1 + 500)


def test_n2_in_the_next_cycle_counts():
    # the cycle's own clock values are A and N; N2 is the first clock entry of the next cycle
    t = _times([T1, 0, 4, T1 + 500, T1 + 100, 0, 3, T1 + 105])
    assert t[3] == ('backfilled', T1 + 100)
    # same, but the next cycle's clock value disagrees with N
    t = _times([T1, 0, 4, T1 + 500, T1 + 100, 0, 3, T1 + 50])
    assert t[3] == ('backfilled', T1 + 500)


def test_a_without_n2_is_decided_by_n_alone():
    t = _times([T1, 0, 4, T1 + 500, T1 + 100])
    assert t[3] == ('backfilled', T1 + 100)


def test_within_sixty_seconds_is_not_an_outlier():
    t = _times([T1, 0, 4, T1 + 160, T1 + 100, T1 + 105])    # A later than N by exactly 60 s
    assert t[3] == ('backfilled', T1 + 160)


def test_past_outlier_is_rejected_whatever_the_gap_between_n_and_p():
    p = T1 + 1000
    # previous cycle ends at p; A is 500 s earlier; N is three days after p (parking), N2 follows N
    n = p + 3 * 86400
    t = _times([T1, p, 0, 3, p - 500, n, n + 5])
    assert t[4] == ('backfilled', n) and t[3] == ('backfilled', n - 3)
    assert t[5] == ('clock', p - 500)


def test_past_step_where_n_is_also_before_p_is_a_wrap_not_an_outlier():
    p = T1 + 1000
    t = _times([T1, p, 0, 3, T1 - 5000, T1 - 4990, T1 - 4980])
    assert t[4] == ('backfilled', T1 - 5000)


def test_single_clock_entry_keeps_its_anchor():
    t = _times([T1, T1 + 5, 0, 3, T1 - 90000])
    assert t[4] == ('backfilled', T1 - 90000)


def test_rejection_never_turns_boot_entries_into_uptime():
    # N is far from every neighbour; the old fallback would have left uptime
    n = T1 + 100
    t = _times([T1, 0, 4, T1 + 500, n, n + 5, n + 4000])
    assert t[3][0] == 'backfilled' and t[2][0] == 'backfilled'


def test_rejected_a_is_still_displayed_as_decoded():
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(_log((T1, OPEN), (0, OPEN), (4, CLOSE), (T1 + 500, REG), (T1 + 100, OPEN), (T1 + 105, CLOSE)))))
    assert es[4]['timestamp'] == time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(T1 + 500)) and es[4]['time_source'] == 'clock'


# --- backfill window: a backfilled time stays within the file's clock times plus or minus 12 months ---

DAY = 86400
YEAR = 365 * DAY


def _tabular(entries_bytes, fmt):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'test.bin')
        _write_minimal_rev0_file(path, entries_bytes)
        ld = LogData(LogFile(path), timezone_offset=0)
        out = os.path.join(d, 'test.' + fmt)
        ld.emit_tabular_decoding(out, out_format=fmt)
        return open(out, encoding='utf-8-sig').read()


def _txt_rows(text):
    """entry number -> the TXT line, for entry lines."""
    rows = {}
    for line in text.splitlines():
        if line[:1] == ' ' and line[1:6].isdigit():
            rows[int(line[1:6])] = line
    return rows


def test_backfill_window_is_clock_range_plus_minus_twelve_months_inside_floor_and_ceiling():
    mar_2020 = int(datetime(2020, 3, 15, 8, 0, 0, tzinfo=timezone.utc).timestamp())
    jul_2021 = int(datetime(2021, 7, 31, 8, 0, 0, tzinfo=timezone.utc).timestamp())
    lo, hi = Gen2.backfill_window([jul_2021, mar_2020], FIXED_NOW)
    assert lo == int(datetime(2019, 3, 15, 8, 0, 0, tzinfo=timezone.utc).timestamp())
    assert hi == int(datetime(2022, 7, 31, 8, 0, 0, tzinfo=timezone.utc).timestamp())
    # near 2010 the floor wins; near the ceiling clock_max wins
    lo, _ = Gen2.backfill_window([Gen2.CLOCK_MIN + 30 * DAY], FIXED_NOW)
    assert lo == Gen2.CLOCK_MIN
    _, hi = Gen2.backfill_window([LIMIT_2026 - DAY], FIXED_NOW)
    assert hi == LIMIT_2026
    # no clock times: floor to ceiling
    assert Gen2.backfill_window([], FIXED_NOW) == (Gen2.CLOCK_MIN, LIMIT_2026)
    # 29 February one year on is 28 February
    feb_29 = int(datetime(2024, 2, 29, 12, 0, 0, tzinfo=timezone.utc).timestamp())
    assert Gen2.shift_months(feb_29, 12) == int(datetime(2025, 2, 28, 12, 0, 0, tzinfo=timezone.utc).timestamp())


def test_garbage_uptime_of_decades_is_invalid_and_does_not_split_the_cycle():
    g = 26 * YEAR
    data = _log((T1 - 5000, OPEN), (0, OPEN), (3, CLOSE), (g, REG), (6, OPEN), (T1, CLOSE))
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(data)))
    assert es[4]['time_source'] == 'invalid' and es[4]['timestamp'] is None
    assert es[4]['raw_timestamp'] == g and 'uptime_s' not in es[4] and es[4]['sort_timestamp'] is None
    # without it 0, 3, 6 are one cycle, placed from 6
    assert (es[2]['time_source'], es[2]['sort_timestamp']) == ('backfilled', T1 - 6)
    assert (es[3]['time_source'], es[3]['sort_timestamp']) == ('backfilled', T1 - 3)
    assert (es[5]['time_source'], es[5]['sort_timestamp']) == ('backfilled', T1)
    # the same value as the last uptime before the date does not move the others decades back
    data = _log((0, OPEN), (3, CLOSE), (g, REG), (T1, CLOSE))
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(data)))
    assert es[3]['time_source'] == 'invalid'
    assert es[1]['sort_timestamp'] == T1 - 3 and es[2]['sort_timestamp'] == T1


def test_long_but_plausible_uptime_inside_the_window_keeps_its_date():
    # parked 200 days with the bike on (plausible for a BMS); the date follows
    data = _log((T1 - 400 * DAY, OPEN), (100 * DAY, OPEN), (200 * DAY, CLOSE), (T1, REG))
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(data)))
    assert (es[2]['time_source'], es[2]['sort_timestamp']) == ('backfilled', T1 - 100 * DAY)
    assert (es[3]['time_source'], es[3]['sort_timestamp']) == ('backfilled', T1)
    assert es[3]['uptime_s'] == 200 * DAY


def test_last_uptime_before_the_anchor_garbage_within_the_window_width():
    # clock times span four years, so a three-year uptime is not ruled out by length,
    # but counted back from the anchor it puts the power-on before the window
    late = T1 + 4 * YEAR - 30 * DAY
    data = _log((0, OPEN), (3, CLOSE), (5, REG), (3 * YEAR, OPEN), (T1, CLOSE), (late, OPEN))
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(data)))
    assert es[4]['time_source'] == 'invalid' and es[4]['timestamp'] is None
    # placed from 5, the last uptime whose power-on is inside the window
    assert [es[n]['sort_timestamp'] for n in (1, 2, 3)] == [T1 - 5, T1 - 2, T1]
    assert all(es[n]['time_source'] == 'backfilled' for n in (1, 2, 3))


def test_future_dated_entry_shows_unknown_and_sorts_by_log_position():
    future = 1_938_902_400     # 2031-06-01: beyond FIXED_NOW's ceiling
    data = _log((T1, OPEN), (future, CLOSE), (T1 + 10, REG))
    es = _with_now(FIXED_NOW, lambda: _entries(data))
    assert [e['entry_number'] for e in es] == [3, 2, 1]        # newest first, 2 just after 1
    e = _by_number(es)[2]
    assert e['time_source'] == 'invalid' and e['timestamp'] is None and e['raw_timestamp'] == future
    assert e['sort_timestamp'] is None
    txt = _with_now(FIXED_NOW, lambda: _txt(data))
    assert 'Unknown' in _txt_rows(txt)[2] and '2031' not in txt
    for fmt in ('csv', 'tsv'):
        out = _with_now(FIXED_NOW, lambda: _tabular(data, fmt))
        assert '2031' not in out
        assert any('Unknown' in line for line in out.splitlines()[1:])


def test_invalid_from_backfill_shows_unknown_in_text():
    data = _log((0, OPEN), (3, CLOSE), (26 * YEAR, REG), (T1, CLOSE))
    rows = _txt_rows(_with_now(FIXED_NOW, lambda: _txt(data)))
    assert 'Unknown' in rows[3] and '1988' not in rows[1] + rows[2] + rows[3]


def test_file_with_one_clock_entry():
    # window is that one time plus or minus 12 months
    ok = _log((0, OPEN), (300 * DAY, CLOSE), (T1, REG))
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(ok)))
    assert (es[2]['time_source'], es[2]['sort_timestamp']) == ('backfilled', T1)
    assert (es[1]['time_source'], es[1]['sort_timestamp']) == ('backfilled', T1 - 300 * DAY)
    # 400 days counted back from the only date is outside the window; nothing else can place it
    bad = _log((400 * DAY, CLOSE), (T1, REG))
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(bad)))
    assert es[1]['time_source'] == 'invalid' and es[1]['timestamp'] is None
    assert es[2]['time_source'] == 'clock'


def test_uptime_only_file_keeps_uptime_and_drops_what_cannot_fit():
    # no clock times: window is 2010 to the ceiling, about 19 years wide at FIXED_NOW
    es = _with_now(FIXED_NOW, lambda: _by_number(_entries(_log((5, OPEN), (26 * YEAR, CLOSE), (9, REG)))))
    assert es[1]['time_source'] == 'uptime' and es[3]['time_source'] == 'uptime'
    assert es[2]['time_source'] == 'invalid'
