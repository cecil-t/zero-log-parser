"""A raw clock value before 1 January of (VIN model year - 2) is not a date. Invented VINs only."""
import calendar, os, sys
from datetime import datetime, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from zero_log_parser import Gen2

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
VIN_2014 = '538TT1Z28EAA00001'   # check digit valid, model year code E (2014)
VIN_2019 = '538TT1Z23KAA00001'   # K (2019)
FLOOR_2014 = calendar.timegm((2012, 1, 1, 0, 0, 0))


def _e(raw, event='x'):
    return {'original_timestamp': raw, 'event': event}


def _run(raws, floor):
    out = Gen2.assign_legacy_times([(0, _e(r, str(i)), i) for i, r in enumerate(raws)], 0, now=NOW, clock_floor=floor)
    return {p['event']: p for _, p, _ in out}


def test_vin_clock_floor():
    assert Gen2.vin_clock_floor(VIN_2014) == FLOOR_2014
    assert Gen2.vin_clock_floor(VIN_2019) == calendar.timegm((2017, 1, 1, 0, 0, 0))
    assert Gen2.vin_clock_floor('538TT1Z29EAA00001') is None     # check digit fails
    assert Gen2.vin_clock_floor('538TT1Z2XUAA00001') is None     # U is no model-year code
    assert Gen2.vin_clock_floor(None) is None
    assert Gen2.vin_clock_floor('Unknown') is None


def test_value_below_floor_is_invalid():
    good = calendar.timegm((2015, 6, 1, 12, 0, 0))
    early = calendar.timegm((2011, 3, 1, 12, 0, 0))   # after 2010, before 2012
    r = _run([good, early, good + 60], FLOOR_2014)
    assert r['1']['time_source'] == 'invalid'
    assert r['0']['time_source'] == r['2']['time_source'] == 'clock'
    # without a floor the 2010 rule is unchanged
    assert _run([good, early, good + 60], None)['1']['time_source'] == 'clock'


def test_damaged_anchor_below_floor_is_skipped():
    real = calendar.timegm((2015, 6, 1, 12, 0, 0))
    damaged = calendar.timegm((2010, 12, 8, 17, 0, 32))
    # a key-on cycle: uptime 0, 1, 2, then a damaged clock value, then the real clock
    r = _run([0, 1, 2, damaged, real], FLOOR_2014)
    assert r['3']['time_source'] == 'invalid'
    for k in ('0', '1', '2'):
        assert r[k]['time_source'] == 'backfilled'
    assert r['2']['time'] == datetime.fromtimestamp(real, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    # production behaviour without a floor: the damaged value anchors the cycle in 2010
    r0 = _run([0, 1, 2, damaged, real], None)
    assert r0['2']['time'].startswith('2010-12-08')


def test_floor_never_below_2010():
    assert Gen2.vin_clock_floor('538TT1Z2_AAA00001'.replace('_', '0')) in (None, Gen2.CLOCK_MIN)
