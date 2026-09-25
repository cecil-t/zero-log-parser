"""
Tests for file-type-aware dispatch of entry types 0x10 / 0x11 (queue item
21, analysis/mbb_dispatch_fix.md).

Gen2._entry_parsers() was one shared, file-type-blind dispatch table.
Types 0x10 and 0x11 are a namespace collision between the classic BMS and
MBB firmwares: BMS writes bms_state ("Entering"/"Exiting Hibernate") and
bms_isolation_fault ("Chassis Isolation Fault") at these ids; the classic
MBB firmware's own event-log renderer (analysis/mbb_firmware_strings.md
Section 4) names the same ids "BMS Throt En Wire Disable" / "BMS Throt
Wire Re-enable" (8 bytes: u32 LE vpack mV, u32 LE thr_en mV), which the
parser had always routed through the BMS decoders instead, since nothing
in the dispatch table knew which file it was looking at.

_entry_parsers() now takes an optional log_type (LogFile.log_type_mbb /
log_type_bms / log_type_unknown / None) and overrides 0x10/0x11 only when
it is definitely 'MBB'; every other value keeps the pre-existing BMS
decoders, and every other type id is untouched. parse_entry() and
collect_paged_bms_entries() both thread it through from
LogData._collect_and_process_entries, which passes self.log_file.log_type.

Real samples: decoder-level tests use real payload bytes pulled with the
real entry walker (scratch/mbb_dispatch_fix/, source file and entry time
given for each), the same convention as
tests/test_mbb_classic_renderer_types.py. Dispatch-level tests use
synthetic raw entries, the same convention as
tests/test_bms_cell_telemetry_decode.py, since those exercise the
plumbing (parse_entry's own signature, LogData's own call site) rather
than any one payload's fields.
"""

import base64
import logging
import os
import struct
import sys
import tempfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2, LogFile, LogData


def _hex(s):
    return bytearray(bytes.fromhex(s.replace(' ', '')))


def _decode_mbb(message_type, payload):
    return Gen2._entry_parsers(log_type=LogFile.log_type_mbb)[message_type](payload)


# 1708495471512_538SMCZ67HCG07765_MBB_2024-02-19.bin, 2024-02-16 09:55:21.
SAMPLE_10_A = _hex('00 b6 01 00 0c 00 00 00')
# 1573352239053_538sm7z29fca05015_MBB_2019-11-10.bin, 2019-11-09 03:34:49.
SAMPLE_10_B = _hex('ec 96 01 00 00 00 00 00')

# 538SD5Z27ECB03639_MBB_2018-03-29.bin, 2018-03-28 13:22:53.
SAMPLE_11_A = _hex('c4 b8 01 00 1b 12 00 00')
# 538SD5Z27ECB04404_MBB_2020-11-29.bin, 2020-11-20 00:07:54.
SAMPLE_11_B = _hex('3b 8b 01 00 1b 12 00 00')

# 02_538SMDZB4HCA08745_BMS0_2018-11-03.bin, a real BMS file: 0x10 payloads
# are 1 byte (entering/exiting flag), 0x11 payloads are 5 bytes (ohms +
# cell number) - structurally incompatible with the 8-byte MBB shape, so
# these also double as evidence the two never collide on decoded shape.
SAMPLE_BMS_10_ENTERING = _hex('01')
SAMPLE_BMS_10_EXITING = _hex('00')
# 2018-10-13 22:58:50, resistance_ohms=59595, cell_number=4.
SAMPLE_BMS_11 = _hex('cb e8 00 00 04')


def test_0x10_mbb_decodes_as_throttle_enable_wire_disable():
    e = _decode_mbb(0x10, SAMPLE_10_A)
    assert e['event'] == 'BMS Throt En Wire Disable'
    assert e['structured_data'] == {'vpack_voltage_volts': 112.128, 'thr_en_voltage_volts': 0.012}
    e = _decode_mbb(0x10, SAMPLE_10_B)
    assert e['structured_data'] == {'vpack_voltage_volts': 104.172, 'thr_en_voltage_volts': 0.0}


def test_0x11_mbb_decodes_as_throttle_wire_reenable():
    e = _decode_mbb(0x11, SAMPLE_11_A)
    assert e['event'] == 'BMS Throt Wire Re-enable'
    assert e['structured_data'] == {'vpack_voltage_volts': 112.836, 'thr_en_voltage_volts': 4.635}
    e = _decode_mbb(0x11, SAMPLE_11_B)
    assert e['structured_data'] == {'vpack_voltage_volts': 101.179, 'thr_en_voltage_volts': 4.635}


def test_0x10_0x11_mbb_other_lengths_fall_back():
    e = _decode_mbb(0x10, _hex('00 b6 01'))
    assert 'structured_data' not in e
    assert e['conditions'].startswith('Raw data:')
    e = _decode_mbb(0x11, _hex('c4 b8 01 00 1b'))
    assert 'structured_data' not in e
    assert e['conditions'].startswith('Raw data:')


def test_bms_files_0x10_0x11_unchanged_by_new_decoders():
    # The BMS-side decoders themselves are untouched: called directly on
    # real BMS payloads, they still give exactly what they always gave.
    assert Gen2.bms_state(SAMPLE_BMS_10_ENTERING) == {'event': 'Entering Hibernate'}
    assert Gen2.bms_state(SAMPLE_BMS_10_EXITING) == {'event': 'Exiting Hibernate'}
    fault = Gen2.bms_isolation_fault(SAMPLE_BMS_11)
    assert fault['event'] == 'Chassis Isolation Fault'
    assert fault['structured_data']['resistance_ohms'] == 59595
    assert fault['structured_data']['cell_number'] == 4


def test_entry_parsers_default_and_bms_and_unknown_keep_old_dispatch():
    # No log_type (every pre-existing caller in this codebase and its
    # tests), log_type='BMS', and log_type='Unknown Type' (a file that
    # isn't definitely MBB) must all keep routing 0x10/0x11 to the BMS
    # decoders - this is the actual risk in this change, not the MBB side.
    for log_type in (None, LogFile.log_type_bms, LogFile.log_type_unknown):
        parsers = Gen2._entry_parsers(log_type)
        assert parsers[0x10] == Gen2.bms_state
        assert parsers[0x11] == Gen2.bms_isolation_fault


def test_entry_parsers_mbb_routes_0x10_0x11_to_new_decoders():
    parsers = Gen2._entry_parsers(LogFile.log_type_mbb)
    assert parsers[0x10] == Gen2.mbb_throttle_enable_wire_disable
    assert parsers[0x11] == Gen2.mbb_throttle_enable_wire_reenable


def test_entry_parsers_log_type_does_not_disturb_other_type_ids():
    # Every id but 0x10/0x11 must be identical (by behavior, not lambda
    # identity - _entry_parsers() builds a fresh dict, and closures for
    # ids like 0x1e/0x4b/0x52 are new objects each call) whether log_type
    # is 'MBB', 'BMS', or omitted. This is the explicit no-regression
    # check step 5 asked for: the two already-shipped decoders that hit
    # this same namespace-collision root cause, 0x3d
    # (contactor_closed_or_precharge_failed, split by payload length) and
    # 0x4B/0x4C/0x4D (state_snapshot_dispatch, split by payload shape),
    # must behave identically under the new parameterized table.
    default_parsers = Gen2._entry_parsers()
    mbb_parsers = Gen2._entry_parsers(LogFile.log_type_mbb)
    bms_parsers = Gen2._entry_parsers(LogFile.log_type_bms)
    assert set(default_parsers) == set(mbb_parsers) == set(bms_parsers)  # same ids dispatched either way

    # Direct classmethod references compare equal (bound-method equality)
    # across separate _entry_parsers() calls; lambda-wrapped entries
    # (0x1e/0x1f/0x4b/0x4c/0x4d/0x52/0x53) don't, since each call builds
    # fresh closures, so those are checked behaviorally below instead.
    direct_ids = [t for t in default_parsers if t not in (0x10, 0x11)
                  and default_parsers[t].__name__ != '<lambda>']
    assert direct_ids  # sanity: not every other id is a lambda
    for t in direct_ids:
        assert default_parsers[t] == mbb_parsers[t] == bms_parsers[t]

    # Direct behavioral check on the two decoders step 5 names.
    precharge_4byte = _hex('d6 00 01 00')
    assert (mbb_parsers[0x3d](precharge_4byte) == bms_parsers[0x3d](precharge_4byte)
            == default_parsers[0x3d](precharge_4byte)
            == Gen2.contactor_closed_or_precharge_failed(precharge_4byte))

    mbb_shaped_snapshot = bytearray((i % 100) + 1 for i in range(46))
    struct.pack_into('<I', mbb_shaped_snapshot, 0, 123000)
    mbb_shaped_snapshot[35:39] = b'RUN\x00'
    assert (mbb_parsers[0x4b](mbb_shaped_snapshot) == bms_parsers[0x4b](mbb_shaped_snapshot)
            == default_parsers[0x4b](mbb_shaped_snapshot)
            == Gen2.state_snapshot_dispatch(0x4b, mbb_shaped_snapshot))


def _raw_entry(message_type, payload, timestamp=1_600_000_000):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def test_parse_entry_end_to_end_mbb_vs_bms_log_type():
    logger = logging.getLogger('test_mbb_dispatch_0x10_0x11')
    raw10 = _raw_entry(0x10, SAMPLE_10_A)
    raw11 = _raw_entry(0x11, SAMPLE_11_A)

    _length, entry, _unhandled = Gen2.parse_entry(raw10, 0, 0, logger, log_type=LogFile.log_type_mbb)
    assert entry['event'] == 'BMS Throt En Wire Disable'
    assert entry['structured_data'] == {'vpack_voltage_volts': 112.128, 'thr_en_voltage_volts': 0.012}

    _length, entry, _unhandled = Gen2.parse_entry(raw11, 0, 0, logger, log_type=LogFile.log_type_mbb)
    assert entry['event'] == 'BMS Throt Wire Re-enable'

    # Omitting log_type, passing 'BMS', or passing 'Unknown Type' (a file
    # whose own magic string and filename both failed to say MBB or BMS -
    # analysis/mbb_dispatch_fix.md Section on log_type routing) must all
    # decode the same 8-byte MBB payload with the BMS decoder instead (a
    # real risk: bms_state() and bms_isolation_fault() don't length-gate,
    # so they will produce *some* output from an 8-byte buffer, just the
    # wrong one). Previously only checked at the _entry_parsers() table
    # level for 'Unknown Type'; added here too so the actual entry point
    # every real caller uses is covered, not just the table it calls.
    for log_type in (None, LogFile.log_type_bms, LogFile.log_type_unknown):
        _length, entry, _unhandled = Gen2.parse_entry(raw10, 0, 0, logger, log_type=log_type)
        assert entry['event'] in ('Entering Hibernate', 'Exiting Hibernate')
        _length, entry, _unhandled = Gen2.parse_entry(raw11, 0, 0, logger, log_type=log_type)
        assert entry['event'] == 'Chassis Isolation Fault'


def test_parse_entry_real_bms_payloads_unchanged_with_bms_log_type():
    logger = logging.getLogger('test_mbb_dispatch_0x10_0x11')
    raw10 = _raw_entry(0x10, SAMPLE_BMS_10_ENTERING)
    raw11 = _raw_entry(0x11, SAMPLE_BMS_11)

    for log_type in (None, LogFile.log_type_bms, LogFile.log_type_unknown):
        _length, entry, _unhandled = Gen2.parse_entry(raw10, 0, 0, logger, log_type=log_type)
        assert entry['event'] == 'Entering Hibernate'
        _length, entry, _unhandled = Gen2.parse_entry(raw11, 0, 0, logger, log_type=log_type)
        assert entry['event'] == 'Chassis Isolation Fault'
        assert entry['structured_data']['resistance_ohms'] == 59595


# LogFile.has_classic_vin(): a narrow, file-level signal, independent of
# LogFile.get_log_type()'s own fragile magic-string/filename detection,
# that lets LogData._collect_and_process_entries() upgrade an Unknown
# Type file to MBB for 0x10/0x11 dispatch when a real, FMVSS 565
# checksum-valid VIN sits at the known classic offset (0x240 or 0x252).
# Investigated and scoped in analysis/mbb_dispatch_fix.md's dated
# follow-up section: 36 of the 68 Unknown Type files carrying 0x10/0x11
# entries have this signal (448 of 1,086 entries), validated against
# every real BMS file in the file set (0 of 2,797 ever show a valid
# classic VIN there) and against the 20 files that are genuinely MBB by
# entry-type census but have no VIN at any known offset (this signal
# correctly does not reach them - see NO_VIN_UNKNOWN_TYPE below).
#
# Real samples, zlib-compressed and base64-encoded inline, the same
# convention as tests/test_json_log_info.py. Each is the smallest prefix
# that still reaches at least one real 0x10 entry (checked against the
# whole file when the samples were cut).

# 0_538SM4Z25DCA03015_MBB_2020-08-02.bin, first 0x800 bytes: printable
# junk lands at both offset 0x000 and 0x00d (get_log_type() never falls
# through to the filename), so log_type is Unknown Type, but a real,
# checksum-valid VIN sits at 0x240 and the file's own entries are
# overwhelmingly the classic MBB-only ids.
CLASSIC_VIN_UNKNOWN_TYPE = (
    'eNrtVc1rE0EUfxOrSRpJE0VEKHEsaHqouskm5qMoSZNUsKQtDeaggZiPyUdJdkOaIL17EKTgQezH'
    'QYz+B4uHQg+KNCfF+i+I4EGPnjyU+HbzOakGz8UfzL75ze/N25l5b3YbjUYjmlqn1EWdgsNNHS6/'
    '2+V3+qDVg9YN730jgOhamwsgTQGIEeDplx3yKWCG3Z9PyIuPF2DDq7loaB0A5NB+2NvRBh2QgiDa'
    '9+fbeiJxOtn11WEzdfpyd34Hq9hfhT5KQ7ppiOPKYOpEe8wwMK81BHVRZEA3jw3HORK3dZyASReT'
    '5XQ6KaZFMetLCg5B9A2cB1cbbr8gqLXRtQi36I1FXfec7nAoKIjoBbDR8P94ifhDWXkGy+oUHnws'
    'BhyyIME8LMB0nMAkPII3eh2ZIYRkAR/WgOWZVdEZMMgvDGAxwyUc5eY/+N627+xGzZJOCpexPix2'
    'gF1TJ92JKydV89g6D9MwDnMwge/uLOx4ZXg0XiN8WPOz2Gx4ILQcB+XyoZbaOI3VK5XSOl2q16ic'
    'o7EKy1DR4/GqTgDKxPXn9/H2OvYjY3p9nzY5CvsRaEZu9WgzglNVusk7b/6rGkC6xatbfdWHdJtX'
    't/uqfaR6A2kqwe2oTZscbe9oqkd7kRnvzPrqV6R5Xs0nuB0VeLXAR/67qtIirxb76p2RqXS6vd5X'
    'iINZgM/Y2Jn25VEuapNCwUWBBkMLlFWrcvUazch1qXbTAUroUL1C4cjc3dt+GpWz9RKja5kCKzOa'
    'KaSkPMvSXFUu00VZYrQsZxmtyXSlLklFKa9xUGzaGzohVtgaq/npsvyQVa8uSaAYXdrdJYpBu8VE'
    'OSfCEXQHuQ/A/6WPWvqERf3onX1LQP0zKpMz4/AbRsdS3Q=='
)

# 538SD5Z27ECB03639_BMS0_2017-07-09.bin, first 0x400 bytes: a real BMS
# file, also Unknown Type (same magic-string gap), no VIN at either
# classic offset - the negative control every real BMS file in the file
# set confirms (0/2,797).
GENUINE_BMS_UNKNOWN_TYPE = (
    'eNpzcXUKdbdScHb0UwhKTU7NLMvMS1cIrsxLLmbYFPb3FnNcpAtERXB5ZklyBki2JF8hOb80Jz83'
    'CUTngTX4Oyvk5qek6oFYVgqmxqo6CmEIpqeVgq6RqZmBQa4jwyYR0d18cZEMSdMZGRgmATEQbOLg'
    '2AMS26T2F0S7INzk5x+C6S75v3tRVflk5mUreBYruOSX5zFsUkSWds0rSS1KTVHwTMlJVQguSSxJ'
    'ZdjEy3sIqOAc53nOr/83yTMfAXK6+Hr4FPTrflUwWVsBHcYMclUXX6b4JoO/N4HSYfk5JYnpqQqO'
    'yUX5xcUKzvl5JYnJJflFVgrGpmbmRrlhChr+2YmVmkC3MVeJxUW28LXzKWmDjVs0DWpcCx/IowLV'
    'QGlGIK0kCfKw4l8QjcetHBwgBYybVLApBKrJS0mqhKlV/auMqcY5I7EoHRx4EEWyyIqQAy+0AOR6'
    'FUmQ69v4lJXArp8JdD3ThAvMENcr/VVB1YsRNWp/VSUJR6DSXzUC5ohIgFQwggJPOJ2RQR6USERE'
    'UcR+gcSs/+5wRiRRYCrMT0tTAIZIfllqkYIpMOklpmSVFpcAwyGtKD9XwcJQFZR8LcxVQcZpuwOj'
    'YOVWRoa5GxgZhP7+/w8MbbAY0Bs67sSkQzRV6OkQSRp7OjQCKjgPS4fGQM5C/iX8WmazfFYzRF7a'
    'Ck04C/ndJIDp0NMdbzq0MDY0RUqH5n+9EZYHpRanlpSAXA50pYFCSmkqKBRSi4ryiwAF+0LH'
)

# 538XXCZ43JCC09678_MBB_2020-09-19.bin, first 0x400 bytes: genuinely
# classic MBB content by entry-type census (thousands of MBB-only ids,
# zero BMS-only ids, in the full file), but no VIN at any known offset,
# classic or Gen3 - has_classic_vin() correctly does not reach it. This
# is the honest limit of this fix's scope, not a bug; see the dated
# follow-up section in analysis/mbb_dispatch_fix.md.
NO_VIN_UNKNOWN_TYPE = (
    'eNqLDyktysvMS1fwd3NTcHF2cdZTcMtJTC+2UjCoMDBg2CT3lwEIXFydQt2tFIJSi1NLrBQC8stT'
    'i3T98xg2cZqAZBlZNnEaMIBZUAYj4yYXZI2++SmlOakKxckZqbmpCskZiXnpqSkKaUX5uQp++Xmp'
    'Crn5KakKJfkKzhmJRekg14AEgJYbM2CAOf///2dgsPkPl2XELsuhARbYpAJWxcTQNZ0RzSRDi/Qk'
    'A18nJ4Yrfl5nP4KFYPTspxYHRM7s2wWjFwKBV2megoKFgpGBkYGCgbmVkbGVoQnDqX27/kEwA4iG'
    '6b+46jaYTmLYt+uWkTfD/5kMDCvPyDI86+ViYPZBOOH/eQYGZiC9Wt8MzNdi6GDQA+pREYPIh/mn'
    'xcPUpqi/tf+96o39+n0MDCKSQC8B7Su3YGAQ90cyDw2gB16fMCQQVgujBgZCPSNYzxx1BoaHtsSb'
    'Ow9q3goC5qIDQubikkc3lxGuAtUeRUlIklCH6gXxv6z0fIQwcQEQvP71Z3k50OGawKgI9jI2NjSP'
    'cg0yMDQ0xOLi11iSgRGygkxTY4uICOcoE2MvZ2cDSzNzYBTFyzEs4WZY5RaBahZbLUN4O0OcG0Od'
    'N0O5EMPEKIYp39gZGbUY775jYmP8nsLwijGd8QTjFAeBVVMEp29imr2K4dkWhk//9YNZGb7/BDr+'
    'pgCfMcNyxU6GXwxmjPeAGnUZWxhFGbYx3GOIZAhi+AH000qGcwwvGeYlvIJYGXRAnRPMkGLsBFFc'
    'ACedNbw='
)


def _load_real_file(sample, filename):
    d = tempfile.mkdtemp(prefix='mbbdispatch')
    path = os.path.join(d, filename)
    with open(path, 'wb') as f:
        f.write(zlib.decompress(base64.b64decode(sample)))
    try:
        lf = LogFile(path)
        ld = LogData(lf)
        return lf, ld
    finally:
        os.unlink(path)
        os.rmdir(d)


def test_has_classic_vin_true_routes_real_unknown_type_file_to_mbb_decoder():
    lf, ld = _load_real_file(CLASSIC_VIN_UNKNOWN_TYPE, '0_538SM4Z25DCA03015_MBB_2020-08-02.bin')
    assert lf.log_type == LogFile.log_type_unknown
    assert lf.has_classic_vin is True
    hits = [e for e in ld._processed_entries if e.message_type == '0x10']
    assert hits
    assert hits[0].event == 'BMS Throt En Wire Disable'
    assert hits[0].structured_data == {'vpack_voltage_volts': 114.451, 'thr_en_voltage_volts': 0.003}


def test_has_classic_vin_false_keeps_real_bms_unknown_type_file_on_bms_decoder():
    lf, ld = _load_real_file(GENUINE_BMS_UNKNOWN_TYPE, '538SD5Z27ECB03639_BMS0_2017-07-09.bin')
    assert lf.log_type == LogFile.log_type_unknown
    assert lf.has_classic_vin is False
    hits = [e for e in ld._processed_entries if e.message_type == '0x10']
    assert hits
    assert hits[0].event == 'Exiting Hibernate'
    assert hits[0].structured_data is None


def test_has_classic_vin_false_for_known_mbb_content_with_no_recoverable_vin():
    # The honest scope limit, not a bug: this file's own entry-type
    # census (analysis/mbb_dispatch_fix.md) is overwhelmingly classic
    # MBB, but no VIN is recoverable at any known offset, so the narrow
    # VIN-based signal correctly declines to route it - closing this
    # gap needs the full entry-census approach the follow-up scoped as
    # a separate, larger piece of work, not this fix.
    lf, ld = _load_real_file(NO_VIN_UNKNOWN_TYPE, '538XXCZ43JCC09678_MBB_2020-09-19.bin')
    assert lf.log_type == LogFile.log_type_unknown
    assert lf.has_classic_vin is False


def test_has_classic_vin_false_for_short_buffer():
    # Guarded by size the same way get_version_and_header()'s own
    # _legacy_vin_present() is: a buffer too short for the 0x252 offset
    # must not raise, just report no VIN.
    d = tempfile.mkdtemp(prefix='mbbdispatch')
    path = os.path.join(d, 'tiny.bin')
    try:
        with open(path, 'wb') as f:
            f.write(bytes(64))
        tiny = LogFile(path)
        assert tiny.has_classic_vin is False
    finally:
        os.unlink(path)
        os.rmdir(d)
