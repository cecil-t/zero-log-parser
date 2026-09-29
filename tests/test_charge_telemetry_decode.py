"""
Tests for entry type 0x49 ("Charging Telemetry") in Gen2.charge_telemetry():
a fixed 31-byte payload emitted with every CHRG-state 0x52/0x4C entry.
Layout: the shared 6-byte prefix, u32 constant at 6, u16 measurement at 10,
15 undecoded bytes at 12-26 (kept in raw_hex), u32 constant at 27.

Same conventions as the other files in this directory: plain test_*
functions, stdlib only, synthetic in-process buffers built from the layout
documented in analysis/type_0x49.md, no dataset files checked in. The
payload defaults are a real entry from the corpus.
"""

import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

REAL = bytes.fromhex('b0fa09009102' '60cb0100' '7300' '5a05000c0000000000000000000106' '109e0100')


def _payload(subsecond=0x09fab0, const_a=117600, measurement=115, const_b=106000, tail=None):
    buf = bytearray(REAL)
    struct.pack_into('<IBB', buf, 0, subsecond, 0x91, 0x02)
    struct.pack_into('<I', buf, 6, const_a)
    struct.pack_into('<H', buf, 10, measurement)
    struct.pack_into('<I', buf, 27, const_b)
    if tail is not None:
        buf[12:27] = tail
    return buf


def test_fields_decode_from_their_offsets():
    out = Gen2.charge_telemetry(_payload())
    assert out['event'] == 'Charging Telemetry'
    sd = out['structured_data']
    assert sd['subsecond_us'] == 0x09fab0
    assert sd['sequence'] == 0x91
    assert sd['marker'] == 0x02
    assert sd['constant_a'] == 117600
    assert sd['measurement_a'] == 115
    assert sd['constant_b'] == 106000


def test_undecoded_bytes_are_kept_in_raw_hex():
    tail = bytes(range(1, 16))
    sd = Gen2.charge_telemetry(_payload(tail=tail))['structured_data']
    assert sd['raw_hex'] == tail.hex()


def test_measurement_is_sixteen_bit():
    # Newer-platform files carry values above 255 (byte 11 = 0x01).
    sd = Gen2.charge_telemetry(_payload(measurement=0x0127))['structured_data']
    assert sd['measurement_a'] == 295


def test_older_firmware_constant_a_is_not_rejected():
    assert Gen2.charge_telemetry(_payload(const_a=117400))['structured_data']['constant_a'] == 117400


def test_wrong_length_falls_back_to_raw_hex():
    # Real non-FST 0x49 entries seen in legacy files: 0, 1, 17, 24, 85, 146, 246 bytes.
    for n in (0, 1, 24, 30, 32, 85):
        out = Gen2.charge_telemetry(bytearray(n))
        assert 'structured_data' not in out, n
        assert out['event'] == 'Unknown Type 73'


def test_implausible_subsecond_value_falls_back_to_raw_hex():
    assert 'structured_data' in Gen2.charge_telemetry(_payload(subsecond=1000000))
    for value in (1000001, 0xc2a8c367, 0xffffffff):
        assert 'structured_data' not in Gen2.charge_telemetry(_payload(subsecond=value)), value


def test_parse_entry_dispatches_end_to_end():
    logger = logging.getLogger('test_charge_telemetry_decode')
    body = bytes([0x49]) + struct.pack('<I', 1_560_970_273) + bytes(_payload())
    raw = bytearray([0xb2, len(body) + 2]) + bytearray(body)
    length, entry, _unhandled = Gen2.parse_entry(raw, 0, 0, logger)
    assert length == len(raw)
    assert entry['event'] == 'Charging Telemetry'
    assert entry['message_type'] == '0x49'
    assert entry['structured_data']['constant_b'] == 106000
