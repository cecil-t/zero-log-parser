"""Tests for Gen3 records the decoders used to decline (analysis/gen3_declined.md):
0x4B/0x4C/0x4D cell telemetry damaged by the page marker, decoded with the
covered fields withheld. Synthetic buffers through Gen2.collect_paged_bms_entries,
the same way test_marker_field_corruption.py builds them; all values invented."""

import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

MARK = b'\x00\xf0\xff\x00'
LOGGER = logging.getLogger('test_gen3_declined')
T = 1_700_000_000


def _entry(message_type, timestamp, payload):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def _cell_payload(length=43, shift=0, subsecond_us=432_000, sequence=17, prefix_marker=0xf9,
                  low=3811, unloaded=0, high=3829, soc=63, current_ma=-4321, pack_mv=104_567):
    """A valid BMS cell telemetry payload (0x4B 43/45, 0x4C 61/63 with shift 4,
    0x4D 69/71 with shift 8), every decoded field at a distinct value."""
    p = bytearray(length)
    struct.pack_into('<I', p, 0, subsecond_us)
    p[4], p[5] = sequence, prefix_marker
    b = 14 + shift
    struct.pack_into('<HHH', p, b, low, unloaded, high)
    p[b + 6] = soc
    struct.pack_into('<i', p, b + 7, current_ma)
    p[b + 11] = 31                       # BMS temperature
    p[b + 24] = 7                        # report mode
    if b + 28 <= length:
        p[b + 25:b + 28] = pack_mv.to_bytes(3, 'little')
    return p


def _decode_one(buf):
    collected = Gen2.collect_paged_bms_entries(bytes(buf), LOGGER)
    assert len(collected) == 1
    return collected[0][1]


def _assert_cells(sd, pack=True):
    assert sd['voltage_low_cell_volts'] == 3.811
    assert sd['voltage_high_cell_volts'] == 3.829
    assert sd['state_of_charge_percent'] == 63
    assert sd['battery_current_amps'] == -4.321
    assert sd['bms_temperature_c'] == 31
    if pack:
        assert sd['pack_voltage_volts'] == 104.567


# --- Step 1: marker over the sub-second prefix ---

def test_marker_at_each_prefix_position_is_decoded_with_the_prefix_fields_withheld():
    expected = {0: ['subsecond_us'], 1: ['sequence', 'subsecond_us'], 2: ['marker', 'sequence', 'subsecond_us']}
    for pos, withheld in expected.items():
        payload = _cell_payload()
        payload[pos:pos + 4] = MARK
        entry = _decode_one(_entry(0x4b, T, payload))
        sd = entry['structured_data']
        assert entry['event'] == 'BMS Cell Telemetry', pos
        assert sd['corrupted_fields'] == withheld, pos
        for name in withheld:
            assert sd[name] is None
        for name in {'subsecond_us', 'sequence', 'marker'} - set(withheld):
            assert sd[name] is not None
        _assert_cells(sd)
        assert sd['raw_hex'] == bytes(payload).hex()     # the bytes as they are in the file


def test_marker_over_the_prefix_of_a_0x4d_record():
    payload = _cell_payload(length=69, shift=8)
    payload[1:5] = MARK
    sd = _decode_one(_entry(0x4d, T, payload))['structured_data']
    assert sd['corrupted_fields'] == ['sequence', 'subsecond_us']
    _assert_cells(sd)


def test_out_of_range_sub_second_without_a_marker_stays_declined():
    payload = _cell_payload(subsecond_us=3_000_000)
    entry = _decode_one(_entry(0x4b, T, payload))
    assert entry.get('structured_data') is None
    assert entry['conditions'].startswith('Raw data: ')
