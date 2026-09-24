"""
Tests for entry types 0x4B / 0x4C / 0x4D ("BMS Cell Telemetry") in
Gen2.bms_cell_telemetry(): the BMS-side record family that shares these
three type codes with the MBB-side "State Snapshot" family
(Gen2.state_snapshot) but is a different, disjoint layout (43/45, 61/63,
69/71 payload bytes vs. 46/77/89) - confirmed real and distinct in
analysis/bms_fst_type_family_recheck.md, then reversed and confirmed at
full population scale from an external lead in
analysis/bms_fst_offset_shift_test.md.

Same conventions as the sibling test files in this directory: plain
test_* functions, stdlib only, synthetic in-process buffers, no dataset
files checked in. Filler bytes avoid 0xB2 and 0xFE (the entry header and
escape bytes) so the same payload can be wrapped in a raw entry for the
parse_entry() test.
"""

import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

TIERS = {
    0x4b: (0, (43, 45)),
    0x4c: (4, (61, 63)),
    0x4d: (8, (69, 71)),
}
FIELD_BASE = Gen2.BMS_CELL_TELEMETRY_FIELD_BASE


def _payload(message_type, length=None, subsecond=123000, prefix=0x02e6,
             voltage_low=3700, voltage_unloaded=3750, voltage_high=3720,
             soc=85, current_ma=-1500, pack_voltage_mv=103_800, temp_c=22):
    shift, valid_lengths = TIERS[message_type]
    if length is None:
        length = valid_lengths[-1]  # the longer variant, carries every field
    base = FIELD_BASE + shift
    buf = bytearray((i % 100) + 1 for i in range(length))
    struct.pack_into('<I', buf, 0, subsecond)
    struct.pack_into('<H', buf, 4, prefix)
    if base + 0 + 2 <= length:
        struct.pack_into('<H', buf, base + 0, voltage_low)
    if base + 2 + 2 <= length:
        struct.pack_into('<H', buf, base + 2, voltage_unloaded)
    if base + 4 + 2 <= length:
        struct.pack_into('<H', buf, base + 4, voltage_high)
    if base + 6 + 1 <= length:
        buf[base + 6] = soc
    if base + 7 + 2 <= length:
        struct.pack_into('<h', buf, base + 7, current_ma)
    if base + 25 + 3 <= length:
        pv_bytes = pack_voltage_mv.to_bytes(3, 'little')
        buf[base + 25:base + 28] = pv_bytes
    if base + 30 + 1 <= length:
        buf[base + 30] = temp_c & 0xff
    return buf


def test_each_tier_decodes_the_core_fields():
    for message_type in TIERS:
        out = Gen2.bms_cell_telemetry(message_type, _payload(message_type))
        assert out['event'] == 'BMS Cell Telemetry'
        sd = out['structured_data']
        assert sd['voltage_low_cell_volts'] == 3.700
        assert sd['voltage_unloaded_cell_volts'] == 3.750
        assert sd['voltage_high_cell_volts'] == 3.720
        assert sd['state_of_charge_percent'] == 85
        assert sd['battery_current_amps'] == -1.500
        assert sd['pack_voltage_volts'] == 103.800


def test_negative_current_means_charging_by_sign():
    out = Gen2.bms_cell_telemetry(0x4b, _payload(0x4b, current_ma=-2500))
    assert out['structured_data']['battery_current_amps'] == -2.500
    out = Gen2.bms_cell_telemetry(0x4b, _payload(0x4b, current_ma=1800))
    assert out['structured_data']['battery_current_amps'] == 1.800


def test_short_0x4b_variant_omits_temperature():
    # The 43-byte 0x4B variant is too short to hold the temperature byte
    # (which needs offset 44); the 45-byte variant holds it.
    short = Gen2.bms_cell_telemetry(0x4b, _payload(0x4b, length=43))
    assert 'bms_temp_celsius' not in short['structured_data']
    long = Gen2.bms_cell_telemetry(0x4b, _payload(0x4b, length=45))
    assert long['structured_data']['bms_temp_celsius'] == 22


def test_0x4c_and_0x4d_always_include_temperature():
    for message_type, (shift, lengths) in TIERS.items():
        if message_type == 0x4b:
            continue
        for length in lengths:
            out = Gen2.bms_cell_telemetry(message_type, _payload(message_type, length=length))
            assert 'bms_temp_celsius' in out['structured_data'], (message_type, length)


def test_raw_hex_preserves_the_whole_payload():
    for message_type in TIERS:
        payload = _payload(message_type)
        sd = Gen2.bms_cell_telemetry(message_type, payload)['structured_data']
        assert bytes.fromhex(sd['raw_hex']) == bytes(payload)


def test_wrong_length_falls_back_to_raw_hex():
    cases = [(0x4b, 44), (0x4b, 46), (0x4b, 61), (0x4c, 60), (0x4c, 69), (0x4d, 63), (0x4d, 68)]
    for message_type, length in cases:
        out = Gen2.bms_cell_telemetry(message_type, _payload(message_type, length=length))
        assert 'structured_data' not in out, (message_type, length)
        assert out['conditions'].startswith('Raw data:')


def test_empty_payload_does_not_raise():
    out = Gen2.bms_cell_telemetry(0x4b, bytearray())
    assert out['event'] == 'Unknown Type 75'
    assert out['conditions'] == 'No additional data'


def test_implausible_subsecond_value_falls_back_to_raw_hex():
    assert 'structured_data' in Gen2.bms_cell_telemetry(0x4b, _payload(0x4b, subsecond=1000000))
    for value in (1000001, 0x7fffffff, 0xffffffff):
        out = Gen2.bms_cell_telemetry(0x4b, _payload(0x4b, subsecond=value))
        assert 'structured_data' not in out, value


def test_state_snapshot_dispatch_prefers_mbb_shape_then_falls_through():
    # A real MBB State Snapshot payload (46 bytes, valid tag) must still
    # decode exactly as before - state_snapshot_dispatch must not change
    # its output at all.
    mbb_payload = bytearray((i % 100) + 1 for i in range(46))
    struct.pack_into('<I', mbb_payload, 0, 123000)
    mbb_payload[35:39] = b'RUN\x00'
    direct = Gen2.state_snapshot(0x4b, mbb_payload)
    dispatched = Gen2.state_snapshot_dispatch(0x4b, mbb_payload)
    assert direct == dispatched
    assert dispatched['event'] == 'State Snapshot'

    # A BMS-shaped payload (43/45/61/63/69/71) must reach the new decoder.
    for message_type in TIERS:
        bms_payload = _payload(message_type)
        out = Gen2.state_snapshot_dispatch(message_type, bms_payload)
        assert out['event'] == 'BMS Cell Telemetry'

    # Anything matching neither shape still falls back exactly as before.
    out = Gen2.state_snapshot_dispatch(0x4b, bytearray(b'\x01\x02\x03'))
    assert out['event'] == 'Unknown Type 75'


def test_parse_entry_dispatches_all_three_types_end_to_end():
    logger = logging.getLogger('test_bms_cell_telemetry_decode')
    for message_type in TIERS:
        payload = _payload(message_type)
        timestamp = 1_600_000_000
        body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
        raw = bytearray([0xb2, len(body) + 2]) + bytearray(body)
        length, entry, _unhandled = Gen2.parse_entry(raw, 0, 0, logger)
        assert length == len(raw)
        assert entry['event'] == 'BMS Cell Telemetry'
        assert entry['message_type'] == '0x%X' % message_type
        assert entry['structured_data']['state_of_charge_percent'] == 85
