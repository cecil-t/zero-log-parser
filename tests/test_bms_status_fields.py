"""
Tests for the BMS-side fields added to Gen2.bms_cell_telemetry() beyond the
cell-voltage block: sleep indicator, report mode, temperature bytes, load
and bus flags, hottest/coldest cell temperature, full-charge capacity and its
twin, charge current limit and the 0x4B fault-flag bytes. Evidence:
analysis/bms_fields_and_text_events.md. Offsets are payload offsets of the
0x4B shape; 0x4C adds 4 and 0x4D adds 8.

Same conventions as the other files in this directory: plain test_*
functions, stdlib only, synthetic in-process buffers, no dataset files.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

SHIFT = {0x4b: 0, 0x4c: 4, 0x4d: 8}
VARIANTS = [(0x4b, 43), (0x4b, 45), (0x4c, 61), (0x4c, 63), (0x4d, 69), (0x4d, 71)]
LONG = {(0x4b, 45), (0x4c, 63), (0x4d, 71)}


def _payload(message_type, length, **bytes_at):
    """A valid payload (sub-second 123000, sequence 5, marker 1) with every
    other byte a harmless 1; bytes_at maps 0x4B-shape payload offsets to byte
    values (shifted for the tier)."""
    buf = bytearray([1]) * length
    struct.pack_into('<I', buf, 0, 123000)
    buf[4] = 5
    for name, value in bytes_at.items():
        buf[int(name[1:]) + SHIFT[message_type]] = value
    return buf


def _decode(message_type, payload):
    return Gen2.bms_cell_telemetry(message_type, payload)


def test_sleep_indicator_and_boolean_on_every_variant():
    for message_type, length in VARIANTS:
        for raw, expected in ((0x00, False), (0x20, True), (0x40, None), (0x60, None)):
            sd = _decode(message_type, _payload(message_type, length, p10=raw))['structured_data']
            assert sd['bms_sleep_indicator'] == raw
            assert sd['bms_sleeping'] is expected
        sd = _decode(message_type, _payload(message_type, length, p10=0xff))['structured_data']
        assert sd['bms_sleep_indicator'] is None and sd['bms_sleeping'] is None


def test_report_mode_labels_only_the_confirmed_value():
    for message_type, length in VARIANTS:
        sd = _decode(message_type, _payload(message_type, length, p38=7))['structured_data']
        assert sd['bms_report_mode'] == 7 and sd['bms_report_mode_label'] == 'active'
        for raw in (1, 2, 3, 4, 5, 6):
            sd = _decode(message_type, _payload(message_type, length, p38=raw))['structured_data']
            assert sd['bms_report_mode'] == raw and sd['bms_report_mode_label'] is None
        sd = _decode(message_type, _payload(message_type, length, p38=0xf0))['structured_data']
        assert sd['bms_report_mode'] is None


def test_bms_temperature_byte_at_payload_25():
    for message_type, length in VARIANTS:
        sd = _decode(message_type, _payload(message_type, length, p25=21))['structured_data']
        assert sd['bms_temperature_c'] == 21
        sd = _decode(message_type, _payload(message_type, length, p25=0xff))['structured_data']
        assert sd['bms_temperature_c'] is None


def test_load_and_bus_flags_only_on_the_newer_layout():
    for message_type, length in VARIANTS:
        sd = _decode(message_type, _payload(message_type, length, p28=0xff, p29=1))['structured_data']
        if (message_type, length) in LONG:
            assert sd['bms_load_flag'] == 0xff and sd['bms_bus_engaged'] is True
            sd = _decode(message_type, _payload(message_type, length, p28=0x78, p29=0))['structured_data']
            assert sd['bms_load_flag'] == 0x78 and sd['bms_bus_engaged'] is False
            sd = _decode(message_type, _payload(message_type, length, p29=2))['structured_data']
            assert sd['bms_bus_engaged'] is None
            sd = _decode(message_type, _payload(message_type, length, p28=0xf0, p29=0xf0))['structured_data']
            assert sd['bms_load_flag'] is None and sd['bms_bus_engaged'] is None
        else:
            assert 'bms_load_flag' not in sd and 'bms_bus_engaged' not in sd


def test_cell_temperatures_at_the_variant_offsets_and_not_on_0x4b():
    offsets = Gen2.BMS_CELL_TEMPERATURE_OFFSETS
    assert set(offsets) == {(0x4c, 61), (0x4c, 63), (0x4d, 69), (0x4d, 71)}
    for (message_type, length), (cold_at, hot_at) in offsets.items():
        payload = bytearray([1]) * length
        struct.pack_into('<I', payload, 0, 123000)
        payload[cold_at], payload[hot_at] = 17, 23
        sd = _decode(message_type, payload)['structured_data']
        assert sd['cell_temperature_coldest_c'] == 17 and sd['cell_temperature_hottest_c'] == 23
    for length in (43, 45):
        sd = _decode(0x4b, _payload(0x4b, length))['structured_data']
        assert 'cell_temperature_hottest_c' not in sd


def test_full_charge_capacity_register_and_twin_on_0x4d():
    for (message_type, length), (a, b) in Gen2.BMS_CAPACITY_OFFSETS.items():
        payload = bytearray([1]) * length
        struct.pack_into('<I', payload, 0, 123000)
        payload[a:a + 3] = (140344).to_bytes(3, 'little')
        payload[b:b + 3] = (140283).to_bytes(3, 'little')
        sd = _decode(message_type, payload)['structured_data']
        assert sd['full_charge_capacity_ah'] == 140.344
        assert sd['full_charge_capacity_twin_ah'] == 140.283
        payload[a:a + 3] = b'\xf0\xf0\xf0'
        payload[b:b + 3] = b'\xff\xff\xff'
        sd = _decode(message_type, payload)['structured_data']
        assert sd['full_charge_capacity_ah'] is None and sd['full_charge_capacity_twin_ah'] is None
    assert set(Gen2.BMS_CAPACITY_OFFSETS) == {(0x4d, 69), (0x4d, 71)}
    sd = _decode(0x4b, _payload(0x4b, 45))['structured_data']
    assert 'full_charge_capacity_ah' not in sd


def test_charge_current_limit_u16_with_sentinels_as_none():
    for (message_type, length), at in Gen2.BMS_CHARGE_LIMIT_OFFSETS.items():
        payload = bytearray([1]) * length
        struct.pack_into('<I', payload, 0, 123000)
        struct.pack_into('<H', payload, at, 150)
        assert _decode(message_type, payload)['structured_data']['bms_charge_current_limit_amps'] == 150
        struct.pack_into('<H', payload, at, 0xfff0)
        assert _decode(message_type, payload)['structured_data']['bms_charge_current_limit_amps'] is None
    assert 'bms_charge_current_limit_amps' not in _decode(0x4b, _payload(0x4b, 45))['structured_data']


def test_fault_flag_bytes_on_0x4b_only():
    sd = _decode(0x4b, _payload(0x4b, 43, p11=4, p30=0x60))['structured_data']
    assert sd['pack_fault_flags_a'] == 4 and sd['pack_fault_flags_b'] == 0x60
    sd = _decode(0x4b, _payload(0x4b, 43, p11=0xf0, p30=0xff))['structured_data']
    assert sd['pack_fault_flags_a'] is None and sd['pack_fault_flags_b'] is None
    for message_type, length in ((0x4c, 61), (0x4d, 69)):
        sd = _decode(message_type, _payload(message_type, length))['structured_data']
        assert 'pack_fault_flags_a' not in sd


def test_conditions_gain_a_status_fragment_and_cell_voltage_fields_are_unchanged():
    out = _decode(0x4d, _payload(0x4d, 71, p38=7))
    assert 'Mode:7' in out['conditions'] and out['conditions'].startswith('SOC:')
    assert 'voltage_low_cell_volts' in out['structured_data']
    assert 'raw_hex' in out['structured_data']
