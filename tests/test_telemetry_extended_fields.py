"""
Tests for the fields entry types 0x51 / 0x52 / 0x53 share beyond SOC, pack
voltage and battery current (Gen2.telemetry_extended_fields()): DC bus
voltage/current, motor RPM, five temperatures, two validity flags, and the
variant-dependent tail (12 V DC-DC voltage, distance counter, speed, range
estimate). Everything is addressed relative to the start of the 4-byte state
tag; evidence in analysis/gen3_page_claims.md.

Same conventions as the other files in this directory: plain test_* functions,
stdlib only, synthetic in-process buffers, no dataset files checked in.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

TAG = {0x51: 35, 0x52: 39, 0x53: 43}
TAIL_LONG = {'aux': 29, 'counter': 35, 'speed': 39, 'range': 43}
TAIL_SHORT = {'counter': 31, 'speed': 35, 'range': 39}


def _decode(message_type, payload):
    if message_type == 0x51:
        return Gen2.vehicle_state_telemetry(payload)
    return Gen2.vehicle_state_telemetry_tier(message_type, payload)


def _payload(message_type, length, state=b'RUN\x00', flags=0, dc_bus_mv=105300, dc_bus_ma=30200,
             rpm=2932, ambient_c100=1250, temps=(42, 19, 16, 15), aux_uv=13101776,
             counter=62684, speed_quotient=3942, range_raw=8069):
    tag = TAG[message_type]
    buf = bytearray(length)
    struct.pack_into('<I', buf, 0, 76000)
    buf[4] = 0x30
    buf[5] = 0xf9
    buf[tag:tag + 4] = state
    buf[tag - 25] = flags
    buf[tag - 21:tag - 18] = dc_bus_mv.to_bytes(3, 'little')
    struct.pack_into('<i', buf, tag - 17, dc_bus_ma)
    struct.pack_into('<H', buf, tag - 13, rpm)
    struct.pack_into('<h', buf, tag + 9, ambient_c100)
    for rel, value in zip((13, 17, 21, 25), temps):
        buf[tag + rel] = value
    buf[tag - 9] = 64
    struct.pack_into('<I', buf, tag - 8, 105144)
    struct.pack_into('<i', buf, tag - 4, 12273)
    tail = {}
    if (message_type, length) in ((0x52, 85), (0x53, 99), (0x51, 68)):
        tail['aux'] = 29
    if message_type in (0x52, 0x53) and length in (85, 99):
        tail.update(TAIL_LONG)
    elif message_type in (0x52, 0x53) and length in (81, 95):
        tail.update(TAIL_SHORT)
    if 'aux' in tail:
        buf[tag + 29:tag + 32] = aux_uv.to_bytes(3, 'little')
    if 'counter' in tail:
        buf[tag + tail['counter']:tag + tail['counter'] + 3] = counter.to_bytes(3, 'little')
        struct.pack_into('<I', buf, tag + tail['speed'], speed_quotient * 18750)
        struct.pack_into('<H', buf, tag + tail['range'], range_raw)
    return buf


def test_pre_tag_and_temperature_fields_decode_on_every_variant():
    for message_type, length in ((0x51, 64), (0x51, 68), (0x52, 81), (0x52, 85),
                                 (0x53, 95), (0x53, 99)):
        sd = _decode(message_type, _payload(message_type, length))['structured_data']
        assert sd['motor_controller_data_valid'] is True
        assert sd['bms_data_valid'] is True
        assert sd['dc_bus_voltage_volts'] == 105.3
        assert sd['dc_bus_current_amps'] == 30.2
        assert sd['motor_rpm'] == 2932
        assert sd['ambient_temperature_c'] == 12.5
        assert sd['motor_temperature_c'] == 42
        assert sd['controller_temperature_c'] == 19
        assert sd['pack_temperature_warmest_c'] == 16
        assert sd['pack_temperature_coldest_c'] == 15


def test_dc_bus_current_and_ambient_temperature_are_signed():
    sd = _decode(0x52, _payload(0x52, 85, dc_bus_ma=-13100, ambient_c100=-98))['structured_data']
    assert sd['dc_bus_current_amps'] == -13.1
    assert sd['ambient_temperature_c'] == -0.98


def test_long_variants_carry_dc_dc_voltage_and_the_full_tail():
    for message_type, length in ((0x52, 85), (0x53, 99)):
        sd = _decode(message_type, _payload(message_type, length))['structured_data']
        assert sd['dc_dc_bus_voltage_volts'] == 13.101776
        assert sd['distance_counter_raw'] == 62684
        assert sd['speed_raw'] == 3942
        assert sd['range_estimate_raw'] == 8069


def test_0x51_long_variant_carries_only_the_dc_dc_voltage():
    sd = _decode(0x51, _payload(0x51, 68))['structured_data']
    assert sd['dc_dc_bus_voltage_volts'] == 13.101776
    for key in ('distance_counter_raw', 'speed_raw', 'range_estimate_raw'):
        assert key not in sd


def test_short_variants_read_the_tail_four_bytes_earlier_and_have_no_dc_dc_voltage():
    for message_type, length in ((0x52, 81), (0x53, 95)):
        sd = _decode(message_type, _payload(message_type, length))['structured_data']
        assert 'dc_dc_bus_voltage_volts' not in sd
        assert sd['distance_counter_raw'] == 62684
        assert sd['speed_raw'] == 3942
        assert sd['range_estimate_raw'] == 8069


def test_variants_without_a_mapped_tail_carry_no_tail_fields():
    sd = _decode(0x51, _payload(0x51, 64))['structured_data']
    for key in ('dc_dc_bus_voltage_volts', 'distance_counter_raw', 'speed_raw', 'range_estimate_raw'):
        assert key not in sd
    sd = _decode(0x53, _payload(0x53, 93))['structured_data']
    for key in ('dc_dc_bus_voltage_volts', 'distance_counter_raw', 'speed_raw', 'range_estimate_raw'):
        assert key not in sd


def test_controller_flag_turns_controller_side_fields_into_none():
    for flags in (0x0a, 0x14, 0x1e):
        sd = _decode(0x52, _payload(0x52, 85, flags=flags, dc_bus_mv=0, dc_bus_ma=0, rpm=0,
                                    temps=(0, 0, 16, 15), speed_quotient=0))['structured_data']
        assert sd['motor_controller_data_valid'] is False
        assert sd['bms_data_valid'] is True
        for key in ('dc_bus_voltage_volts', 'dc_bus_current_amps', 'motor_rpm',
                    'motor_temperature_c', 'controller_temperature_c', 'speed_raw'):
            assert sd[key] is None
        # the pack-side temperatures and the ambient temperature are not in this group
        assert sd['pack_temperature_warmest_c'] == 16
        assert sd['ambient_temperature_c'] == 12.5


def test_bms_flag_sets_its_validity_indicator_but_leaves_shipped_pack_fields_alone():
    for flags in (0x60, 0xc0, 0xe0):
        sd = _decode(0x51, _payload(0x51, 64, flags=flags))['structured_data']
        assert sd['bms_data_valid'] is False
        assert sd['motor_controller_data_valid'] is True
        assert sd['pack_voltage_volts'] == 105.144        # unchanged shipped behaviour
        assert sd['battery_current_amps'] == 12.273


def test_both_flags_set_together_and_neither():
    sd = _decode(0x53, _payload(0x53, 99, flags=0x6a))['structured_data']
    assert sd['motor_controller_data_valid'] is False and sd['bms_data_valid'] is False
    sd = _decode(0x53, _payload(0x53, 99, flags=0))['structured_data']
    assert sd['motor_controller_data_valid'] is True and sd['bms_data_valid'] is True


def test_speed_that_is_not_an_exact_multiple_of_18750_is_none():
    payload = _payload(0x52, 85)
    struct.pack_into('<I', payload, TAG[0x52] + 39, 4294967295)
    assert _decode(0x52, payload)['structured_data']['speed_raw'] is None


def test_zero_rpm_with_a_valid_controller_group_stays_zero_not_none():
    sd = _decode(0x52, _payload(0x52, 85, rpm=0, speed_quotient=0))['structured_data']
    assert sd['motor_rpm'] == 0
    assert sd['speed_raw'] == 0


def test_conditions_strings_carry_the_new_fields():
    cond = _decode(0x52, _payload(0x52, 85))['conditions']
    for text in ('Vdc:105.3V', 'Idc:30.2A', 'RPM:2932', 'Tamb:12.50C', 'Tmotor:42C', 'Tctrl:19C',
                 'Tpack:16/15C', 'Vdcdc:13.10V', 'Counter(raw):62684', 'Speed(raw):3942',
                 'Range(raw):8069', 'Valid(ctrl/bms):1/1'):
        assert text in cond
    cond = _decode(0x51, _payload(0x51, 64, flags=0x0a))['conditions']
    assert 'Vdc:n/a' in cond and 'RPM:n/a' in cond and 'Valid(ctrl/bms):0/1' in cond
    assert 'Temp1:' in cond   # the shipped 0x51 fields are still there


def test_shipped_0x51_temperature_keys_are_unchanged():
    sd = _decode(0x51, _payload(0x51, 64))['structured_data']
    assert (sd['temperature_1_celsius'], sd['temperature_4_celsius']) == (42, 15)
