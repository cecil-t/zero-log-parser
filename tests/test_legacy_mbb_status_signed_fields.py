"""
Regression tests for the signedness of classic (REV0/REV1) MBB status
fields (analysis/legacy_mbb_disarmed_current.md).

The MBB firmware renders Riding (0x2c) and Disarmed (0x3c) with the same
template and the same payload reads, so the two decoders must agree on
every shared field. Battery current at 0x10 is a signed 16-bit value.

All payloads here are invented: they are built field by field to the
33-byte layout, so each value under test is known exactly.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2


def _status_payload(pack_hi=20, pack_lo=18, soc=64, mv=104500, motor_temp=25, ctrl_temp=22, rpm=0,
                    batt_amps=0, mods=0x03, motor_amps=0, ambient=15, odo=12345):
    """33-byte Riding/Disarmed payload, little-endian, at the firmware's offsets."""
    p = bytearray(33)
    struct.pack_into('<b', p, 0x00, pack_hi)
    struct.pack_into('<b', p, 0x01, pack_lo)
    struct.pack_into('<H', p, 0x02, soc)
    struct.pack_into('<I', p, 0x04, mv)
    struct.pack_into('<h', p, 0x08, motor_temp)
    struct.pack_into('<h', p, 0x0a, ctrl_temp)
    struct.pack_into('<H', p, 0x0c, rpm)
    struct.pack_into('<h', p, 0x10, batt_amps)
    struct.pack_into('<B', p, 0x12, mods)
    struct.pack_into('<h', p, 0x13, motor_amps)
    struct.pack_into('<h', p, 0x15, ambient)
    struct.pack_into('<I', p, 0x17, odo)
    return p


def _decode(message_type, payload):
    return Gen2._entry_parsers()[message_type](payload)


def test_disarmed_negative_battery_current():
    # A parked bike on the charger: -15 A (bytes f1 ff).
    out = _decode(0x3c, _status_payload(batt_amps=-15))
    assert out['event'] == 'Disarmed'
    assert out['structured_data']['battery_current_amps'] == -15
    assert 'BattAmps: -15,' in out['conditions']


def test_disarmed_minus_one_amp_is_not_255():
    # ff ff: the value the uint8 read showed as 255 A.
    out = _decode(0x3c, _status_payload(batt_amps=-1))
    assert out['structured_data']['battery_current_amps'] == -1


def test_disarmed_current_beyond_one_byte():
    # Outside the int8 range: only a 16-bit read gets it right.
    assert _decode(0x3c, _status_payload(batt_amps=-200))['structured_data']['battery_current_amps'] == -200
    assert _decode(0x3c, _status_payload(batt_amps=300))['structured_data']['battery_current_amps'] == 300


def test_disarmed_positive_current_unchanged():
    out = _decode(0x3c, _status_payload(batt_amps=7))
    assert out['structured_data']['battery_current_amps'] == 7


def test_disarmed_and_riding_agree_on_battery_current():
    for amps in (-128, -67, -1, 0, 1, 127, 128, 255):
        payload = _status_payload(batt_amps=amps, rpm=0)
        assert _decode(0x3c, payload)['structured_data']['battery_current_amps'] == amps
        assert _decode(0x2c, payload)['structured_data']['battery_current_amps'] == amps


def test_disarmed_other_fields_unchanged():
    sd = _decode(0x3c, _status_payload(batt_amps=-15))['structured_data']
    assert sd['state_of_charge_percent'] == 64
    assert sd['pack_voltage_volts'] == 104.5
    assert sd['motor_rpm'] == 0
    assert sd['ambient_temp_celsius'] == 15
    assert sd['odometer_km'] == 12345


def _charging_payload(pack_hi=20, pack_lo=18, soc=64, mv=104500, batt_amps=-12, mods=0x03, ambient=15):
    """15-byte Charging payload at the firmware's offsets."""
    p = bytearray(15)
    struct.pack_into('<b', p, 0x00, pack_hi)
    struct.pack_into('<b', p, 0x01, pack_lo)
    struct.pack_into('<H', p, 0x02, soc)
    struct.pack_into('<I', p, 0x04, mv)
    struct.pack_into('<h', p, 0x08, batt_amps)
    struct.pack_into('<B', p, 0x0c, mods)
    struct.pack_into('<h', p, 0x0d, ambient)
    return p


def test_pack_temps_below_freezing():
    # -4 C high, -8 C low (bytes fc f8): the uint8 read showed 252 C and 248 C.
    for message_type in (0x2c, 0x3c):
        sd = _decode(message_type, _status_payload(pack_hi=-4, pack_lo=-8))['structured_data']
        assert (sd['pack_temp_high_celsius'], sd['pack_temp_low_celsius']) == (-4, -8)
    sd = _decode(0x2d, _charging_payload(pack_hi=-4, pack_lo=-8))['structured_data']
    assert (sd['pack_temp_high_celsius'], sd['pack_temp_low_celsius']) == (-4, -8)


def test_pack_temp_invalid_thermistor_value():
    # -100 C (byte 9c), the firmware's invalid-thermistor value, kept as-is (was 156 C).
    out = _decode(0x3c, _status_payload(pack_hi=-100, pack_lo=-100))
    assert out['structured_data']['pack_temp_high_celsius'] == -100
    assert 'PackTemp: h -100C, l -100C' in out['conditions']


def test_pack_temps_above_freezing_unchanged():
    for message_type in (0x2c, 0x3c):
        sd = _decode(message_type, _status_payload(pack_hi=35, pack_lo=31))['structured_data']
        assert (sd['pack_temp_high_celsius'], sd['pack_temp_low_celsius']) == (35, 31)
    sd = _decode(0x2d, _charging_payload(pack_hi=35, pack_lo=31))['structured_data']
    assert (sd['pack_temp_high_celsius'], sd['pack_temp_low_celsius']) == (35, 31)
    assert sd['battery_current_amps'] == -12
