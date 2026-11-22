"""
Fields that lie past the end of a short legacy record decode as None, not as
the zero that BinaryTools.unpack()'s padding would give. A record that holds
every field decodes exactly as before. All payloads are invented.
"""

import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import BinaryTools, Gen2

P = Gen2._entry_parsers()


def _sd(t, payload):
    return P[t](bytearray(payload))['structured_data']


def _riding(length=27):
    p = bytearray(27)
    struct.pack_into('<bbHIhhH', p, 0, 21, 20, 77, 104321, 35, 30, 2500)
    struct.pack_into('<hB', p, 0x10, 45, 0x03)
    struct.pack_into('<hhI', p, 0x13, 60, 18, 12345)
    return p[:length]


def test_unpack_fit_matches_unpack_inside_the_buffer():
    rng = random.Random(7)
    for _ in range(500):
        buf = bytearray(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
        for t in ('int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32'):
            size = struct.calcsize('<' + BinaryTools.TYPES[t])
            for at in range(0, len(buf) + 2):
                got = BinaryTools.unpack_fit(t, buf, at)
                if at + size <= len(buf):
                    assert got == BinaryTools.unpack(t, buf, at)
                else:
                    assert got is None


def test_le_fit():
    assert BinaryTools.le_fit(b'\x01\x02\x03', 0, 3) == 0x030201
    assert BinaryTools.le_fit(b'\x01\x02', 0, 3) is None


def test_riding_full_record_unchanged():
    sd = _sd(0x2c, _riding())
    assert sd['ambient_temp_celsius'] == 18 and sd['odometer_km'] == 12345
    assert sd['motor_current_amps'] == 60 and sd['mods'] == '11'


def test_riding_21_byte_record_has_no_ambient_or_odometer():
    full, short = _sd(0x2c, _riding()), _sd(0x2c, _riding(21))
    assert short['ambient_temp_celsius'] is None
    assert short['odometer_km'] is None
    for k in full:
        if k not in ('ambient_temp_celsius', 'odometer_km'):
            assert short[k] == full[k], k


def test_disarmed_one_byte_record_keeps_only_byte_0():
    sd = _sd(0x3c, _riding(1))
    assert sd['pack_temp_high_celsius'] == 21
    others = {k: v for k, v in sd.items() if k not in ('pack_temp_high_celsius', 'vehicle_state')}
    assert all(v is None for v in others.values()), others
    assert P[0x3c](bytearray(_riding(1)))['conditions'].startswith('PackTemp: h 21C, l n/aC')


def test_charging_13_byte_record_has_no_ambient():
    p = bytearray(15)
    struct.pack_into('<bbHIh', p, 0, 20, 18, 64, 104500, -12)
    struct.pack_into('<Bb', p, 0x0c, 3, 15)
    assert _sd(0x2d, p)['ambient_temp_celsius'] == 15
    short = _sd(0x2d, p[:13])
    assert short['ambient_temp_celsius'] is None
    assert short['mods'] == 3 and short['battery_current_amps'] == -12


def test_contactor_14_byte_record():
    p = bytearray(25)
    struct.pack_into('<BBIIIIh', p, 0, 0x01, 0, 100500, 101000, 99000, 95000, -3)
    full = _sd(0x33, p)
    assert full['capacitor_voltage_volts'] == 95.0 and full['battery_current_amps'] == -3
    short = _sd(0x33, p[:14])
    assert short['capacitor_voltage_volts'] is None
    assert short['battery_current_amps'] is None
    assert short['precharge_percent'] is None
    assert short['module_voltage_volts'] == 100.5


def test_current_limited_2_byte_record():
    p = bytearray(7)
    struct.pack_into('<HHbH', p, 0, 120, 3300, 30, 200)
    full = _sd(0x39, p)
    assert full['limit_percentage'] == 60.0 and full['current_reduction_amps'] == 80
    short = _sd(0x39, p[:2])
    assert short['limit_current_amps'] == 120
    for k in ('min_cell_voltage_mv', 'min_cell_voltage_volts', 'max_pack_temp_celsius',
              'max_current_amps', 'limit_percentage', 'current_reduction_amps'):
        assert short[k] is None, k


def test_discharge_level_short_record():
    p = bytearray(22)
    struct.pack_into('<HHbbIBIBI', p, 0, 3700, 3720, 20, 25, 30000000, 64, 103500, 0x01, 0)
    struct.pack_into('<iH', p, 0x10, -5000000, 3710)
    full = _sd(0x03, p)
    assert full['current_amps'] == -5 and full['voltage_unloaded_cell_volts'] == 3.71
    short = _sd(0x03, p[:12])
    assert short['state_of_charge_percent'] == 64
    assert short['pack_voltage_volts'] is None and short['current_amps'] is None
    assert short['mode'] is None and short['voltage_unloaded_cell_volts'] is None
