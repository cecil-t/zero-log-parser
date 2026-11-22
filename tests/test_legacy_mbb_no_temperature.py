"""Classic MBB records: -100 C is the firmware's no-reading temperature and
decodes as None. Invented payloads."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2
P = Gen2._entry_parsers()


def _riding(ph=-100, pl=-100, mot=-100, ctl=40, amb=-100):
    p = bytearray(27)
    struct.pack_into('<bbHIhhH', p, 0, ph, pl, 77, 104321, mot, ctl, 2500)
    struct.pack_into('<hB', p, 0x10, 45, 0x03)
    struct.pack_into('<hhI', p, 0x13, 60, amb, 12345)
    return p


def test_riding_and_disarmed():
    for t in (0x2c, 0x3c):
        sd = P[t](_riding())['structured_data']
        assert sd['pack_temp_high_celsius'] is None and sd['pack_temp_low_celsius'] is None
        assert sd['motor_temp_celsius'] is None and sd['ambient_temp_celsius'] is None
        assert sd['controller_temp_celsius'] == 40


def test_real_negative_temperature_kept():
    sd = P[0x2c](_riding(ph=-5, pl=-7, mot=-3, amb=-1))['structured_data']
    assert (sd['pack_temp_high_celsius'], sd['pack_temp_low_celsius'], sd['ambient_temp_celsius']) == (-5, -7, -1)


def test_charging():
    p = bytearray(15)
    struct.pack_into('<bbHIh', p, 0, -100, 12, 64, 104500, -12)
    struct.pack_into('<Bb', p, 0x0c, 3, -100)
    sd = P[0x2d](p)['structured_data']
    assert sd['pack_temp_high_celsius'] is None and sd['ambient_temp_celsius'] is None
    assert sd['pack_temp_low_celsius'] == 12


def test_disable_temp_and_current_limited():
    sd = P[0x1e](bytearray(struct.pack('<bBH', -100, 1, 0x10)))['structured_data']
    assert sd['pack_temp_celsius'] is None
    sd = P[0x39](bytearray(struct.pack('<HHbH', 120, 3300, -100, 200)))['structured_data']
    assert sd['max_pack_temp_celsius'] is None
