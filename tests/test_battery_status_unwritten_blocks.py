"""Legacy MBB module contactor events (0x33): Opening and Registered rows that
leave the module-voltage / system max-min block all zero decode those fields as
None. Invented payloads."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2


def _p(event, vmod, smax, smin, vcap, cur, length=23, tail=b'\x78\x0b\x00'):
    p = bytearray(struct.pack('<BBIIIIh', event, 1, vmod, smax, smin, vcap, cur)) + bytearray(tail)
    return p[:length]


def _sd(p):
    return Gen2.battery_status(p)['structured_data']


def test_opening_all_zero_after_module():
    sd = _sd(_p(0, 0, 0, 0, 0, 0, length=14))
    for k in ('module_voltage_volts', 'system_max_voltage_volts', 'system_min_voltage_volts',
              'capacitor_voltage_volts', 'battery_current_amps', 'voltage_difference_volts'):
        assert sd[k] is None, k
    assert sd['module_number'] == 1


def test_opening_zero_voltage_block_real_capacitor():
    sd = _sd(_p(0, 0, 0, 0, 101875, 0))
    assert sd['module_voltage_volts'] is None and sd['system_max_voltage_volts'] is None
    assert sd['capacitor_voltage_volts'] == 101.875
    assert sd['battery_current_amps'] == 0      # a lone zero that can be real


def test_registered_real_module_voltage_zero_system_block():
    sd = _sd(_p(2, 101000, 0, 0, 0, 0, length=29, tail=b'serialno\x00'))
    assert sd['module_voltage_volts'] == 101.0
    assert sd['system_max_voltage_volts'] is None and sd['system_min_voltage_volts'] is None


def test_closing_untouched():
    sd = _sd(_p(1, 0, 0, 0, 95000, 0))
    assert sd['module_voltage_volts'] == 0.0 and sd['system_max_voltage_volts'] == 0.0


def test_opening_with_readings_untouched():
    sd = _sd(_p(0, 101000, 101200, 100900, 99000, -2))
    assert (sd['module_voltage_volts'], sd['system_max_voltage_volts'], sd['battery_current_amps']) == (101.0, 101.2, -2)
