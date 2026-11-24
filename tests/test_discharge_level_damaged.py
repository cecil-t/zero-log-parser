"""Legacy BMS Discharge level records whose values cannot all be readings are
withheld (Gen2.discharge_level_damaged). Invented values only."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2


def _row(low=3624, high=3632, soc=24, pack=101579, current_ua=-60_000_000, unloaded=3610, mode=1, ah=10_000_000):
    x = bytearray(22)
    struct.pack_into('<HHbb', x, 0, low, high, 33, 38)
    struct.pack_into('<I', x, 6, ah)
    x[0x0a] = soc
    struct.pack_into('<I', x, 0x0b, pack)
    x[0x0f] = mode
    struct.pack_into('<iH', x, 0x10, current_ua, unloaded)
    return x


def test_real_row_kept():
    sd = Gen2.bms_discharge_level(_row())['structured_data']
    assert 'corrupted_fields' not in sd and sd['current_amps'] == -60.0 and sd['pack_voltage_volts'] == 101.579


def test_each_test_withholds_every_value():
    for kw in (dict(unloaded=9215), dict(low=38200), dict(high=3500, low=3600), dict(soc=111),
               dict(pack=136000), dict(current_ua=-1_044_898_000)):
        sd = Gen2.bms_discharge_level(_row(**kw))['structured_data']
        assert sd['corrupted_fields'], kw
        assert all(sd[k] is None for k in sd['corrupted_fields'])
        assert sd['current_amps'] is None and sd['pack_voltage_volts'] is None and sd['state_of_charge_percent'] is None


def test_low_readings_of_a_discharged_pack_kept():
    sd = Gen2.bms_discharge_level(_row(low=1001, high=1888, pack=33218, soc=0, current_ua=0, unloaded=0))['structured_data']
    assert 'corrupted_fields' not in sd and sd['voltage_low_cell_volts'] == 1.001


def test_large_real_current_kept():
    sd = Gen2.bms_discharge_level(_row(current_ua=-560_000_000))['structured_data']
    assert 'corrupted_fields' not in sd and sd['current_amps'] == -560.0
