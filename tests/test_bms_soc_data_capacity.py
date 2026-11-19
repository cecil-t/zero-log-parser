"""BMS "SOC:" debug text: the fourth value is the nominal capacity in mAh, not a pack voltage. Invented values."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from zero_log_parser import Gen2, TXT_UNIT_BY_KEY


def test_compact_format():
    e = Gen2._debug_text_entry('SOC:21,40000,182,40000,100,100,100,1')
    sd = e['structured_data']
    assert e['event'] == 'SOC Data'
    assert sd['nominal_capacity_mah'] == 40000
    assert sd['pack_voltage_volts'] is None and sd['pack_voltage_mv'] is None
    assert sd['soc_percent_1'] == 100


def test_extended_format():
    e = Gen2._debug_text_entry('SOC:1311,34569,1169,60000,98,96,97,2,4099,4081,4084,1189')
    sd = e['structured_data']
    assert sd['nominal_capacity_mah'] == 60000
    assert sd['pack_voltage_volts'] is None and sd['pack_voltage_mv'] is None
    assert sd['voltage_max_volts'] == 4.099 and sd['current_amps'] == 1.189


def test_txt_unit():
    assert TXT_UNIT_BY_KEY['nominal_capacity_mah'] == 'mAh'
