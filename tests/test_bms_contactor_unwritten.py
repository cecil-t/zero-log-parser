"""Legacy BMS contactor records with a pack voltage of 0: not written."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2


def _row(closed=1, pack=0, switched=0, current=0):
    return bytes([closed]) + struct.pack('<IIi', pack, switched, current)


def test_all_zero_block_is_none():
    sd = Gen2.bms_contactor_state(_row())['structured_data']
    for k in ('pack_voltage_volts', 'pack_voltage_mv', 'switched_voltage_volts', 'switched_voltage_mv', 'precharge_percent',
              'discharge_current_amps', 'discharge_current_ma'):
        assert sd[k] is None, k
    assert sd['contactor_state'] == 'closed'


def test_current_with_pack_zero_kept():
    sd = Gen2.bms_contactor_state(_row(current=-64000))['structured_data']
    assert sd['pack_voltage_volts'] is None and sd['switched_voltage_volts'] is None and sd['discharge_current_amps'] == -64.0


def test_pack_zero_with_a_switched_voltage():
    sd = Gen2.bms_contactor_state(_row(switched=101_000))['structured_data']
    assert sd['pack_voltage_volts'] is None and sd['precharge_percent'] is None and sd['switched_voltage_volts'] == 101.0


def test_zero_current_next_to_a_real_pack_kept():
    sd = Gen2.bms_contactor_state(_row(pack=102_000, switched=101_500))['structured_data']
    assert sd['discharge_current_amps'] == 0.0 and sd['pack_voltage_volts'] == 102.0 and sd['precharge_percent'] is not None
