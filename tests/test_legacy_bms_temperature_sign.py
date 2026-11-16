"""
Regression tests for the signedness of the legacy BMS "Discharge level"
(type 0x03) temperatures (analysis/legacy_mbb_disarmed_current.md): the
pack temperature at 0x04 and the BMS board temperature at 0x05 are signed
bytes. Unlike the MBB pack temperatures there is no invalid-sensor value
in the BMS data, so none is tested here.

All payloads are invented, built field by field to the 22-byte layout.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2


def _discharge_level(pack_temp=21, bms_temp=24, low_mv=3950, high_mv=3962, ah=12.5, soc=64,
                     pack_mv=110700, mode=0x01, micro_amps=-4500000, unloaded_mv=3955):
    p = bytearray(22)
    struct.pack_into('<H', p, 0x00, low_mv)
    struct.pack_into('<H', p, 0x02, high_mv)
    struct.pack_into('<b', p, 0x04, pack_temp)
    struct.pack_into('<b', p, 0x05, bms_temp)
    struct.pack_into('<I', p, 0x06, int(ah * 1000000))
    struct.pack_into('<B', p, 0x0a, soc)
    struct.pack_into('<I', p, 0x0b, pack_mv)
    struct.pack_into('<B', p, 0x0f, mode)
    struct.pack_into('<i', p, 0x10, micro_amps)
    struct.pack_into('<H', p, 0x14, unloaded_mv)
    return p


def _decode(payload):
    return Gen2._entry_parsers()[0x03](payload)


def test_pack_and_board_temps_below_freezing():
    # -4 C pack, -2 C board (bytes fc fe): the uint8 read showed 252 C and 254 C.
    out = _decode(_discharge_level(pack_temp=-4, bms_temp=-2))
    assert out['event'] == 'Discharge level'
    sd = out['structured_data']
    assert (sd['pack_temp_celsius'], sd['bms_temp_celsius']) == (-4, -2)
    assert 'PT:-04C, BT:-02C' in out['conditions']


def test_coldest_signed_value():
    sd = _decode(_discharge_level(pack_temp=-128, bms_temp=-1))['structured_data']
    assert (sd['pack_temp_celsius'], sd['bms_temp_celsius']) == (-128, -1)


def test_positive_temps_unchanged():
    out = _decode(_discharge_level(pack_temp=35, bms_temp=41))
    sd = out['structured_data']
    assert (sd['pack_temp_celsius'], sd['bms_temp_celsius']) == (35, 41)
    assert 'PT:035C, BT:041C' in out['conditions']


def test_other_fields_unchanged():
    sd = _decode(_discharge_level(pack_temp=-4, bms_temp=-2))['structured_data']
    assert sd['state_of_charge_percent'] == 64
    assert sd['pack_voltage_volts'] == 110.7
    assert sd['current_amps'] == -4  # the decoder truncates to whole amps
    assert sd['mode'] == 'Bike On'
