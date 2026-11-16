"""
Regression tests for the legacy MBB Charging (0x2d) "MbbChgEn" flag
(analysis/legacy_mbb_disarmed_current.md): the firmware renderer prints Yes
when payload byte 0x0a is non-zero and No when it is zero. The parser used
to report Yes for every entry.

All payloads are invented, built field by field to the 15-byte layout.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2


def _charging(flag, amps=-12, length=15):
    p = bytearray(15)
    struct.pack_into('<b', p, 0x00, 20)
    struct.pack_into('<b', p, 0x01, 18)
    struct.pack_into('<H', p, 0x02, 64)
    struct.pack_into('<I', p, 0x04, 104500)
    struct.pack_into('<h', p, 0x08, amps)
    struct.pack_into('<B', p, 0x0a, flag)
    struct.pack_into('<B', p, 0x0c, 0x03)
    struct.pack_into('<h', p, 0x0d, 15)
    return p[:length]


def _decode(payload):
    return Gen2._entry_parsers()[0x2d](payload)


def test_charge_enabled():
    out = _decode(_charging(1, amps=-12))
    assert out['structured_data']['mbb_charge_enabled'] is True
    assert 'MbbChgEn: Yes, BmsChgEn: No' in out['conditions']


def test_charge_paused():
    # Byte 0x0a = 0: the MBB has charging switched off (current near 0 A).
    out = _decode(_charging(0, amps=0))
    assert out['structured_data']['mbb_charge_enabled'] is False
    assert 'MbbChgEn: No, BmsChgEn: No' in out['conditions']


def test_any_nonzero_byte_is_yes():
    # The firmware's test is zero / non-zero.
    assert _decode(_charging(0x20))['structured_data']['mbb_charge_enabled'] is True


def test_short_payload_keeps_previous_value():
    # Too short to hold byte 0x0a: unchanged from before (Yes).
    out = _decode(_charging(0, length=10))
    assert out['structured_data']['mbb_charge_enabled'] is True


def test_other_fields_unchanged():
    sd = _decode(_charging(0, amps=0))['structured_data']
    assert sd['battery_current_amps'] == 0
    assert sd['state_of_charge_percent'] == 64
    assert sd['bms_charge_enabled'] is False
