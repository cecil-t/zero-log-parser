"""Current Sensor Zeroed (legacy BMS 0x0d): the correction factor is a signed
16-bit value at offset 4. Invented payloads."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2


def _sd(old, new, corr):
    return Gen2._entry_parsers()[0x0d](bytearray(struct.pack('<HHh', old, new, corr)))['structured_data']


def test_negative_correction_factor():
    sd = _sd(2500, 2489, -11)
    assert sd['correction_factor'] == -11
    assert sd['adjustment_millivolts'] == -11


def test_positive_correction_factor():
    assert _sd(2500, 2507, 7)['correction_factor'] == 7


def test_five_byte_record_has_no_correction_factor():
    p = bytearray(struct.pack('<HHh', 2500, 2489, -11))[:5]
    assert Gen2._entry_parsers()[0x0d](p)['structured_data']['correction_factor'] is None
