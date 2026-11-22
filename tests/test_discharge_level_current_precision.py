"""Legacy BMS Discharge level current: the int32 is microamps and is kept to
0.001 A (it used to be truncated to whole amps). Invented payloads."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2, TXT_FORMAT_BY_EVENT_KEY


def _sd(micro_amps):
    p = bytearray(22)
    struct.pack_into('<HHbbIBIB', p, 0, 3700, 3720, 20, 25, 30000000, 64, 103500, 0x02)
    struct.pack_into('<iH', p, 0x10, micro_amps, 3710)
    return Gen2._entry_parsers()[0x03](p)['structured_data']


def test_sub_amp_part_kept():
    assert _sd(-1_820_456)['current_amps'] == -1.82
    assert _sd(-900_000)['current_amps'] == -0.9
    assert _sd(255_813_953)['current_amps'] == 255.814


def test_whole_amps_unchanged():
    assert _sd(-5_000_000)['current_amps'] == -5.0


def test_txt_prints_one_decimal():
    assert TXT_FORMAT_BY_EVENT_KEY[('Discharge level', 'current_amps')] == ('.1f', 'A')
