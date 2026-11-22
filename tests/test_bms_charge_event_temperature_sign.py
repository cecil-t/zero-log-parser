"""Legacy BMS Charged To Full (0x04) / Discharged To Low (0x06): pack and BMS
temperatures are signed bytes. Invented payloads."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2


def _payload(pt, bt):
    return bytearray(struct.pack('<HHbbIBI', 3600, 3650, pt, bt, 20_000_000, 95, 115_000))


def test_below_freezing():
    for t in (0x04, 0x06):
        sd = Gen2._entry_parsers()[t](_payload(-3, -1))['structured_data']
        assert (sd['pack_temp_celsius'], sd['bms_temp_celsius']) == (-3, -1)


def test_above_freezing_unchanged():
    sd = Gen2._entry_parsers()[0x04](_payload(22, 30))['structured_data']
    assert (sd['pack_temp_celsius'], sd['bms_temp_celsius']) == (22, 30)
