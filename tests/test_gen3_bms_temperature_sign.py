"""Gen3 BMS telemetry temperatures are signed bytes; 0xF0/0xFF stay None.
Invented payloads."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2


def _payload(bms_t, cold, hot):
    buf = bytearray(63)
    struct.pack_into('<I', buf, 0, 250_000)
    buf[4], buf[5] = 3, 9
    base = 18
    struct.pack_into('<HHHBi', buf, base, 3810, 3805, 3842, 61, 12_500)
    buf[25 + 4], buf[49], buf[50] = bms_t, cold, hot
    return buf


def test_below_freezing():
    sd = Gen2.bms_cell_telemetry(0x4c, _payload(0xfe, 0xfd, 0xfc))['structured_data']
    assert (sd['bms_temperature_c'], sd['cell_temperature_coldest_c'], sd['cell_temperature_hottest_c']) == (-2, -3, -4)


def test_fill_bytes_stay_none():
    sd = Gen2.bms_cell_telemetry(0x4c, _payload(0xf0, 0xff, 0xf0))['structured_data']
    assert sd['bms_temperature_c'] is None and sd['cell_temperature_coldest_c'] is None


def test_above_freezing_unchanged():
    sd = Gen2.bms_cell_telemetry(0x4c, _payload(24, 20, 23))['structured_data']
    assert (sd['bms_temperature_c'], sd['cell_temperature_coldest_c'], sd['cell_temperature_hottest_c']) == (24, 20, 23)
