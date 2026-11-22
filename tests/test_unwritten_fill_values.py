"""All-ones (and 0x7FFFFFFF) fill left in a field the firmware never wrote
decodes as None. Invented payloads."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import BinaryTools, Gen2
P = Gen2._entry_parsers()


def test_not_fill():
    assert BinaryTools.not_fill(0xffffff, 0xffffff) is None
    assert BinaryTools.not_fill(123, 0xffffff) == 123
    assert BinaryTools.not_fill(None, 0xffffff) is None


def test_riding_odometer_all_ones():
    p = bytearray(27)
    struct.pack_into('<bbHIhhH', p, 0, 21, 20, 77, 104321, 35, 30, 2500)
    struct.pack_into('<hhI', p, 0x13, 60, 18, 0xffffffff)
    assert P[0x2c](p)['structured_data']['odometer_km'] is None


def test_charging_pack_voltage_not_set():
    p = bytearray(15)
    struct.pack_into('<bbHIh', p, 0, 20, 18, 0, 0x7fffffff, 0)
    assert P[0x2d](p)['structured_data']['pack_voltage_volts'] is None


def test_gen3_bms_pack_voltage_fill():
    buf = bytearray(45)
    struct.pack_into('<I', buf, 0, 250_000)
    buf[4], buf[5] = 3, 9
    struct.pack_into('<HHHBi', buf, 14, 3810, 3805, 3842, 61, 12_500)
    buf[39:42] = b'\xff\xff\xff'
    assert Gen2.bms_cell_telemetry(0x4b, buf)['structured_data']['pack_voltage_volts'] is None
    buf[39:42] = (104_500).to_bytes(3, 'little')
    assert Gen2.bms_cell_telemetry(0x4b, buf)['structured_data']['pack_voltage_volts'] == 104.5
