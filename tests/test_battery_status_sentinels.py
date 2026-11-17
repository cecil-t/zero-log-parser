"""Type 0x33: -100 mV capacitor marker and the non-serial bytes of the non-Registered events are None."""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from zero_log_parser import Gen2


def _payload(event, vcap_mv, tail):
    x = bytearray(0x14)
    x[0] = event
    struct.pack_into('<I', x, 0x2, 110_000)
    struct.pack_into('<I', x, 0x6, 110_000)
    struct.pack_into('<I', x, 0xa, 109_000)
    struct.pack_into('<i', x, 0x0e, vcap_mv)
    return bytes(x) + tail


def test_opening_row_marker_and_filler_are_none():
    sd = Gen2.battery_status(_payload(0, -100, b'\x78\x0b\x00'))['structured_data']
    assert sd['capacitor_voltage_volts'] is None
    assert sd['serial_number'] is None


def test_closing_row_keeps_a_real_vcap():
    out = Gen2.battery_status(_payload(1, 99_562, b'\x3c\xff\x00'))
    assert out['structured_data']['capacitor_voltage_volts'] == 99.562
    assert out['structured_data']['serial_number'] is None
    out = Gen2.battery_status(_payload(1, -100, b'\x3c\xff\x00'))
    assert out['structured_data']['precharge_percent'] is None
    assert 'vcap: n/aV' in out['conditions'] and 'prechg: n/a%' in out['conditions']


def test_registered_keeps_its_serial():
    sd = Gen2.battery_status(_payload(2, 0, b'TSTPK001\x00'))['structured_data']
    assert sd['serial_number'] == 'TSTPK001'
