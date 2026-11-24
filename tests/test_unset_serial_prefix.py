"""The firmware's not-set serial UNINITIALIZED, or a prefix of it of at least
6 characters (a narrower field holds its start), is not a serial."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2


def test_prefixes():
    for v in ('UNINITIALIZED', 'UNINITIA', 'UNINIT', 'UNINITIA\x00\x00'):
        assert Gen2.is_unset_serial(v), v
    for v in ('UNINI', 'UNINITX', '14xx0001', '', None, 'uninitia'):
        assert not Gen2.is_unset_serial(v), v


def _battery_status(event, serial):
    payload = bytearray(0x14)
    payload[0], payload[1] = event, 3
    struct.pack_into('<IIII', payload, 2, 350_000, 400_000, 300_000, 340_000)
    return bytes(payload) + serial + b'\x00'


def test_module_serial_not_set_is_none():
    assert Gen2.battery_status(_battery_status(2, b'UNINITIALIZED'))['structured_data']['serial_number'] is None
    assert Gen2.battery_status(_battery_status(2, b'SN0001'))['structured_data']['serial_number'] == 'SN0001'
