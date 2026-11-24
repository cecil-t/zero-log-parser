"""Classic MBB types 0x02 (High Throttle Disable, u16 thr mV), 0x31 (BMS
Isolation Fault, u8 BMS number) and 0x3e (ten C/B int32 mV pairs), decoded
from the layouts the classic MBB firmware's own renderer reads. Other
payload lengths keep the raw fallback. Invented values only."""
import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2


def _parse(message_type, payload, log_type='MBB'):
    body = bytes([message_type]) + struct.pack('<I', 1_600_000_000) + bytes(payload)
    raw = bytearray([0xb2, len(body) + 2]) + bytearray(body)
    _length, entry, _ = Gen2.parse_entry(raw, 0, 0, logging.getLogger('t'), log_type=log_type)
    return entry


def test_high_throttle_disable_reads_the_throttle_voltage():
    entry = _parse(0x02, struct.pack('<H', 1425))
    assert entry['event'] == 'High Throttle Disable'
    assert entry['structured_data'] == {'thr_voltage_volts': 1.425}
    assert entry['conditions'] == 'thr: 1.425V'
    assert entry['log_level'] == 'INFO'


def test_high_throttle_disable_other_lengths_stay_raw():
    entry = _parse(0x02, b'Cell 5 too High')
    assert entry['event'] == 'High Throttle Disable'
    assert 'structured_data' not in entry and entry['conditions'].startswith('Raw data:')


def test_bms_isolation_fault_reads_the_bms_number():
    for n in (0, 1):
        entry = _parse(0x31, bytes([n]))
        assert entry['event'] == 'MBB BMS Isolation Fault'
        assert entry['structured_data'] == {'module_number': n}
        assert entry['conditions'] == 'BMS: %d' % n
        assert entry['log_level'] == 'ERROR'
    assert 'structured_data' not in _parse(0x31, b'\x00\x01')


def _pairs(pairs):
    return b''.join(struct.pack('<ii', c, b) for c, b in pairs)


def test_precharge_pairs_decode_c_and_b():
    pairs = [(60500 + 4500 * n, 111875) for n in range(9)] + [(111875, 111812)]
    sd = _parse(0x3e, _pairs(pairs))['structured_data']
    assert sd['c_voltage_1_volts'] == 60.5 and sd['b_voltage_1_volts'] == 111.875
    assert sd['c_voltage_10_volts'] == 111.875 and sd['b_voltage_10_volts'] == 111.812
    assert len(sd) == 20


def test_unfilled_precharge_pairs_are_none():
    pairs = [(-100, -100)] * 8 + [(111250, 111000), (111250, 111062)]
    entry = _parse(0x3e, _pairs(pairs))
    sd = entry['structured_data']
    for n in range(1, 9):
        assert sd['c_voltage_%d_volts' % n] is None and sd['b_voltage_%d_volts' % n] is None
    assert sd['c_voltage_9_volts'] == 111.25 and sd['b_voltage_10_volts'] == 111.062
    assert entry['conditions'].startswith('C1: n/a B1: n/a')
    # -100 in one value only is not the unfilled form: shown as read
    sd = _parse(0x3e, _pairs([(-100, 111000)] + [(100000, 111000)] * 9))['structured_data']
    assert sd['c_voltage_1_volts'] == -0.1 and sd['b_voltage_1_volts'] == 111.0


def test_precharge_pairs_other_lengths_stay_raw():
    entry = _parse(0x3e, b'\xb2')
    assert entry['event'] == 'Cell Voltages' and 'structured_data' not in entry


def test_not_decoded_in_bms_files():
    from zero_log_parser import LogFile
    for t in (0x02, 0x31, 0x3e):
        assert t not in Gen2._entry_parsers(LogFile.log_type_bms)
        assert t in Gen2._entry_parsers(LogFile.log_type_mbb)
        assert t in Gen2._entry_parsers(LogFile.log_type_unknown)
    entry = _parse(0x02, struct.pack('<H', 1425), log_type=LogFile.log_type_bms)
    assert 'structured_data' not in entry and entry['conditions'].startswith('Raw data:')
