"""
Tests for the Gen3 BMS cell-telemetry fields decoded in Task D4
(analysis/gen3_bms_d4.md): lowest and highest cell index, cell imbalance,
discharge current limit, the 0x4C adjusted capacity, the 0x4D pack voltage
unreadable flag and the 0x4B/39 reduced-reporting flag. Every value here is
invented. Plain test_* functions, stdlib only, synthetic payloads, no
dataset files.
"""

import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

MARK = b'\x00\xf0\xff\x00'
LOGGER = logging.getLogger('test_gen3_bms_d4')
SHIFT = {0x4b: 0, 0x4c: 4, 0x4d: 8}


def _payload(message_type, length):
    """A valid cell-telemetry payload: sub-second 250000, sequence 3, marker 9,
    cells 3.810/3.805/3.842 V, SOC 61%, current 12.5 A, BMS temperature 24 C,
    every other byte 0."""
    buf = bytearray(length)
    struct.pack_into('<I', buf, 0, 250_000)
    buf[4], buf[5] = 3, 9
    base = 14 + SHIFT[message_type]
    struct.pack_into('<HHHBi', buf, base, 3810, 3805, 3842, 61, 12_500)
    buf[base + 11] = 24
    return buf


def _decode(message_type, payload):
    return Gen2.bms_cell_telemetry(message_type, payload)


def _entry(message_type, timestamp, payload):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def _decode_paged(message_type, payload):
    collected = Gen2.collect_paged_bms_entries(bytes(_entry(message_type, 1_760_000_000, payload)), LOGGER)
    assert len(collected) == 1
    return collected[0][1]


# --- lowest and highest cell index -------------------------------------------

def test_cell_indices_on_the_long_variants_only():
    for (message_type, length), at in Gen2.BMS_CELL_INDEX_OFFSETS.items():
        payload = _payload(message_type, length)
        payload[at], payload[at + 1] = 17, 4
        out = _decode(message_type, payload)
        sd = out['structured_data']
        assert sd['lowest_cell_index'] == 17 and sd['highest_cell_index'] == 4
        assert 'Cells:low#17 high#4' in out['conditions']
    assert set(Gen2.BMS_CELL_INDEX_OFFSETS) == {(0x4b, 45), (0x4c, 63), (0x4d, 71)}
    for message_type, length in ((0x4b, 43), (0x4c, 61), (0x4d, 69)):
        sd = _decode(message_type, _payload(message_type, length))['structured_data']
        assert 'lowest_cell_index' not in sd and 'highest_cell_index' not in sd


def test_cell_index_unavailable_is_none_and_zero_is_kept():
    payload = _payload(0x4b, 45)
    payload[43], payload[44] = 0xff, 0xff
    out = _decode(0x4b, payload)
    assert out['structured_data']['lowest_cell_index'] is None
    assert out['structured_data']['highest_cell_index'] is None
    assert 'Cells:low#n/a high#n/a' in out['conditions']
    payload[43], payload[44] = 0, 0
    sd = _decode(0x4b, payload)['structured_data']
    assert sd['lowest_cell_index'] == 0 and sd['highest_cell_index'] == 0


def test_0x4b_at_45_bytes_has_no_unknown_byte_left():
    assert all(kind != 'unknown' for _, _, kind, _ in Gen2.payload_layout(0x4b, 45))


def test_cell_index_under_a_page_marker_is_withheld():
    payload = _payload(0x4b, 45)
    payload[39:42] = (107_000).to_bytes(3, 'little')
    payload[43], payload[44] = 12, 20
    payload[41:45] = MARK
    sd = _decode_paged(0x4b, payload)['structured_data']
    assert 'lowest_cell_index' in sd['corrupted_fields'] and 'highest_cell_index' in sd['corrupted_fields']
    assert sd['lowest_cell_index'] is None and sd['highest_cell_index'] is None
    assert sd['state_of_charge_percent'] == 61 and sd['voltage_low_cell_volts'] == 3.81


# --- cell imbalance -------------------------------------------------------------

def test_cell_imbalance_s16_at_the_variant_offsets():
    assert Gen2.BMS_IMBALANCE_OFFSETS == {(0x4c, 61): 59, (0x4c, 63): 61, (0x4d, 69): 63, (0x4d, 71): 65}
    for (message_type, length), at in Gen2.BMS_IMBALANCE_OFFSETS.items():
        payload = _payload(message_type, length)
        struct.pack_into('<h', payload, at, 32)
        out = _decode(message_type, payload)
        assert out['structured_data']['cell_imbalance_mv'] == 32 and 'Imb:32mV' in out['conditions']
        struct.pack_into('<h', payload, at, -3)
        assert _decode(message_type, payload)['structured_data']['cell_imbalance_mv'] == -3
        struct.pack_into('<H', payload, at, 0xf0f0)
        out = _decode(message_type, payload)
        assert out['structured_data']['cell_imbalance_mv'] is None and 'Imb:n/a' in out['conditions']
    for length in (43, 45):
        assert 'cell_imbalance_mv' not in _decode(0x4b, _payload(0x4b, length))['structured_data']


def test_cell_imbalance_under_a_page_marker_is_withheld():
    payload = _payload(0x4d, 71)
    struct.pack_into('<h', payload, 65, 37)
    payload[63:67] = MARK
    sd = _decode_paged(0x4d, payload)['structured_data']
    assert 'cell_imbalance_mv' in sd['corrupted_fields'] and sd['cell_imbalance_mv'] is None
    assert sd['battery_current_amps'] == 12.5


# --- discharge current limit ------------------------------------------------------

def test_discharge_limit_is_the_word_before_the_charge_limit():
    for (message_type, length), at in Gen2.BMS_DISCHARGE_LIMIT_OFFSETS.items():
        assert Gen2.BMS_CHARGE_LIMIT_OFFSETS[(message_type, length)] == at + 2
        payload = _payload(message_type, length)
        struct.pack_into('<HH', payload, at, 1230, 123)
        out = _decode(message_type, payload)
        sd = out['structured_data']
        assert sd['bms_discharge_current_limit_amps'] == 1230 and sd['bms_charge_current_limit_amps'] == 123
        assert 'ChgLim:123A, DisLim:1230A' in out['conditions']
        struct.pack_into('<H', payload, at, 0xffff)
        out = _decode(message_type, payload)
        assert out['structured_data']['bms_discharge_current_limit_amps'] is None and 'DisLim:n/a' in out['conditions']
    assert 'bms_discharge_current_limit_amps' not in _decode(0x4b, _payload(0x4b, 45))['structured_data']


def test_discharge_limit_under_a_page_marker_is_withheld():
    payload = _payload(0x4c, 61)
    struct.pack_into('<HH', payload, 50, 990, 99)
    payload[48:52] = MARK
    sd = _decode_paged(0x4c, payload)['structured_data']
    assert 'bms_discharge_current_limit_amps' in sd['corrupted_fields']
    assert sd['bms_discharge_current_limit_amps'] is None and sd['bms_charge_current_limit_amps'] == 99


# --- adjusted capacity in 0x4C ----------------------------------------------------------

def test_0x4c_capacity_register_without_a_twin():
    for (message_type, length), at in (((0x4c, 61), 54), ((0x4c, 63), 56)):
        assert Gen2.BMS_CAPACITY_OFFSETS[(message_type, length)] == (at,)
        payload = _payload(message_type, length)
        payload[at:at + 3] = (138_512).to_bytes(3, 'little')
        out = _decode(message_type, payload)
        sd = out['structured_data']
        assert sd['full_charge_capacity_ah'] == 138.512 and 'full_charge_capacity_twin_ah' not in sd
        assert 'Cap:138.512Ah' in out['conditions']
        payload[at:at + 3] = b'\xff\xff\xff'
        assert _decode(message_type, payload)['structured_data']['full_charge_capacity_ah'] is None


def test_0x4c_capacity_under_a_page_marker_is_withheld():
    payload = _payload(0x4c, 63)
    payload[56:59] = (141_002).to_bytes(3, 'little')
    payload[55:59] = MARK
    sd = _decode_paged(0x4c, payload)['structured_data']
    assert 'full_charge_capacity_ah' in sd['corrupted_fields'] and sd['full_charge_capacity_ah'] is None


# --- pack voltage unreadable flag in 0x4D --------------------------------------------------

def test_0x4d_byte_19_is_the_0x4b_byte_11_flag():
    for length in (69, 71):
        payload = _payload(0x4d, length)
        payload[19] = 4
        assert _decode(0x4d, payload)['structured_data']['pack_fault_flags_a'] == 4
        payload[19] = 0
        assert _decode(0x4d, payload)['structured_data']['pack_fault_flags_a'] == 0
        payload[19] = 0xf0
        assert _decode(0x4d, payload)['structured_data']['pack_fault_flags_a'] is None
    payload = _payload(0x4b, 43)
    payload[11] = 4
    assert _decode(0x4b, payload)['structured_data']['pack_fault_flags_a'] == 4


def test_0x4d_byte_19_under_a_page_marker_is_withheld():
    payload = _payload(0x4d, 69)
    payload[19] = 4
    payload[16:20] = MARK
    sd = _decode_paged(0x4d, payload)['structured_data']
    assert 'pack_fault_flags_a' in sd['corrupted_fields'] and sd['pack_fault_flags_a'] is None
