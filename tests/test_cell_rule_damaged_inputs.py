"""Gen3 BMS cell telemetry with no unloaded-cell reading and SOC 0 on a full
pack shows no SOC, unloaded cell or zero current. When the bytes that rule
decides on are damaged (a page marker over them, or a page that does not
continue the entry), the decision rests on bytes that are not the record's:
the record's own unloaded cell, SOC and current are shown where their bytes
are intact, and withheld (listed in corrupted_fields) where they are not.
Invented values only."""
import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

MARK = b'\x00\xf0\xff\x00'
LOGGER = logging.getLogger('test_cell_rule_damaged_inputs')
PARSERS = Gen2._entry_parsers('BMS', gen3_text=True)


def _entry(payload, timestamp=1_700_000_000, message_type=0x4b):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def _payload(soc=0, unloaded=0, current_ma=0, pack_mv=108_000):
    """A 43-byte 0x4B payload, base offset 14, awake (sleep indicator 0)."""
    payload = bytearray(43)
    struct.pack_into('<I', payload, 0, 500_000)
    payload[4], payload[5] = 10, 7
    struct.pack_into('<HHHBi', payload, 14, 3800, unloaded, 3900, soc, current_ma)
    payload[39:42] = pack_mv.to_bytes(3, 'little')
    payload[42] = 0xab
    return payload


def _decode_one(buf):
    collected = Gen2.collect_paged_bms_entries(bytes(buf), LOGGER)
    assert len(collected) == 1
    return collected[0][1]['structured_data']


def test_rule_applies_when_nothing_is_damaged():
    payload = _payload()
    payload[31:35] = MARK
    sd = _decode_one(_entry(payload))
    assert 'corrupted_fields' not in sd
    assert sd['voltage_unloaded_cell_volts'] is None and sd['state_of_charge_percent'] is None
    assert sd['battery_current_amps'] is None and sd['pack_voltage_volts'] == 108.0


def test_marker_over_the_pack_keeps_the_records_own_readings():
    payload = _payload()
    payload[39:43] = MARK
    sd = _decode_one(_entry(payload))
    assert sd['corrupted_fields'] == ['pack_voltage_volts']
    assert sd['pack_voltage_volts'] is None
    assert sd['voltage_unloaded_cell_volts'] == 0.0
    assert sd['state_of_charge_percent'] == 0
    assert sd['battery_current_amps'] == 0.0


def test_marker_over_a_low_pack_lists_only_the_pack():
    # The record's own pack is under 100 V, so the rule does not apply; a
    # filled pack would make it apply, which does not make the other fields
    # damaged.
    payload = _payload(pack_mv=60_000)
    payload[39:43] = MARK
    sd = _decode_one(_entry(payload))
    assert sd['corrupted_fields'] == ['pack_voltage_volts']
    assert sd['voltage_unloaded_cell_volts'] == 0.0 and sd['state_of_charge_percent'] == 0


def test_marker_over_soc_and_current_withholds_them_and_keeps_the_unloaded_cell():
    payload = _payload()
    payload[20:24] = MARK
    sd = _decode_one(_entry(payload))
    assert {'state_of_charge_percent', 'battery_current_amps'} <= set(sd['corrupted_fields'])
    assert 'voltage_unloaded_cell_volts' not in sd['corrupted_fields']
    assert sd['state_of_charge_percent'] is None and sd['battery_current_amps'] is None
    assert sd['voltage_unloaded_cell_volts'] == 0.0
    assert sd['pack_voltage_volts'] == 108.0


def _spliced(entry_at):
    """Header page, page 1 holding the entry at entry_at, then a copy of
    page 1 where the entry should continue, then two more copies."""
    page1 = bytearray(b'\x11' * 128)
    e = _entry(_payload(), timestamp=0x5d400000)
    page1[entry_at:] = e[:128 - entry_at]
    buf = bytes(128) + bytes(page1) * 4
    return buf, (128 + entry_at, len(e))


def test_entry_running_into_another_page_before_the_pack():
    # 7 header bytes, so the boundary lands at payload offset 128 - 90 - 7 = 31:
    # the cells, SOC and current are the record's own, the pack is not.
    buf, span = _spliced(90)
    start, _ = span
    block = Gen2.parse_entry(bytearray(buf), start, 0, logger=None, log_type='BMS', gen3_text=True)[1]
    collected = [(0, block, 0)]
    assert Gen2.withhold_spliced_fields(bytearray(buf), collected, [span], PARSERS) == 1
    sd = collected[0][1]['structured_data']
    assert 'pack_voltage_volts' in sd['corrupted_fields'] and sd['pack_voltage_volts'] is None
    assert sd['voltage_unloaded_cell_volts'] == 0.0
    assert sd['state_of_charge_percent'] == 0
    assert sd['battery_current_amps'] == 0.0
    for k in ('voltage_unloaded_cell_volts', 'state_of_charge_percent', 'battery_current_amps'):
        assert k not in sd['corrupted_fields']
