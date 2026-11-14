"""
Tests for entry types 0x4B / 0x4C / 0x4D ("State Snapshot") in
Gen2.state_snapshot(): one record family in three sizes (46 / 77 / 89
payload bytes) carrying a 4-byte null-padded ASCII state tag at a fixed
offset relative to the end of a telemetry sub-block that widens by 4 bytes
per tier (tag at payload offset 35 / 39 / 43).

Same conventions as the other files in this directory: plain test_*
functions, stdlib only. Every input is a synthetic buffer built in-process
from the layout documented in analysis/atomicdog_family_decode.md and
analysis/fst_part1_decoders.md; no dataset files are checked in. Bytes the
decoder does not interpret are filled with a deterministic pattern that
avoids 0xB2 and 0xFE (the entry header and escape bytes), so the same
payload can be wrapped in a raw entry for the parse_entry() test.
"""

import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

TIERS = {
    0x4b: ('small', 46, 35),
    0x4c: ('medium', 77, 39),
    0x4d: ('large', 89, 43),
}
ALL_TAGS = ['RUN', 'PWSU', 'CHRG', 'WAIT', 'STOP', 'HIB', 'WAKE', 'FWUP', 'STRT']


def _payload(message_type, tag=b'RUN\x00', subsecond=123000, prefix=0x02e6,
             length=None, tag_offset=None):
    """Synthetic payload for one tier. Filler bytes are 1..100 (never 0xB2 or
    0xFE); the u32 at 0 and the u16 at 4 are then overwritten, and the tag
    is placed at the tier's offset unless another offset is given."""
    _tier, size, offset = TIERS[message_type]
    if length is not None:
        size = length
    if tag_offset is not None:
        offset = tag_offset
    buf = bytearray((i % 100) + 1 for i in range(size))
    struct.pack_into('<I', buf, 0, subsecond)
    struct.pack_into('<H', buf, 4, prefix)
    buf[offset:offset + len(tag)] = tag
    return buf


def _tag(name):
    return name.encode('ascii').ljust(4, b'\x00')


def test_each_tier_decodes_state_and_tier():
    for message_type, (tier, _size, _offset) in TIERS.items():
        out = Gen2.state_snapshot(message_type, _payload(message_type, _tag('CHRG')))
        assert out['event'] == 'State Snapshot'
        sd = out['structured_data']
        assert sd['state'] == 'CHRG'
        assert sd['snapshot_tier'] == tier
        assert 'CHRG' in out['conditions'] and tier in out['conditions']


def test_all_nine_known_tags_decode_on_every_tier():
    for message_type in TIERS:
        for name in ALL_TAGS:
            out = Gen2.state_snapshot(message_type, _payload(message_type, _tag(name)))
            assert out['structured_data']['state'] == name, (message_type, name)


def test_prefix_fields_are_read_from_the_first_six_bytes():
    out = Gen2.state_snapshot(0x4b, _payload(0x4b, _tag('RUN'), subsecond=987000, prefix=0xf934))
    sd = out['structured_data']
    assert sd['subsecond_us'] == 987000
    assert sd['sequence'] == 0x34
    assert sd['marker'] == 0xf9


def test_leading_field_is_not_labelled_odometer():
    # The leading u32 matches odometer_m's scale but is a sub-second
    # timestamp fraction (analysis/fst_part1_decoders.md); it must not be
    # exposed under an odometer name.
    sd = Gen2.state_snapshot(0x4b, _payload(0x4b))['structured_data']
    assert not any('odo' in key for key in sd)


def test_raw_hex_preserves_the_whole_payload():
    for message_type in TIERS:
        payload = _payload(message_type, _tag('WAIT'))
        sd = Gen2.state_snapshot(message_type, payload)['structured_data']
        assert bytes.fromhex(sd['raw_hex']) == bytes(payload)


def test_tag_is_read_at_the_tier_specific_offset():
    # A valid tag at the 0x4B offset (35) must not make a 0x4C payload
    # decode: 0x4C's own tag slot (39) holds filler here.
    payload = _payload(0x4c, _tag('RUN'), tag_offset=35)
    out = Gen2.state_snapshot(0x4c, payload)
    assert 'structured_data' not in out
    assert out['conditions'].startswith('Raw data:')


def test_wrong_length_falls_back_to_raw_hex():
    # 45/47 around the small tier, the one real 40-byte truncated capture
    # (tag still readable at 35 but the record is short), and 0x4C/0x4D
    # payloads handed the wrong tier's size.
    cases = [(0x4b, 45), (0x4b, 47), (0x4b, 40), (0x4c, 76), (0x4d, 90), (0x4c, 89), (0x4d, 77)]
    for message_type, length in cases:
        out = Gen2.state_snapshot(message_type, _payload(0x4b, _tag('WAIT'), length=length))
        assert 'structured_data' not in out, (message_type, length)
        assert out['conditions'].startswith('Raw data:')


def test_unknown_or_malformed_tag_falls_back_to_raw_hex():
    bad_tags = [b'ABCD', b'RUNX', b'RU\x00N', b'\x00\x00\x00\x00', b'run\x00', b'REV\x00', b'\xff\xff\xff\xff']
    for tag in bad_tags:
        out = Gen2.state_snapshot(0x4b, _payload(0x4b, tag))
        assert 'structured_data' not in out, tag


def test_empty_payload_does_not_raise():
    out = Gen2.state_snapshot(0x4b, bytearray())
    assert out['event'] == 'Unknown Type 75'
    assert out['conditions'] == 'No additional data'


def test_fallback_keeps_the_unknown_type_label():
    # Anything not decoded reports exactly what it did before this decoder
    # existed, so output for entries that fall back is unchanged.
    for message_type in TIERS:
        out = Gen2.state_snapshot(message_type, bytearray(b'\x01\x02\x03'))
        assert out['event'] == 'Unknown Type %d' % message_type


def test_parse_entry_dispatches_all_three_types_end_to_end():
    logger = logging.getLogger('test_state_snapshot_decode')
    for message_type in TIERS:
        payload = _payload(message_type, _tag('PWSU') if message_type == 0x4b else _tag('CHRG'))
        timestamp = 1_600_000_000
        body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
        raw = bytearray([0xb2, len(body) + 2]) + bytearray(body)
        length, entry, _unhandled = Gen2.parse_entry(raw, 0, 0, logger)
        assert length == len(raw)
        assert entry['event'] == 'State Snapshot'
        assert entry['message_type'] == '0x%X' % message_type
        assert entry['structured_data']['state'] == ('PWSU' if message_type == 0x4b else 'CHRG')


def test_implausible_subsecond_value_falls_back_to_raw_hex():
    # No real entry has a sub-second value above 1,000,000 (the maximum seen
    # is exactly 1,000,000, which still decodes).
    assert 'structured_data' in Gen2.state_snapshot(0x4b, _payload(0x4b, _tag('RUN'), subsecond=1000000))
    for value in (1000001, 0x7fffffff, 0xffffffff):
        out = Gen2.state_snapshot(0x4b, _payload(0x4b, _tag('RUN'), subsecond=value))
        assert 'structured_data' not in out, value


# ---- the decoded block (atomicdog Gen3 datasheet periodic_small/medium/large, checked in
# analysis/gen3_mbb_partials.md section 4). All values are invented. ----

FIELDS = {
    0x4b: {'dcv': 14, 'rpm': 22, 'soc': 26, 'pv': 27, 'pi': 31, 'speed': 40},
    0x4c: {'dcv': 18, 'rpm': 26, 'soc': 30, 'pv': 31, 'pi': 35, 'speed': 44,
           'amb': 54, 't1': 58, 't2': 62, 'bh': 66, 'bl': 70, 'mods': 74},
    0x4d: {'dcv': 22, 'rpm': 30, 'soc': 34, 'pv': 35, 'pi': 39, 'speed': 48,
           'amb': 58, 't1': 62, 't2': 66, 'bh': 70, 'bl': 74},
}


def _measured(message_type, dcv=104300, pv=104512, pi=-23456, speed=48 * 56250, temps=(17, 41, 33, 22, 19)):
    buf = _payload(message_type, _tag('RUN'))
    o = FIELDS[message_type]
    struct.pack_into('<i', buf, o['dcv'], dcv)
    struct.pack_into('<i', buf, o['rpm'], 2713)
    buf[o['soc']] = 63
    struct.pack_into('<I', buf, o['pv'], pv)
    struct.pack_into('<i', buf, o['pi'], pi)
    struct.pack_into('<i', buf, o['speed'], speed)
    if 'amb' in o:
        for key, value in zip(('amb', 't1', 't2', 'bh', 'bl'), temps):
            struct.pack_into('<i', buf, o[key], value)
    if 'mods' in o:
        buf[o['mods']] = 2
    return buf


def test_every_tier_decodes_the_shared_block():
    for message_type in TIERS:
        sd = Gen2.state_snapshot(message_type, _measured(message_type))['structured_data']
        assert sd['dc_bus_voltage_volts'] == 104.3
        assert sd['motor_rpm'] == 2713
        assert sd['state_of_charge_percent'] == 63
        assert sd['pack_voltage_volts'] == 104.512
        assert sd['battery_current_amps'] == -23.456
        assert sd['speed_kmh'] == 2.7               # 48 x 56,250 mm/h
        assert sd['state'] == 'RUN'


def test_medium_and_large_tiers_decode_temperatures():
    for message_type in (0x4c, 0x4d):
        sd = Gen2.state_snapshot(message_type, _measured(message_type))['structured_data']
        assert (sd['ambient_temperature_c'], sd['motor_temp_c'], sd['inverter_temp_c'],
                sd['pack_temperature_warmest_c'], sd['pack_temperature_coldest_c']) == (17, 41, 33, 22, 19)
    sd = Gen2.state_snapshot(0x4b, _measured(0x4b))['structured_data']
    assert 'ambient_temperature_c' not in sd and 'bms_modules_on_can' not in sd


def test_medium_tier_decodes_the_bms_module_count():
    assert Gen2.state_snapshot(0x4c, _measured(0x4c))['structured_data']['bms_modules_on_can'] == 2
    assert 'bms_modules_on_can' not in Gen2.state_snapshot(0x4d, _measured(0x4d))['structured_data']


def test_controller_fields_are_none_when_the_dc_bus_voltage_reads_zero():
    for message_type in TIERS:
        sd = Gen2.state_snapshot(message_type, _measured(message_type, dcv=0, temps=(17, 0, 0, 22, 19)))['structured_data']
        assert sd['dc_bus_voltage_volts'] is None and sd['motor_rpm'] is None
        assert sd['pack_voltage_volts'] == 104.512
        if message_type != 0x4b:
            assert sd['motor_temp_c'] is None and sd['inverter_temp_c'] is None
            assert sd['ambient_temperature_c'] == 17 and sd['pack_temperature_coldest_c'] == 19


def test_pack_fields_are_none_when_the_pack_voltage_reads_zero():
    for message_type in TIERS:
        out = Gen2.state_snapshot(message_type, _measured(message_type, pv=0, pi=0))
        sd = out['structured_data']
        assert sd['pack_voltage_volts'] is None and sd['battery_current_amps'] is None
        assert sd['state_of_charge_percent'] == 63
        assert 'Vpack:n/aV, I:n/aA' in out['conditions']


def test_negative_speed_and_out_of_range_temperatures_are_none():
    sd = Gen2.state_snapshot(0x4c, _measured(0x4c, speed=-56250, temps=(17, 41, 33, 500, 19)))['structured_data']
    assert sd['speed_kmh'] is None
    assert sd['pack_temperature_warmest_c'] is None and sd['pack_temperature_coldest_c'] == 19


def test_negative_temperatures_decode():
    sd = Gen2.state_snapshot(0x4d, _measured(0x4d, temps=(-7, 41, 33, -3, -5)))['structured_data']
    assert (sd['ambient_temperature_c'], sd['pack_temperature_warmest_c'], sd['pack_temperature_coldest_c']) == (-7, -3, -5)


def test_conditions_carry_state_tier_and_pack_summary():
    out = Gen2.state_snapshot(0x4b, _measured(0x4b))
    assert out['conditions'] == 'State: RUN, tier: small, SOC:63%, Vpack:104.512V, I:-23.456A, speed:2.7km/h'
