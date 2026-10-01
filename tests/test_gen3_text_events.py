"""
Tests for Gen2.gen3_text_event(): structured_data parsed from Gen3 (FST) 0xFD
text entries, and the guarantee that Gen2.debug_message() leaves the event
text of those entries exactly as it was. Gen3 text payloads start with the
6-byte FST prefix; the message is payload[6:], NUL terminated. Evidence:
analysis/bms_fields_and_text_events.md.

Same conventions as the other files in this directory.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import BinaryTools, Gen2

ARTIFACT = b'\x00\xf0\xff\x00'


def _gen3(text, subsecond=161000):
    if isinstance(text, str):
        text = text.encode('latin1')
    return bytearray(struct.pack('<I', subsecond) + bytes([0, 1]) + text + b'\x00')


def test_charge_and_discharge_limits():
    sd = Gen2.gen3_text_event(_gen3('Ch limits: curr 143 cap 143 act 2147483647 pow 14829'))
    assert sd['text_event'] == 'limits' and sd['limit_direction'] == 'charge'
    assert (sd['limit_curr'], sd['limit_cap'], sd['limit_act'], sd['limit_pow']) == (143, 143, 2147483647, 14829)
    sd = Gen2.gen3_text_event(_gen3('Disch limits: curr 1279 cap 1279 act 0 pow 133656'))
    assert sd['limit_direction'] == 'discharge' and sd['limit_pow'] == 133656


def test_twelve_volt_charge_lines():
    for word, phase in (('Requesting', 'requesting'), ('Stopping', 'stopping'), ('Starting', 'starting')):
        sep = '  ' if word != 'Requesting' else ' '
        sd = Gen2.gen3_text_event(_gen3(
            f'{word} 12v charge.{sep}DC-DC 286904uV, Battery 13183824uV, Combined 12271050uV, Ambient 11C'))
        assert sd['text_event'] == 'twelve_volt_charge' and sd['charge_phase'] == phase
        assert sd['dc_dc_volts'] == 0.286904 and sd['battery_volts'] == 13.183824
        assert sd['combined_volts'] == 12.27105 and sd['ambient_temperature_c'] == 11
    sd = Gen2.gen3_text_event(_gen3('Stopping 12v charge.  DC-DC 1uV, Battery 2uV, Combined 3uV, Ambient -4C'))
    assert sd['ambient_temperature_c'] == -4


def test_module_registration_both_forms():
    sd = Gen2.gen3_text_event(_gen3('Registering Mod 2 (101829mV, 0 brick )'))
    assert sd['module_number'] == 2 and sd['module_voltage_volts'] == 101.829 and sd['brick_count'] == 0
    sd = Gen2.gen3_text_event(_gen3('Registering Module 1 ( 99000mV )'))
    assert sd['module_number'] == 1 and sd['module_voltage_volts'] == 99.0 and 'brick_count' not in sd


def test_fault_lines_and_unknown_codes():
    sd = Gen2.gen3_text_event(_gen3('Fault pending: HVIL_OPEN sets in 2 seconds'))
    assert (sd['fault_state'], sd['fault_code'], sd['fault_sets_in_seconds']) == ('pending', 'HVIL_OPEN', 2)
    sd = Gen2.gen3_text_event(_gen3('Fault cleared: INVALID/NO PACK TYPE'))
    assert sd['fault_state'] == 'cleared' and sd['fault_code'] == 'INVALID/NO PACK TYPE'
    assert 'fault_sets_in_seconds' not in Gen2.gen3_text_event(_gen3('Fault set: LPB+ LOW'))
    assert Gen2.gen3_text_event(_gen3('Fault set: INVALID/NO CEYPE')) is None     # damaged code


def test_bms_state_hibernate_and_precharge():
    assert Gen2.gen3_text_event(_gen3('Entering ZERO_BMS_STATE_PRECHARGE_COMPLETE'))['bms_state'] == 'PRECHARGE_COMPLETE'
    assert Gen2.gen3_text_event(_gen3('Entering ZERO_BMS_STATE_IDL')) is None
    sd = Gen2.gen3_text_event(_gen3('Saving Stats, Hibernating for 31536000 sec'))
    assert sd['hibernate_seconds'] == 31536000 and sd['storage_mode'] is True
    sd = Gen2.gen3_text_event(_gen3('Saving stats, hibernating for 3600 sec'))
    assert sd['hibernate_seconds'] == 3600 and sd['storage_mode'] is False
    assert Gen2.gen3_text_event(_gen3('Precharge: 95%'))['precharge_percent'] == 95
    assert Gen2.gen3_text_event(_gen3('Precharge complete')) is None


def test_page_boundary_artifact_inside_a_word_is_removed_before_matching():
    sd = Gen2.gen3_text_event(_gen3(b'Entering ZERO' + ARTIFACT + b'_BMS_STATE_IDLE'))
    assert sd['bms_state'] == 'IDLE' and sd['text'] == 'Entering ZERO_BMS_STATE_IDLE'


def test_damaged_or_other_text_is_not_parsed():
    for text in ('Saving stats, hibernating foN sec', 'Exiting Hibernate', 'Kill Sw = STOP',
                 'Ch limits: curr 14', 'Registering Mod 2 (1018'):
        assert Gen2.gen3_text_event(_gen3(text)) is None
    assert Gen2.gen3_text_event(bytearray(b'\xf0\xff\x00ting Hibernate\x00')) is None


def test_classic_text_entries_without_a_prefix_are_not_touched():
    assert Gen2.gen3_text_event(bytearray(b'Precharge: 95%\x00')) is None
    assert Gen2.gen3_text_event(bytearray(b'SOC:1,2,3\x00')) is None


def _raw_entry(payload, message_type=0xfd, timestamp=1_700_000_000):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def _parse(payload, gen3_text):
    import logging
    raw = _raw_entry(payload)
    length, entry, _ = Gen2.parse_entry(raw, 0, 0, logging.getLogger('t'), gen3_text=gen3_text)
    assert length == len(raw)
    return entry


def test_gen3_mbb_and_bms_text_entries_render_the_real_message():
    for marker_byte in (0x02, 0x01):            # MBB / BMS prefix marker values
        payload = _gen3('Saving Stats, Hibernating for 3600 sec')
        payload[5] = marker_byte
        entry = _parse(payload, gen3_text=True)
        assert entry['event'] == 'Saving Stats, Hibernating for 3600 sec'
        assert entry['structured_data']['hibernate_seconds'] == 3600
    entry = _parse(_gen3('Kill Sw = STOP'), gen3_text=True)
    assert entry['event'] == 'Kill Sw = STOP' and 'structured_data' not in entry


def test_log_level_prefixes_still_work_on_gen3_text():
    entry = _parse(_gen3('DEBUG: Turning ON DCDC'), gen3_text=True)
    assert entry['event'] == 'Turning ON DCDC' and entry['log_level'] == 'DEBUG'


def test_legacy_path_is_unchanged_by_the_gen3_flag_being_off():
    # The same bytes through the legacy path (gen3_text False) render exactly
    # as before: the string read from payload byte 0.
    payload = _gen3('Precharge: 95%')
    legacy = _parse(payload, gen3_text=False)
    assert legacy['event'] == Gen2.debug_message(payload)['event']      # junk, as before
    assert legacy['event'] != 'Precharge: 95%'
    classic = _parse(bytearray(b'Precharge: 95%\x00'), gen3_text=False)
    assert classic['event'] == 'Precharge: 95%' and 'structured_data' not in classic
    # and a classic entry is not affected by the debug_message() refactor
    out = Gen2.debug_message(bytearray(b'DEBUG: hello\x00'))
    assert out['event'] == 'hello' and out['log_level'] == 'DEBUG'


def test_marker_inside_a_message_is_shown_as_a_corrupted_span_not_deleted():
    payload = _gen3(b'Entering ZERO' + ARTIFACT + b'_STATE_IDLE')
    entry = _parse(payload, gen3_text=True)
    assert entry['event'] == 'Entering ZERO{corrupted: 4 bytes lost}_STATE_IDLE'
    # the structured parse keeps matching on the marker-removed form, as before
    rendered = Gen2.gen3_text_message(payload)
    assert rendered['parse_text'] == 'Entering ZERO_STATE_IDLE' and rendered['bytes_lost'] == 4


def test_marker_overlapping_the_start_of_the_message():
    payload = bytearray(struct.pack('<I', 161000) + b'\x00' + b'\x00\xf0\xff\x00' + b'ting Hibernate\x00')
    payload = payload[:5] + bytearray(b'\x00\xf0\xff\x00ting Hibernate\x00')   # marker at byte 5
    rendered = Gen2.gen3_text_message(payload)
    assert rendered['display'] == '{corrupted: 3 bytes lost}ting Hibernate' and rendered['bytes_lost'] == 3


def test_message_destroyed_by_the_marker_follows_the_corrupted_convention():
    entry = _parse(_gen3(ARTIFACT), gen3_text=True)
    assert entry['event'] == '{corrupted: 4 bytes lost}'
    assert entry['structured_data']['bytes_corrupted'] is True
    assert entry['structured_data']['corrupted_byte_count'] == 4


def test_damaged_tail_bytes_are_shown_as_undecoded_hex_not_garbage():
    entry = _parse(_gen3(b'Saving stats,\xb2FM\xe2'.replace(b'\xb2', b'\xb3')), gen3_text=True)
    assert entry['event'] == 'Saving stats,{undecoded hex: b3 46 4d e2}'


def test_prefix_damage_without_a_marker_is_left_to_the_legacy_decoder():
    damaged = bytearray(b'p_\xfa\xff\xff\xff\x1d\xd8\x03\x04\x06')
    assert Gen2.gen3_text_message(damaged) is None
    assert _parse(damaged, gen3_text=True)['event'] == _parse(damaged, gen3_text=False)['event']
    # a legacy BMS sibling-format entry: two odd bytes then plain text, unchanged
    sibling = bytearray(b'\x90\xd6full_precharge: 132, command_delay: 5\x00')
    assert _parse(sibling, gen3_text=True)['event'] == _parse(sibling, gen3_text=False)['event']
    # a marker over the sub-second field leaves the message readable
    marked = bytearray(ARTIFACT[:4] + b'\x01\x01' + b'Fault cleared: HVIL_OPEN\x00')
    entry = _parse(marked, gen3_text=True)
    assert entry['event'] == 'Fault cleared: HVIL_OPEN'
    assert entry['structured_data']['fault_code'] == 'HVIL_OPEN'



def test_plain_text_entries_in_a_rev3_file_are_left_to_the_legacy_decoder():
    # log_version REV3 also covers legacy-platform ring-buffer files whose text
    # has no FST prefix: it must render exactly as it did, not as undecoded hex.
    entry = _parse(bytearray(b'DEBUG: Reset: Power-On\x00'), gen3_text=True)
    assert entry['event'] == 'Reset: Power-On' and entry['log_level'] == 'DEBUG'
    assert Gen2.gen3_text_message(bytearray(b'INFO:  Enabling charger\x00')) is None


def test_legacy_path_keeps_the_structured_data_it_had_for_prefixed_payloads():
    # Files outside the FST path (unknown log_version) that nonetheless carry
    # the prefix: debug_message() gives them the same structured_data as before.
    out = Gen2.debug_message(_gen3('Precharge: 95%'))
    assert out['structured_data']['precharge_percent'] == 95
