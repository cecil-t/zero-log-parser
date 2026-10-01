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


def test_event_text_is_left_exactly_as_before():
    payload = _gen3('Precharge: 95%')
    out = Gen2.debug_message(payload)
    # parse_entry() would have run improve_message_parsing() on the plain
    # event; the structured path applies the same call, so the text matches.
    from zero_log_parser import improve_message_parsing
    plain = BinaryTools.unpack_str(payload, 0x0, count=len(payload) - 1)
    expected = improve_message_parsing(plain, '')[:2]
    assert (out['event'], out['conditions']) == expected
    assert out['structured_data']['precharge_percent'] == 95
    out = Gen2.debug_message(_gen3('Kill Sw = STOP'))
    assert 'structured_data' not in out
