"""Tests for the log level of Gen3 fault state text ("Fault set|pending|cleared:
NAME"): set is ERROR, pending WARNING, cleared INFO, whatever the FAULT
keyword in determine_log_level() says. Other messages keep their level.
Payloads are built the way test_gen3_text_events.py builds them; the seconds
values and the unknown fault code are invented."""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2, determine_log_level


def _gen3(text, subsecond=161000):
    return bytearray(struct.pack('<I', subsecond) + bytes([0, 1]) + text.encode('latin1') + b'\x00')


def _level(text):
    return Gen2.gen3_debug_message(_gen3(text))['log_level']


def test_fault_set_is_error():
    assert _level('Fault set: HVIL_OPEN') == 'ERROR'


def test_fault_pending_is_warning():
    assert _level('Fault pending: HVIL_OPEN sets in 7 seconds') == 'WARNING'


def test_fault_cleared_is_info():
    assert _level('Fault cleared: HVIL_OPEN') == 'INFO'


def test_legacy_debug_path_gives_the_same_levels():
    for text, want in (('Fault set: DC_DC_LOW', 'ERROR'),
                       ('Fault pending: DC_DC_LOW sets in 3 seconds', 'WARNING'),
                       ('Fault cleared: DC_DC_LOW', 'INFO')):
        assert Gen2.debug_message(_gen3(text))['log_level'] == want


def test_fault_code_unknown_to_the_table_uses_the_text():
    """No structured_data for a code outside GEN3_FAULT_CODES; the event
    text still carries the state."""
    entry = Gen2.gen3_debug_message(_gen3('Fault cleared: NOT_A_REAL_CODE_X9'))
    assert 'structured_data' not in entry or entry['structured_data'] is None
    assert entry['log_level'] == 'INFO'


def test_restored_display_text_uses_the_structured_state():
    """A restored line shows {restored: ...} spans inside the event text; the
    state comes from the structured data parsed from the restored text."""
    sd = {'text': 'Fault cleared: HVIL_OPEN', 'text_event': 'fault', 'fault_state': 'cleared',
          'fault_code': 'HVIL_OPEN', 'from_restored_text': True}
    entry = Gen2._debug_text_entry('Fa{restored: ult }cleared: HVIL_OPEN', sd)
    assert entry['log_level'] == 'INFO'


def test_withheld_fault_state_falls_back_to_the_text():
    sd = {'text': 'Fault set: HVIL_OPEN', 'text_event': 'fault', 'fault_state': None, 'fault_code': None}
    assert Gen2._debug_text_entry('Fault set: HVIL_OPEN', sd)['log_level'] == 'ERROR'


def test_non_fault_messages_keep_their_level():
    """Messages that are not fault state text are left to determine_log_level()
    (or their explicit level) as before, including the "set & cleared" form."""
    for text in ('CAN1 ACK error. count=12',
                 'Fault set & cleared since last time faults logged: HVIL_OPEN',
                 'Updating bank bootable/default settings...'):
        entry = Gen2.gen3_debug_message(_gen3(text))
        assert entry['log_level'] is None
        assert determine_log_level(entry['event']) == 'ERROR'
    assert Gen2.gen3_debug_message(_gen3('WARNING: low aux battery'))['log_level'] == 'WARNING'
