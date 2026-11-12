"""Tests for the log level of Gen3 fault state text ("Fault set|pending|cleared:
NAME"): set is ERROR, pending WARNING, cleared INFO, whatever the FAULT
keyword in determine_log_level() says. Other messages keep their level.
The seconds values and the second fault name are invented."""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2, determine_log_level


def _gen3(text, subsecond=161000):
    """A Gen3 0xFD payload: the 6-byte entry prefix, then the NUL-terminated text."""
    return bytearray(struct.pack('<I', subsecond) + bytes([0, 1]) + text.encode('latin1') + b'\x00')


def _level(text):
    return Gen2.gen3_debug_message(_gen3(text))['log_level']


def test_fault_set_is_error():
    assert _level('Fault set: HVIL_OPEN') == 'ERROR'


def test_fault_pending_is_warning():
    assert _level('Fault pending: HVIL_OPEN sets in 7 seconds') == 'WARNING'


def test_fault_cleared_is_info():
    assert _level('Fault cleared: HVIL_OPEN') == 'INFO'


def test_any_fault_name_uses_the_state():
    for text, want in (('Fault set: NOT_A_REAL_CODE_X9', 'ERROR'),
                       ('Fault pending: NOT_A_REAL_CODE_X9 sets in 3 seconds', 'WARNING'),
                       ('Fault cleared: NOT_A_REAL_CODE_X9', 'INFO')):
        assert _level(text) == want


def test_plain_text_debug_message_gives_the_same_levels():
    for text, want in (('Fault set: DC_DC_LOW', 'ERROR'),
                       ('Fault pending: DC_DC_LOW sets in 3 seconds', 'WARNING'),
                       ('Fault cleared: DC_DC_LOW', 'INFO')):
        assert Gen2.debug_message(bytearray(text.encode('latin1') + b'\x00'))['log_level'] == want


def test_non_fault_messages_keep_their_level():
    """Messages that are not fault state text get no level here, including
    the "set & cleared" form, and are left to determine_log_level() (or
    their explicit level) as before."""
    for text in ('CAN1 ACK error. count=12',
                 'Fault set & cleared since last time faults logged: HVIL_OPEN',
                 'Updating bank bootable/default settings...'):
        entry = Gen2.gen3_debug_message(_gen3(text))
        assert entry['log_level'] is None
        assert determine_log_level(entry['event']) == 'ERROR'
    assert Gen2.gen3_debug_message(_gen3('WARNING: low aux battery'))['log_level'] == 'WARNING'
