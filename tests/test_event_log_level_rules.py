"""Tests for EVENT_LOG_LEVEL_RULES: levels set by what an event means, applied
before the keyword match in determine_log_level(). One case per rule, the
soft reset split both ways, and events the rules leave alone. Text entries
(type 0xFD) go through a synthetic legacy file end to end; counts, times,
bank and module numbers are invented."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import EVENT_LOG_LEVEL_RULES, determine_log_level, event_log_level
from test_legacy_timestamps import T1, _entries, _entry

CASES = {
    'can-bus-error': ('CAN2 STUFF error. count=37', 'WARNING'),
    'cib-routine': ('CIB timeout: 4321 ms', 'INFO'),
    'charger-fault-cleared': ('CHARGER 3: Overtemp fault cleared', 'INFO'),
    'read-failed-reset-defaults': ('Odometer Read Failed, Resetting to 12345 km', 'WARNING'),
    'sevcon-restart': ('Restarting Sevcon to clear cutout fault', 'WARNING'),
    'retrying': ('Precharge timeout on mod 7, retrying', 'WARNING'),
    'default-word': ('Making bank 2 default boot bank on BMS 5...', 'INFO'),
    'errors-cleared': ('Enabled bms 4 clear faults flag', 'INFO'),
    'watchdog-setup': ('Setting watchdog timeout to 17 seconds to allow bootloader time to start...', 'INFO'),
    'set-and-cleared': ('Fault set & cleared since last time faults logged: HIGH_THROTTLE', 'WARNING'),
    'non-critical-contactor': ('Sending non critical contactor open command to PackIO. TSIPS: 987ms', 'WARNING'),
    'bluetooth': ('RN-42 autoconnect sequence failed after 9  retries', 'WARNING'),
    'dash-comms': ('Failed to send nav pkt to dash. ISOTP_RET=6', 'WARNING'),
    'soft-reset-crash': ('CPU Soft Reset:            Hard Fault', 'ERROR'),
    'soft-reset-other': ('CPU Soft Reset:            Key cycle from charge fault shutdown', 'WARNING'),
    'abs-sila': ('ABS SILA reporting an error', 'WARNING'),
}

UNCHANGED = (
    'Chassis Isolation Fault',
    'CHARGER 3: Overtemp fault set',
    'SelfTest Failed. Flags: 0x0042',
    'Entering Critical Error Shutdown',
    'WDT Timeout.',
)


def _levels(texts):
    buf = bytearray()
    for i, text in enumerate(texts):
        buf += _entry(0xFD, T1 + i, text.encode('latin1') + b'\x00')
    return {e['event']: e['log_level'] for e in _entries(buf)}


def test_every_rule_has_a_case():
    assert {rule for rule, _, _ in EVENT_LOG_LEVEL_RULES} == set(CASES)


def test_each_rule_sets_its_level_end_to_end():
    got = _levels([text for text, _ in CASES.values()])
    for rule, (text, level) in CASES.items():
        assert got[text] == level, rule
        assert event_log_level(text) == level, rule


def test_soft_reset_split_both_ways():
    # The firmware pads the reason with a run of spaces; a leading space also occurs.
    crash = ['CPU Soft Reset:            Hard Fault', ' CPU Soft Reset:            Hard Fault']
    other = ['CPU Soft Reset:            Key cycle from charge fault shutdown',
             'CPU Soft Reset:            Key cycle from critical error shutdown.',
             'CPU Soft Reset: Failed to Hibernate',
             'CPU Soft Reset: Hibernate Aborted']
    got = _levels(crash + other)
    assert [got[t] for t in crash] == ['ERROR'] * 2
    assert [got[t] for t in other] == ['WARNING'] * 4


def test_rn42_retry_text_is_warning():
    assert event_log_level('Turn off command mode on RN-42 failed after 3 retries, toggling reset pin') == 'WARNING'
    assert event_log_level('RN-42 configuration FAILED') == 'WARNING'


def test_keep_events_stay_error():
    got = _levels(UNCHANGED)
    for text in UNCHANGED:
        assert got[text] == 'ERROR' == determine_log_level(text), text


def test_rules_do_not_widen_to_neighbouring_text():
    """Text that shares words with a rule but is not one of its events falls
    through to the keyword match."""
    for text in ('CAN2 bus off error', 'CHARGER 3: Overtemp fault set',
                 'CPU Soft Reset: Brownout fault', 'Settings Read Failed',
                 'Accelerometer Selftest Failed'):
        assert event_log_level(text) == determine_log_level(text) == 'ERROR', text
