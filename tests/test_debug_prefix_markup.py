"""The level prefix ("DEBUG:", "INFO:", "ERROR:", "WARNING:") is removed with
the space after it, and only the prefix is cut: a line whose next character
is not a space keeps it, so a marker span tag right after the prefix stays
intact. event_as_read keeps its earlier form. Invented text only."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

MARK = b'\x00\xf0\xff\x00'


def test_prefix_and_space_removed():
    for line, event, level in (('DEBUG: Could not read FLASH', 'Could not read FLASH', 'DEBUG'),
                               ('INFO: Contactor open', 'Contactor open', 'INFO'),
                               ('ERROR: Fault set', 'Fault set', 'ERROR'),
                               ('WARNING: Low cell', 'Low cell', 'WARNING')):
        entry = Gen2._debug_text_entry(line)
        assert entry['event'] == event and entry['log_level'] == level


def test_span_tag_right_after_the_prefix_stays_intact():
    entry = Gen2._debug_text_entry('DEBUG:{corrupted: 4 bytes lost}ld not read FLASH')
    assert entry['event'] == '{corrupted: 4 bytes lost}ld not read FLASH'
    assert entry['log_level'] == 'DEBUG'


def _table(rows):
    Gen2._gen3_text_index_cache.clear()
    Gen2._gen3_restore_cache.clear()
    idx = Gen2.gen3_text_index([{'id': i, 't': [list(tk) for tk in toks]} for i, toks in rows])
    for key in ('BMS', 'MBB', 'ALL'):
        Gen2._gen3_text_index_cache[key] = idx


def test_restored_line_keeps_its_tag_and_event_as_read_is_unchanged():
    _table([('B1', [('lit', 'DEBUG: Could not read FLASH at address '), ('H', 10, 10)])])
    try:
        text = b'DEBUG:' + MARK + b'ld not read FLASH at address 0x0012ABCD'
        payload = struct.pack('<I', 161000) + bytes([0, 1]) + text + b'\x00'
        entry = Gen2.gen3_debug_message(bytearray(payload), 'BMS')
        assert entry['event'] == '{restored:  Cou}ld not read FLASH at address 0x0012ABCD'
        assert entry['event_as_read'] == 'corrupted: 4 bytes lost}ld not read FLASH at address 0x0012ABCD'
        assert entry['restored_spans'] == [{'offset': 6, 'length': 4, 'text': ' Cou'}]
    finally:
        Gen2._gen3_text_index_cache.clear()
        Gen2._gen3_restore_cache.clear()
