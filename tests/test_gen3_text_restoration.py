"""
Tests for the restoration of page-marker-damaged Gen3 text from a fixed table of known messages
(Gen2.gen3_text_message / gen3_debug_message / gen3_text_event with a board), and for the newline rules
(a trailing newline is dropped, one inside the message is kept and shown as " | " in text and tabular
output). Rule: restore only when exactly one template matches every surviving byte, under exactly one
reading of the marker (it overwrote four characters, or it was inserted), and every lost character falls
in fixed text, never inside a variable number.

Same conventions as the other files in this directory: plain test_* functions, stdlib only, synthetic
in-process buffers. The unit tests inject their own tiny table; the end-to-end test uses the shipped one.
"""

import logging
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2, LogData, LogFile, ProcessedLogEntry
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))
from coverage_audit import final_class

MARK = b'\x00\xf0\xff\x00'


def _gen3(text, subsecond=161000):
    if isinstance(text, str):
        text = text.encode('latin1')
    return bytearray(struct.pack('<I', subsecond) + bytes([0, 1]) + text + b'\x00')


def _table(bms=(), mbb=()):
    """Install a tiny table: each template is (id, [tokens]); tokens are ('lit', text) or ('N', lo, hi)."""
    def idx(rows):
        return Gen2.gen3_text_index([{'id': i, 't': [list(tk) for tk in toks]} for i, toks in rows])
    Gen2._gen3_text_index_cache.clear()
    Gen2._gen3_restore_cache.clear()
    Gen2._gen3_text_index_cache['BMS'] = idx(bms)
    Gen2._gen3_text_index_cache['MBB'] = idx(mbb)
    Gen2._gen3_text_index_cache['ALL'] = idx(list(bms) + list(mbb))


def _reset():
    Gen2._gen3_text_index_cache.clear()
    Gen2._gen3_restore_cache.clear()


def _parse(payload, board):
    raw = bytearray([0xb2, len(payload) + 7, 0xfd]) + bytearray(struct.pack('<I', 1_700_000_000)) + bytearray(payload)
    length, entry, _ = Gen2.parse_entry(raw, 0, 0, logging.getLogger('t'), gen3_text=True, log_type=board)
    return entry


def test_fixed_text_restored_when_one_template_matches():
    _table(bms=[('B1', [('lit', 'Entering ZERO_BMS_STATE_IDLE')]), ('B2', [('lit', 'Entering ZERO_BMS_STATE_STANDBY')])])
    entry = _parse(_gen3(b'Entering ZERO' + MARK + b'_STATE_IDLE'), 'BMS')
    assert entry['event'] == 'Entering ZERO{restored: _BMS}_STATE_IDLE'
    assert entry['text_restored'] is True and entry['restoration_kind'] == 'strict'
    assert entry['template_id'] == 'B1' and entry['restoration_reading'] == 'overwrite'
    assert entry['restored_spans'] == [{'offset': 13, 'length': 4, 'text': '_BMS'}]
    assert entry['event_as_read'] == 'Entering ZERO{corrupted: 4 bytes lost}_STATE_IDLE'
    # the structured parse comes from the restored text and says so
    assert entry['structured_data']['bms_state'] == 'IDLE' and entry['structured_data']['from_restored_text'] is True
    _reset()


def test_parameterized_template_restores_fixed_text_around_a_surviving_number():
    _table(bms=[('B9', [('lit', 'Saving stats, hibernating for '), ('N', 1, 8), ('lit', ' sec')])])
    entry = _parse(_gen3(b'Saving stats, hiber' + MARK + b'ing for 3600 sec'.replace(b'ing', b'ng')), 'BMS')
    assert entry['event'] == 'Saving stats, hiber{restored: nati}ng for 3600 sec'
    assert entry['restoration_kind'] == 'parameterized'
    assert entry['structured_data']['hibernate_seconds'] == 3600
    _reset()


def test_a_lost_digit_is_never_restored():
    _table(bms=[('B9', [('lit', 'Saving stats, hibernating for '), ('N', 1, 8), ('lit', ' sec')])])
    entry = _parse(_gen3(b'Saving stats, hibernating for 36' + MARK[:4] + b'ec'), 'BMS')   # marker over the last digits
    assert 'text_restored' not in entry
    assert entry['event'] == 'Saving stats, hibernating for 36{corrupted: 4 bytes lost}ec'
    _reset()


def test_two_matching_templates_is_ambiguous_and_stays_damaged():
    _table(bms=[('B1', [('lit', 'Entering ZERO_BMS_STATE_IDLE')]), ('B2', [('lit', 'Entering ZERO_BMS_STATE_IDLX')])])
    entry = _parse(_gen3(b'Entering ZERO_BMS_STATE_' + MARK[:4]), 'BMS')    # IDLE or IDLX: the lost four fit both
    assert 'text_restored' not in entry and '{corrupted: 4 bytes lost}' in entry['event']
    _reset()


def test_no_template_stays_damaged():
    _table(bms=[('B1', [('lit', 'Entering ZERO_BMS_STATE_IDLE')])])
    entry = _parse(_gen3(b'Something else' + MARK + b' entirely'), 'BMS')
    assert 'text_restored' not in entry and entry['event'] == 'Something else{corrupted: 4 bytes lost} entirely'
    _reset()


def test_the_inserted_marker_reading_restores_without_a_tag():
    _table(bms=[('B1', [('lit', 'Faulted')])])
    entry = _parse(_gen3(b'Fault' + MARK + b'ed'), 'BMS')     # nothing was lost: the marker sat between the characters
    assert entry['event'] == 'Faulted' and entry['text_restored'] is True and entry['restoration_reading'] == 'inserted'
    assert entry['restored_spans'] == [{'offset': 5, 'length': 0, 'text': ''}]
    _reset()


def test_both_readings_fitting_is_ambiguous():
    _table(bms=[('B1', [('lit', 'abcdefgh')]), ('B2', [('lit', 'abcd')])])
    # 'abcd' + marker (4 lost) + nothing: overwrite fits abcdefgh, insert fits abcd
    entry = _parse(_gen3(b'abcd' + MARK), 'BMS')
    assert 'text_restored' not in entry
    _reset()


def test_board_selects_the_table_and_none_never_restores():
    _table(bms=[('B1', [('lit', 'Entering ZERO_BMS_STATE_IDLE')])], mbb=[('M1', [('lit', 'Cruise control turned on')])])
    damaged = _gen3(b'Entering ZERO' + MARK + b'_STATE_IDLE')
    assert _parse(damaged, 'BMS')['text_restored'] is True
    assert 'text_restored' not in _parse(damaged, 'MBB')               # other board's table has nothing for it
    assert 'text_restored' not in _parse(damaged, None)                # a direct call has no board
    assert _parse(damaged, 'Unknown Type')['text_restored'] is True    # unknown type tries both tables
    assert Gen2.gen3_text_message(damaged)['restored'] is None
    _reset()


def test_marker_over_the_start_of_the_message_can_be_restored():
    _table(bms=[('B1', [('lit', 'Exiting Hibernate')])])
    payload = bytearray(struct.pack('<I', 161000) + b'\x00') + bytearray(MARK + b'ing Hibernate\x00')
    payload = payload[:5] + bytearray(MARK + b'ting Hibernate\x00')       # marker at payload byte 5: three message bytes lost
    rendered = Gen2.gen3_text_message(payload, 'BMS')
    assert rendered['display'] == '{corrupted: 3 bytes lost}ting Hibernate'
    assert rendered['display_restored'] == '{restored: Exi}ting Hibernate'
    _reset()


def test_gen3_text_event_from_restored_text_carries_the_flag():
    _table(bms=[('B1', [('lit', 'Entering ZERO_BMS_STATE_IDLE')])])
    data = Gen2.gen3_text_event(_gen3(b'Entering ZERO' + MARK + b'_STATE_IDLE'), 'BMS')
    assert data['bms_state'] == 'IDLE' and data['from_restored_text'] is True
    assert 'from_restored_text' not in Gen2.gen3_text_event(_gen3('Entering ZERO_BMS_STATE_IDLE'), 'BMS')
    _reset()


def test_trailing_newline_is_dropped_and_not_undecoded():
    entry = _parse(_gen3(b'MTC pending change by 3 from 0 to 0\n'), 'MBB')
    assert entry['event'] == 'MTC pending change by 3 from 0 to 0' and 'undecoded' not in entry['event']
    assert not entry.get('event_has_newline')


def test_newline_inside_the_message_is_kept_and_flagged():
    entry = _parse(_gen3(b'first line\nsecond line'), 'MBB')
    assert entry['event'] == 'first line\nsecond line' and entry['event_has_newline'] is True
    entry = ProcessedLogEntry(1, 't', 0.0, 'INFO', 'first line\nsecond line', '', event_has_newline=True)
    assert LogData._event_text(entry) == 'first line | second line'
    other = ProcessedLogEntry(1, 't', 0.0, 'INFO', 'a\nb', '')
    assert LogData._event_text(other) == 'a\nb'            # only Gen3 text entries are rewritten


def test_newline_with_other_unreadable_bytes_and_erased_runs_stay_undecoded():
    entry = _parse(_gen3(b'Saving stats,\n\xaa\xaa\xaa\xaa'), 'MBB')
    assert '{undecoded hex:' in entry['event']
    entry = _parse(_gen3(b'Saving stats,\xaa\xaa\xaa\xaa'), 'MBB')
    assert entry['event'] == 'Saving stats,{undecoded hex: aa aa aa aa}'


def test_classifier_order_partial_damaged_restored_full():
    assert final_class('layout unknown bytes', True, True) == 'partial'
    assert final_class(None, True, False) == 'damaged'
    assert final_class(None, False, True) == 'restored'
    assert final_class(None, False, False) == 'full'


def test_end_to_end_with_the_shipped_table_text_and_json():
    import json
    entry0 = bytes(bytearray([0xb2, 0, 0xfd]) + struct.pack('<I', 1_700_000_000) + _gen3(b'Entering ZERO' + MARK + b'_STATE_IDLE'))
    entry0 = bytes([0xb2, len(entry0)]) + entry0[2:]
    buf = bytearray(entry0)
    buf += b'\xff' * (384 - len(buf))
    buf[128:132] = MARK
    buf[256:260] = MARK
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'test_BMS0.bin')
        with open(path, 'wb') as f:
            f.write(bytes(buf))
        ld = LogData(LogFile(path), timezone_offset=0)
        txt, js = os.path.join(d, 'o.txt'), os.path.join(d, 'o.json')
        ld.emit_zero_compatible_decoding(txt)
        ld.emit_json_decoding(js)
        text = open(txt, encoding='utf-8-sig').read()
        doc = json.load(open(js))
    assert 'Entering ZERO{restored: _BMS}_STATE_IDLE' in text and '{corrupted' not in text
    e = [x for x in doc['entries'] if x['event'].startswith('Entering ZERO')][0]
    assert e['text_restored'] is True and e['restoration_kind'] == 'strict' and e['template_id'].startswith('B')
    assert e['restored_spans'] == [{'offset': 13, 'length': 4, 'text': '_BMS'}]
    assert e['event_as_read'] == 'Entering ZERO{corrupted: 4 bytes lost}_STATE_IDLE'
