"""Tests for tools/build_gen3_text_templates.py: which messages become templates (seen intact in at least two
different files, observed messages only), what becomes a slot (only a number that varies), provenance, and
determinism."""

import collections
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))
from build_gen3_text_templates import build_templates, segments_of, table_document


def _file(board, **lines):
    return {'board': board, 'intact': collections.Counter(lines), 'damaged': []}


def test_a_message_needs_two_different_files():
    files = {'a': _file('BMS', **{'Entering ZERO_BMS_STATE_IDLE': 5, 'Seen once only': 3}),
             'b': _file('BMS', **{'Entering ZERO_BMS_STATE_IDLE': 2})}
    t = build_templates(files, 2)
    texts = [x['t'] for x in t['BMS']]
    assert texts == [[['lit', 'Entering ZERO_BMS_STATE_IDLE']]]
    assert t['BMS'][0]['files'] == 2 and t['BMS'][0]['count'] == 7 and t['BMS'][0]['id'] == 'B0001'
    assert build_templates(files, 1)['BMS'][1]['t'] == [['lit', 'Seen once only']]


def test_a_number_is_a_slot_only_where_it_varies():
    files = {'a': _file('BMS', **{'Saving stats, hibernating for 3600 sec': 1, 'CAN0 queue 7 full': 1}),
             'b': _file('BMS', **{'Saving stats, hibernating for 86400 sec': 1, 'CAN0 queue 9 full': 1})}
    t = {tuple(map(tuple, x['t'])): x for x in build_templates(files, 2)['BMS']}
    keys = list(t)
    assert (('lit', 'Saving stats, hibernating for '), ('N', 4, 5), ('lit', ' sec')) in keys
    # the 0 in CAN0 never varies: fixed text; only the queue number is a slot
    assert (('lit', 'CAN0 queue '), ('N', 1, 1), ('lit', ' full')) in keys


def test_hex_slot_and_boards_are_kept_apart():
    files = {'a': _file('MBB', **{'Fault 0x00000001': 1}), 'b': _file('MBB', **{'Fault 0x000000a2': 1}),
             'c': _file('BMS', **{'Fault 0x00000001': 1}), 'd': _file('BMS', **{'Fault 0x00000001': 1})}
    t = build_templates(files, 2)
    assert t['MBB'][0]['t'] == [['lit', 'Fault '], ['H', 10, 10]]
    assert t['BMS'][0]['t'] == [['lit', 'Fault 0x00000001']]


def test_output_is_deterministic_and_has_provenance():
    files = {k: _file('BMS', **{'Hello world': 1}) for k in ('c', 'a', 'b')}
    one = table_document(build_templates(files, 2), files, 2)
    two = table_document(build_templates(dict(reversed(list(files.items()))), 2), files, 2)
    assert one == two
    row = one['boards']['BMS'][0]
    assert set(row) == {'id', 't', 'files', 'count', 'ex'} and row['ex'] == sorted(row['ex']) and len(row['ex']) == 3


def test_segments_of_splits_a_display_line_on_its_corrupted_spans():
    assert segments_of('ab{corrupted: 4 bytes lost}cd') == [('t', 'ab'), ('gap', 4), ('t', 'cd')]
    assert segments_of('{corrupted: 3 bytes lost}x') == [('gap', 3), ('t', 'x')]
