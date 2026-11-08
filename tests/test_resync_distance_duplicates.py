"""
Tests for the zero-length entry step in LogData._collect_and_process_entries's
REV0/REV1/REV3 (non-paged) loop.

The duplicate case needs two things at once: the file's last real entry is a
zero-length delimiter (0xb2 followed by a 0x00 length byte), and that entry's
0xb2 sits some distance after the point the preceding entry's length advanced
read_pos to (non-entry padding between them). With no further 0xb2 in the
buffer, stepping to read_pos + 1 found and emitted that same entry again once
per padding byte, until the loop's entries_count budget ran out. A zero-length
entry with no padding before it only produces the single trailing phantom
entry this loop already emits, and these tests check that shape too.

Plain test_* functions, stdlib only, synthetic in-process buffers.
"""

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import LogFile, LogData


def _entry(message_type, timestamp, payload):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def _write_minimal_rev0_file(path, entries_bytes):
    """Same minimal REV0 builder test_undecoded_and_corrupted_rendering.py
    uses: MBB magic, an a1a1a1a1 fencepost, an a2a2a2a2 event-log header
    pointing at the given already-framed entry bytes."""
    header = bytearray(0x600)
    header[0:4] = b'MBB\x00'
    header[0x26:0x2a] = b'\xa1\xa1\xa1\xa1'
    header[0x2a:0x2a + 20] = b'Jan  1 2020 00:00:00'
    entries_start = 0x610
    entries_end = entries_start + len(entries_bytes)
    header += b'\xa2\xa2\xa2\xa2'
    header += struct.pack('<III', entries_end, entries_start, len(entries_bytes))
    header += b'\x00' * (entries_start - len(header))
    buf = bytes(header) + bytes(entries_bytes)
    with open(path, 'wb') as f:
        f.write(buf)


def _decode(entries_bytes):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'test.bin')
        _write_minimal_rev0_file(path, entries_bytes)
        ld = LogData(LogFile(path), timezone_offset=0)
        return ld._processed_entries


def _gap_then_trailing_zero_length_entry(gap=20):
    """entry0, entry1, `gap` bytes of non-entry padding, a zero-length entry,
    then 50 bytes with no further 0xb2. entries_count is the number of 0xb2
    bytes in the buffer, so entry0's payload carries 20 0xb2 data bytes to give
    the loop more budget than there are real entries, as stray 0xb2 bytes do
    in real logs. Without that the loop stops after three entries whatever
    the step does."""
    entries = bytearray()
    entries += _entry(0x01, 1_700_000_000, bytes([0xb2] * 20))
    entries += _entry(0x01, 1_700_000_100, bytes(5))
    entries += b'\xff' * gap
    entries += bytearray([0xb2, 0x00])
    entries += b'\x00' * 50
    return entries


def test_trailing_zero_length_entry_after_a_gap_is_not_duplicated():
    # Before the fix this shape emitted the zero-length entry 21 times.
    entries = _gap_then_trailing_zero_length_entry()

    processed = _decode(entries)
    events = [(e.message_type, e.event) for e in processed]

    # Exactly one real zero-length entry, not a run of duplicates of it.
    board_status = [e for e in events if e[1] == 'Board Status']
    assert len(board_status) <= 2, (
        f'expected at most one real zero-length entry plus the trailing '
        f'phantom, got {len(board_status)}: {board_status}')

    reset_events = [e for e in events if e[1] == 'BMS Reset']
    assert len(reset_events) == 2


def test_padding_before_trailing_zero_length_entry_changes_nothing():
    # The same entries with and without the 20 padding bytes before the
    # zero-length entry: padding is not an entry and must not repeat one.
    def signatures(gap):
        entries = _gap_then_trailing_zero_length_entry(gap)
        return sorted((e.message_type, e.original_timestamp, e.event) for e in _decode(entries))

    assert signatures(20) == signatures(0)


def test_zero_length_entry_with_no_gap_before_it_is_unaffected():
    # No padding between entry1 and the zero-length entry: read_pos already
    # equals its position, so the old step also produced only the one
    # trailing phantom. The fix leaves this shape unchanged.
    entries = bytearray()
    entries += _entry(0x01, 1_700_000_000, bytes(5))
    entries += bytearray([0xb2, 0x00])
    entries += b'\x00' * 50

    processed = _decode(entries)
    board_status = [e for e in processed if e.event == 'Board Status']
    assert len(board_status) == 1


def test_normal_trailing_entry_with_leftover_budget_still_gets_one_phantom_not_many():
    # A normal (non-zero-length) last entry with nothing after it never
    # reaches the zero-length branch. The single trailing phantom the loop
    # produces when entries_count overcounts (here, one 0xb2 data byte in a
    # payload) is unchanged: one phantom, not a run of them.
    entries = bytearray()
    entries += _entry(0x01, 1_700_000_000, bytes(5))
    entries += _entry(0x01, 1_700_000_100, bytes([0xb2, 1, 2, 3, 4]))  # one incidental 0xb2 data byte

    processed = _decode(entries)
    events = [e.event for e in processed]
    assert events.count('BMS Reset') == 2
    assert events.count('Board Status') == 1
