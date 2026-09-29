"""
Tests for the resync-distance fix in LogData._collect_and_process_entries's
REV0/REV1/REV3 (non-paged) loop. See analysis/
marker_masking_and_duplicate_entries.md for the full characterization.

The trigger requires two things at once: the file's own last real entry is a
zero-length delimiter (0xb2 followed by a 0x00 length byte), AND that
entry's own 0xb2 sits some distance after the point the PRECEDING entry's
own length advanced read_pos to (a gap of non-entry padding between them).
When nothing follows the zero-length entry (no further 0xb2 anywhere), the
old code's `read_pos = read_pos + 1` fallback re-found and re-emitted that
same entry once per byte of that gap, before the loop's fixed entries_count
budget ran out. A zero-length entry with NO gap before it (read_pos already
equal to its own position) only ever produces the one already-documented,
harmless trailing phantom entry (out of scope, left unchanged here) - this
file's tests distinguish the two shapes rather than only checking the buggy
one.

Same conventions as the other files in this directory: plain test_*
functions, stdlib only, synthetic in-process buffers, no dataset files
checked in.
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


def test_trailing_zero_length_entry_after_a_gap_is_not_duplicated():
    # entry0, entry1, then 20 bytes of non-entry padding, then a real
    # zero-length entry, then an unrecoverable gap with no further 0xb2 -
    # exactly the shape that produced 22 duplicate entries before this fix.
    entries = bytearray()
    entries += _entry(0x01, 1_700_000_000, bytes(5))
    entries += _entry(0x01, 1_700_000_100, bytes(5))
    entries += b'\xff' * 20
    entries += bytearray([0xb2, 0x00])
    entries += b'\x00' * 50

    processed = _decode(entries)
    events = [(e.message_type, e.event) for e in processed]

    # Exactly one real zero-length entry, not a run of duplicates of it.
    board_status = [e for e in events if e[1] == 'Board Status']
    assert len(board_status) <= 2, (
        f'expected at most one real zero-length entry plus the one already-'
        f'documented trailing phantom, got {len(board_status)}: {board_status}')

    reset_events = [e for e in events if e[1] == 'BMS Reset']
    assert len(reset_events) == 2


def test_each_byte_span_is_decoded_at_most_once():
    # The general correctness property this fix restores: no two entries in
    # the output share the same (message_type, original_timestamp, event)
    # triple from a genuinely duplicated decode of one span. (Two
    # *different* real entries coincidentally matching on all three is not
    # what this checks for; the synthetic buffer here has none such.)
    entries = bytearray()
    entries += _entry(0x01, 1_700_000_000, bytes(5))
    entries += _entry(0x01, 1_700_000_100, bytes(5))
    entries += b'\xff' * 20
    entries += bytearray([0xb2, 0x00])
    entries += b'\x00' * 50

    processed = _decode(entries)
    signature_counts = {}
    for e in processed:
        sig = (e.message_type, e.original_timestamp, e.event)
        signature_counts[sig] = signature_counts.get(sig, 0) + 1
    duplicated = {sig: n for sig, n in signature_counts.items() if n > 1}
    assert not duplicated, f'entries decoded more than once: {duplicated}'


def test_zero_length_entry_with_no_gap_before_it_is_unaffected():
    # No padding between entry1 and the zero-length entry - read_pos already
    # equals its own position, so even the OLD code only ever produced the
    # one harmless trailing phantom, never a duplicate. This fix must not
    # change that shape (out of scope, per the task).
    entries = bytearray()
    entries += _entry(0x01, 1_700_000_000, bytes(5))
    entries += bytearray([0xb2, 0x00])
    entries += b'\x00' * 50

    processed = _decode(entries)
    board_status = [e for e in processed if e.event == 'Board Status']
    assert len(board_status) == 1


def test_normal_trailing_entry_with_leftover_budget_still_gets_one_phantom_not_many():
    # A normal (non-zero-length) last entry with nothing after it: this
    # fix's own lines (the zero-length branch) are never reached at all for
    # it (length > 0 always takes the other, untouched branch), so the
    # already-documented single trailing phantom this loop can produce when
    # entries_count overcounts (one incidental 0xb2 data byte in a payload,
    # here) is unchanged by this fix - one phantom, never a run of them.
    entries = bytearray()
    entries += _entry(0x01, 1_700_000_000, bytes(5))
    entries += _entry(0x01, 1_700_000_100, bytes([0xb2, 1, 2, 3, 4]))  # one incidental 0xb2 data byte

    processed = _decode(entries)
    events = [e.event for e in processed]
    assert events.count('BMS Reset') == 2
    assert events.count('Board Status') == 1
