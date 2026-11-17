"""Walked entries that are erased flash (0xff after the 0xb2 and length byte) are not entries."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from zero_log_parser import Gen2


def test_erased_span_whole_length():
    buf = b'\x00' * 4 + b'\xb2\x3d' + b'\xff' * 59 + b'\xb2\x07\x2a\x01\x02\x03\x04'
    assert Gen2.is_erased_span(buf, (4, 0x3d))


def test_erased_span_stops_at_next_entry():
    # a length byte that runs into the next real entry: only the bytes before that 0xb2 count
    buf = b'\xb2' + b'\xff' * 37 + b'\xb2\x26\xfd' + b'\x00' * 300
    assert Gen2.is_erased_span(buf, (0, 255))


def test_real_entries_are_kept():
    assert not Gen2.is_erased_span(b'\xb2\x07\x2a\x01\x02\x03\x04', (0, 7))
    # an entry with some 0xff payload bytes but a real type byte
    assert not Gen2.is_erased_span(b'\xb2\x0c\x33' + b'\xff' * 9, (0, 12))
    # the fixed legacy padding block (0xff run then 0xa0 bytes) is not erased flash
    assert not Gen2.is_erased_span(b'\xb2' + b'\xff' * 10 + b'\xa0' * 20, (0, 0xff))
    assert not Gen2.is_erased_span(b'\xb2\xff\xff\xff', (0, 4))   # too short to be an entry
    assert not Gen2.is_erased_span(b'\xb2\xff', None)
