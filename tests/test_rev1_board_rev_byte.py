"""REV1 MBB header Board rev.: the byte at 0x269, after a constant 0xa4 at 0x268."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from zero_log_parser import LogData, REV0, REV1


def test_rev1_board_rev_is_the_byte_after_0xa4():
    for rev in (1, 7, 8, 11, 12, 13, 14):
        raw = bytes(0x268) + bytes([0xa4, rev, 0x00, 0xaa])
        assert LogData.classic_board_rev(raw, 0x268, REV1) == rev


def test_other_contents_keep_the_uint16_read():
    assert LogData.classic_board_rev(bytes(0x268) + b'\x00\x00\x00\x00', 0x268, REV1) == 0
    assert LogData.classic_board_rev(bytes(0x268) + b'\xff\xff\xff\xff', 0x268, REV1) == 0xffff
    # REV0 keeps its uint16 field even if a 0xa4 byte happens to be there
    assert LogData.classic_board_rev(bytes(0x27d) + b'\xa4\x03', 0x27d, REV0) == 0x03a4
    assert LogData.classic_board_rev(bytes(0x27d) + b'\x03\x00', 0x27d, REV0) == 3
