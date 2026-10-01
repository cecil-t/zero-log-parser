"""
Tests for the crash fixes: files that cannot be decoded at all now raise
UnreadableLogError with a plain reason instead of a bare TypeError
("'>=' not supported between NoneType and int", no 0xb2 marker) or
struct.error (file shorter than the classic fixed-offset header).

Same conventions as the other files here: plain test_* functions, stdlib
only, synthetic in-process files, no dataset files checked in.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import LogFile, LogData, UnreadableLogError


def _load(name, data):
    d = tempfile.mkdtemp()
    p = os.path.join(d, name)
    with open(p, 'wb') as f:
        f.write(data)
    return LogData(LogFile(p), timezone_offset=0, verbosity_level=0)


def _reason(name, data):
    try:
        _load(name, data)
    except UnreadableLogError as e:
        return str(e)
    raise AssertionError('expected UnreadableLogError for %s' % name)


def test_text_export_is_reported_as_text():
    msg = _reason('export.bin', b'\r\n\r\n' + b'*' * 40 + b'\r\nZero MBB log\r\n' * 50)
    assert 'is text' in msg and 'not a Zero binary log' in msg


def test_erased_flash_image():
    msg = _reason('BMS0.bin', b'\xff' * 131072)
    assert 'erased flash image' in msg


def test_all_zero_file():
    assert 'all zero bytes' in _reason('x.bin', b'\x00' * 4096)


def test_binary_without_entry_marker():
    # not text, not erased, no 0xa2a2a2a2 header, no 0xb2 byte anywhere
    data = bytes((i * 7) % 0xb0 + 1 for i in range(2000))
    assert b'\xb2' not in data and b'\xa2\xa2\xa2\xa2' not in data
    assert 'no log entries found' in _reason('mystery.bin', data)


def test_truncated_classic_mbb_header():
    # 256 bytes of a classic file: far shorter than the VIN offsets at 0x240
    msg = _reason('538XXDZ42NCC17248_MBB_2022-03-22.bin', b'\x00@\x07\x00\x00\x00\x00\x00' * 32)
    assert '256 bytes' in msg and 'classic VIN fields' in msg


def test_truncated_classic_bms_header():
    # unknown version byte falls back to the REV0 layout, which reads the
    # serials at 0x300; a 512 byte fragment cannot hold them
    data = bytearray(b'\xa3\xa3\xa3\xa3\xb8\x06\x00\x00' + b'\x80' * 504)
    msg = _reason('fragment_BMS0.bin', bytes(data))
    assert '512 bytes' in msg and 'BMS serial numbers' in msg


def test_message_has_no_traceback_text():
    msg = _reason('t.bin', b'\xff' * 64)
    assert 'Traceback' not in msg and 'struct.error' not in msg
