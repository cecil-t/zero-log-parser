"""Tests for the classic MBB model field: REV1 reads it at 0x26C, after the
lead byte at 0x26B, and REV0 at 0x27F, both as a 16-byte null-terminated
field. Synthetic header images, invented VINs and serial numbers."""

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import LogData, LogFile, REV0, REV1

WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
TRANSLIT = {c: i + 1 for i, c in enumerate('ABCDEFGH')}
TRANSLIT.update({c: i + 1 for i, c in enumerate('JKLMN')})
TRANSLIT.update({'P': 7, 'R': 9})
TRANSLIT.update({c: i + 2 for i, c in enumerate('STUVWXYZ')})
TRANSLIT.update({d: int(d) for d in '0123456789'})


def make_vin(tail):
    """A check-digit-valid invented VIN."""
    template = '538SMZZ00' + 'HCA' + tail
    total = sum(TRANSLIT[c] * w for c, w in zip(template, WEIGHTS))
    check = 'X' if total % 11 == 10 else str(total % 11)
    return template[:8] + check + template[9:]


VIN_A = make_vin('90001')
VIN_B = make_vin('90002')


def rev1_file(model, lead=0xaa, vin=VIN_A):
    buf = bytearray(0x40000)
    buf[0:4] = b'MBB\x00'
    buf[0x26:0x2a] = b'\xa1\xa1\xa1\xa1'
    buf[0x2a:0x3e] = b'Jan  2 2019 10:11:12'
    buf[0x210:0x21c] = b'TST000000001'
    buf[0x252:0x263] = vin.encode('ascii')
    struct.pack_into('<HH', buf, 0x266, 33, 2980)
    buf[0x26b] = lead
    buf[0x26c:0x26c + len(model)] = model
    return bytes(buf)


def rev0_file(model, vin=VIN_B):
    buf = bytearray(0x40000)
    buf[0:4] = b'MBB\x00'
    buf[0x26:0x2a] = b'\xa1\xa1\xa1\xa1'
    buf[0x2a:0x3e] = b'Mar  3 2015 10:11:12'
    buf[0x200:0x215] = b'2015_mbb_abcdef_00001'
    buf[0x240:0x251] = vin.encode('ascii')
    struct.pack_into('<HH', buf, 0x27b, 25, 3)
    buf[0x27f:0x27f + len(model)] = model
    return bytes(buf)


def parse(data):
    d = tempfile.mkdtemp()
    path = os.path.join(d, 'log.bin')
    with open(path, 'wb') as f:
        f.write(data)
    try:
        lf = LogFile(path)
        ld = object.__new__(LogData)
        ld.log_file = lf
        return ld.get_version_and_header(lf)
    finally:
        os.unlink(path)
        os.rmdir(d)


def test_rev1_four_character_model_after_0xaa_lead_byte():
    version, header = parse(rev1_file(b'DS11'))
    assert version == REV1
    assert header['VIN'] == VIN_A
    assert header['Model'] == 'DS11'


def test_rev1_five_character_model():
    assert parse(rev1_file(b'FXE11'))[1]['Model'] == 'FXE11'


def test_rev1_three_character_model():
    assert parse(rev1_file(b'FXS'))[1]['Model'] == 'FXS'


def test_rev1_model_after_0x41_lead_byte_has_no_leading_a():
    """Board rev. 420 files carry 0x41 ('A') at 0x26B instead of 0xaa. It is
    the lead byte, not part of the model: SR, not ASR."""
    assert parse(rev1_file(b'SR', lead=0x41))[1]['Model'] == 'SR'


def test_rev0_model_longer_than_three_characters():
    version, header = parse(rev0_file(b'FXS11'))
    assert version == REV0
    assert header['VIN'] == VIN_B
    assert header['Model'] == 'FXS11'


def test_rev0_four_character_model():
    assert parse(rev0_file(b'NONE'))[1]['Model'] == 'NONE'


def test_full_width_model_field_is_cut_at_sixteen_bytes():
    """A field with no zero byte reads as its 16 bytes and no further."""
    buf = bytearray(rev0_file(b'ABCDEFGHIJKLMNOP'))
    buf[0x28f:0x293] = b'XYZW'
    assert parse(bytes(buf))[1]['Model'] == 'ABCDEFGHIJKLMNOP'
