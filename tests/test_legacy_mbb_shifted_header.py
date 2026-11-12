"""Tests for LogData.find_shifted_classic_header and its use in
get_version_and_header(): a classic MBB header block that sits at a
0x100-aligned base other than 0 is read when the standard offsets find no
VIN, and only then; the model it reads, and the initial date of the same
header image. Synthetic buffers, invented VINs and serial numbers."""

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
    """A check-digit-valid invented VIN: 538 prefix, placeholder at
    position 9 replaced by the computed check digit."""
    template = '538SMZZ00' + 'HCA' + tail
    total = sum(TRANSLIT[c] * w for c, w in zip(template, WEIGHTS))
    check = 'X' if total % 11 == 10 else str(total % 11)
    return template[:8] + check + template[9:]


VIN_A = make_vin('90001')
VIN_B = make_vin('90002')


def rev1_image(vin, serial=b'TST000000001', model=b'SR', firmware=33, board=2980):
    """The first 0x300 bytes of a REV1 MBB file, laid out as real files
    are: magic and first run date at 0, the header block at 0x200."""
    img = bytearray(0x300)
    img[0:4] = b'MBB\x00'
    img[0x26:0x2a] = b'\xa1\xa1\xa1\xa1'
    img[0x2a:0x3e] = b'Jan  2 2019 10:11:12'
    img[0x200:0x204] = b'\xa0\xa0\xa0\xa0'
    img[0x210:0x210 + len(serial)] = serial
    img[0x230] = 0xeb
    img[0x231:0x245] = b'Jan  2 2019 10:11:10'
    img[0x251] = 0x69
    img[0x252:0x263] = vin.encode('ascii')
    struct.pack_into('<HH', img, 0x266, firmware, board)
    img[0x26b] = 0xaa
    img[0x26c:0x26c + len(model)] = model
    return bytes(img)


def rev0_image(vin, serial=b'2015_mbb_abcdef_00001', model=b'DS', firmware=25, board=3):
    img = bytearray(0x300)
    img[0:4] = b'MBB\x00'
    img[0x26:0x2a] = b'\xa1\xa1\xa1\xa1'
    img[0x2a:0x3e] = b'Mar  3 2015 10:11:12'
    img[0x200:0x200 + len(serial)] = serial
    img[0x220:0x234] = b'Mar  3 2015 10:11:10'
    img[0x240:0x251] = vin.encode('ascii')
    img[0x257:0x25b] = b'\xa0\xa0\xa0\xa0'
    struct.pack_into('<HH', img, 0x27b, firmware, board)
    img[0x27f:0x27f + len(model)] = model
    return bytes(img)


def place(image, base, size=0x40000):
    """A file of the given size with the header image starting at base:
    a positive base leaves base bytes of filler in front, a negative base
    cuts the first -base bytes of the image off."""
    buf = bytearray(b'\x00' * size)
    if base >= 0:
        buf[base:base + len(image)] = image
    else:
        buf[0:len(image) + base] = image[-base:]
    return bytes(buf)


def parse(data, name='log.bin'):
    d = tempfile.mkdtemp()
    path = os.path.join(d, name)
    with open(path, 'wb') as f:
        f.write(data)
    try:
        lf = LogFile(path)
        ld = object.__new__(LogData)
        ld.log_file = lf
        version, header = ld.get_version_and_header(lf)
        return version, header, ld
    finally:
        os.unlink(path)
        os.rmdir(d)


def assert_fields(header, ld, vin, model, firmware, board, serial):
    assert header['VIN'] == vin
    assert header['Model'] == model
    assert header['Firmware rev.'] == firmware
    assert header['Board rev.'] == board
    assert header['Serial number'] == serial


def test_rev1_block_0x100_later():
    _, header, ld = parse(place(rev1_image(VIN_A), 0x100))
    assert_fields(header, ld, VIN_A, 'SR', 33, 2980, 'TST000000001')


def test_rev1_block_0x100_earlier():
    """The capture starts at flash 0x100: magic and first run date are
    missing, the block sits at 0x100."""
    _, header, ld = parse(place(rev1_image(VIN_A), -0x100))
    assert_fields(header, ld, VIN_A, 'SR', 33, 2980, 'TST000000001')


def test_rev1_block_at_0x800_in_131072_byte_file():
    """Magic at 0 and the block at 0x800 (base +0x600)."""
    img = rev1_image(VIN_A)
    buf = bytearray(place(img[0x200:], 0x800, size=0x20000))
    buf[0:0x200] = img[0:0x200]
    _, header, ld = parse(bytes(buf))
    assert_fields(header, ld, VIN_A, 'SR', 33, 2980, 'TST000000001')


def test_rev1_header_image_near_end_of_rotated_capture():
    _, header, ld = parse(place(rev1_image(VIN_A), 0x3e200))
    assert_fields(header, ld, VIN_A, 'SR', 33, 2980, 'TST000000001')


def test_rev0_block_0x400_later():
    _, header, ld = parse(place(rev0_image(VIN_B), 0x400))
    assert_fields(header, ld, VIN_B, 'DS', 25, 3, '2015_mbb_abcdef_00001')


def test_file_name_is_not_used():
    """Same result whatever the file is called, including a name with a
    different valid VIN in it."""
    data = place(rev1_image(VIN_A), 0x100)
    for name in ('log.bin', f'{VIN_B}_MBB_2020-01-01.bin'):
        _, header, ld = parse(data, name)
        assert header['VIN'] == VIN_A


def test_standard_header_wins_over_a_second_block():
    """The standard block reads, and another valid block with different
    values sits elsewhere: the standard one is kept."""
    buf = bytearray(place(rev1_image(VIN_A), 0))
    buf[0x3e200:0x3e500] = rev1_image(VIN_B, serial=b'TST000000002', model=b'DS', firmware=40, board=3492)
    version, header, ld = parse(bytes(buf))
    assert version == REV1
    assert_fields(header, ld, VIN_A, 'SR', 33, 2980, 'TST000000001')


def test_block_with_a_bad_neighbouring_field_is_rejected():
    """A check-digit-valid VIN whose serial is not serial-shaped."""
    _, header, ld = parse(place(rev0_image(VIN_B, serial=b'2\x7f\x7f\x7fl'), 0x400))
    assert header['Model'] == 'Unknown'
    assert header['VIN'] == 'Unknown'


def test_vin_failing_the_check_digit_is_rejected():
    bad = VIN_A[:8] + ('1' if VIN_A[8] != '1' else '2') + VIN_A[9:]
    _, header, ld = parse(place(rev1_image(bad), 0x100))
    assert header['VIN'] == 'Unknown'


def test_find_returns_nearest_block_and_its_layout():
    data = bytearray(place(rev1_image(VIN_A), 0x100))
    found = LogData.find_shifted_classic_header(data)
    assert found['layout'] == REV1 and found['base'] == 0x100
    found = LogData.find_shifted_classic_header(bytearray(place(rev0_image(VIN_B), 0x400)))
    assert found['layout'] == REV0 and found['base'] == 0x400


def test_shifted_file_keeps_its_log_version():
    """Only header fields change: a file the standard offsets cannot read
    keeps the log_version it had (REV3 here, from the a1a1a1a1 fallback)."""
    version, _, _ = parse(place(rev1_image(VIN_A), 0x100))
    assert version not in (REV0, REV1)


def rev1_with_lead(model, lead):
    img = bytearray(rev1_image(VIN_A, model=model))
    img[0x26b] = lead
    return bytes(img)


def test_shifted_path_reads_the_same_model_as_the_standard_path():
    for model, lead in ((b'DS11', 0xaa), (b'FXE11', 0xaa), (b'SR', 0x41)):
        img = rev1_with_lead(model, lead)
        _, standard, _ = parse(place(img, 0))
        _, shifted, _ = parse(place(img, 0x100))
        assert shifted['VIN'] == VIN_A
        assert shifted['Model'] == standard['Model'] == model.decode()
    _, standard, _ = parse(place(rev0_image(VIN_B, model=b'FXS11'), 0))
    _, shifted, _ = parse(place(rev0_image(VIN_B, model=b'FXS11'), 0x400))
    assert shifted['Model'] == standard['Model'] == 'FXS11'


def test_shifted_block_initial_date_replaces_junk_at_0x2a():
    """A 131,072-byte file with the REV0 header image at +0x400: the fixed
    0x2a read finds log text, the shifted image has the date."""
    buf = bytearray(place(rev0_image(VIN_B), 0x400, size=0x20000))
    buf[0x2a:0x3a] = b'are now Closed\x00\x00'
    _, header, _ = parse(bytes(buf))
    assert header['VIN'] == VIN_B
    assert header['Initial date'] == 'Mar  3 2015 10:11:12'
    assert LogData.find_shifted_classic_header(bytes(buf))['Initial date'] == 'Mar  3 2015 10:11:12'


def test_valid_initial_date_already_read_is_kept():
    buf = bytearray(place(rev0_image(VIN_B), 0x400, size=0x20000))
    buf[0x2a:0x3e] = b'Apr  4 2016 01:02:03'
    _, header, _ = parse(bytes(buf))
    assert header['Initial date'] == 'Apr  4 2016 01:02:03'


def test_no_initial_date_when_the_image_start_is_cut_off():
    """Capture starting after flash 0: the a1a1a1a1 fence of the shifted
    image is not in the file, so no date is taken from it."""
    found = LogData.find_shifted_classic_header(place(rev1_image(VIN_A), -0x100))
    assert found is not None and found['Initial date'] is None


def test_uninitialized_serial_shown_as_stored_on_both_paths():
    """UNINITIALIZED is what an unprogrammed board writes as its serial. The
    standard path shows it as stored, and so does a shifted block that
    passes every other check."""
    for base in (0, 0x400):
        _, header, _ = parse(place(rev0_image(VIN_B, serial=b'UNINITIALIZED'), base))
        assert header['Serial number'] == 'UNINITIALIZED'
        assert header['VIN'] == VIN_B
