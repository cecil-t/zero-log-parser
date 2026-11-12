"""Tests for the classic MBB header fields: the REV0/REV1 model field, the
initial date of a shifted header block, and placeholder serials in the
shifted-block check. Synthetic buffers, invented VINs and serial numbers."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import LogData, REV0, REV1
from test_legacy_mbb_shifted_header import VIN_A, VIN_B, parse, place, rev0_image, rev1_image


def rev1_with_lead(model, lead):
    img = bytearray(rev1_image(VIN_A, model=model))
    img[0x26b] = lead
    return bytes(img)


def test_rev1_four_character_model_after_0xaa_lead_byte():
    version, header, _ = parse(place(rev1_image(VIN_A, model=b'DS11'), 0))
    assert version == REV1
    assert header['Model'] == 'DS11'


def test_rev1_five_character_model():
    _, header, _ = parse(place(rev1_image(VIN_A, model=b'FXE11'), 0))
    assert header['Model'] == 'FXE11'


def test_rev1_three_character_model():
    _, header, _ = parse(place(rev1_image(VIN_A, model=b'FXS'), 0))
    assert header['Model'] == 'FXS'


def test_rev1_model_after_0x41_lead_byte_has_no_leading_a():
    """Board rev. 420 files carry 0x41 ('A') at 0x26B instead of 0xaa. It is
    the lead byte, not part of the model: SR, not ASR."""
    _, header, _ = parse(place(rev1_with_lead(b'SR', 0x41), 0))
    assert header['Model'] == 'SR'


def test_rev0_model_longer_than_three_characters():
    version, header, _ = parse(place(rev0_image(VIN_B, model=b'FXS11'), 0))
    assert version == REV0
    assert header['Model'] == 'FXS11'


def test_shifted_path_reads_the_same_model_as_the_standard_path():
    for model, lead in ((b'DS11', 0xaa), (b'FXE11', 0xaa), (b'SR', 0x41)):
        img = rev1_with_lead(model, lead)
        _, standard, _ = parse(place(img, 0))
        _, shifted, ld = parse(place(img, 0x100))
        assert ld.vin_source == 'header'
        assert shifted['Model'] == standard['Model'] == model.decode()
    _, standard, _ = parse(place(rev0_image(VIN_B, model=b'FXS11'), 0))
    _, shifted, _ = parse(place(rev0_image(VIN_B, model=b'FXS11'), 0x400))
    assert shifted['Model'] == standard['Model'] == 'FXS11'


def test_shifted_block_initial_date_replaces_junk_at_0x2a():
    """A 131,072-byte file with the REV0 header image at +0x400: the fixed
    0x2a read finds log text, the shifted image has the date."""
    buf = bytearray(place(rev0_image(VIN_B), 0x400, size=0x20000))
    buf[0x2a:0x3a] = b'are now Closed\x00\x00'
    _, header, ld = parse(bytes(buf))
    assert ld.vin_source == 'header'
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
