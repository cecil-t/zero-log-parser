"""
Tests for entry type 0xfb ("System Information", queue item 9,
analysis/type_0xfb_decode.md).

LOG_STRUCTURE.md documents this as an identifier, VIN, serial numbers
and firmware version, written once per log session. Before this change
it had no registered decoder at all (0xfb was absent from
Gen2._entry_parsers()'s dict, so every entry fell through to
unhandled_entry_format(), the same generic raw-hex report every truly
undecoded type gets, with only a nicer event label from
get_message_type_description()).

Confirmed against the real file set, not assumed from the field names:
both MBB and BMS firmware write this same type id, with genuinely
different payloads (the same class of collision queue item 21 fixed
for 0x10/0x11). MBB's copy carries the vehicle VIN behind a 4-byte
'MBB\\0' self-identifier at a fixed relative offset; BMS's carries no
VIN anywhere in the payload, a 'BMS\\0' identifier instead, and its
own board serial/firmware part number in different field positions.
Gen2.mbb_system_information() is gated on the payload's own identifier
bytes rather than the file's log_type, so it decodes correctly inside
an Unknown Type file too and declines correctly on real BMS payloads
without needing log_type threaded into _entry_parsers() for this id.

Real samples: entry message bytes pulled with the real entry walker
against files in the current file set (source file given for each),
the same convention as tests/test_mbb_dispatch_0x10_0x11.py.
"""

import base64
import logging
import struct
import sys
import os
import tempfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2, LogFile, LogData


def _hex(s):
    return bytearray(bytes.fromhex(s))


# 20200205_15.13_538ZFAZ75LCK12639_MBB.bin, the file's single 0xfb entry.
# A clean sample: no byte-stuffing escape anywhere in the fields this
# decoder reads, real Board rev./Firmware rev. confirmed against
# fix/gen3-header-decode's own fixed-offset read for the same file
# (Board rev. 2, Firmware rev. 14).
CLEAN_MBB = _hex(
    'e80300003b004d424200000000000000e84e535246000000000000000000000000003533385a46415a37354c434b31323633390000'
    '534a303431395a4552303038370000000000000000000000000000000000000034302d30383135350002000e00260131646130326331000000'
)

# 20200116_01.16_538ZFAZ72LCK11447_MBB1.bin, the file's single 0xfb
# entry. The raw entry (before unescape_block runs) carries one literal
# 0xfe escape byte at raw offset 0x5D, between this payload's Model
# field and its Board rev./Firmware rev. fields. fix/gen3-header-decode
# reads Board rev./Firmware rev. from raw whole-file offsets that never
# account for this escape-byte removal, and gets 0/0 for both on this
# file - confirmed wrong by direct byte inspection (see
# analysis/type_0xfb_decode.md): this decoder, working on the same
# already-unescaped payload every other entry decoder here uses, reads
# the real values (2, 6) instead. Kept as its own test specifically
# because it is the one population where the two access paths disagree
# and this decoder is the one that is right.
ESCAPE_BUG_MBB = _hex(
    '581501003afb4d424200000000000000e84e535246000000000000000000000000003533385a46415a37324c434b31313434370000'
    '736a343031387a6572303436320000000000000000000000000000000000000058b2000000000000000200060064666237613237000000'
)

# 20191222_14.53_538ZFAZ78LCK12313_BMS.bin, the file's single 0xfb
# entry - a real, genuinely BMS-side payload. 'BMS\x00' identifier at
# the same relative offset the MBB case uses for 'MBB\x00'; no VIN
# anywhere in the payload (confirmed by exhaustive substring search
# against the file's own real VIN, analysis/type_0xfb_decode.md). Must
# fall back to the existing raw-hex report unchanged, not be
# misinterpreted with the MBB field layout.
REAL_BMS = _hex(
    '90a00b0018fa424d5300000000000000465354204d6f6e6f00000000000000000434302d30383138342d30310000000000736a313131397a6572313131300000003230686d30343730000000000000000037352d303831353600000000000000000b000c016437333237363400000000000000000002'
)


def test_clean_mbb_payload_decodes_all_documented_fields():
    e = Gen2.mbb_system_information(CLEAN_MBB)
    assert e['event'] == 'System Information'
    assert e['structured_data'] == {
        'vin': '538ZFAZ75LCK12639',
        'model': 'SRF',
        'serial_number': 'SJ0419ZER0087',
        'firmware_version': '40-08155',
        'board_rev': 2,
        'firmware_rev': 14,
    }
    assert 'VIN: 538ZFAZ75LCK12639' in e['conditions']


def test_escape_byte_file_decodes_board_and_firmware_rev_correctly():
    # This is the real coverage/value-add case: fix/gen3-header-decode's
    # fixed-offset read of this exact file gives Board rev. 0 and
    # Firmware rev. 0 (wrong, confirmed by direct byte inspection,
    # analysis/type_0xfb_decode.md). This decoder gets the true values.
    e = Gen2.mbb_system_information(ESCAPE_BUG_MBB)
    assert e['structured_data']['vin'] == '538ZFAZ72LCK11447'
    assert e['structured_data']['board_rev'] == 2
    assert e['structured_data']['firmware_rev'] == 6
    assert e['structured_data']['serial_number'] == 'sj4018zer0462'


def test_real_bms_payload_falls_back_to_raw_hex():
    e = Gen2.mbb_system_information(REAL_BMS)
    assert 'structured_data' not in e
    assert e['conditions'].startswith('Raw data:')
    # description still comes from get_message_type_description(), the
    # same event label an unregistered type would have carried before
    # this decoder existed - this proves the fallback is unchanged, not
    # a new or different generic report.
    assert e['event'] == Gen2.get_message_type_description(0xfb)


def test_garbled_identifier_falls_back_to_raw_hex():
    # Neither 'MBB\x00' nor a recognizable identifier at the expected
    # offsets - must not guess.
    garbage = bytearray(110)
    garbage[6:10] = b'\x00\x00\x00\x00'
    e = Gen2.mbb_system_information(garbage)
    assert 'structured_data' not in e


def test_too_short_payload_falls_back_to_raw_hex():
    e = Gen2.mbb_system_information(bytearray(4))
    assert 'structured_data' not in e


def test_shift_1_synthetic_sample_still_decodes():
    # No real file in the current dataset needs this entry-level shift
    # (all 505 real MBB-identified 0xfb entries land at shift=0, unlike
    # fix/gen3-header-decode's own whole-file offset, which does need it
    # for about 2.6% of files - the entry-based method locates its
    # payload from the entry's own length/type header rather than an
    # assumed constant file offset, so it isn't exposed to that same
    # ambiguity - see analysis/type_0xfb_decode.md). Built from
    # CLEAN_MBB by inserting one byte before the identifier, the same
    # shape test_gen3_header_decode.py uses a real file for at the
    # whole-file level; kept synthetic here since no real sample exists
    # for this code path yet.
    shifted = bytearray(1) + CLEAN_MBB
    e = Gen2.mbb_system_information(shifted)
    assert e['structured_data']['vin'] == '538ZFAZ75LCK12639'
    assert e['structured_data']['board_rev'] == 2


def test_entry_parsers_registers_0xfb_unconditionally():
    # Self-gated on the payload's own identifier bytes, not log_type -
    # unlike 0x10/0x11, this id is registered the same way regardless
    # of what log_type is passed.
    for log_type in (None, LogFile.log_type_mbb, LogFile.log_type_bms, LogFile.log_type_unknown):
        parsers = Gen2._entry_parsers(log_type)
        assert parsers[0xfb] == Gen2.mbb_system_information


def _raw_entry(message_type, payload, timestamp=1_600_000_000):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


# 538DZBZ80SC027736_MBB_SNUNINITIALIZED_2025-08-21_15-25-22_raw.bin, the
# whole file (644 bytes, zlib-compressed and base64-encoded, the same
# convention tests/test_json_log_info.py uses). This is the one real,
# confirmed coverage-gain case: fix/gen3-header-decode's fixed-offset
# read never reaches this file's Gen3 fields at all, since it doesn't
# enter the REV3 branch (raw()[0] != 0xb2, not 262144 bytes, so
# get_version_and_header() falls all the way to the legacy branch,
# which fails every legacy VIN offset too and produces the known
# garbage sentinel: VIN 'ed. Old: 0x4070 N', Model 'Ol', everything
# else 'Unknown' - see analysis/gen3_header_decode.md's "one known edge
# case"). The real entry walker finds this file's single 0xfb entry
# and decodes it correctly regardless: entry walking and header-level
# log_version routing are independent passes in this parser, so an
# entry-level decoder is not limited by a header heuristic that failed
# to recognize the file's format. Recovered VIN matches the filename
# exactly; recovered serial 'UNINITIALIZED' matches the filename's own
# 'SNUNINITIALIZED' fragment; recovered Model 'DSR' is a real Zero
# model line. See analysis/type_0xfb_decode.md.
COVERAGE_GAIN_FILE = (
    'eNqNkD9v00AYxt+67UBH/tPpVYUQ/xqdz05il0pQnxFYIimQtEjZHOdiGzm25ZxpMyB1ZGAMEkgdurEi'
    'fwLYmPgMfAwjhMTZpRIiC+9wevTo+d299xytvJspUM/r+dvlKPHnViiNIv/57fhj8Pn+Kug/OpZ1GoH1'
    'Xbv3HP6epmbYA2tgkB4jtN3WWgB7Xafr9J2dJ87goQ2Lo5NNYqimActwC1ZBM7npNbmrwof3X8YPjgHO'
    'l/1wwkeY5ALDGJ++wJ5wM5GnUNz5VYVungBcKKUpOHqBG/scx1kykcneHooEHzsWFLSOnpxbgotlp88w'
    '5fEojP0zYDhD7ZRSK0RdgyKoifL6ElySlydpWsVV+qpCMp83EG22aTOkGtHNVr5/Fy1XCJ7NUNVUSqlh'
    'VB5LJsMwluurVGsaZotW5o70eCyQthgUj55V73zfUOByWRXy8p+C9s9E9Q/YlmJjbbHGQq/X/XpDgSul'
    'HU69AKNwEorpFnp5liFBz03l6XpCnmlygAQKtWY+3Vbgasn+B9iugSOqwLWSJbHIkgjHketP//Q4auBu'
    'NNpCcqiTNsEuP6g0kRqKezX75nAF1kvGOhgMF9H5tPEbE+63zg=='
)


def _load_real_file(sample, filename):
    d = tempfile.mkdtemp(prefix='fbdecode')
    path = os.path.join(d, filename)
    with open(path, 'wb') as f:
        f.write(zlib.decompress(base64.b64decode(sample)))
    try:
        lf = LogFile(path)
        ld = LogData(lf)
        return lf, ld
    finally:
        os.unlink(path)
        os.rmdir(d)


def test_real_coverage_gain_file_decodes_where_header_read_fails():
    lf, ld = _load_real_file(
        COVERAGE_GAIN_FILE, '538DZBZ80SC027736_MBB_SNUNINITIALIZED_2025-08-21_15-25-22_raw.bin')
    # The existing fixed-offset header read gets nothing usable here.
    assert ld.header_info['VIN'] != '538DZBZ80SC027736'
    assert ld.header_info['Board rev.'] == 'Unknown'
    # This decoder, reached through the real entry walker independent
    # of the header's own (failed) format detection, gets everything.
    fb = [e for e in ld._processed_entries if e.message_type == '0xFB']
    assert len(fb) == 1
    assert fb[0].structured_data == {
        'vin': '538DZBZ80SC027736',
        'model': 'DSR',
        'serial_number': 'UNINITIALIZED',
        'firmware_version': '40-08198',
        'board_rev': 3,
        'firmware_rev': 41,
    }


def test_parse_entry_end_to_end_mbb_and_bms_payloads():
    logger = logging.getLogger('test_type_0xfb_system_information')
    raw_mbb = _raw_entry(0xfb, CLEAN_MBB)
    _length, entry, _unhandled = Gen2.parse_entry(raw_mbb, 0, 0, logger, log_type=LogFile.log_type_mbb)
    assert entry['structured_data']['vin'] == '538ZFAZ75LCK12639'

    raw_bms = _raw_entry(0xfb, REAL_BMS)
    _length, entry, _unhandled = Gen2.parse_entry(raw_bms, 0, 0, logger, log_type=LogFile.log_type_bms)
    assert 'structured_data' not in entry
