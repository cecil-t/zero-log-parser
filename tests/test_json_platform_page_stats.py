"""
Tests for two JSON log_info keys decided in LogData.get_version_and_header:

- platform: 'gen3' for a file that starts with an FST/Gen3 system
  information entry (Gen2.is_fst_platform_file), 'legacy' for a file that
  starts with the classic MBB or BMS magic or whose legacy layout the header
  decode identifies (a valid VIN, a known BMS layout, a ring-buffer file),
  None otherwise. Every file has the key.
- page_stats: FST/Gen3 BMS files only (Gen2.fst_bms_page_stats). The file is
  read as 128-byte pages after the header page; blank pages (one byte value
  throughout) and marker-plus-erased pages (00 f0 ff 00 then 0xff) are left
  out of distinct_pages and repeated_pages.

Neither key appears in the text output.

Plain test_* functions, stdlib only, synthetic bytes and invented values.
"""

import json
import logging
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2, LogData, LogFile, is_valid_vin_checksum, parse_log

logging.disable(logging.CRITICAL)

T0 = 1_700_000_000
VIN_A = '538TESTA4NAB00001'   # invented, valid check digit
PAGE = 128
MARKER = b'\x00\xf0\xff\x00'
ERASED = MARKER + b'\xff' * (PAGE - len(MARKER))


def _escape(body):
    out = bytearray()
    for b in body:
        if b in (0xb2, 0xfe):
            out += bytes([0xfe, (0xfe ^ b) + 1])
        else:
            out.append(b)
    return bytes(out)


def _frame(unescaped):
    body = _escape(unescaped[2:])
    return bytes([0xb2, len(body) + 2]) + body


def _text(s, size):
    raw = s.encode('ascii')
    return raw + b'\x00' * (size - len(raw))


def _fst_header(device):
    h = bytearray([0xb2, 0, 0xfb]) + struct.pack('<II', T0, 250000) + bytes([3, 0])
    h += _text(device, 10)                      # 0x0d device name
    h += _text('FST TEST', 16)                  # 0x17 module model
    h += bytes([2])                             # 0x27 cells in parallel
    h += _text('40-00000-01', 16)               # 0x28 board part
    h += _text('ZZ0000TEST01', 16)              # 0x38 serial (invented)
    h += _text('BCBM9999', 16)                  # 0x48 BCBM id (invented)
    h += _text('75-00001', 16)                  # 0x58 firmware part
    h += struct.pack('<HH', 7, 321)             # 0x68 fw rev, 0x6a build
    h += _text('abc1234', 16)                   # 0x6c commit hash
    h += bytes([1])                             # 0x7c bank
    return _frame(bytes(h))


def _header_page(device='BMS'):
    h = _fst_header(device)
    assert len(h) <= PAGE
    return h + b'\x00' * (PAGE - len(h))


def _entry(text, ts):
    body = bytes([0xfd]) + struct.pack('<I', ts) + struct.pack('<I', 1000) + bytes([1, 1]) + text
    return bytes([0xb2, len(body) + 2]) + body


def _data_page(n, prefix=b''):
    """A 128-byte page of text entries, different for every n."""
    page = bytearray(prefix)
    i = 0
    while True:
        e = _entry(b'page %04d line %d\x00' % (n, i), T0 + 60 * n + i)
        if len(page) + len(e) > PAGE:
            break
        page += e
        i += 1
    return bytes(page) + b'\x00' * (PAGE - len(page))


def _run(data, name):
    """(LogData, TXT text, JSON log_info) for data saved as name."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, name)
        with open(path, 'wb') as f:
            f.write(data)
        ld = LogData(LogFile(path), timezone_offset=0)
        out = os.path.join(d, 'out.txt')
        parse_log(path, out, output_format='txt', logger=logging.getLogger('t'))
        txt = open(out, encoding='utf-8-sig').read()
        parse_log(path, out, output_format='json', logger=logging.getLogger('t'))
        log_info = json.load(open(out.replace('.txt', '.json')))['log_info']
    return ld, txt, log_info


def _no_text_output(txt):
    assert 'platform' not in txt.lower() and 'page_stats' not in txt and 'repeated' not in txt.lower()


def test_invented_vin():
    assert is_valid_vin_checksum(VIN_A)


# Gen3 BMS

def test_normal_gen3_bms_file():
    data = _header_page() + b''.join(_data_page(n) for n in range(8))
    ld, txt, log_info = _run(data, 'synthetic.bin')
    assert ld.log_file.log_type == 'BMS'
    assert log_info['platform'] == 'gen3'
    assert log_info['page_stats'] == {'page_size': 128, 'total_pages': 8,
                                      'distinct_pages': 8, 'repeated_pages': 0}
    assert list(log_info['page_stats']) == ['page_size', 'total_pages', 'distinct_pages', 'repeated_pages']
    _no_text_output(txt)


def test_gen3_bms_file_with_long_runs_of_repeated_pages():
    a, b, c = _data_page(1), _data_page(2), _data_page(3)
    blank = b'\xff' * PAGE
    # runs of 40, 25 and 1, then a back to a once (not the page before),
    # then two blank pages that do not count either way
    pages = [a] * 40 + [b] * 25 + [c] + [a] + [blank, blank]
    ld, txt, log_info = _run(_header_page() + b''.join(pages), 'synthetic.bin')
    assert log_info['platform'] == 'gen3'
    assert log_info['page_stats'] == {'page_size': 128, 'total_pages': 69,
                                      'distinct_pages': 3, 'repeated_pages': 39 + 24}
    _no_text_output(txt)


def test_paged_131328_byte_file_with_marker_plus_erased_pages():
    distinct = [_data_page(n, prefix=MARKER) for n in range(20)]
    pages = distinct[:11] + [distinct[10]] + distinct[11:]   # one copy of page 11
    pages += [ERASED] * (1025 - len(pages))
    data = _header_page() + b''.join(pages)
    assert len(data) == 131_328 and Gen2.is_paged_bms_format(data)
    ld, txt, log_info = _run(data, 'synthetic.bin')
    assert log_info['platform'] == 'gen3'
    assert log_info['page_stats'] == {'page_size': 128, 'total_pages': 1025,
                                      'distinct_pages': 20, 'repeated_pages': 1}
    _no_text_output(txt)


def test_partial_last_page_is_not_counted():
    data = _header_page() + _data_page(1) + _data_page(2) + b'\x11' * 40
    assert Gen2.fst_bms_page_stats(data)['total_pages'] == 2


def test_gen3_mbb_file_has_platform_and_no_page_stats():
    data = _header_page('MBB') + b''.join(_data_page(n) for n in range(4))
    ld, txt, log_info = _run(data, 'synthetic.bin')
    assert ld.log_file.log_type == 'MBB'
    assert log_info['platform'] == 'gen3'
    assert 'page_stats' not in log_info


# Legacy and unrecognized

def _event_log(buf):
    """An a2a2a2a2 event log header at 0x600 pointing at one legacy entry."""
    payload = bytearray(46)
    struct.pack_into('<I', payload, 0, 1000)
    payload[5] = 0x02
    payload[35:39] = b'RUN\x00'
    body = bytes([0x4b]) + struct.pack('<I', T0) + payload
    entry = bytes([0xb2, len(body) + 2]) + body
    start = 0x610
    buf[0x600:0x604] = b'\xa2\xa2\xa2\xa2'
    buf[0x604:0x610] = struct.pack('<III', start + len(entry), start, len(entry))
    buf[start:start + len(entry)] = entry


def _classic_mbb(vin, size=0x40000):
    """A classic MBB file: magic, first-run date, a VIN at the REV0 offset
    (0x240) when given, and one entry."""
    buf = bytearray(size)
    buf[0:4] = b'MBB\x00'
    buf[0x26:0x2a] = b'\xa1\xa1\xa1\xa1'
    buf[0x2a:0x2a + 20] = b'Jan  1 2020 00:00:00'
    buf[0x200:0x200 + 13] = b'TESTSERIAL001'
    if vin:
        buf[0x240:0x240 + 17] = vin.encode()
    buf[0x27f:0x282] = b'SRX'
    _event_log(buf)
    return bytes(buf)


def test_legacy_file():
    ld, txt, log_info = _run(_classic_mbb(VIN_A), 'synthetic.bin')
    assert ld.header_info['VIN'] == VIN_A
    assert log_info['platform'] == 'legacy'
    assert 'page_stats' not in log_info
    _no_text_output(txt)


def test_legacy_ring_buffer_file():
    # starts with an ordinary entry, not an 0xfb system information entry
    data = _entry(b'ring buffer line\x00', T0) + b'\xff' * 1000
    ld, txt, log_info = _run(data, 'synthetic_MBB.bin')
    assert not Gen2.is_fst_platform_file(data)
    assert log_info['platform'] == 'legacy'
    assert 'page_stats' not in log_info


def test_classic_mbb_magic_without_vin_is_legacy():
    # MBB magic but no VIN at any known offset. 131,072 bytes: a 262,144-byte
    # file with no VIN and an a1a1a1a1 fencepost is read as a ring-buffer file.
    ld, txt, log_info = _run(_classic_mbb(None, size=0x20000), 'synthetic.bin')
    assert ld.header_info['VIN'] == 'Unknown'
    assert log_info['platform'] == 'legacy'
    assert 'page_stats' not in log_info
    _no_text_output(txt)


def test_classic_bms_magic_with_unlisted_layout_byte_is_legacy():
    buf = bytearray(0x40000)
    buf[0:4] = b'BMS\x00'
    buf[4] = 0x11          # not a listed layout byte, and no c0 c0 c0 c0 at 0x300
    _event_log(buf)
    ld, txt, log_info = _run(bytes(buf), 'synthetic.bin')
    assert ld.log_file.log_type == 'BMS'
    assert log_info['platform'] == 'legacy'
    assert 'page_stats' not in log_info


def test_unrecognized_file():
    # no magic, no VIN at any known offset, not a ring-buffer or Gen3 start
    buf = bytearray(_classic_mbb(None, size=0x20000))
    buf[0:4] = b'\x00\x00\x00\x00'
    ld, txt, log_info = _run(bytes(buf), 'synthetic.bin')
    assert ld.log_file.log_type == 'Unknown Type'
    assert log_info['platform'] is None
    assert 'page_stats' not in log_info
    _no_text_output(txt)


def test_bms_file_with_erased_start_is_unrecognized():
    # log type from the file name; the magic and layout byte are erased
    buf = bytearray(0x40000)
    buf[0:5] = b'\xff' * 5
    _event_log(buf)
    ld, txt, log_info = _run(bytes(buf), 'synthetic_BMS.bin')
    assert ld.log_file.log_type == 'BMS'
    assert log_info['platform'] is None
    assert 'page_stats' not in log_info
