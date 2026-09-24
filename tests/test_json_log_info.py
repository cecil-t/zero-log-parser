"""
Regression tests for LogData.emit_json_decoding()'s log_info block.

It used to read self.vin, self.serial_number, self.initial_date,
self.model, self.firmware_rev and self.board_rev through getattr(...,
'Unknown'). Nothing anywhere in the codebase ever sets those attributes, so
log_info was 'Unknown' in every field for every file. It now reads the same
header_info dict (from get_version_and_header) that the text output's
header block already prints. See analysis/json_emitter_fix.md.

Unlike the synthetic-buffer tests elsewhere in this directory, these use
real bytes from the file set: the leading bytes of four real log files,
zlib-compressed and base64-encoded inline. Each prefix is the smallest one
that reproduces the full file's log_version and header_info exactly
(checked against the whole file when the samples were cut), so the header
values asserted below are what the parser really decodes for those files:
- REV0 MBB: 10.12.18BikeLog.bin, first 0x400 bytes
- REV1 MBB: 538SMCZ66HCG07739_MBB_2020-05-22.bin, first 0x400 bytes
- REV3 (Gen3/FST) MBB: 20200205_15.15_538ZFAZ75LCK12639_MBB.bin, the
  whole 128-byte file
- REV1 BMS: 538SD5Z27ECB04404_BMS0_2021-02-27.bin, first 0x800 bytes; a
  BMS header carries no VIN, model, firmware or board rev, so those must
  stay 'Unknown' while initial_date, bms_serial_number and
  pack_serial_number are filled in

bms_serial_number and pack_serial_number (added after the first fix) read
header_info's 'BMS serial number' and 'Pack serial number'; MBB headers
carry neither key, so the three MBB samples check both stay 'Unknown'.
"""

import base64
import json
import os
import sys
import tempfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import LogFile, LogData, REV0, REV1, REV3


REV0_MBB = (
    'eNrzdXJiWONneIabkQEIYPQpkzf2eYwIeiEQBKcWKBgZKRgZGJorGJpYGVpYmRox/IcDhsuL'
    'OBglHTcxrGT9/7+qSY4hzZuVoUZFgKGTg5GhahcDHPw/z8CQAKR3FciB+fEMiQw2QIMSxSHy'
    'Yc0HomFqjWawMbg1szBsb2ZgOCjMwCCWxcCgPIWBgRkq7wQzEwqYGFDBir9g7zBshtLMaOoZ'
    'GBjB9CVPoFklSG5EAyDdjEjmboSad/YvI4p96OYOfgCMTpP43KSkeANjC7NUw3gDAzMDYyQf'
    'YYl1QwZY7AOBqbFFsK9plJGZq7OjgbGlpQUDg+L3oscLgACrVqQEYwqMjuBg1AhLYchjcGPw'
    'ZtAIY2SQYWhhuM7OyKjDyPg/hYERSDoITBHcxFTB0MTwX5+V4SfQEAE+BkUGBiagJFg7IywS'
    'El5BzDugzgmRAEcKA0MoSI86A8MObqjYghnVIPEC8RSg3cwMomAMFDcACgJxhzDEvKEToSQC'
    'AGx9Lqg='
)

REV1_MBB = (
    'eNrNkl9IU1Ecxz/nkloLZJIFBuF6cTEY7e7PXTMMm1DCmMRmSMvU1kwaPam1kpIeipJeEgaB'
    'RSQZ1o0ekhH1tocerAd7CIqIrBejNHroZRXROndrti4L6a0vnPs953d+3+/5/bi/cDDIk47V'
    'Hw9hoMShAw+3T5TxpMTOYwM2W8DmdqkBm+ptdqvNLpX8MrCccNO1FC/oS9yEyimHQrwX4llB'
    'SIdwHcvIP4UqyW/vicJ5CxdxcrN7qKF43+GY7SnlHn2sFFZqGG6tK8ZaWuDO4TI/EzDhfH3x'
    'ncFfbNZBMT5jlz0H/913eAVfM1by/dt9mW/enFdRWKb1Xnq/8Dt6XeJN7fTBlCzwmQJDSa9b'
    '1Ub6B12az1Oh4qUKY+AqTzji82yLhttimtbettvl93sC0LuJqRr0aORPr+rTdI3Ts4vREKl6'
    'xmOkMzVCOMTrT0q1yCVYFANiVqRbrXq67vKMckXnXYbP+a3RKnJfZfEvrbUepjeP8Q1NmZdC'
    'pzgr1nOfefYR4Yvs6TZzfOBa32LxyUjWvqaw2SjGDLLsPWeV/3rkwVrYIBJ0NxnjyPHOhqtJ'
    '4jqNneIHTNjJqLAHf0Kay3Z9xid7QU5hI49IMimen9kBr1bN8UK0w0kYhRTcgCm4G6PfyXcL'
    '+w3zQCu5/P+Cn8XEl3U='
)

REV3_MBB = (
    'eNrbVPr7ym2ruIxOTgYbBl8nJwYIeOEXHOTGgAxMjS2i3ByjzE19nL0NjcyMLRkYgr0MTAwt'
    'o1yDDAwszBkwgYmBroGFoakpAxMDH4Mao2FKooFRsiGqGgBdRBOa'
)

REV1_BMS = (
    'eNrFVG1sU1UYfi7rZK3dVpiILMQdliD7Bbd3m6QNLGN2m9NtzOFispCNu/UWarbe7faUEfRH'
    '4wfR8QPDohJCBEQyIROhslBJnDWOkSjGaYJGotNEg9lQ1DAzXZj1PXcVu9pF3Q99et/7nHPP'
    '+3Hu857birotGKtXD1+72iMBRwmb2zljpUyRFZk5S9xysVtR8N7Q+d9mDYLrP+/bLPx/7D1m'
    'cjcmNoDQUD1wQcwH6y5bxHzP+ECG4OnmXEnwqehr6wV/Vwgzz+Rk3ZfC/05n9CvBfU/1fiM4'
    'Ues8EnjfVmOu3+3SusX8YvNUS4+E/x2tjW+crSV+bvW+rBri7+87c+XRAiA8+OltYv1cy/7F'
    'pmNsMraIyEXmScQWOYAzNuB1O7D0dqArB+jPBZZlAQfpWQ1FniB7jCyf/MaXAnFaHyBefgew'
    'lyzqENoAPnq+2wr8ROPjlGeE4nuWAOvIpygPWEk8slfC8h0HzH40j7yQL7hpZ95LBeI9encd'
    'raY9XC/6zPouzW21Hz9xuQE4eVHCw14JjY7D9kxkJ3a+jGwVSmBBIeJxmH2Im5DPTVxN1ucE'
    'PyVt7Y7emsdTkKqnK3EOtyU4NQ6Q4pY0eRaOGGEkFLuyj6p9SLblAdmpyM2VjXKJXJqm49ec'
    'Lt7mdJWUznck3knz/ThBPbxJfY2Sxn5FdrpaO/WA3uHnO9JkUPIetzy4sgs4Gz4koUMqvzFF'
    'G+3/lW5HxspUhH1S2GP/YNj6bLvDN2wd25394jPU45ujVOQRMfLQN0af47fxQ8ANBXoGnuc5'
    'Lmk8A6c35PbbsLicer5OuDdsm5it2RlbYzUHq3Hp7RVicK/teBZ5nA4/JOEXUXvjATfwdQvJ'
    'bx7tIXEbpecF09gvRRU8uaIMUj7DmxjGzyiUfsAq6ZP7sy/V25t4zmDY3os+wzF10PFqZlPW'
    'Rwx3HcEFh+WLJTi5Bq88nfPWWHZkdFEo/l/jGGEoExgmyxKvxJi8SzZRLLtZVdW/uxApnxFZ'
    'PJUVTdVuVqF6maHRrUv3B7hmUO6qBJg/yPQQD/q9GuvQt7M2PRTwBhFZOzO9tb61QlcNL6vx'
    'MBdBuBpaV4fa7g8Ix8SScz1EzrWIlCXXrDQM3WC1lNLQfLrRqXKueZk3pDGuszbaS4/h59of'
    'O6Loe5KjRZxX5SpTOdN9vqDGhR5uRKpm5qojkzqbiv+8/pk6qVmcC9I4NYuy8CwvE9h1CQ46'
    '63voXzOycY6WO7UAn9VE41q7EFI1NQz6twdUHjI0d1JLEXGnD77lTS0Jct2gNFwXkZuU2d+8'
    'ZedpYfKZ+kv//y54Tv9/BwnenjU='
)

LOG_INFO_KEYS = [('vin', 'VIN'), ('serial_number', 'Serial number'),
                 ('initial_date', 'Initial date'), ('model', 'Model'),
                 ('firmware_rev', 'Firmware rev.'), ('board_rev', 'Board rev.'),
                 ('bms_serial_number', 'BMS serial number'),
                 ('pack_serial_number', 'Pack serial number')]


def _json_for(sample, suffix):
    d = tempfile.mkdtemp(prefix='jsonloginfo')
    path = os.path.join(d, 'sample' + suffix)
    with open(path, 'wb') as f:
        f.write(zlib.decompress(base64.b64decode(sample)))
    try:
        ld = LogData(LogFile(path), timezone_offset=0)
        out = os.path.join(d, 'out.txt')
        ld.emit_json_decoding(out)
        with open(os.path.join(d, 'out.json'), encoding='utf-8') as f:
            return ld, json.load(f)
    finally:
        for name in os.listdir(d):
            os.unlink(os.path.join(d, name))
        os.rmdir(d)


def _assert_matches_header(ld, j):
    for json_key, header_key in LOG_INFO_KEYS:
        assert j['log_info'][json_key] == ld.header_info.get(header_key, 'Unknown')


def test_rev0_mbb():
    ld, j = _json_for(REV0_MBB, '_MBB.bin')
    assert ld.log_version == REV0
    assert j['log_info'] == {
        'vin': '538SM5Z26ECA03998', 'serial_number': '2014_mbb_0386e1_00603',
        'initial_date': 'Sep 22 2017 14:18:52', 'model': 'SS',
        'firmware_rev': 53, 'board_rev': 3,
        'bms_serial_number': 'Unknown', 'pack_serial_number': 'Unknown'}
    _assert_matches_header(ld, j)


def test_rev1_mbb():
    ld, j = _json_for(REV1_MBB, '_MBB.bin')
    assert ld.log_version == REV1
    assert j['log_info'] == {
        'vin': '538SMCZ66HCG07739', 'serial_number': 'sj4216zer0653',
        'initial_date': 'Aug  9 2019 14:21:01', 'model': 'SR',
        'firmware_rev': 29, 'board_rev': 1956,
        'bms_serial_number': 'Unknown', 'pack_serial_number': 'Unknown'}
    _assert_matches_header(ld, j)


def test_rev3_gen3_mbb():
    ld, j = _json_for(REV3_MBB, '_MBB.bin')
    assert ld.log_version == REV3
    assert j['log_info'] == {
        'vin': '538ZFAZ75LCK12639', 'serial_number': 'Unknown',
        'initial_date': 'Unknown', 'model': 'SRF',
        'firmware_rev': 14, 'board_rev': 2,
        'bms_serial_number': 'Unknown', 'pack_serial_number': 'Unknown'}
    _assert_matches_header(ld, j)


def test_rev1_bms_serials_and_absent_keys():
    ld, j = _json_for(REV1_BMS, '_BMS0.bin')
    assert ld.log_version == REV1
    assert j['log_info'] == {
        'vin': 'Unknown', 'serial_number': 'Unknown',
        'initial_date': 'Oct  5 2020 14:03:22', 'model': 'Unknown',
        'firmware_rev': 'Unknown', 'board_rev': 'Unknown',
        'bms_serial_number': 'SJ0120ZER0405', 'pack_serial_number': '19tb1945'}
    _assert_matches_header(ld, j)
