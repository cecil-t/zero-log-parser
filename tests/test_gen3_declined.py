"""Tests for Gen3 records the decoders used to decline (analysis/gen3_declined.md):
0x4B/0x4C/0x4D cell telemetry damaged by the page marker, decoded with the
covered fields withheld. Synthetic buffers through Gen2.collect_paged_bms_entries,
the same way test_marker_field_corruption.py builds them; all values invented."""

import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

MARK = b'\x00\xf0\xff\x00'
LOGGER = logging.getLogger('test_gen3_declined')
T = 1_700_000_000


def _entry(message_type, timestamp, payload):
    body = bytes([message_type]) + struct.pack('<I', timestamp) + bytes(payload)
    return bytearray([0xb2, len(body) + 2]) + bytearray(body)


def _cell_payload(length=43, shift=0, subsecond_us=432_000, sequence=17, prefix_marker=0xf9,
                  low=3811, unloaded=0, high=3829, soc=63, current_ma=-4321, pack_mv=104_567):
    """A valid BMS cell telemetry payload (0x4B 43/45, 0x4C 61/63 with shift 4,
    0x4D 69/71 with shift 8), every decoded field at a distinct value."""
    p = bytearray(length)
    struct.pack_into('<I', p, 0, subsecond_us)
    p[4], p[5] = sequence, prefix_marker
    b = 14 + shift
    struct.pack_into('<HHH', p, b, low, unloaded, high)
    p[b + 6] = soc
    struct.pack_into('<i', p, b + 7, current_ma)
    p[b + 11] = 31                       # BMS temperature
    p[b + 24] = 7                        # report mode
    if b + 28 <= length:
        p[b + 25:b + 28] = pack_mv.to_bytes(3, 'little')
    return p


def _decode_one(buf):
    collected = Gen2.collect_paged_bms_entries(bytes(buf), LOGGER)
    assert len(collected) == 1
    return collected[0][1]


def _assert_cells(sd, pack=True):
    assert sd['voltage_low_cell_volts'] == 3.811
    assert sd['voltage_high_cell_volts'] == 3.829
    assert sd['state_of_charge_percent'] == 63
    assert sd['battery_current_amps'] == -4.321
    assert sd['bms_temperature_c'] == 31
    if pack:
        assert sd['pack_voltage_volts'] == 104.567


# --- Step 1: marker over the sub-second prefix ---

def test_marker_at_each_prefix_position_is_decoded_with_the_prefix_fields_withheld():
    expected = {0: ['subsecond_us'], 1: ['sequence', 'subsecond_us'], 2: ['marker', 'sequence', 'subsecond_us']}
    for pos, withheld in expected.items():
        payload = _cell_payload()
        payload[pos:pos + 4] = MARK
        entry = _decode_one(_entry(0x4b, T, payload))
        sd = entry['structured_data']
        assert entry['event'] == 'BMS Cell Telemetry', pos
        assert sd['corrupted_fields'] == withheld, pos
        for name in withheld:
            assert sd[name] is None
        for name in {'subsecond_us', 'sequence', 'marker'} - set(withheld):
            assert sd[name] is not None
        _assert_cells(sd)
        assert sd['raw_hex'] == bytes(payload).hex()     # the bytes as they are in the file


def test_marker_over_the_prefix_of_a_0x4d_record():
    payload = _cell_payload(length=69, shift=8)
    payload[1:5] = MARK
    sd = _decode_one(_entry(0x4d, T, payload))['structured_data']
    assert sd['corrupted_fields'] == ['sequence', 'subsecond_us']
    _assert_cells(sd)


def test_out_of_range_sub_second_without_a_marker_stays_declined():
    payload = _cell_payload(subsecond_us=3_000_000)
    entry = _decode_one(_entry(0x4b, T, payload))
    assert entry.get('structured_data') is None
    assert entry['conditions'].startswith('Raw data: ')


# --- Step 2: one byte longer, the marker over an escape byte ---

def _escape(body):
    """The writer's escaping: 0xfe -> fe 01, 0xb2 -> fe 4d (unescape_block's inverse)."""
    out = bytearray()
    for b in body:
        out += b'\xfe\x01' if b == 0xfe else b'\xfe\x4d' if b == 0xb2 else bytes([b])
    return out


def _marked_record(message_type, payload, k):
    """The wire form of a record whose payload byte k is 0xb2 (escaped as a
    pair), with the page marker written over that pair and the two bytes
    after it: the pair no longer combines, so it unescapes one byte long."""
    payload = bytearray(payload)
    payload[k] = 0xb2
    escaped = _escape(bytes([message_type]) + struct.pack('<I', T) + bytes(payload))
    e = escaped.index(b'\xfe\x4d')
    escaped[e:e + 4] = MARK
    return bytearray([0xb2, len(escaped) + 2]) + escaped


def test_record_one_byte_long_is_realigned_and_the_fields_by_the_marker_withheld():
    # The marker over payload bytes 21-24 (battery current), starting at its
    # first, second and last byte. Fields touching the marker span or the
    # byte either side of it are withheld; fields after it read at their
    # real offsets, which shows the extra byte was taken out.
    cases = {
        21: {'state_of_charge_percent', 'battery_current_amps'},
        22: {'battery_current_amps'},
        24: {'battery_current_amps', 'bms_temperature_c', 'bms_status_word'},
    }
    for k, must in cases.items():
        entry = _decode_one(_marked_record(0x4b, _cell_payload(), k))
        sd = entry['structured_data']
        assert entry['event'] == 'BMS Cell Telemetry', k
        assert len(bytes.fromhex(sd['raw_hex'])) == 43, k
        assert must <= set(sd['corrupted_fields']), (k, sd['corrupted_fields'])
        for name in sd['corrupted_fields']:
            assert sd[name] is None
        assert sd['voltage_low_cell_volts'] == 3.811 and sd['voltage_high_cell_volts'] == 3.829
        assert sd['pack_voltage_volts'] == 104.567, k
        assert sd['bms_report_mode'] == 7, k
        assert sd['subsecond_us'] == 432_000 and sd['sequence'] == 17


def test_record_one_byte_long_with_the_marker_on_the_cell_block_of_a_0x4d():
    entry = _decode_one(_marked_record(0x4d, _cell_payload(length=69, shift=8), 23))
    sd = entry['structured_data']
    assert {'voltage_low_cell_volts', 'voltage_unloaded_cell_volts'} <= set(sd['corrupted_fields'])
    assert sd['state_of_charge_percent'] == 63 and sd['pack_voltage_volts'] == 104.567


def test_record_one_byte_long_without_a_marker_stays_declined():
    entry = _decode_one(_entry(0x4b, T, _cell_payload(length=44)))
    assert entry.get('structured_data') is None


# --- Step 3: 0x4B at 39 bytes, the 43-byte record without the pack voltage ---

def _short_payload(length, shift):
    p = _cell_payload(length=length, shift=shift)
    p[10 + shift] = 0x20                 # sleep indicator
    p[26 + shift:30 + shift] = b'\xd8\xf3\x07\x06'
    return p


def test_0x4b_39_decodes_with_the_43_byte_fields_and_no_pack_voltage():
    entry = Gen2.state_snapshot_dispatch(0x4b, _short_payload(39, 0))
    sd = entry['structured_data']
    assert entry['event'] == 'BMS Cell Telemetry'
    _assert_cells(sd, pack=False)
    assert 'pack_voltage_volts' not in sd             # not in the record: neither shown nor withheld
    assert 'corrupted_fields' not in sd
    assert sd['bms_report_mode'] == 7 and sd['bms_sleeping'] is True
    assert sd['bms_status_word'] == 0x0607f3d8
    assert 'Vpack' not in entry['conditions']
    assert sd['subsecond_us'] == 432_000


def test_misframed_or_implausible_39_byte_records_stay_declined():
    framed = _short_payload(39, 0)
    framed[31:39] = b'\xb2\x2fExit'[:8].ljust(8, b'i')    # another entry's header and a run of text
    implausible = _short_payload(39, 0)
    struct.pack_into('<H', implausible, 18, 9000)          # high cell 9 V
    for payload in (framed, implausible):
        entry = Gen2.state_snapshot_dispatch(0x4b, payload)
        assert entry.get('structured_data') is None


# --- Step 4: 0x4D at 63 and 0x4C at 55, the aligned head only ---

def test_short_0x4d_and_0x4c_decode_the_head_and_leave_the_tail_raw():
    for message_type, length, shift in ((0x4d, 63, 8), (0x4c, 55, 4)):
        head = Gen2.BMS_CELL_TELEMETRY_SHORT[(message_type, length)]
        payload = _short_payload(length, shift)
        payload[head:] = bytes(range(0x11, 0x11 + length - head))     # an invented tail
        entry = Gen2.state_snapshot_dispatch(message_type, payload)
        sd = entry['structured_data']
        assert entry['event'] == 'BMS Cell Telemetry', hex(message_type)
        _assert_cells(sd, pack=False)
        assert sd['bms_report_mode'] == 7
        for name in ('pack_voltage_volts', 'cell_temperature_coldest_c', 'cell_temperature_hottest_c',
                     'full_charge_capacity_ah', 'bms_charge_current_limit_amps'):
            assert name not in sd, (hex(message_type), name)
        assert sd['raw_hex'] == bytes(payload).hex()     # the tail is kept, undecoded
        kinds = {i: k for a, b, k, _ in Gen2.payload_layout(message_type, length) for i in range(a, b)}
        assert all(kinds[i] == Gen2.LAYOUT_UNKNOWN for i in range(head, length))


# --- Step 5: the LIMP state tag on 0x51 ---

def test_0x51_with_state_tag_limp_decodes_and_shows_it_as_written():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_vehicle_state_telemetry_decode import _payload, _tag
    for length in (64, 68):
        out = Gen2.vehicle_state_telemetry(_payload(length, _tag('LIMP')))
        assert out['structured_data']['vehicle_state'] == 'LIMP', length
        assert out['event'] == 'Vehicle State (LIMP)'
        assert out['conditions'].startswith('State: LIMP, ')
    assert 'structured_data' not in Gen2.vehicle_state_telemetry(_payload(68, _tag('LIMB')))


# --- Step 6: the BMS 0xFB system information record as an entry ---

def _bms_fb_payload(shift=0):
    """An invented BMS 0xfb payload, laid out at the header offsets that
    fst_bms_header_fields() reads (header offset = payload offset + 7);
    shift -1 drops a byte before the device name, +1 adds one after it."""
    h = bytearray(0x6c + 7)
    h[0x0d:0x11] = b'BMS\x00'
    for offset, text in ((0x17, b'FST Test'), (0x28, b'40-01234-05'), (0x38, b'tt0000zzz9999'),
                         (0x48, b'bcbm0001'), (0x58, b'75-01234')):
        h[offset:offset + len(text)] = text
    struct.pack_into('<HH', h, 0x68, 21, 4321)
    payload = h[7:]
    if shift == -1:
        payload = payload[:4] + payload[5:]
    elif shift == 1:
        payload = payload[:0x12 - 7] + b'\x00' + payload[0x12 - 7:]
    return bytearray(payload)


def test_bms_system_information_decodes_with_the_header_fields_and_part_number():
    for shift in (0, -1, 1):
        entry = Gen2.mbb_system_information(_bms_fb_payload(shift))
        assert entry['event'] == 'BMS System Information', shift
        assert entry['structured_data'] == {
            'module_model': 'FST Test', 'part_number': '40-01234-05', 'bms_serial_number': 'tt0000zzz9999',
            'bcbm_id': 'bcbm0001', 'firmware_part': '75-01234', 'firmware_rev': 21, 'firmware_build': 4321}, shift
        assert entry['conditions'].startswith('Module: FST Test, Part: 40-01234-05, ')


def test_bms_system_information_without_a_confirmed_shift_stays_raw():
    payload = _bms_fb_payload()
    payload[0x58 - 7:0x58 - 7 + 8] = b'xx-yyyyy'          # the firmware part anchor is gone
    entry = Gen2.mbb_system_information(payload)
    assert 'structured_data' not in entry and entry['conditions'].startswith('Raw data:')
