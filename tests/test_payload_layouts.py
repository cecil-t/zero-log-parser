"""
Tests for the declared payload layouts (Gen2.payload_layout): what every byte of
a raw_hex-keeping decoder's payload is, field, reserved or unknown. Two
guards: no raw_hex decoder is missing a layout for a length it accepts, and
the layouts do not over-claim (flip every byte of a valid payload: a byte
declared field must change some decoded output, a byte declared reserved or
unknown must not).

Same conventions as the other files in this directory: stdlib only, synthetic
in-process payloads, no dataset files checked in.
"""

import inspect
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2, LogFile

FIELD, RESERVED, UNKNOWN = Gen2.LAYOUT_FIELD, Gen2.LAYOUT_RESERVED, Gen2.LAYOUT_UNKNOWN

# Gen2 methods that mention raw_hex but are not entry decoders.
NOT_DECODERS = {'_marker_corrupted_entry', 'undecoded_hex_display', 'mark_bytes_corrupted',
                '_withhold_marker_corrupted_fields', '_enumerate_structured_fields',
                '_set_structured_field', 'gen3_debug_message', 'gen3_text_message',
                'collect_paged_bms_entries', 'payload_layout', '_telemetry_layout',
                '_charger_layout', 'telemetry_extended_fields', 'telemetry_pack_fields',
                'bms_telemetry_status_fields'}


def _decoder_lengths():
    """decoder method name -> {message type: accepted payload lengths}, read from the same
    class constants the decoders use."""
    charger = tuple(Gen2.CHARGER_RECORD_OFFSET + Gen2.CHARGER_RECORD_LEN * n for n in (1, 2, 3, 4))
    return {
        'bms_storage_stats': {0x0f: (Gen2.BMS_STORAGE_STATS_LENGTH,)},
        'high_motor_controller_temp': {0x26: (Gen2.HIGH_MOTOR_CONTROLLER_TEMP_LENGTH,)},
        'charger_info': {0x48: charger},
        'gen3_firmware_build_info': {0x4e: Gen2.GEN3_FIRMWARE_BUILD_INFO_LENGTHS},
        'state_snapshot': {t: (v[1],) for t, v in Gen2.STATE_SNAPSHOT_TIERS.items()},
        'bms_cell_telemetry': {t: v[1] for t, v in Gen2.BMS_CELL_TELEMETRY_TIERS.items()},
        'vehicle_state_telemetry': {0x51: Gen2.VEHICLE_STATE_TELEMETRY_LENGTHS},
        'vehicle_state_telemetry_tier': {t: v[1] for t, v in Gen2.TELEMETRY_TIERS.items()},
    }


def test_every_raw_hex_decoder_declares_layouts_for_every_length_it_accepts():
    lengths = _decoder_lengths()
    emitters = set()
    for name, member in inspect.getmembers(Gen2):
        func = getattr(member, '__func__', None)
        if func is None or name.startswith('__'):
            continue
        try:
            source = inspect.getsource(func)
        except (OSError, TypeError):
            continue
        if re.search(r"['\"]raw_hex['\"]", source) and name not in NOT_DECODERS:
            emitters.add(name)
    assert emitters == set(lengths), (emitters ^ set(lengths))
    for name, per_type in lengths.items():
        for message_type, accepted in per_type.items():
            for length in accepted:
                layout = Gen2.payload_layout(message_type, length)
                assert layout is not None, (name, hex(message_type), length)


def test_layouts_cover_the_payload_exactly_with_valid_kinds():
    for name, per_type in _decoder_lengths().items():
        for message_type, accepted in per_type.items():
            for length in accepted:
                layout = Gen2.payload_layout(message_type, length)
                position = 0
                for start, stop, kind, label in layout:
                    assert start == position and stop > start
                    assert kind in (FIELD, RESERVED, UNKNOWN) and label
                    position = stop
                assert position == length, (hex(message_type), length)
    assert Gen2.payload_layout(0x51, 63) is None and Gen2.payload_layout(0x77, 10) is None


def test_the_flag_copy_is_a_declared_field_and_tag_29_stays_unknown():
    for message_type, tier_lengths in ((0x51, (64, 68)), (0x52, (81, 85)), (0x53, (95, 99))):
        tag = 35 if message_type == 0x51 else Gen2.TELEMETRY_TIERS[message_type][2]
        for length in tier_lengths:
            kinds = {i: (k, label) for s, e, k, label in Gen2.payload_layout(message_type, length) for i in range(s, e)}
            assert kinds[tag + 5] == (FIELD, 'validity_flags_copy')
            assert kinds[tag - 25][0] == FIELD
            if message_type in (0x52, 0x53):
                assert kinds[tag - 29][0] == UNKNOWN          # unexplained, never marked copy or reserved


# ---- the byte-flip check, over one synthetic valid payload per (type, length) ----

def _filler(length):
    return bytearray((i % 90) + 1 for i in range(length))     # never 0xF0 / 0xFF, nonzero


def _payload(message_type, length):
    buf = _filler(length)
    if message_type in (0x0f, 0x26, 0x54):
        return buf
    struct.pack_into('<I', buf, 0, 123000)
    buf[4], buf[5] = 5, 1
    if message_type in (0x51, 0x52, 0x53):
        tag = 35 if message_type == 0x51 else Gen2.TELEMETRY_TIERS[message_type][2]
        buf[tag:tag + 4] = b'RUN\x00'
        buf[tag - 25] = 0                                   # validity flags clear: gated fields visible
        for rel in (9, 13, 17, 21, 25):                     # the temperature words must hold a plausible value
            struct.pack_into('<i', buf, tag + rel, 10)
        for key, offset in Gen2.TELEMETRY_TAIL_FIELDS.get((message_type, length), {}).items():
            if key == 'speed':
                struct.pack_into('<I', buf, tag + offset, 3942 * Gen2.TELEMETRY_SPEED_STEP)
    elif message_type in (0x4b, 0x4c, 0x4d) and (message_type, length) in {
            (t, v[1]) for t, v in Gen2.STATE_SNAPSHOT_TIERS.items()}:
        tag = Gen2.STATE_SNAPSHOT_TIERS[message_type][2]
        buf[tag:tag + 4] = b'RUN\x00'
    elif message_type in (0x4b, 0x4c, 0x4d):                # BMS cell telemetry
        shift = Gen2.BMS_CELL_TELEMETRY_TIERS[message_type][0]
        buf[10 + shift] = 0x00
        buf[28 + shift] = 0x78
        buf[29 + shift] = 0x01
        buf[38 + shift] = 0x07
        buf[11], buf[30] = 0, 0
        for lo_hi in Gen2.BMS_CELL_TEMPERATURE_OFFSETS.get((message_type, length), ()):
            buf[lo_hi] = 20
    elif message_type == 0x4e:
        text = b'Jun  4 2019 17:39:46'
        buf[:] = bytearray(length)
        struct.pack_into('<I', buf, 0, 123000)
        buf[4], buf[5] = 5, 1
        buf[10:10 + len(text)] = text
        if length == 58:
            buf[52:58] = b'bankb\x00'
        else:                                               # 60: bank, then a build-number suffix string
            buf[44:50] = b'banka\x00'
            buf[50:58] = b'1da02c1\x00'
    elif message_type == 0x48:
        for record in range((length - 6) // 49):
            start = 6 + record * 49
            buf[start:start + 10] = b'Calex 720W'
    return buf


def _log_type(message_type, length):
    bms = {(t, n) for t, v in Gen2.BMS_CELL_TELEMETRY_TIERS.items() for n in v[1]}
    return LogFile.log_type_bms if (message_type, length) in bms or message_type == 0x0f else LogFile.log_type_mbb


def _flatten(value, prefix=''):
    out = {}
    if isinstance(value, dict):
        for k, v in value.items():
            if k not in ('raw_hex', 'build_info_suffix_raw_hex'):
                out.update(_flatten(v, f'{prefix}{k}.'))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.update(_flatten(v, f'{prefix}{i}.'))
    else:
        out[prefix] = value
    return out


def _output(message_type, length, payload):
    parser = Gen2._entry_parsers(_log_type(message_type, length), gen3_text=True)[message_type]
    result = parser(bytearray(payload))
    return (result.get('event'), result.get('conditions'), _flatten(result.get('structured_data') or {}))


def test_declared_field_bytes_change_decoded_output_and_the_rest_do_not():
    checked = 0
    for name, per_type in _decoder_lengths().items():
        for message_type, accepted in per_type.items():
            for length in accepted:
                if message_type == 0x48 and length > 55:
                    continue                                 # the record layout repeats; one and two records are covered
                payload = _payload(message_type, length)
                baseline = _output(message_type, length, payload)
                assert baseline[2], (hex(message_type), length, 'synthetic payload was not decoded')
                for start, stop, kind, label in Gen2.payload_layout(message_type, length):
                    for offset in range(start, stop):
                        changed = False
                        for delta in (0x01, 0x04, 0x10):
                            flipped = bytearray(payload)
                            flipped[offset] ^= delta
                            if _output(message_type, length, flipped) != baseline:
                                changed = True
                                break
                        if kind == FIELD:
                            assert changed, f'{hex(message_type)}/{length} byte {offset} declared field {label} changes nothing'
                        else:
                            assert not changed, f'{hex(message_type)}/{length} byte {offset} declared {kind} changes decoded output'
                        checked += 1
    assert checked > 500
