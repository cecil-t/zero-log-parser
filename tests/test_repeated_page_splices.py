"""Early Gen3 BMS logs that store each 128-byte page many times over: a
0x4B/0x4C/0x4D entry that runs past its page into a page that does not
continue it shows no field read from the other page's bytes
(Gen2.is_repeated_page_layout, Gen2.withhold_spliced_fields). Invented
values only."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zero_log_parser import Gen2

PARSERS = Gen2._entry_parsers('BMS', gen3_text=True)


def _cell_payload():
    """An invented 39-byte 0x4B cell telemetry payload."""
    x = bytearray(39)
    x[0:6] = struct.pack('<I', 500000) + bytes([4, 9])
    struct.pack_into('<HHH', x, 14, 3906, 3904, 3919)
    x[20] = 80                                   # SOC
    struct.pack_into('<i', x, 21, -1500)         # current, mA
    x[25] = 18                                   # temperature
    x[26:30] = bytes([0xd8, 0x03, 0x04, 0x04])   # status word
    x[38] = 7                                    # report mode
    return bytes(x)


def _framed(payload, t=0x5d400000):
    body = bytes([0x4b]) + struct.pack('<I', t) + payload
    return bytes([0xb2, len(body) + 2]) + body


def _buf(entry_at, page_after):
    """Header page, then page 1 holding the entry at entry_at (page offset),
    then page 2 as given (the page stored next), then two copies of page 1."""
    page1 = bytearray(b'\x11' * 128)
    e = _framed(_cell_payload())
    page1[entry_at:] = e[:128 - entry_at]
    rest = e[128 - entry_at:]
    page2 = bytearray(page_after(bytes(page1), rest))
    buf = bytes(128) + bytes(page1) + bytes(page2) + bytes(page1) * 2
    return buf, (128 + entry_at, len(e))


def _run(buf, span):
    start, length = span
    block = Gen2.parse_entry(bytearray(buf), start, 0, logger=None, log_type='BMS', gen3_text=True)[1]
    collected = [(0, block, 0)]
    n = Gen2.withhold_spliced_fields(bytearray(buf), collected, [span], PARSERS)
    return n, collected[0][1]['structured_data']


def test_layout_detection():
    buf, _ = _buf(95, lambda p1, rest: p1)
    assert Gen2.is_repeated_page_layout(buf)
    distinct = bytes(128) + b''.join(bytes([k + 1]) * 128 for k in range(20))
    assert not Gen2.is_repeated_page_layout(distinct)


def test_entry_running_into_a_copied_page_is_withheld():
    def copy_with_7(p1, rest):
        # page 2 is a copy of page 1, not the continuation; the foreign byte
        # that lands on the report mode happens to be 7 ("active")
        p2 = bytearray(p1)
        p2[12] = 7
        return p2
    buf, span = _buf(95, copy_with_7)
    n, sd = _run(buf, span)
    assert n == 1
    # the entry crosses at payload offset 26: the status word, flags and mode are foreign
    assert {'bms_status_word', 'bms_report_mode', 'bms_report_mode_label'} <= set(sd['corrupted_fields'])
    for k in sd['corrupted_fields']:
        assert sd[k] is None
    # the cell block and SOC before the boundary stay
    assert sd['voltage_low_cell_volts'] == 3.906 and sd['state_of_charge_percent'] == 80
    assert sd['battery_current_amps'] == -1.5 and sd['bms_temperature_c'] == 18


def test_entry_whose_page_continues_is_unchanged():
    def cont(p1, rest):
        page2 = bytearray(b'\x22' * 128)
        page2[:len(rest)] = rest
        page2[len(rest)] = 0xb2                  # the next entry starts right after it
        return page2
    buf, span = _buf(95, cont)
    n, sd = _run(buf, span)
    assert n == 0 and 'corrupted_fields' not in sd and sd['bms_report_mode'] == 7


def test_entry_inside_one_page_is_unchanged():
    buf, span = _buf(40, lambda p1, rest: p1)
    n, sd = _run(buf, span)
    assert n == 0 and 'corrupted_fields' not in sd


def test_boundary_before_the_payload_withholds_every_field():
    def rest_then_other(p1, rest):
        page2 = bytearray(b'\x22' * 128)
        page2[:len(rest)] = rest                 # decodes, but the stream does not continue after it
        return page2
    buf, span = _buf(125, rest_then_other)       # the boundary falls inside the time bytes
    n, sd = _run(buf, span)
    assert n == 1
    assert all(sd[k] is None for k in sd['corrupted_fields'])
    assert {'voltage_low_cell_volts', 'state_of_charge_percent', 'subsecond_us'} <= set(sd['corrupted_fields'])
