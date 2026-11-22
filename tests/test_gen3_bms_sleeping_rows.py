"""Gen3 BMS cell telemetry written while the BMS sleeps (sleep indicator 0x20)
with the unloaded cell at 0 V: SOC, current and the unloaded cell are no
readings (None); pack and cell voltages stay. Invented payloads."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2
SHIFT = {0x4b: 0, 0x4c: 4, 0x4d: 8}


def _payload(mt, unloaded, soc, current_ma, sleep):
    buf = bytearray({0x4b: 45, 0x4c: 63, 0x4d: 71}[mt])
    struct.pack_into('<I', buf, 0, 250_000)
    buf[4], buf[5] = 3, 9
    base = 14 + SHIFT[mt]
    struct.pack_into('<HHHBi', buf, base, 3810, unloaded, 3842, soc, current_ma)
    struct.pack_into('<I', buf, base + 25, 104_500)
    buf[10 + SHIFT[mt]] = sleep
    return buf


def test_sleeping_row():
    for mt in SHIFT:
        sd = Gen2.bms_cell_telemetry(mt, _payload(mt, 0, 0, 0, 0x20))['structured_data']
        assert sd['state_of_charge_percent'] is None
        assert sd['battery_current_amps'] is None
        assert sd['voltage_unloaded_cell_volts'] is None
        assert sd['voltage_low_cell_volts'] == 3.81 and sd['pack_voltage_volts'] == 104.5


def test_awake_row_with_unloaded_zero_kept():
    sd = Gen2.bms_cell_telemetry(0x4b, _payload(0x4b, 0, 0, 0, 0x00))['structured_data']
    assert sd['state_of_charge_percent'] == 0 and sd['voltage_unloaded_cell_volts'] == 0.0


def test_sleeping_row_with_unloaded_reading_kept():
    sd = Gen2.bms_cell_telemetry(0x4b, _payload(0x4b, 3805, 61, 12_500, 0x20))['structured_data']
    assert sd['state_of_charge_percent'] == 61 and sd['battery_current_amps'] == 12.5
