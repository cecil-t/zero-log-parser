"""Legacy MBB Riding and Disarmed rows written before the battery reported:
bytes 4-26 all zero on a full-length record (Gen2.status_block_unwritten)."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2

BLOCK = ('pack_voltage_volts', 'motor_temp_celsius', 'controller_temp_celsius', 'motor_rpm', 'battery_current_amps',
         'motor_current_amps', 'ambient_temp_celsius', 'odometer_km')


def _row(temps=(30, 28), soc=0, rest=None):
    x = bytearray(27)
    x[0], x[1] = temps
    struct.pack_into('<H', x, 2, soc)
    if rest is not None:
        x[4:27] = rest
    return x


def test_zero_block_is_none_in_both_decoders():
    for decoder, mods_key in ((Gen2.run_status, 'mods'), (Gen2.disarmed_status, 'modules_status')):
        sd = decoder(_row())['structured_data']
        assert all(sd[k] is None for k in BLOCK) and sd[mods_key] is None and sd['state_of_charge_percent'] is None
        assert sd['pack_temp_high_celsius'] == 30 and sd['pack_temp_low_celsius'] == 28


def test_soc_written_on_a_zero_block_stays():
    sd = Gen2.run_status(_row(soc=61))['structured_data']
    assert sd['state_of_charge_percent'] == 61 and sd['pack_voltage_volts'] is None


def test_whole_record_zero_takes_the_temperatures_too():
    sd = Gen2.run_status(_row(temps=(0, 0)))['structured_data']
    assert sd['pack_temp_high_celsius'] is None and sd['pack_temp_low_celsius'] is None
    sd = Gen2.run_status(_row(temps=(30, 0)))['structured_data']
    assert sd['pack_temp_high_celsius'] == 30 and sd['pack_temp_low_celsius'] == 0


def test_any_written_byte_in_the_block_keeps_the_row():
    rest = bytearray(23); rest[19:23] = struct.pack('<I', 9466)      # odometer only
    sd = Gen2.run_status(_row(rest=rest))['structured_data']
    assert sd['odometer_km'] == 9466 and sd['pack_voltage_volts'] == 0.0 and sd['state_of_charge_percent'] == 0


def test_short_record_unchanged():
    sd = Gen2.run_status(bytes(21))['structured_data']
    assert sd['pack_voltage_volts'] == 0.0 and sd['odometer_km'] is None
