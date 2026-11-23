"""Type 0x49 charging state (Gen2.charging_state). Invented values only."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2, Gen3TelemetryFirmware


def _payload(target=80, current=18, pilot=55, out=9, sched=0, slots=(14, 34, 20, 42), allowed=10, hard=106000, tgt_mv=117600):
    p = struct.pack('<IBB', 152000, 7, 2)
    p += struct.pack('<I', tgt_mv) + struct.pack('<H', pilot) + bytes([target]) + struct.pack('<H', out)
    p += struct.pack('<i', current) + bytes([0, sched]) + bytes(slots) + bytes([1, allowed]) + struct.pack('<I', hard)
    assert len(p) == 31
    return bytearray(p)


def _fw(rev):
    return Gen3TelemetryFirmware(rev)


def test_fields_at_rev_17_and_later():
    sd = Gen2.charging_state(_payload(), firmware=_fw(30), timestamp=1)['structured_data']
    assert sd['charge_voltage_target_volts'] == 117.6 and sd['charge_target_pct'] == 80
    assert sd['charge_current_amps'] == 18.0 and sd['evse_allowed_current_amps'] == 10
    assert sd['schedule_enabled'] is False and sd['charging_enabled'] is True and sd['evse_disconnect_flags'] == 0
    assert (sd['schedule_window_a_duration_min'], sd['schedule_window_a_start_min'],
            sd['schedule_window_b_duration_min'], sd['schedule_window_b_start_min']) == (420, 1020, 600, 1260)
    assert sd['hard_charge_voltage_target_volts'] == 106.0
    assert sd['raw_hex'] == bytes(_payload()).hex()
    # the two undecoded fields are not exposed as values
    assert not any(k in sd for k in ('evse_pilot_current_a', 'charger_output_current_amps'))


def test_charge_current_in_ma_up_to_rev_15():
    sd = Gen2.charging_state(_payload(current=12899), firmware=_fw(15), timestamp=1)['structured_data']
    assert sd['charge_current_amps'] == 12.899


def test_no_firmware_context_leaves_rev_dependent_fields_none():
    sd = Gen2.charging_state(_payload())['structured_data']
    assert sd['charge_current_amps'] is None and sd['schedule_window_b_start_min'] is None
    assert sd['charge_target_pct'] == 80


def test_schedule_windows_only_from_rev_13():
    sd = Gen2.charging_state(_payload(slots=(114, 43, 178, 61)), firmware=_fw(9), timestamp=1)['structured_data']
    assert sd['schedule_window_a_start_min'] is None and sd['schedule_window_b_duration_min'] is None
    sd = Gen2.charging_state(_payload(slots=(50, 1, 2, 3)), firmware=_fw(30), timestamp=1)['structured_data']
    assert sd['schedule_window_a_duration_min'] is None     # not a slot value


def test_target_127_is_no_limit():
    assert Gen2.charging_state(_payload(target=127), firmware=_fw(30), timestamp=1)['structured_data']['charge_target_pct'] is None
    assert Gen2.charging_state(_payload(target=101), firmware=_fw(30), timestamp=1)['structured_data']['charge_target_pct'] is None


def test_hard_target_zero_is_disabled():
    assert Gen2.charging_state(_payload(hard=0), firmware=_fw(30), timestamp=1)['structured_data']['hard_charge_voltage_target_volts'] is None


def test_wrong_length_or_bad_prefix_falls_back():
    assert 'structured_data' not in Gen2.charging_state(_payload()[:30]) or \
        'charge_target_pct' not in (Gen2.charging_state(_payload()[:30]).get('structured_data') or {})
    bad = _payload(); bad[0:4] = struct.pack('<I', 2_000_000)
    assert 'charge_target_pct' not in (Gen2.charging_state(bad).get('structured_data') or {})


def test_info_level_and_dispatch():
    r = Gen2.charging_state(_payload(), firmware=_fw(30), timestamp=1)
    assert r['event'] == 'Charging State' and r['log_level'] == 'INFO'
    assert Gen2._entry_parsers()[0x49] == Gen2.charging_state


def test_redecode_fills_the_current_from_the_file_revision():
    payload = {'message_type': '0x49', 'original_timestamp': 100}
    payload.update(Gen2.charging_state(_payload(current=21)))
    assert payload['structured_data']['charge_current_amps'] is None
    Gen3TelemetryFirmware.redecode([(0, payload, 0)], 30)
    assert payload['structured_data']['charge_current_amps'] == 21.0
