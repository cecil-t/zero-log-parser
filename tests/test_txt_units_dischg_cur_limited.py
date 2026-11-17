"""TXT units for the Batt Dischg Cur Limited fields."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from zero_log_parser import TXT_UNIT_BY_KEY


def test_units():
    assert TXT_UNIT_BY_KEY['max_current_amps'] == 'A'
    assert TXT_UNIT_BY_KEY['max_pack_temp_celsius'] == '°C'
    assert TXT_UNIT_BY_KEY['is_current_limited'] == ''
