"""Header and System Information strings that are not values: a model that is
log text or binary bytes, a firmware version that is not a part number, and a
serial reading UNINITIALIZED. Invented values."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import Gen2


def test_model_text():
    for ok in ('SR', 'FXS11', 'S_A1', 'DS_AUS', 'NONE', 'SRF'):
        assert Gen2.model_text(ok) == ok
    for bad in ('', '\x01', ' Mo', 'G: ', '3, ', ']', '\x02M\x0f', 'ing', 'aIN', 'Cul', None):
        assert Gen2.model_text(bad) == 'Unknown'


def test_firmware_version_text():
    assert Gen2.firmware_version_text('40-08198') == '40-08198'
    for bad in ('`', '40-', '-1', ' 40', None):
        assert Gen2.firmware_version_text(bad) == 'Unknown'


def test_unset_serial():
    assert 'UNINITIALIZED' in Gen2.UNSET_SERIALS
