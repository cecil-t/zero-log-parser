"""LogData.require_zero_log: a file with no board type, platform or VIN whose
entries are mostly unknown types with impossible dates is not a Zero log."""
import os, sys, types
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zero_log_parser import LogData, LogFile, UnreadableLogError


def _stub(n, unknown, invalid, log_type=LogFile.log_type_unknown, platform=None, vin_source=None):
    ents = [types.SimpleNamespace(event=('Unknown Type 211' if i < unknown else 'Board Status'),
                                  time_source=('invalid' if i < invalid else 'clock')) for i in range(n)]
    ld = object.__new__(LogData)
    ld.log_file = types.SimpleNamespace(log_type=log_type, file_path='x.bin')
    ld.header_json_fields = {'platform': platform}
    ld.vin_source = vin_source
    ld._get_processed_entries = lambda: ents
    return ld


def test_noise_rejected():
    with pytest.raises(UnreadableLogError):
        _stub(100, 80, 75).require_zero_log()


def test_real_damaged_log_kept():
    _stub(100, 29, 14).require_zero_log()          # the most unknown-heavy real log measured
    _stub(100, 80, 75, platform='legacy').require_zero_log()
    _stub(100, 80, 75, vin_source='header').require_zero_log()
    _stub(100, 80, 75, log_type=LogFile.log_type_mbb).require_zero_log()
