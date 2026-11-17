"""The header Initial date (the firmware build date) is 'Unknown' unless it is a real "Mmm dd yyyy hh:mm:ss"."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from zero_log_parser import LogData


def test_build_date_text():
    assert LogData.is_build_date_text('Jun 12 2019 16:44:38')
    assert LogData.is_build_date_text('Jun  1 2019 16:44:38')
    for bad in (',', '>', 'd', 'ike Shut Off After I', '0,100,0', '\x02', '', None,
                'Ju 14 2017 09:45:15', 'Aap 20 2017 02:p1:14', 'Feb 30 2017 01:02:03'):
        assert not LogData.is_build_date_text(bad), bad
