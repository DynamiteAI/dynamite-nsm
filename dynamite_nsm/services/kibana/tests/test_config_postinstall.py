"""
These tests are for post-installation checks, they access data from the current installation and not from a
test environment.
"""

import os


def test_kibana_home_set_and_exists(dynamite_environment):
    kibana_home = dynamite_environment.get('KIBANA_HOME')
    assert kibana_home is not None
    assert os.path.exists(kibana_home)
    assert os.path.isdir(kibana_home)


def test_kibana_config_set_and_exists(dynamite_environment):
    kibana_conf = dynamite_environment.get('KIBANA_PATH_CONF')
    assert kibana_conf is not None
    assert os.path.exists(kibana_conf)
    assert os.path.isdir(kibana_conf)


def test_kibana_logs_set_and_exists(dynamite_environment):
    kibana_logs = dynamite_environment.get('KIBANA_LOGS')
    assert kibana_logs is not None
    assert os.path.exists(kibana_logs)
    assert os.path.isdir(kibana_logs)

