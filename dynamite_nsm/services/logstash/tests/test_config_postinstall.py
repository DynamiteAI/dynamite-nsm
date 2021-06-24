# These tests are for post-installation checks, they access data from the current instalation and not from a test environment.

import os
from dynamite_nsm.tests.fixtures import dynamite_environment

def test_logstash_home_set_and_exists(dynamite_environment):
    logstash_home = dynamite_environment.get('LS_HOME')
    assert logstash_home is not None
    assert os.path.exists(logstash_home)
    assert os.path.isdir(logstash_home)

def test_logstash_config_set_and_exists(dynamite_environment):
    logstash_conf = dynamite_environment.get('LS_PATH_CONF')
    assert logstash_conf is not None
    assert os.path.exists(logstash_conf)
    assert os.path.isdir(logstash_conf)


def test_logstash_logs_set_and_exists(dynamite_environment):
    logstash_logs = dynamite_environment.get('LS_LOGS')
    assert logstash_logs is not None
    assert os.path.exists(logstash_logs)
    assert os.path.isdir(logstash_logs)

