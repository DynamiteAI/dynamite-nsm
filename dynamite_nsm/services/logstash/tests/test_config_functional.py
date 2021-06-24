# These tests create, write and read from temporary files created specifically for the tests, for postinstallation tests use test_config_postinstall.py
import yaml
from dynamite_nsm.services.logstash.config import ConfigManager
from dynamite_nsm.tests.fixtures import dynamite_environment

def test_load_and_modify_logstash_config_file(logstash_test_dir, logstash_test_config_yaml, dynamite_environment):
    cfg_mgr = ConfigManager(logstash_test_dir, verbose=True)
    fixtureyaml = {}
    with open(logstash_test_config_yaml, 'r') as yamlfile:
        fixtureyaml = yaml.load(yamlfile)
    assert cfg_mgr
    assert fixtureyaml
    assert fixtureyaml.get('node.name') == cfg_mgr.node_name
    assert fixtureyaml.get('path.data') == cfg_mgr.path_data
    assert fixtureyaml.get('path.logs') == cfg_mgr.path_logs
    assert fixtureyaml.get('pipeline.batch.delay') == cfg_mgr.pipeline_batch_delay
    assert fixtureyaml.get('pipeline.batch.size') == cfg_mgr.pipeline_batch_size


