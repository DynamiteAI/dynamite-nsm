# These tests create, write and read from temporary files created specifically for the tests, for postinstallation tests use test_config_postinstall.py
import yaml
from dynamite_nsm.services.kibana.config import ConfigManager

def test_load_fixture_file(kibana_test_dir, kibana_test_config_yaml, dynamite_environment):
    cfg_mgr = ConfigManager(kibana_test_dir, verbose=True)
    fixtureyaml = {}
    with open(kibana_test_config_yaml, 'r') as yamlfile:
        fixtureyaml = yaml.load(yamlfile)
    assert cfg_mgr
    assert cfg_mgr.host == fixtureyaml.get('server.host')
    assert cfg_mgr.port == fixtureyaml.get('server.port')
    assert cfg_mgr.elasticsearch_targets == fixtureyaml.get('elasticsearch.hosts')
    assert cfg_mgr.elasticsearch_password == fixtureyaml.get('elasticsearch.password')
    assert cfg_mgr.elasticsearch_username == fixtureyaml.get('elasticsearch.username')