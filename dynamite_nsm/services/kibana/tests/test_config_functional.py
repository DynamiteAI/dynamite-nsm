"""
WARNING!
These tests create, write and read from temporary files created specifically for the tests,
for postinstallation tests use test_config_postinstall.py
"""

import yaml
from dynamite_nsm.services.kibana.config import ConfigManager


def test_load_and_modify_kibana_config_file(kibana_test_dir, kibana_test_config_yaml, dynamite_environment):
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
    changedport = "1.2.3.4"
    changedhost = "5431"
    changed_es_targs = ["http://1.2.3.4:9292"]
    changed_es_pw = "whats!a*lucene?"
    changed_es_usr = "searchymcsearchface"
    cfg_mgr.host = changedhost
    cfg_mgr.port = changedport
    cfg_mgr.elasticsearch_password = changed_es_pw
    cfg_mgr.elasticsearch_targets = changed_es_targs
    cfg_mgr.elasticsearch_username = changed_es_usr
    cfg_mgr.commit()
    del cfg_mgr
    del fixtureyaml
    fixtureyaml = {}
    with open(kibana_test_config_yaml, 'r') as yamlfile:
        fixtureyaml = yaml.load(yamlfile)
    assert fixtureyaml.get('server.host') == changedhost
    assert fixtureyaml.get('server.port') == changedport
    assert fixtureyaml.get('elasticsearch.hosts') == changed_es_targs
    assert fixtureyaml.get('elasticsearch.password') == changed_es_pw
    assert fixtureyaml.get('elasticsearch.username') == changed_es_usr
    cfg_mgr = ConfigManager(kibana_test_dir, verbose=True)
    assert cfg_mgr.host == changedhost
    assert cfg_mgr.port == changedport
    assert cfg_mgr.elasticsearch_targets == changed_es_targs
    assert cfg_mgr.elasticsearch_password == changed_es_pw
    assert cfg_mgr.elasticsearch_username == changed_es_usr

