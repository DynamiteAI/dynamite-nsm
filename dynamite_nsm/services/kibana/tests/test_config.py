import os
import shutil
import unittest

from dynamite_nsm.services.kibana import config


def create_dummy_kibanayaml(es_config_directory):
    example_config_string =\
    '''
elasticsearch.hosts:
- http://localhost:9200
elasticsearch.password: changeme
elasticsearch.username: elastic
pid.file: /var/run/dynamite/kibana/kibana.pid
server.host: 0.0.0.0
server.port: 5601
    '''
    with open(os.path.join(es_config_directory, 'kibana.yml'), 'w') as f:
        f.write(example_config_string)


class Tests(unittest.TestCase):

    def setUp(self):
        self.config_root = '/etc/dynamite/test'
        self.config_directory = os.path.join(self.config_root, 'kibana')

        # Setup Test Space
        os.makedirs(self.config_directory, exist_ok=True)
        create_dummy_kibanayaml(self.config_directory)

        self.config_manager = config.ConfigManager(configuration_directory=self.config_directory)

    def test_kibanayaml_update_path_logs(self):
        self.config_manager.path_logs = '/etc/dynamite/kibana/test/config'
        self.config_manager.write_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.configuration_directory == '/etc/dynamite/kibana/test/config')

    def test_kibanayaml_username(self):
        self.config_manager.elasticsearch_username = 'jamin123'
        self.config_manager.write_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.elasticsearch_username == 'jamin123')

    def test_kibanayaml_password(self):
        self.config_manager.elasticsearch_password = '!jamin111&^@1'
        self.config_manager.write_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.elasticsearch_password == '!jamin111&^@1')

    def tearDown(self):
        shutil.rmtree(self.config_root, ignore_errors=True)
