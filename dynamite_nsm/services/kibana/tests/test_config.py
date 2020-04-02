import os
import shutil
import unittest

from dynamite_nsm.services.kibana import config


def create_dummy_kibanayaml(kb_config_directory):
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
    with open(os.path.join(kb_config_directory, 'kibana.yml'), 'w') as f:
        f.write(example_config_string)


class Tests(unittest.TestCase):

    def setUp(self):
        self.config_root = '/etc/dynamite/test'
        self.config_directory = os.path.join(self.config_root, 'kibana')

        # Setup Test Space
        os.makedirs(self.config_directory, exist_ok=True)
        create_dummy_kibanayaml(self.config_directory)

        self.config_manager = config.ConfigManager(configuration_directory=self.config_directory)

    def test_kibanayaml_update_server_host(self):
        self.config_manager.server_host = 'localhost'
        self.config_manager.write_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.server_host == 'localhost')

    def test_kibanayaml_update_server_port(self):
        self.config_manager.server_port = 9999
        self.config_manager.write_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.server_port == 9999)

    def test_kibanayaml_update_username(self):
        self.config_manager.elasticsearch_username = 'jamin123'
        self.config_manager.write_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.elasticsearch_username == 'jamin123')

    def test_kibanayaml_update_password(self):
        self.config_manager.elasticsearch_password = '!jamin111&^@1'
        self.config_manager.write_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.elasticsearch_password == '!jamin111&^@1')

    def tearDown(self):
        shutil.rmtree(self.config_root, ignore_errors=True)
