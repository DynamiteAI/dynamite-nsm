import shutil
import unittest

from dynamite_nsm.services.elasticsearch import config


class Tests(unittest.TestCase):

    def setUp(self):
        self.config_directory = '/etc/dynamite/elasticsearch'
        self.config_manager = config.ConfigManager(configuration_directory=self.config_directory)

    def test_elasticyaml_update(self):
        self.config_manager.path_logs = '/var/log/dynamite/test/logs'
        self.config_manager.write_elasticsearch_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.path_logs == '/var/log/dynamite/test/logs')

    def tearDown(self):
        shutil.rmtree(self.config_directory, ignore_errors=True)