import os
import shutil
import unittest

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.elasticsearch import config


class Tests(unittest.TestCase):

    def setUp(self):
        self.config_path = '/etc/dynamite/test'
        self.config_directory = os.path.join(self.config_path, 'elasticsearch')
        utilities.download_file(const.DEFAULT_CONFIGS_URL,
                      const.DEFAULT_CONFIGS_ARCHIVE_NAME, stdout=True)
        utilities.extract_archive(os.path.join(const.INSTALL_CACHE, 'default_configs.tar.gz'), self.config_path)

        self.config_manager = config.ConfigManager(configuration_directory=self.config_directory)

    def test_elasticyaml_update(self):
        self.config_manager.path_logs = '/var/log/dynamite/test/logs'
        self.config_manager.write_elasticsearch_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.path_logs == '/var/log/dynamite/test/logs')

    def tearDown(self):
        shutil.rmtree(self.config_directory, ignore_errors=True)