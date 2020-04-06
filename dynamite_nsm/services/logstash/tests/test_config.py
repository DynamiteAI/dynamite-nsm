import os
import shutil
import unittest

from dynamite_nsm import utilities
from dynamite_nsm.services.logstash import config


def create_dummy_logstashyaml(ls_config_directory):
    example_config_string =\
    '''
node.name: ls-1
path.data: /opt/dynamite/logstash/data/
path.logs: /var/log/dynamite/logstash/
pipeline.batch.delay: 50
pipeline.batch.size: 125
    '''
    with open(os.path.join(ls_config_directory, 'logstash.yml'), 'w') as f:
        f.write(example_config_string)


def create_dummy_javaopts(ls_config_directory):
    example_config_string = \
    '''
-Xms4g
-Xmx4g
    '''
    with open(os.path.join(ls_config_directory, 'jvm.options'), 'w') as f:
        f.write(example_config_string)


class Tests(unittest.TestCase):

    def setUp(self):
        self.config_root = '/etc/dynamite/test'
        self.config_directory = os.path.join(self.config_root, 'logstash')

        # Setup Test Space
        utilities.makedirs(self.config_directory, exist_ok=True)
        create_dummy_logstashyaml(self.config_directory)
        create_dummy_javaopts(self.config_directory)

        self.config_manager = config.ConfigManager(configuration_directory=self.config_directory)

    def test_logstashyaml_update_node_name(self):
        self.config_manager.node_name = 'logstash-1'
        self.config_manager.write_logstash_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.node_name == 'logstash-1')

    def test_logstashyaml_update_path_data(self):
        self.config_manager.path_data = '/var/log/dynamite/data/'
        self.config_manager.write_logstash_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.path_data == '/var/log/dynamite/data/')

    def test_logstashyaml_update_pipeline_batch_delay(self):
        self.config_manager.pipeline_batch_delay = 10
        self.config_manager.write_logstash_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.pipeline_batch_delay == 10)

    def test_javaopts_update_heapsize(self):
        self.config_manager.java_maximum_memory = 10
        self.config_manager.java_initial_memory = 10
        self.config_manager.write_jvm_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert(config_manager_read.java_initial_memory == 10 and config_manager_read.java_maximum_memory == 10)

    def tearDown(self):
        shutil.rmtree(self.config_root, ignore_errors=True)
