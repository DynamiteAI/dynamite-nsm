import os
import shutil
import unittest

from dynamite_nsm.services.elasticsearch import config


def create_dummy_elasticyaml(es_config_directory):
    example_config_string = \
        '''
    cluster.initial_master_nodes:
    - es-1
    cluster.name: dynamite-cluster
    discovery.seed_hosts:
    - localhost
    http.port: 9200
    indices.query.bool.max_clause_count: 8192
    network.host: 0.0.0.0
    node.name: es-1
    path.data: /opt/dynamite/elasticsearch/data/
    path.logs: /var/log/dynamite/elasticsearch/
    search.max_buckets: 100000
    xpack.security.enabled: true
    xpack.security.transport.ssl.enabled: true
    xpack.security.transport.ssl.keystore.path: config/elastic-certificates.p12
    xpack.security.transport.ssl.truststore.path: config/elastic-certificates.p12
    xpack.security.transport.ssl.verification_mode: certificate
        '''
    with open(os.path.join(es_config_directory, 'elasticsearch.yml'), 'w') as f:
        f.write(example_config_string)


def create_dummy_javaopts(es_config_directory):
    example_config_string = \
        '''
    -Xms4g
    -Xmx4g
        '''
    with open(os.path.join(es_config_directory, 'jvm.options'), 'w') as f:
        f.write(example_config_string)


class Tests(unittest.TestCase):

    def setUp(self):
        self.config_root = '/etc/dynamite/test'
        self.config_directory = os.path.join(self.config_root, 'elasticsearch')

        # Setup Test Space
        os.makedirs(self.config_directory, exist_ok=True)
        create_dummy_elasticyaml(self.config_directory)
        create_dummy_javaopts(self.config_directory)

        self.config_manager = config.ConfigManager(configuration_directory=self.config_directory)

    def test_elasticyaml_update_path_logs(self):
        self.config_manager.path_logs = '/var/log/dynamite/test/logs'
        self.config_manager.write_elasticsearch_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert (config_manager_read.path_logs == '/var/log/dynamite/test/logs')

    def test_elasticyaml_update_cluster_name(self):
        self.config_manager.cluster_name = 'my-new-cluster'
        self.config_manager.write_elasticsearch_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert (config_manager_read.cluster_name == 'my-new-cluster')

    def test_elasticyaml_update_network_host(self):
        self.config_manager.network_host = 'myhost.local'
        self.config_manager.write_elasticsearch_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert (config_manager_read.network_host == 'myhost.local')

    def test_javaopts_update_heapsize(self):
        self.config_manager.java_maximum_memory = 10
        self.config_manager.java_initial_memory = 10
        self.config_manager.write_jvm_config()

        config_manager_read = config.ConfigManager(self.config_directory)

        assert (config_manager_read.java_initial_memory == 10 and config_manager_read.java_maximum_memory == 10)

    def tearDown(self):
        shutil.rmtree(self.config_root, ignore_errors=True)
