from yaml import load
from yaml import Loader
from typing import Optional

from dynamite_nsm.services.base.config import JavaOptionsConfigManager, YamlConfigManager


class ConfigManager(YamlConfigManager):

    def __init__(self, configuration_directory: str):
        extract_tokens = {
            'node_name': ('node.name',),
            'cluster_name': ('cluster.name',),
            'seed_hosts': ('discovery.seed_hosts',),
            'initial_master_nodes': ('cluster.initial_master_nodes',),
            'network_host': ('network.host',),
            'http_port': ('http.port',),
            'path_data': ('path.data',),
            'path_logs': ('path.logs',),
            'search_max_buckets': ('search.max_buckets',),
        }
        self.node_name = None
        self.cluster_name = None
        self.seed_hosts = None
        self.initial_master_nodes = None
        self.network_host = None
        self.http_port = None
        self.path_logs = None
        self.search_max_buckets = None
        self.configuration_directory = configuration_directory
        self.elasticsearch_config_path = f'{self.configuration_directory}/elasticsearch.yml'

        with open(self.elasticsearch_config_path) as configyaml:
            self.config_data_raw = load(configyaml, Loader=Loader)
        super().__init__(self.config_data_raw, **extract_tokens)
        self.parse_yaml_file()

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        """
        Write out an updated configuration file, and optionally backup the old one.

        :param out_file_path: The path to the output file; if none given overwrites existing
        :param backup_directory: The path to the backup directory
        """
        if not out_file_path:
            out_file_path = self.elasticsearch_config_path

        super(ConfigManager, self).write_config(out_file_path, backup_directory)


class JavaHeapOptionsConfigManager(JavaOptionsConfigManager):

    def __init__(self, configuration_directory):
        self.configuration_directory = configuration_directory
        self.elasticsearch_jvm_config_path = f'{self.configuration_directory}/jvm.options'
        with open(self.elasticsearch_jvm_config_path) as jvm_config:
            data = {'data': jvm_config.readlines()}
        super().__init__(data)

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        if not out_file_path:
            out_file_path = self.elasticsearch_jvm_config_path
        super(JavaHeapOptionsConfigManager, self).write_config(out_file_path, backup_directory)
