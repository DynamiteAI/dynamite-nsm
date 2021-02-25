from yaml import load
from yaml import Loader
from typing import Optional
from dynamite_nsm.services.base.config import YamlConfigManager


class ConfigManager(YamlConfigManager):

    def __init__(self, configuration_directory: str):
        extract_tokens = {
            'host': ('server.host',),
            'port': ('server.port',),
            'elasticsearch_targets': ('elasticsearch.hosts',),
            'elasticsearch_username': ('elasticsearch.username',),
            'elasticsearch_password': ('elasticsearch.password',),
        }
        self.host = None
        self.port = None
        self.elasticsearch_targets = None
        self.elasticsearch_username = None
        self.elasticsearch_password = None
        self.configuration_directory = configuration_directory
        self.kibana_config_path = f'{self.configuration_directory}/kibana.yml'
        with open(self.kibana_config_path) as configyaml:
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
            out_file_path = self.kibana_config_path

        super(ConfigManager, self).write_config(out_file_path, backup_directory)