from typing import Optional

from yaml import Loader
from yaml import load

from dynamite_nsm.services.base.config import YamlConfigManager


class ConfigManager(YamlConfigManager):

    def __init__(self, configuration_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """Manage Kibana Configuration
        Args:
            configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
            stdout: Print output to console
            verbose: Include detailed debug messages
        Returns:
            None
        """
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
        super().__init__(self.config_data_raw, name='KIBANACFG', verbose=verbose, stdout=stdout, **extract_tokens)
        self.parse_yaml_file()

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None,
               top_text: Optional[str] = None) -> None:
        """Write out an updated configuration file, and optionally backup the old one.
        Args:
            out_file_path: The path to the output file; if none given overwrites existing
            backup_directory: The path to the backup directory
            top_text: The text to be appended at the top of the config file (typically used for YAML version header)
        Returns:
            None
        """
        if not out_file_path:
            out_file_path = self.kibana_config_path

        super(ConfigManager, self).commit(out_file_path, backup_directory)
