from yaml import load
from yaml import Loader
from typing import Optional
from dynamite_nsm.services.base.config import JavaOptionsConfigManager, YamlConfigManager


class ConfigManager(YamlConfigManager):

    def __init__(self, configuration_directory: str):
        extract_tokens = {
            'node_name': ('node.name',),
            'path_data': ('path.data',),
            'path_logs': ('path.logs',),
            'pipeline_batch_size': ('pipeline.batch.size',),
            'pipeline_batch_delay': ('pipeline.batch.delay',)
        }

        self.node_name = None
        self.path_data = None
        self.path_logs = None
        self.pipeline_batch_size = None
        self.pipeline_batch_delay = None
        self.configuration_directory = configuration_directory
        self.logstash_config_path = f'{self.configuration_directory}/logstash.yml'

        with open(self.logstash_config_path) as configyaml:
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
            out_file_path = self.logstash_config_path

        super(ConfigManager, self).write_config(out_file_path, backup_directory)


class JavaHeapOptionsConfigManager(JavaOptionsConfigManager):

    def __init__(self, configuration_directory):
        self.configuration_directory = configuration_directory
        self.logstash_jvm_config_path = f'{self.configuration_directory}/jvm.options'
        with open(self.logstash_jvm_config_path) as jvm_config:
            data = {'data': jvm_config.readlines()}
        super().__init__(data)

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        if not out_file_path:
            out_file_path = self.logstash_jvm_config_path
        super(JavaHeapOptionsConfigManager, self).write_config(out_file_path, backup_directory)
