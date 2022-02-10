import os
from datetime import datetime
from typing import Optional

from yaml import Loader
from yaml import load, dump

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base.config import YamlConfigManager
from dynamite_nsm.services.base.config_objects.filebeat.misc import IndexTemplateSettings, InputLogs, FieldProcessors, \
    KibanaSettings
from dynamite_nsm.services.base.config_objects.filebeat.targets import ElasticsearchTargets, LogstashTargets, \
    KafkaTargets, RedisTargets


class InvalidAgentTag(Exception):
    """
    Thrown when Filebeat agent tag is invalid
    """

    def __init__(self):
        msg = "Agent tag must be between 5 and 30 characters, and contain alphanumeric and '_' characters only."
        super(InvalidAgentTag, self).__init__(msg)


class ConfigManager(YamlConfigManager):
    """Manage main Filebeat Configuration"""

    def __init__(self, install_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """
        Configure Filebeat
        Args:
            install_directory: The path to the filebeat installation directory (E.G /opt/dynamite/filebeat)
            verbose: Include detailed debug messages
            stdout: Print output to console
        ___

        # Instance Variables
        - `input_logs` - A `misc.InputLogs` instance representing the log paths to be monitored (if ECS is disabled)
        - `field_processors` - A `misc.FieldProcessors` instance representing fields to be manipulated at parse time.
        - `index_template_settings` - A `misc.IndexTemplateSettings` instance representing the Elasticsearch index
        template settings to be used
        - `elasticsearch_targets` - A `targets.ElasticsearchTargets` instance used when sending logs directly to
        Elasticsearch.
        - `logstash_targets` - A `targets.LogstashTargets` instance used when sending logs to Logstash.
        - `kafka_targets` - A `targets.KafkaTargets` instance used when sending logs to Kafka.
        - `redis_targets` - A `targets.RedisTargets` instance used when sending logs to Redis.
        """
        extract_tokens = {
            '_inputs_raw': ('filebeat.inputs',),
            '_elasticsearch_targets_raw': ('output.elasticsearch',),
            '_logstash_targets_raw': ('output.logstash',),
            '_kafka_targets_raw': ('output.kafka',),
            '_redis_targets_raw': ('output.redis',),
            '_index_template_settings_raw': ('setup.template',),
            '_kibana_settings_raw': ('setup.kibana',),
            '_processors_raw': ('processors',)
        }
        self._inputs_raw = {}
        self._processors_raw = {}
        self._index_template_settings_raw = {}
        self._kibana_settings_raw = {}
        self._elasticsearch_targets_raw = {}
        self._logstash_targets_raw = {}
        self._kafka_targets_raw = {}
        self._redis_targets_raw = {}
        self.install_directory = install_directory
        self.filebeat_config_path = f'{self.install_directory}/filebeat.yml'

        with open(self.filebeat_config_path, 'r') as configyaml:
            self.config_data_raw = load(configyaml, Loader=Loader)
        super().__init__(self.config_data_raw, name='filebeat.config', verbose=verbose, stdout=stdout, **extract_tokens)

        self.parse_yaml_file()
        try:
            agent_tag = self._processors_raw[0].get('add_fields', {}).get('fields', {}).get(
                'originating_agent_tag')
        except IndexError:
            agent_tag = None

        try:
            log_paths = self._inputs_raw[0].get('paths', [])
        except IndexError:
            log_paths = []

        self.input_logs = InputLogs(
            monitor_log_paths=log_paths
        )

        self.field_processors = FieldProcessors(
            originating_agent_tag=agent_tag
        )
        self.index_template_settings = IndexTemplateSettings(
            enabled=self._index_template_settings_raw.get('enabled', False),
            overwrite=self._index_template_settings_raw.get('overwrite', False),
            index_name=self._index_template_settings_raw.get('name', 'filebeat'),
            index_pattern=self._index_template_settings_raw.get('pattern', 'filebeat-*'),
        )

        self.kibana_settings = KibanaSettings(
            enabled=self._kibana_settings_raw.get('enabled'),
            kibana_target_str=self._kibana_settings_raw.get('host'),
            kibana_protocol=self._kibana_settings_raw.get('protocol')
        )

        self.elasticsearch_targets = ElasticsearchTargets(
            target_strings=self._elasticsearch_targets_raw.get('hosts'),
            index=self._elasticsearch_targets_raw.get('index'),
            ssl_certificate_authorities=self._elasticsearch_targets_raw.get('ssl', {}).get('certificate_authorities'),
            username=self._elasticsearch_targets_raw.get('username'),
            password=self._elasticsearch_targets_raw.get('password'),
            ssl_enabled=self._elasticsearch_targets_raw.get('ssl', False),
            ssl_certificate=self._elasticsearch_targets_raw.get('ssl', {}).get('certificate'),
            ssl_key=self._elasticsearch_targets_raw.get('ssl', {}).get('key'),
            ssl_verification_mode=self._elasticsearch_targets_raw.get('ssl', {}).get('verification_mode'),
            enabled=self._elasticsearch_targets_raw.get('enabled', False)
        )

        self.logstash_targets = LogstashTargets(
            target_strings=self._logstash_targets_raw.get('hosts'),
            index=self._logstash_targets_raw.get('index'),
            load_balance=self._logstash_targets_raw.get('loadbalance'),
            socks_5_proxy_url=self._logstash_targets_raw.get('proxy_url'),
            pipelines=self._logstash_targets_raw.get('pipelining'),
            max_batch_size=self._logstash_targets_raw.get('bulk_max_size'),
            ssl_enabled=self._logstash_targets_raw.get('ssl', False),
            ssl_certificate_authorities=self._logstash_targets_raw.get('ssl', {}).get('certificate_authorities'),
            ssl_certificate=self._logstash_targets_raw.get('ssl', {}).get('certificate'),
            ssl_key=self._logstash_targets_raw.get('ssl', {}).get('key'),
            ssl_verification_mode=self._logstash_targets_raw.get('ssl', {}).get('verification_mode'),
            enabled=self._logstash_targets_raw.get('enabled', False)
        )

        self.kafka_targets = KafkaTargets(
            target_strings=self._kafka_targets_raw.get('hosts'),
            topic=self._kafka_targets_raw.get('topic'),
            username=self._kafka_targets_raw.get('username'),
            password=self._kafka_targets_raw.get('password'),
            ssl_enabled=self._kafka_targets_raw.get('ssl', False),
            ssl_certificate_authorities=self._kafka_targets_raw.get('ssl', {}).get('certificate_authorities'),
            ssl_certificate=self._kafka_targets_raw.get('ssl', {}).get('certificate'),
            ssl_key=self._kafka_targets_raw.get('ssl', {}).get('key'),
            ssl_verification_mode=self._kafka_targets_raw.get('ssl', {}).get('verification_mode'),
            enabled=self._kafka_targets_raw.get('enabled', False)
        )

        self.redis_targets = RedisTargets(
            target_strings=self._redis_targets_raw.get('hosts'),
            index=self._redis_targets_raw.get('index'),
            password=self._redis_targets_raw.get('password'),
            load_balance=self._redis_targets_raw.get('loadbalance'
                                                     ''),
            db=self._redis_targets_raw.get('db'),
            ssl_enabled=self._redis_targets_raw.get('ssl', False),
            ssl_certificate_authorities=self._redis_targets_raw.get('ssl', {}).get('certificate_authorities'),
            ssl_certificate=self._redis_targets_raw.get('ssl', {}).get('certificate'),
            ssl_key=self._redis_targets_raw.get('ssl', {}).get('key'),
            ssl_verification_mode=self._redis_targets_raw.get('ssl', {}).get('verification_mode'),
            enabled=self._redis_targets_raw.get('enabled', False)
        )

    @classmethod
    def from_raw_text(cls, raw_text: str, install_directory: Optional[str] = None):
        """Alternative method for creating configuration file from raw text
        Args:
            raw_text: The string representing the configuration file
            install_directory: The install directory for Filebeat
        Returns:
             An instance of ConfigManager
        """
        tmp_dir = f'{const.CONFIG_PATH}/.tmp'
        tmp_config = f'{tmp_dir}/filebeat.yml'
        utilities.makedirs(tmp_dir)
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(install_directory=tmp_dir)
        if install_directory:
            c.install_directory = install_directory
        return c

    def enable_ecs_normalization(self) -> None:
        """Enable ECS normalization for Zeek/Suricata logs
        Returns:
            None
        """
        modules_path = os.path.join(self.install_directory, 'modules.d')
        if not os.path.exists(modules_path):
            return
        if os.path.exists(os.path.join(modules_path, 'zeek.yml.disabled')):
            os.rename(os.path.join(modules_path, 'zeek.yml.disabled'), os.path.join(modules_path, 'zeek.yml'))
        if os.path.exists(os.path.join(modules_path, 'suricata.yml.disabled')):
            os.rename(os.path.join(modules_path, 'suricata.yml.disabled'), os.path.join(modules_path, 'suricata.yml'))
        self.input_logs.enabled = False

    def disable_ecs_normalization(self) -> None:
        """
        Disable ECS normalization for Zeek/Suricata logs
        Returns:
            None
        """
        modules_path = os.path.join(self.install_directory, 'modules.d')
        if not os.path.exists(modules_path):
            return
        if os.path.exists(os.path.join(modules_path, 'zeek.yml')):
            os.rename(os.path.join(modules_path, 'zeek.yml'), os.path.join(modules_path, 'zeek.yml.disabled'))
        if os.path.exists(os.path.join(modules_path, 'suricata.yml')):
            os.rename(os.path.join(modules_path, 'suricata.yml'), os.path.join(modules_path, 'suricata.yml.disabled'))
        self.input_logs.enabled = True

    def is_ecs_normalization_available(self) -> bool:
        """Check if the applicable modules (zeek/suricata) have been patched to point to the correct log locations

        Returns:
             True, if ECS normalization is available (can be enabled)
        """
        modules_path = os.path.join(self.install_directory, 'modules.d')
        return os.path.exists(os.path.join(modules_path, '.patched'))

    def is_ecs_normalization_enabled(self) -> bool:
        """Check if ECS normalization is enabled over generic inputs
        Returns:
             True, if ECS normalization is enabled.
        """
        modules_path = os.path.join(self.install_directory, 'modules.d')
        zeek_module_exists = os.path.exists(os.path.join(modules_path, 'zeek.yml'))
        suricata_module_exists = os.path.exists(os.path.join(modules_path, 'suricata.yml'))
        return zeek_module_exists and suricata_module_exists

    def patch_modules(self, zeek_log_directory: str, suricata_log_directory: str) -> None:
        """and patch the directory paths to point to the Dynamite configured paths
        Args:
            zeek_log_directory: The path to the Zeek current log directory
            suricata_log_directory: The path to the Suricata log directory
        Returns:
            None
        """

        def write_module(path, data):
            self.logger.debug(f'Writing module {path}')
            with open(path, 'w') as module_yaml:
                dump(data, module_yaml, default_flow_style=False)

        suricata_module_path = None
        zeek_module_path = None
        suricata_module_data = None
        zeek_module_data = None
        modules_path = os.path.join(self.install_directory, 'modules.d')
        self.logger.debug(f'Located modules at {modules_path}')
        if not os.path.exists(modules_path):
            return
        for module in os.listdir(modules_path):
            if not (module.endswith('.yml') or module.endswith('.yaml') or module.endswith('.disabled')):
                continue
            if 'zeek' in module:
                zeek_module_path = os.path.join(modules_path, module)
                self.logger.debug(f'Setting {module} path -> {zeek_module_path}')
            elif 'suricata' in module:
                suricata_module_path = os.path.join(modules_path, module)
                self.logger.debug(f'Setting {module} path -> {suricata_module_path}')
        if zeek_module_path:
            self.logger.debug(f'Located Filebeat module {zeek_module_path}')
            with open(zeek_module_path, 'r') as zeek_module_yaml:
                zeek_module_data = load(zeek_module_yaml, Loader=Loader)
            for k, v in zeek_module_data[0].items():
                if isinstance(v, dict):
                    if k == 'connection':
                        k = 'conn'
                    zeek_full_path = os.path.join(zeek_log_directory, k + '.log')
                    v['var.paths'] = [zeek_full_path]
                    self.logger.debug(f'Patching path {k} -> {v}')
        if suricata_module_path:
            self.logger.debug(f'Located Filebeat module {zeek_module_path}')
            with open(suricata_module_path, 'r') as suricata_module_yaml:
                suricata_module_data = load(suricata_module_yaml, Loader=Loader)
            for k, v in suricata_module_data[0].items():
                suricata_full_path = os.path.join(suricata_log_directory, k + '.json')
                if isinstance(v, dict):
                    v['var.paths'] = [suricata_full_path]
                    self.logger.debug(f'Patching path {k} -> {v}')

        patch_file = open(os.path.join(modules_path, '.patched'), 'w')
        if zeek_module_data:
            write_module(zeek_module_path, zeek_module_data)
            patch_file.write(str(datetime.utcnow()) + '\n')
        if suricata_module_data:
            write_module(suricata_module_path, suricata_module_data)
            patch_file.write(str(datetime.utcnow()) + '\n')
        patch_file.close()

    def switch_to_elasticsearch_target(self) -> None:
        """Convenience method that enables ElasticSearch, and disables all other targets
        Returns:
            None
        """
        self.elasticsearch_targets.enabled = True
        self.kafka_targets.enabled = False
        self.logstash_targets.enabled = False
        self.redis_targets.enabled = False

    def switch_to_kafka_target(self) -> None:
        """Convenience method that enables Kafka, and disables all other targets
        Returns:
            None
        """
        self.elasticsearch_targets.enabled = False
        self.kafka_targets.enabled = True
        self.logstash_targets.enabled = False
        self.redis_targets.enabled = False

    def switch_to_logstash_target(self) -> None:
        """Convenience method that enables Logstash, and disables all other targets
        Returns:
            None
        """
        self.elasticsearch_targets.enabled = False
        self.kafka_targets.enabled = False
        self.logstash_targets.enabled = True
        self.redis_targets.enabled = False

    def switch_to_redis_target(self) -> None:
        """Convenience method that enables Redis, and disables all other targets
        Returns:
            None
        """
        self.elasticsearch_targets.enabled = False
        self.kafka_targets.enabled = False
        self.logstash_targets.enabled = False
        self.redis_targets.enabled = True

    def reset(self, out_file_path: Optional[str] = None, default_config_path: Optional[str] = None):
        """Reset a configuration file back to its default
        Args:
            out_file_path: The path to the output file
            default_config_path: The path to the default configuration
        Returns:
            None
        """
        if not out_file_path:
            out_file_path = f'{self.install_directory}/filebeat.yml'
        if not default_config_path:
            default_config_path = f'{const.DEFAULT_CONFIGS}/filebeat/filebeat.yml'
        super(ConfigManager, self).reset(out_file_path, default_config_path)
        self.commit(out_file_path=out_file_path)

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None,
               top_text: Optional[str] = None) -> None:
        """Write out an updated configuration file, and optionally backup the old one.
        Args:
            out_file_path: The path to the output file; if none given overwrites existing
            backup_directory: The path to the backup directory
            top_text: If specified, the first line of the configuration file will be set to the value of your choosing.
        Returns:
            None
        """
        if not out_file_path:
            out_file_path = f'{self.install_directory}/filebeat.yml'
        self._inputs_raw = self.input_logs.get_raw()
        self._processors_raw = self.field_processors.get_raw()
        self._index_template_settings_raw = self.index_template_settings.get_raw()
        self._kibana_settings_raw = self.kibana_settings.get_raw()
        self._elasticsearch_targets_raw = self.elasticsearch_targets.get_raw()
        self._kafka_targets_raw = self.kafka_targets.get_raw()
        self._logstash_targets_raw = self.logstash_targets.get_raw()
        self._redis_targets_raw = self.redis_targets.get_raw()
        super(ConfigManager, self).commit(out_file_path, backup_directory)
