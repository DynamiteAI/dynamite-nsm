import os
import time
import shutil
from datetime import datetime
from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import utilities
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.filebeat import exceptions as filebeat_exceptions


class ConfigManager:
    tokens = {
        'inputs': ('filebeat.inputs',),
        'elasticsearch_targets': ('output.elasticsearch',),
        'logstash_targets': ('output.logstash',),
        'kafka_targets': ('output.kafka',),
        'redis_targets': ('output.redis',),
        'processors': ('processors',)
    }

    def __init__(self, install_directory, backup_configuration_directory=None):
        self.install_directory = install_directory
        self.backup_configuration_directory = backup_configuration_directory

        self.inputs = []
        self.elasticsearch_targets = {}
        self.kafka_targets = {}
        self.logstash_targets = {}
        self.redis_targets = {}
        self.processors = []

        self._parse_filebeatyaml()

    def _parse_filebeatyaml(self):

        def set_instance_var_from_token(variable_name, data):
            """
            :param variable_name: The name of the instance variable to update
            :param data: The parsed yaml object
            :return: True if successfully located
            """
            if variable_name not in self.tokens.keys():
                return False
            key_path = self.tokens[variable_name]
            value = data
            try:
                for k in key_path:
                    value = value[k]
                setattr(self, var_name, value)
            except KeyError:
                pass
            return True

        filebeatyaml_path = os.path.join(self.install_directory, 'filebeat.yml')
        try:
            with open(filebeatyaml_path, 'r') as configyaml:
                self.config_data = load(configyaml, Loader=Loader)
        except IOError:
            raise filebeat_exceptions.ReadFilebeatConfigError("Could not locate config at {}".format(filebeatyaml_path))
        except Exception as e:
            raise filebeat_exceptions.ReadFilebeatConfigError(
                "General exception when opening/parsing config at {}; {}".format(filebeatyaml_path, e))

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def disable_log_input(self):
        """
        Disable generic filebeat log input
        """
        for i, _input in enumerate(self.inputs):
            if _input['type'] == 'log':
                _input['enabled'] = False
                self.inputs[i] = _input

    def enable_log_input(self):
        """
        Enable generic filebeat log input
        """

        for i, _input in enumerate(self.inputs):
            if _input['type'] == 'log':
                _input['enabled'] = True
                self.inputs[i] = _input

    def enable_ecs_normalization(self):
        """
        Enable ECS normalization for Zeek/Suricata logs
        """
        modules_path = os.path.join(self.install_directory, 'modules.d')
        if not os.path.exists(modules_path):
            return
        if os.path.exists(os.path.join(modules_path, 'zeek.yml.disabled')):
            os.rename(os.path.join(modules_path, 'zeek.yml.disabled'), os.path.join(modules_path, 'zeek.yml'))
        if os.path.exists(os.path.join(modules_path, 'suricata.yml.disabled')):
            os.rename(os.path.join(modules_path, 'suricata.yml.disabled'), os.path.join(modules_path, 'suricata.yml'))
        self.disable_log_input()

    def disable_ecs_normalization(self):
        """
        Disable ECS normalization for Zeek/Suricata logs
        """
        modules_path = os.path.join(self.install_directory, 'modules.d')
        if not os.path.exists(modules_path):
            return
        if os.path.exists(os.path.join(modules_path, 'zeek.yml')):
            os.rename(os.path.join(modules_path, 'zeek.yml'), os.path.join(modules_path, 'zeek.yml.disabled'))
        if os.path.exists(os.path.join(modules_path, 'suricata.yml')):
            os.rename(os.path.join(modules_path, 'suricata.yml'), os.path.join(modules_path, 'suricata.yml.disabled'))
        self.enable_log_input()

    def disable_elasticsearch_output(self):
        """
        Disable Elasticsearch
        """

        self.elasticsearch_targets['enabled'] = False

    def disable_kafka_output(self):
        """
        Disable Kafka
        """

        self.kafka_targets['enabled'] = False

    def disable_logstash_output(self):
        """
        Disable Logstash
        """

        self.logstash_targets['enabled'] = False

    def disable_redis_output(self):
        """
        Disable Logstash
        """

        self.redis_targets['enabled'] = False

    def enable_elasticsearch_output(self):
        """
        Enable Elasticsearch
        """

        self.elasticsearch_targets['enabled'] = True

    def enable_kafka_output(self):
        """
        Enable Kafka
        """

        self.kafka_targets['enabled'] = True

    def enable_logstash_output(self):
        """
        Enable Logstash
        """

        self.logstash_targets['enabled'] = True

    def enable_redis_output(self):
        """
        Enable Redis
        """

        self.redis_targets['enabled'] = True

    def get_agent_tag(self):
        """
        Get the tag associated to the agent
        :return: A tag associated with the agent
        """
        try:
            return self.processors[0]['add_fields']['fields']['originating_agent_tag']
        except (AttributeError, IndexError, KeyError):
            return None

    def get_elasticsearch_target_hosts(self):
        """
        Get list of Elasticsearch targets that the agent is pointing too
        :return: A list of Elasticsearch hosts, and their service port (E.G ["192.168.0.9:9200"]
        """

        return self.elasticsearch_targets.get('hosts', [])

    def get_elasticsearch_target_config(self):
        """
        Get Elasticsearch target config object
        :return: A Kafka target config object
        """

        return self.elasticsearch_targets

    def get_kafka_target_hosts(self):
        """
        Get list of Kafka targets that the agent is pointing too
        :return: A list of Kafka hosts, and their service port (E.G ["192.168.0.9:9092"]
        """

        return self.kafka_targets.get('hosts', [])

    def get_kafka_target_config(self):
        """
        Get Kafka target config object
        :return: A Kafka target config object
        """

        return self.kafka_targets

    def get_logstash_target_config(self):
        """
        Get Logstash target config object
        :return: A Logstash target config object
        """

        return self.logstash_targets

    def get_logstash_target_hosts(self):
        """
        Get list of Logstash targets that the agent is pointing too
        :return: A list of Logstash hosts, and their service port (E.G ["192.168.0.9:5044"]
        """

        return self.logstash_targets.get('hosts', [])

    def get_redis_target_config(self):
        """
        Get Redis target config object
        :return: A Redis target config object
        """

        return self.redis_targets

    def get_redis_target_hosts(self):
        """
        Get list of Redis targets that the agent is pointing too
        :return: A list of Redis hosts, and their service port (E.G ["192.168.0.9:6379"]
        """

        return self.redis_targets.get('hosts', [])

    def get_monitor_target_paths(self):
        """
        A list of log paths to monitor

        :return: A list of log files to monitor
        """

        try:
            return self.inputs[0]['paths']
        except (AttributeError, IndexError, KeyError):
            return None

    def is_ecs_normalization_available(self):
        """
        Check if the applicable modules (zeek/suricata) have been patched to point to the correct log locations

        :return: True, if ECS normalization is available (can be enabled)
        """
        modules_path = os.path.join(self.install_directory, 'modules.d')
        return os.path.exists(os.path.join(modules_path, '.patched'))

    def is_ecs_normalization_enabled(self):
        """
        Check if ECS normalization is enabled over generic inputs

        :return: True, if ECS normalization is enabled.
        """
        modules_path = os.path.join(self.install_directory, 'modules.d')
        zeek_module_exists = os.path.exists(os.path.join(modules_path, 'zeek.yml'))
        suricata_module_exists = os.path.exists(os.path.join(modules_path, 'suricata.yml'))
        return zeek_module_exists and suricata_module_exists

    def is_elasticsearch_enabled(self):
        """
        Check if Elasticsearch is enabled.
        :return: True, if enabled.
        """

        return self.elasticsearch_targets.get('enabled', False)

    def is_kafka_output_enabled(self):
        """
        Check if Kafka is enabled.
        :return: True, if enabled.
        """

        return self.kafka_targets.get('enabled', False)

    def is_logstash_output_enabled(self):
        """
        Check if LogStash is enabled.
        :return: True, if enabled.
        """

        return self.logstash_targets.get('enabled', False)

    def is_redis_output_enabled(self):
        """
        Check if Redis is enabled
        :return: True, if enabled.
        """
        return self.redis_targets.get('enabled', False)

    def patch_modules(self, zeek_log_directory=None, suricata_log_directory=None):
        """
        Given the paths to Zeek log directory and suricata log directory attempts to locate the modules.d/ configuration
        and patch the directory paths to point to the Dynamite configured paths

        :param zeek_log_directory: The path to the Zeek current log directory
        :param suricata_log_directory: The path to the Suricata log directory
        """

        def write_module(path, data):
            try:
                with open(path, 'w') as module_yaml:
                    dump(data, module_yaml, default_flow_style=False)
            except Exception as e:
                raise filebeat_exceptions.WriteFilebeatModuleError(
                    "General error while attempting to write Filebeat module file to {}; {}".format(
                        path, e))

        suricata_module_path = None
        zeek_module_path = None
        suricata_module_data = None
        zeek_module_data = None
        modules_path = os.path.join(self.install_directory, 'modules.d')
        if not os.path.exists(modules_path):
            return
        for module in os.listdir(modules_path):
            if not (module.endswith('.yml') or module.endswith('.yaml') or module.endswith('.disabled')):
                continue
            if 'zeek' in module:
                zeek_module_path = os.path.join(modules_path, module)
            elif 'suricata' in module:
                suricata_module_path = os.path.join(modules_path, module)
        if zeek_log_directory and zeek_module_path:
            try:
                with open(zeek_module_path, 'r') as zeek_module_yaml:
                    zeek_module_data = load(zeek_module_yaml, Loader=Loader)
            except Exception as e:
                raise filebeat_exceptions.ReadFilebeatModuleError(
                    "General exception when opening/parsing config at {}; {}".format(zeek_module_path, e))
            for k, v in zeek_module_data[0].items():
                if isinstance(v, dict):
                    v['vars.paths'] = [os.path.join(zeek_log_directory, k + '.log')]
        if suricata_log_directory and suricata_module_path:
            try:
                with open(suricata_module_path, 'r') as suricata_module_yaml:
                    suricata_module_data = load(suricata_module_yaml, Loader=Loader)
            except Exception as e:
                raise filebeat_exceptions.ReadFilebeatModuleError(
                    "General exception when opening/parsing config at {}; {}".format(suricata_module_path, e))
            for k, v in suricata_module_data[0].items():
                if isinstance(v, dict):
                    v['vars.paths'] = [os.path.join(suricata_log_directory, k + '.json')]
        patch_file = open(os.path.join(modules_path, '.patched'), 'w')
        if zeek_module_data:
            write_module(zeek_module_path, zeek_module_data)
            patch_file.write(str(datetime.utcnow()))
        if suricata_module_data:
            write_module(suricata_module_path, suricata_module_data)
            patch_file.write(str(datetime.utcnow()))
        patch_file.close()

    def set_agent_tag(self, agent_tag):
        """
        Create a tag to associate events/entities with the originating agent

        :param agent_tag: A tag associated with the agent
        """
        if not self.validate_agent_tag(agent_tag):
            raise filebeat_exceptions.InvalidAgentTag()
        if not self.processors:
            self.processors = [{'add_fields': {'fields': {'originating_agent_tag': agent_tag}}}]
        else:
            for processor in self.processors:
                if list(processor.keys())[0] == 'add_fields':
                    processor['add_fields'] = {'fields': {'originating_agent_tag': agent_tag}}
                    break

    def set_elasticsearch_targets(self, target_hosts, index=None, username=None, password=None, ssl_enabled=False,
                                  ssl_certificate_authorities=None, ssl_certificate=None, ssl_key=None,
                                  ssl_verification_mode='full'):
        """
        :param target_hosts: The list of Elasticsearch nodes to connect to. 
                             The events are distributed to these nodes in round robin order.
        :param index: The index name to write events to.
        :param username: The basic authentication username for connecting to Elasticsearch.
        :param password: The basic authentication password for connecting to Elasticsearch.
        :param ssl_enabled: If True, SSL options are added if given; otherwise they will not be included
        :param ssl_certificate_authorities: The list of root certificates for server verifications.
               If certificate_authorities is empty or not set, the trusted certificate authorities of the host
               system are used. (E.G ["/etc/pki/root/ca.pem"])
        :param ssl_certificate: The path to the certificate for SSL client authentication.
               If the certificate is not specified, client authentication is not available.
               The connection might fail if the server requests client authentication.
        :param ssl_key: The client certificate key used for client authentication. This option is required if
               ssl_certificate is specified.
        :param ssl_verification_mode: This option controls whether the client verifies server certificates and host
               names.
        """
        # TODO We need to add support for non-default indices.
        #  https://www.elastic.co/guide/en/beats/filebeat/current/elasticsearch-output.html#index-option-es
        """
        if not index:
            index = 'dynamite_events-%{+yyyy.MM.dd}'
        """
        self.elasticsearch_targets = {
            'hosts': target_hosts,
            'index': index,
            'username': username,
            'password': password
        }
        if ssl_enabled:
            ssl_options = self.elasticsearch_targets['ssl'] = {}
            if isinstance(ssl_certificate_authorities, list):
                ssl_options['certificate_authorities'] = ssl_certificate_authorities
            if isinstance(ssl_certificate, str):
                ssl_options['certificate'] = ssl_certificate
            if isinstance(ssl_key, str):
                ssl_options['key'] = ssl_key
            if isinstance(ssl_verification_mode, str) and ssl_verification_mode in ['none', 'full']:
                ssl_options['verification_mode'] = ssl_verification_mode

        self.kafka_targets['enabled'] = False
        self.logstash_targets['enabled'] = False
        self.redis_targets['enabled'] = False

    def set_kafka_targets(self, target_hosts, topic, username=None, password=None, ssl_enabled=False,
                          ssl_certificate_authorities=None, ssl_certificate=None, ssl_key=None,
                          ssl_verification_mode='full'):
        """
        Define Kafka endpoints where events should be sent

        :param target_hosts: A list of Kafka brokers, and their service port (E.G ["192.168.0.9:5044"])
        :param topic: A Kafka topic
        :param username: The username used to authenticate to Kafka broker
        :param password: The password used to authenticate to Kafka broker,
        :param ssl_enabled: If True, SSL options are added if given; otherwise they will not be included
        :param ssl_certificate_authorities: The list of root certificates for server verifications.
               If certificate_authorities is empty or not set, the trusted certificate authorities of the host
               system are used. (E.G ["/etc/pki/root/ca.pem"])
        :param ssl_certificate: The path to the certificate for SSL client authentication.
               If the certificate is not specified, client authentication is not available.
               The connection might fail if the server requests client authentication.
        :param ssl_key: The client certificate key used for client authentication. This option is required if
               ssl_certificate is specified.
        :param ssl_verification_mode: This option controls whether the client verifies server certificates and host
               names.
        """

        self.kafka_targets = {
            'hosts': target_hosts,
            'topic': topic,
            'username': username,
            'password': password,
            'enabled': True
        }

        if ssl_enabled:
            ssl_options = self.kafka_targets['ssl'] = {}
            if isinstance(ssl_certificate_authorities, list):
                ssl_options['certificate_authorities'] = ssl_certificate_authorities
            if isinstance(ssl_certificate, str):
                ssl_options['certificate'] = ssl_certificate
            if isinstance(ssl_key, str):
                ssl_options['key'] = ssl_key
            if isinstance(ssl_verification_mode, str) and ssl_verification_mode in ['none', 'full']:
                ssl_options['verification_mode'] = ssl_verification_mode

        self.elasticsearch_targets['enabled'] = False
        self.logstash_targets['enabled'] = False
        self.redis_targets['enabled'] = False

    def set_logstash_targets(self, target_hosts, loadbalance=False, index='dynamite_events-%{+yyyy.MM.dd}',
                             proxy_url=None, pipelining=2, bulk_max_size=2048, ssl_enabled=False,
                             ssl_certificate_authorities=None, ssl_certificate=None, ssl_key=None,
                             ssl_verification_mode='full'):
        """
        Define LogStash endpoints where events should be sent

        :param target_hosts: A list of Logstash hosts, and their service port (E.G ["192.168.0.9:5044"])
        :param loadbalance: If set to true and multiple Logstash hosts are configured, the output plugin load balances
               published events onto all Logstash hosts.
        :param index: The name of the index to include in the %{[@metadata][beat]} field
        :param proxy_url: The full url to the SOCKS5 proxy used for encapsulating the beat protocol
        :param pipelining: Configures the number of batches to be sent asynchronously to Logstash
        :param bulk_max_size: The maximum number of events to bulk in a single Logstash request.
        :param ssl_enabled: If True, SSL options are added if given; otherwise they will not be included
        :param ssl_certificate_authorities: The list of root certificates for server verifications.
               If certificate_authorities is empty or not set, the trusted certificate authorities of the host
               system are used. (E.G ["/etc/pki/root/ca.pem"])
        :param ssl_certificate: The path to the certificate for SSL client authentication.
               If the certificate is not specified, client authentication is not available.
               The connection might fail if the server requests client authentication.
        :param ssl_key: The client certificate key used for client authentication. This option is required if
               ssl_certificate is specified.
        :param ssl_verification_mode: This option controls whether the client verifies server certificates and host
               names.
        """
        if not index:
            index = 'dynamite_events-%{+yyyy.MM.dd}'

        self.logstash_targets = {
            'hosts': target_hosts,
            'enabled': True,
            'loadbalance': loadbalance,
            'pipelining': pipelining,
            'bulk_max_size': bulk_max_size
        }
        if index and isinstance(index, str):
            self.logstash_targets['index'] = index
        if proxy_url and isinstance(proxy_url, str):
            self.logstash_targets['proxy_url'] = proxy_url
        if not pipelining:
            self.logstash_targets['pipelining'] = 2048
        if not bulk_max_size:
            self.logstash_targets['bulk_max_size'] = 2048

        if ssl_enabled:
            ssl_options = self.logstash_targets['ssl'] = {}
            if isinstance(ssl_certificate_authorities, list):
                ssl_options['certificate_authorities'] = ssl_certificate_authorities
            if isinstance(ssl_certificate, str):
                ssl_options['certificate'] = ssl_certificate
            if isinstance(ssl_key, str):
                ssl_options['key'] = ssl_key
            if isinstance(ssl_verification_mode, str) and ssl_verification_mode in ['none', 'full']:
                ssl_options['verification_mode'] = ssl_verification_mode

        self.elasticsearch_targets['enabled'] = False
        self.kafka_targets['enabled'] = False
        self.redis_targets['enabled'] = False

    def set_redis_targets(self, target_hosts, loadbalance=True, workers=None, password=None, db=None,
                          index='dynamite_events', proxy_url=None, bulk_max_size=2048, ssl_enabled=False,
                          ssl_certificate_authorities=None, ssl_certificate=None, ssl_key=None,
                          ssl_verification_mode='full'):
        """
        :param target_hosts: A list of Redis hosts, and their service port (E.G ["192.168.0.9:6379"]
        :param loadbalance: If set to true and multiple hosts or workers are configured, the output plugin load balances
               published events onto all Redis hosts. If set to false, the output plugin sends all events to only one
               host (determined at random) and will switch to another host if the currently selected one becomes
               unreachable. The default value is true.
        :param workers: The number of workers to use for each host configured to publish events to Redis.
               Use this setting along with the loadbalance option.
               For example, if you have 2 hosts and 3 workers,
               in total 6 workers are started (3 for each host).
        :param password: The password to authenticate with. The default is no authentication.
        :param db: The Redis database number where the events are published. The default is 0.
        :param index: The key format string to use. If this string contains field references,
               such as %{[fields.name]}, the fields must exist, or the rule fails.
        :param proxy_url: The full url to the SOCKS5 proxy used for encapsulating the beat protocol
        :param bulk_max_size: The maximum number of events to bulk in a single Redis request or pipeline.
               The default is 2048.
        :param ssl_enabled: If True, SSL options are added if given; otherwise they will not be included
        :param ssl_certificate_authorities: The list of root certificates for server verifications.
               If certificate_authorities is empty or not set, the trusted certificate authorities of the host
               system are used. (E.G ["/etc/pki/root/ca.pem"])
        :param ssl_certificate: The path to the certificate for SSL client authentication.
               If the certificate is not specified, client authentication is not available.
               The connection might fail if the server requests client authentication.
        :param ssl_key: The client certificate key used for client authentication. This option is required if
               ssl_certificate is specified.
        :param ssl_verification_mode: This option controls whether the client verifies server certificates and host
               names.
        """
        self.redis_targets = {
            'hosts': target_hosts,
            'enabled': True,
            'loadbalance': loadbalance,
            'bulk_max_size': bulk_max_size
        }
        if workers and isinstance(workers, int):
            self.redis_targets['worker'] = workers
        if password and isinstance(password, str):
            self.redis_targets['password'] = password
        if isinstance(db, int) and db >= 0:
            self.redis_targets['db'] = db
        if index and isinstance(index, str):
            self.redis_targets['index'] = index
        if proxy_url and isinstance(proxy_url, str):
            self.redis_targets['proxy_url'] = proxy_url
        if not bulk_max_size:
            self.redis_targets['bulk_max_size'] = 2048

        if ssl_enabled:
            ssl_options = self.redis_targets['ssl'] = {}
            if isinstance(ssl_certificate_authorities, list):
                ssl_options['certificate_authorities'] = ssl_certificate_authorities
            if isinstance(ssl_certificate, str):
                ssl_options['certificate'] = ssl_certificate
            if isinstance(ssl_key, str):
                ssl_options['key'] = ssl_key
            if isinstance(ssl_verification_mode, str) and ssl_verification_mode in ['none', 'full']:
                ssl_options['verification_mode'] = ssl_verification_mode

        self.elasticsearch_targets['enabled'] = False
        self.kafka_targets['enabled'] = False
        self.logstash_targets['enabled'] = False

    def set_monitor_target_paths(self, monitor_log_paths):
        """
        Define which logs to monitor and send to Logstash hosts

        :param monitor_log_paths: A list of log files to monitor (wild card '*' accepted)
        """

        if not self.inputs:
            self.inputs = [{
                'type': 'log',
                'enabled': True,
                'paths': monitor_log_paths
            }]
        else:
            for i, _input in enumerate(self.inputs):
                if _input['type'] == 'log':
                    _input = {'type': 'log', 'enabled': True, 'paths': monitor_log_paths}
                    self.inputs[i] = _input

    @staticmethod
    def validate_agent_tag(agent_tag):
        import re
        agent_tag = str(agent_tag)
        tag_length_ok = 30 > len(agent_tag) > 5
        tag_match_pattern = bool(re.findall(r"^[a-zA-Z0-9_]*$", agent_tag))
        return tag_length_ok and tag_match_pattern

    def list_backup_configs(self):
        """
        List configuration backups

        :return: A list of dictionaries with the following keys: ["name", "path", "timestamp"]
        """
        return utilities.list_backup_configurations(os.path.join(self.backup_configuration_directory, 'filebeat.yml.d'))

    def restore_backup_config(self, name):
        """
        Restore a configuration from our config store

        :param name: The name of the configuration file or the keyword "recent" which will restore the most recent
        backup.
        :return: True, if successful
        """
        dest_config_file = os.path.join(self.install_directory, 'filebeat.yml')
        if name == "recent":
            configs = self.list_backup_configs()
            if configs:
                return utilities.restore_backup_configuration(
                    configs[0]['filepath'],
                    dest_config_file)
        return utilities.restore_backup_configuration(
            os.path.join(self.backup_configuration_directory, 'filebeat.yml.d', name), dest_config_file)

    def write_config(self):

        def update_dict_from_path(path, value):
            """
            :param path: A tuple representing each level of a nested path in the yaml document
                        ('vars', 'address-groups', 'HOME_NET') = /vars/address-groups/HOME_NET
            :param value: The new value
            :return: None
            """
            partial_config_data = self.config_data
            for i in range(0, len(path) - 1):
                try:
                    partial_config_data = partial_config_data[path[i]]
                except KeyError:
                    pass
            partial_config_data.update({path[-1]: value})

        # Backup old configuration first
        source_configuration_file_path = os.path.join(self.install_directory, 'filebeat.yml')
        destination_configuration_path = os.path.join(self.backup_configuration_directory, 'filebeat.yml.d')
        if self.backup_configuration_directory:
            try:
                utilities.backup_configuration_file(source_configuration_file_path, destination_configuration_path,
                                                    destination_file_prefix='filebeat.yml.backup')
            except general_exceptions.WriteConfigError:
                raise filebeat_exceptions.WriteFilebeatConfigError(
                    'Suricata configuration failed to write [filebeat.yml].')
            except general_exceptions.ReadConfigError:
                raise filebeat_exceptions.ReadFilebeatConfigError(
                    'Suricata configuration failed to read [filebeat.yml].')

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        try:
            with open(source_configuration_file_path, 'w') as configyaml:
                dump(self.config_data, configyaml, default_flow_style=False)
        except IOError:
            raise filebeat_exceptions.WriteFilebeatConfigError("Could not locate {}".format(self.install_directory))
        except Exception as e:
            raise filebeat_exceptions.WriteFilebeatConfigError(
                "General error while attempting to write new filebeat.yml file to {}; {}".format(
                    self.install_directory, e))