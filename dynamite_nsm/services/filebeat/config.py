import os
import time
import shutil
from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import utilities
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

    def __init__(self, install_directory):
        self.install_directory = install_directory

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

    def set_elasticsearch_targets(self, target_hosts, index='dynamite_events-%{+yyyy.MM.dd}', username=None,
                                  password=None):
        """
        :param target_hosts: The list of Elasticsearch nodes to connect to. 
                             The events are distributed to these nodes in round robin order.
        :param index: The index name to write events to.
        :param username: The basic authentication username for connecting to Elasticsearch.
        :param password: The basic authentication password for connecting to Elasticsearch.
        """
        
        self.elasticsearch_targets = {
            'hosts': target_hosts,
            'index': index,
            'username': username,
            'password': password
        }
        
        self.kafka_targets['enabled'] = False
        self.logstash_targets['enabled'] = False
        self.redis_targets['enabled'] = False
        
    def set_kafka_targets(self, target_hosts, topic, username=None, password=None):
        """
        Define Kafka endpoints where events should be sent

        :param target_hosts: A list of Kafka brokers, and their service port (E.G ["192.168.0.9:5044"])
        :param topic: A Kafka topic
        :param username: The username used to authenticate to Kafka broker
        :param password: The password used to authenticate to Kafka broker
        """

        self.kafka_targets = {
            'hosts': target_hosts,
            'topic': topic,
            'username': username,
            'password': password,
            'enabled': True
        }
        self.elasticsearch_targets['enabled'] = False
        self.logstash_targets['enabled'] = False
        self.redis_targets['enabled'] = False

    def set_logstash_targets(self, target_hosts, loadbalance=False, index=None, proxy_url=None, pipelining=2,
                             bulk_max_size=2048):
        """
        Define LogStash endpoints where events should be sent

        :param target_hosts: A list of Logstash hosts, and their service port (E.G ["192.168.0.9:5044"])
        :param loadbalance: If set to true and multiple Logstash hosts are configured, the output plugin load balances
                            published events onto all Logstash hosts.
        :param index: The name of the index to include in the %{[@metadata][beat]} field
        :param proxy_url: The full url to the SOCKS5 proxy used for encapsulating the beat protocol
        :param pipelining: Configures the number of batches to be sent asynchronously to Logstash
        :param bulk_max_size: The maximum number of events to bulk in a single Logstash request.
        """

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
            
        self.elasticsearch_targets['enabled'] = False
        self.kafka_targets['enabled'] = False
        self.redis_targets['enabled'] = False

    def set_redis_targets(self, target_hosts, loadbalance=True, workers=None, password=None, db=0,
                          index='dynamite_events', proxy_url=None, bulk_max_size=2048):
        """

        :param target_hosts: A list of Redis hosts, and their service port (E.G ["192.168.0.9:6379"]
        :param loadbalance: If set to true and multiple hosts or workers are configured, the output plugin load balances
                            published events onto all Redis hosts.
                            If set to false, the output plugin sends all events to only one host (determined at random)
                            and will switch to another host if the currently selected one becomes unreachable.
                            The default value is true.
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
        if db and isinstance(db, int):
            self.redis_targets['db'] = db
        if index and isinstance(index, str):
            self.redis_targets['index'] = index
        if proxy_url and isinstance(proxy_url, str):
            self.redis_targets['proxy_url'] = proxy_url
            
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
        tag_match_pattern = bool(re.findall("^[a-zA-Z0-9_]*$", agent_tag))
        return tag_length_ok and tag_match_pattern

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
                    print(partial_config_data)
                except KeyError:
                    pass
            partial_config_data.update({path[-1]: value})

        timestamp = int(time.time())
        backup_configurations = os.path.join(self.install_directory, 'config_backups/')
        filebeat_config_backup = os.path.join(backup_configurations, 'filebeat.yml.backup.{}'.format(timestamp))
        try:
            utilities.makedirs(backup_configurations, exist_ok=True)
        except Exception as e:
            raise filebeat_exceptions.WriteFilebeatConfigError(
                "General error while attempting to create backup directory at {}; {}".format(backup_configurations, e))
        try:
            shutil.copy(os.path.join(self.install_directory, 'filebeat.yml'), filebeat_config_backup)
        except Exception as e:
            raise filebeat_exceptions.WriteFilebeatConfigError(
                "General error while attempting to copy old filebeat.yml file to {}; {}".format(
                    backup_configurations, e))
        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        try:
            with open(os.path.join(self.install_directory, 'filebeat.yml'), 'w') as configyaml:
                dump(self.config_data, configyaml, default_flow_style=False)
        except IOError:
            raise filebeat_exceptions.WriteFilebeatConfigError("Could not locate {}".format(self.install_directory))
        except Exception as e:
            raise filebeat_exceptions.WriteFilebeatConfigError(
                "General error while attempting to write new filebeat.yml file to {}; {}".format(
                    self.install_directory, e))
