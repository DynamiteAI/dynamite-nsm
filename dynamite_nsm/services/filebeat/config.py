import os
import time
import shutil
from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm.services.filebeat import exceptions as filebeat_exceptions


class ConfigManager:
    tokens = {
        'inputs': ('filebeat.inputs',),
        'logstash_targets': ('output.logstash', 'hosts'),
        'kafka_targets': ('output.kafka', 'hosts'),
        'processors': ('processors',)
    }

    def __init__(self, install_directory):
        self.install_directory = install_directory

        self.inputs = None
        self.logstash_targets = None
        self.kafka_targets = None
        self.processors = None

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

    def set_agent_tag(self, agent_tag):
        """
        Create a tag to associate events/entities with the originating agent

        :param agent_tag: A tag associated with the agent
        """

        if not self.processors:
            self.processors = [{'add_fields': {'fields': {'originating_agent_tag': agent_tag}}}]
        else:
            for processor in self.processors:
                if list(processor.keys())[0] == 'add_fields':
                    processor['add_fields'] = {'fields': {'originating_agent_tag': agent_tag}}
                    break

    def set_logstash_targets(self, target_hosts):
        """
        Define where events should be sent

        :param target_hosts: A list of Logstash hosts, and their service port (E.G ["192.168.0.9:5044"]
        """
        self.logstash_targets = target_hosts

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

    def get_agent_tag(self):
        """
        Get the tag associated to the agent
        :return: A tag associated with the agent
        """
        try:
            return self.processors[0]['add_fields']['fields']['originating_agent_tag']
        except (AttributeError, IndexError, KeyError):
            return None

    def get_logstash_targets(self):
        """
        A list of Logstash targets that the agent is pointing too
        :return: A list of Logstash hosts, and their service port (E.G ["192.168.0.9:5044"]
        """
        return self.logstash_targets

    def get_monitor_target_paths(self):
        """
        A list of log paths to monitor

        :return: A list of log files to monitor
        """
        try:
            return self.inputs[0]['paths']
        except (AttributeError, IndexError, KeyError):
            return None

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

        timestamp = int(time.time())
        backup_configurations = os.path.join(self.install_directory, 'config_backups/')
        filebeat_config_backup = os.path.join(backup_configurations, 'filebeat.yml.backup.{}'.format(timestamp))
        try:
            os.makedirs(backup_configurations, exist_ok=True)
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
