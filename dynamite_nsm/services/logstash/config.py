import os
import sys
import time
import shutil
import subprocess
from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.logstash.synesis import config as synesis_config
from dynamite_nsm.services.logstash.elastiflow import config as elastiflow_config


class ConfigManager:
    """
    Wrapper for configuring logstash.yml and jvm.options
    """

    tokens = {
        'node_name': ('node.name',),
        'path_data': ('path.data',),
        'path_logs': ('path.logs',),
        'pipeline_batch_size': ('pipeline.batch.size',),
        'pipeline_batch_delay': ('pipeline.batch.delay',)
    }

    def __init__(self, configuration_directory):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/logstash/)
        """
        self.configuration_directory = configuration_directory
        self.java_home = None
        self.ls_home = None
        self.ls_path_conf = None
        self.java_initial_memory = None
        self.java_maximum_memory = None

        self.node_name = None
        self.path_data = None
        self.path_logs = None
        self.pipeline_batch_size = None
        self.pipeline_batch_delay = None

        self._parse_environment_file()
        self._parse_jvm_options()
        self._parse_logstashyaml()

    def _parse_logstashyaml(self):

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

        with open(os.path.join(self.configuration_directory, 'logstash.yml'), 'r') as configyaml:
            self.config_data = load(configyaml, Loader=Loader)

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def _parse_jvm_options(self):
        """
        Parses the initial and max heap allocation from jvm.options configuration
        :return: A dictionary containing the initial_memory and maximum_memory allocated to JVM heap
        """
        config_path = os.path.join(self.configuration_directory, 'jvm.options')
        with open(config_path) as config_f:
            for line in config_f.readlines():
                if not line.startswith('#') and '-Xms' in line:
                    self.java_initial_memory = int(line.replace('-Xms', '').strip()[0:-1])
                elif not line.startswith('#') and '-Xmx' in line:
                    self.java_maximum_memory = int(line.replace('-Xmx', '').strip()[0:-1])

    def _parse_environment_file(self):
        """
        Parses the /etc/dynamite/environment file and returns results for JAVA_HOME, LS_PATH_CONF, LS_HOME;
        stores the results in class variables of the same name
        """
        for line in open(os.path.join(const.CONFIG_PATH, 'environment')).readlines():
            if line.startswith('JAVA_HOME'):
                self.java_home = line.split('=')[1].strip()
            elif line.startswith('LS_PATH_CONF'):
                self.ls_path_conf = line.split('=')[1].strip()
            elif line.startswith('LS_HOME'):
                self.ls_home = line.split('=')[1].strip()

    @staticmethod
    def get_elasticsearch_password():
        """
        :return: The password for the given ElasticSearch instance
        """
        ef_config = elastiflow_config.ConfigManager()
        return ef_config.es_passwd

    @staticmethod
    def set_elasticsearch_password(password):
        """
        :param password: The new password
        """
        ef_config = elastiflow_config.ConfigManager()
        syn_config = synesis_config.ConfigManager()
        ef_config.es_passwd = password
        syn_config.es_passwd = password
        ef_config.write_environment_variables()
        syn_config.write_environment_variables()

    def write_jvm_config(self):
        """
        Overwrites the JVM initial/max memory if settings were updated
        """
        new_output = ''
        with open(os.path.join(self.configuration_directory, 'jvm.options')) as config_f:
            for line in config_f.readlines():
                if not line.startswith('#') and '-Xms' in line:
                    new_output += '-Xms' + str(self.java_initial_memory) + 'g'
                elif not line.startswith('#') and '-Xmx' in line:
                    new_output += '-Xmx' + str(self.java_maximum_memory) + 'g'
                else:
                    new_output += line
                new_output += '\n'

        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        java_config_backup = os.path.join(backup_configurations, 'jvm.options.backup.{}'.format(
            int(time.time())
        ))
        shutil.copy(os.path.join(self.configuration_directory, 'jvm.options'), java_config_backup)
        with open(os.path.join(self.configuration_directory, 'jvm.options'), 'w') as config_f:
            config_f.write(new_output)

    def write_logstash_config(self):

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
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        logstash_config_backup = os.path.join(backup_configurations, 'logstash.yml.backup.{}'.format(timestamp))
        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        shutil.copy(os.path.join(self.configuration_directory, 'logstash.yml'), logstash_config_backup)

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        with open(os.path.join(self.configuration_directory, 'logstash.yml'), 'w') as configyaml:
            dump(self.config_data, configyaml, default_flow_style=False)

    def write_configs(self):
        """
        Writes both the JVM and logstash.yaml configurations, backs up originals
        """
        self.write_logstash_config()
        self.write_jvm_config()


def change_logstash_elasticsearch_password(configuration_directory, password='changeme', prompt_user=True,
                                           stdout=False):
    """
    Change the password used by Logstash to authenticate to Elasticsearch

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/logstash/)
    :param password: The new Elasticsearch password
    :param prompt_user: If True, warning prompt is displayed before proceeding
    :param stdout: Print status to stdout
    :return: True, if successful
    """

    from dynamite_nsm.services.logstash import process as logstash_process

    if prompt_user:
        resp = utilities.prompt_input(
            'Changing the LogStash password can cause LogStash to lose communication with ElasticSearch. '
            'Are you sure you wish to continue? [no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    ConfigManager(configuration_directory).set_elasticsearch_password(password=password)
    return logstash_process.ProcessManager().restart(stdout=True)
