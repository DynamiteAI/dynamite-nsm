import os
import sys
import time
import shutil
import logging
from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.logstash.synesis import config as synesis_config
from dynamite_nsm.services.logstash import exceptions as logstash_exceptions
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

        logstashyaml_path = os.path.join(self.configuration_directory, 'logstash.yml')
        try:
            with open(logstashyaml_path, 'r') as configyaml:
                self.config_data = load(configyaml, Loader=Loader)
        except IOError:
            raise logstash_exceptions.ReadLogstashConfigError("Could not locate config at {}".format(logstashyaml_path))
        except Exception as e:
            raise logstash_exceptions.ReadLogstashConfigError(
                "General exception when opening/parsing config at {}; {}".format(logstashyaml_path, e))

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def _parse_jvm_options(self):
        """
        Parses the initial and max heap allocation from jvm.options configuration
        :return: A dictionary containing the initial_memory and maximum_memory allocated to JVM heap
        """
        config_path = os.path.join(self.configuration_directory, 'jvm.options')
        try:
            with open(config_path) as config_f:
                for line in config_f.readlines():
                    if not line.startswith('#') and '-Xms' in line:
                        self.java_initial_memory = int(line.replace('-Xms', '').strip()[0:-1])
                    elif not line.startswith('#') and '-Xmx' in line:
                        self.java_maximum_memory = int(line.replace('-Xmx', '').strip()[0:-1])
        except IOError:
            raise general_exceptions.ReadJavaConfigError("Could not locate config at {}".format(config_path))
        except Exception as e:
            raise general_exceptions.ReadJavaConfigError(
                "General Exception when opening/parsing config at {}; {}".format(config_path, e))

    def _parse_environment_file(self):
        """
        Parses the /etc/dynamite/environment file and returns results for JAVA_HOME, LS_PATH_CONF, LS_HOME;
        stores the results in class variables of the same name
        """
        env_path = os.path.join(const.CONFIG_PATH, 'environment')
        try:
            with open(env_path) as env_f:
                for line in env_f.readlines():
                    if line.startswith('JAVA_HOME'):
                        self.java_home = line.split('=')[1].strip()
                    elif line.startswith('LS_PATH_CONF'):
                        self.ls_path_conf = line.split('=')[1].strip()
                    elif line.startswith('LS_HOME'):
                        self.ls_home = line.split('=')[1].strip()
        except IOError:
            raise general_exceptions.ReadConfigError("Could not locate environment config at {}".format(env_path))
        except Exception as e:
            raise general_exceptions.ReadConfigError(
                "General Exception when opening/parsing environment config at {}; {}".format(env_path, e))

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
        try:
            ef_config = elastiflow_config.ConfigManager()
            syn_config = synesis_config.ConfigManager()
            ef_config.es_passwd = password
            syn_config.es_passwd = password
            ef_config.write_environment_variables()
            syn_config.write_environment_variables()
        except general_exceptions.ReadConfigError as e:
            raise general_exceptions.ResetPasswordError("Failed to read configuration; {}".format(e))
        except general_exceptions.WriteConfigError as e:
            raise general_exceptions.ResetPasswordError("Failed to write configuration; {}".format(e))

    def write_jvm_config(self):
        """
        Overwrites the JVM initial/max memory if settings were updated
        """
        new_output = ''
        jvm_options_path = os.path.join(self.configuration_directory, 'jvm.options')
        try:
            with open(jvm_options_path) as config_f:
                for line in config_f.readlines():
                    if not line.startswith('#') and '-Xms' in line:
                        new_output += '-Xms' + str(self.java_initial_memory) + 'g'
                    elif not line.startswith('#') and '-Xmx' in line:
                        new_output += '-Xmx' + str(self.java_maximum_memory) + 'g'
                    else:
                        new_output += line
                    new_output += '\n'
        except IOError:
            raise general_exceptions.ReadJavaConfigError("Could not locate {}".format(jvm_options_path))
        except Exception as e:
            raise general_exceptions.ReadJavaConfigError(
                "General Exception when opening/parsing environment config at {}; {}".format(
                    self.configuration_directory, e))

        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        java_config_backup = os.path.join(backup_configurations, 'jvm.options.backup.{}'.format(
            int(time.time())
        ))
        try:
            utilities.makedirs(backup_configurations, exist_ok=True)
        except Exception as e:
            raise general_exceptions.WriteJavaConfigError(
                "General error while attempting to create backup directory at {}; {}".format(backup_configurations, e))
        try:
            shutil.copy(os.path.join(self.configuration_directory, 'jvm.options'), java_config_backup)
        except Exception as e:
            raise general_exceptions.WriteJavaConfigError(
                "General error while attempting to copy old jvm.options file to {}; {}".format(backup_configurations,
                                                                                               e))
        try:
            with open(os.path.join(self.configuration_directory, 'jvm.options'), 'w') as config_f:
                config_f.write(new_output)
        except IOError:
            raise general_exceptions.WriteJavaConfigError("Could not locate {}".format(self.configuration_directory))
        except Exception as e:
            raise general_exceptions.WriteJavaConfigError(
                "General error while attempting to write new jvm.options file to {}; {}".format(
                    self.configuration_directory, e))

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
        try:
            utilities.makedirs(backup_configurations, exist_ok=True)
        except Exception as e:
            raise logstash_exceptions.WriteLogstashConfigError(
                "General error while attempting to create backup directory at {}; {}".format(backup_configurations, e))
        try:
            shutil.copy(os.path.join(self.configuration_directory, 'logstash.yml'), logstash_config_backup)
        except Exception as e:
            raise logstash_exceptions.WriteLogstashConfigError(
                "General error while attempting to copy old logstash.yml file to {}; {}".format(
                    backup_configurations, e))

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        try:
            with open(os.path.join(self.configuration_directory, 'logstash.yml'), 'w') as configyaml:
                dump(self.config_data, configyaml, default_flow_style=False)
        except IOError:
            raise logstash_exceptions.WriteLogstashConfigError(
                "Could not locate {}".format(self.configuration_directory))
        except Exception as e:
            raise logstash_exceptions.WriteLogstashConfigError(
                "General error while attempting to write new logstash.yml file to {}; {}".format(
                    self.configuration_directory, e))

    def write_configs(self):
        """
        Writes both the JVM and logstash.yaml configurations, backs up originals
        """
        self.write_logstash_config()
        self.write_jvm_config()


def change_logstash_elasticsearch_password(password='changeme', prompt_user=True, stdout=True, verbose=False):
    """
    Change the password used by Logstash to authenticate to Elasticsearch

    :param password: The new Elasticsearch password
    :param prompt_user: If True, warning prompt is displayed before proceeding
    :param stdout: Print status to stdout
    :param verbose: Include detailed debug messages
    :return: True, if successful
    """

    from dynamite_nsm.services.logstash import process as logstash_process
    from dynamite_nsm.services.logstash import profile as logstash_profile

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('LOGSTASH', level=log_level, stdout=stdout)

    environment_variables = utilities.get_environment_file_dict()
    if not logstash_profile.ProcessProfiler().is_installed:
        logger.error("Password reset failed. LogStash is not installed on this host.")
        raise general_exceptions.ResetPasswordError("Password reset failed. LogStash is not installed on this host.")
    if prompt_user:
        resp = utilities.prompt_input(
            '\n\033[93m[-] WARNING! Changing the LogStash password can cause LogStash to lose communication with '
            'ElasticSearch. \n[?] Are you sure you wish to continue? [no]|yes):\033[0m ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    ConfigManager(environment_variables.get('LS_PATH_CONF')).set_elasticsearch_password(password=password)
    logstash_process.ProcessManager().restart()
