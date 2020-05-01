import os
import sys
import time
import shutil
import logging
import subprocess

from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.kibana import exceptions as kibana_exceptions


class ApiConfigManager:
    """
    Provides an interface for interacting with the Kibana saved object API
    """

    def __init__(self, configuration_directory):

        self.configuration_directory = configuration_directory
        self.kibana_config = ConfigManager(configuration_directory)

    def create_dynamite_kibana_objects(self, stdout=False):
        """
        Creates Dynamite dashboards, visualizations, and searches

        :param stdout: Print output to console
        :return: True, if created successfully
        """

        kibana_api_objects_path = os.path.join(const.INSTALL_CACHE, const.DEFAULT_CONFIGS, 'kibana', 'objects',
                                               'saved_objects.ndjson')

        server_host = self.kibana_config.server_host
        if server_host.strip() == '0.0.0.0':
            server_host = 'localhost'

        # This isn't ideal, but given there is no easy way to use the urllib/urllib2 libraries for multipart/form-data
        # Shelling out is a reasonable workaround
        kibana_api_import_url = '{}:{}/api/saved_objects/_import'.format(server_host, self.kibana_config.server_port)
        curl_command = 'curl -X POST {} -u {}:"{}" --form file=@{} -H "kbn-xsrf: true" ' \
                       '-H "Content-Type: multipart/form-data" -v'.format(kibana_api_import_url,
                                                                          self.kibana_config.elasticsearch_username,
                                                                          self.kibana_config.elasticsearch_password,
                                                                          kibana_api_objects_path)
        p = subprocess.Popen(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        out, err = p.communicate()
        out, err = out.decode('utf-8'), err.decode('utf-8')
        if p.returncode != 0:
            raise kibana_exceptions.CreateKibanaObjectsError(
                "An error occurred while invoking curl; exited with {}; is it installed?".format(p.returncode))
        if "HTTP/1.1 200" in err or "HTTP/1.1 409" in err:
            if stdout:
                sys.stdout.write('[+] Successfully created ElastiFlow Objects.\n')
        else:
            sys.stderr.write('[-] Failed to create ElastiFlow objects - [{}]\n'.format(err))
            raise kibana_exceptions.CreateKibanaObjectsError(
                "Kibana objects were not created successfully; HTTP Response: {}".format(err))


class ConfigManager:
    """
    Provides an interface for interacting with the kibana.yml
    """
    tokens = {
        'server_host': ('server.host',),
        'server_port': ('server.port',),
        'elasticsearch_hosts': ('elasticsearch.hosts',),
        'elasticsearch_username': ('elasticsearch.username',),
        'elasticsearch_password': ('elasticsearch.password',),
    }

    def __init__(self, configuration_directory):
        self.configuration_directory = configuration_directory
        self.kibana_home = None
        self.kibana_path_conf = None
        self.kibana_logs = None
        self.server_host = None
        self.server_port = None
        self.elasticsearch_hosts = None
        self.elasticsearch_username = None
        self.elasticsearch_password = None
        self._parse_environment_file()
        self._parse_kibanayaml()

    def _parse_kibanayaml(self):

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

        kibanayaml_path = os.path.join(self.configuration_directory, 'kibana.yml')
        try:
            with open(kibanayaml_path, 'r') as configyaml:
                self.config_data = load(configyaml, Loader=Loader)
        except IOError:
            raise kibana_exceptions.ReadKibanaConfigError("Could not locate config at {}".format(kibanayaml_path))
        except Exception as e:
            raise kibana_exceptions.ReadKibanaConfigError(
                "General exception when opening/parsing config at {}; {}".format(kibanayaml_path, e))

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def _parse_environment_file(self):
        """
        Parses the /etc/dynamite/environment file and returns results for JAVA_HOME, KIBANA_PATH_CONF, KIBANA_HOME;
        KIBANA_LOGS

        stores the results in class variables of the same name
        """
        env_path = os.path.join(const.CONFIG_PATH, 'environment')
        try:
            with open(env_path) as env_f:
                for line in env_f.readlines():
                    if line.startswith('JAVA_HOME'):
                        self.java_home = line.split('=')[1].strip()
                    elif line.startswith('KIBANA_PATH_CONF'):
                        self.kibana_path_conf = line.split('=')[1].strip()
                    elif line.startswith('KIBANA_HOME'):
                        self.kibana_home = line.split('=')[1].strip()
                    elif line.startswith('KIBANA_LOGS'):
                        self.kibana_logs = line.split('=')[1].strip()

        except IOError:
            raise general_exceptions.ReadConfigError("Could not locate environment config at {}".format(env_path))
        except Exception as e:
            raise general_exceptions.ReadConfigError(
                "General Exception when opening/parsing environment config at {}; {}".format(env_path, e))

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
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        filebeat_config_backup = os.path.join(backup_configurations, 'kibana.yml.backup.{}'.format(timestamp))
        try:
            utilities.makedirs(backup_configurations, exist_ok=True)
        except Exception as e:
            raise kibana_exceptions.WriteKibanaConfigError(
                "General error while attempting to create backup directory at {}; {}".format(backup_configurations, e))
        try:
            shutil.copy(os.path.join(self.configuration_directory, 'kibana.yml'), filebeat_config_backup)
        except Exception as e:
            raise kibana_exceptions.WriteKibanaConfigError(
                "General error while attempting to copy old kibana.yml file to {}; {}".format(
                    backup_configurations, e))

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        try:
            with open(os.path.join(self.configuration_directory, 'kibana.yml'), 'w') as configyaml:
                dump(self.config_data, configyaml, default_flow_style=False)
        except IOError:
            raise kibana_exceptions.WriteKibanaConfigError("Could not locate {}".format(self.configuration_directory))
        except Exception as e:
            raise kibana_exceptions.WriteKibanaConfigError(
                "General error while attempting to write new kibana.yml file to {}; {}".format(
                    self.configuration_directory, e))


def change_kibana_elasticsearch_password(password='changeme', prompt_user=True, stdout=True, verbose=False):
    """
    Change the password used by Kibana to authenticate to ElasticSearch

    :param password: The new Elasticsearch password
    :param prompt_user: If True, warning prompt is displayed before proceeding
    :param stdout: Print status to stdout
    :param verbose: Include detailed debug messages
    """

    from dynamite_nsm.services.kibana import process as kibana_process
    from dynamite_nsm.services.kibana import profile as kibana_profile

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('KIBANA', level=log_level, stdout=stdout)

    environment_variables = utilities.get_environment_file_dict()
    if not kibana_profile.ProcessProfiler().is_installed:
        logger.error("Password reset failed. Kibana is not installed on this host.")
    if prompt_user:
        resp = utilities.prompt_input(
            '\033[93m[-] WARNING! Changing the Kibana password can cause Kibana to lose communication with '
            'ElasticSearch.\n[?] Are you sure you wish to continue? [no]|yes):\033[0m  ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    try:
        kb_config = ConfigManager(environment_variables.get('KIBANA_PATH_CONF'))
        kb_config.elasticsearch_password = password
        kb_config.write_config()
    except (kibana_exceptions.ReadKibanaConfigError, kibana_exceptions.WriteKibanaConfigError):
        logger.error("Could not read/write Kibana configuration.")
        raise general_exceptions.ResetPasswordError("Could not read/write Kibana configuration.")
    kibana_process.ProcessManager().restart()
