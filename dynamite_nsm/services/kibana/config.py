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
        if "HTTP/1.1 200" in err or "HTTP/1.1 409" in err:
            if stdout:
                sys.stdout.write('[+] Successfully created ElastiFlow Objects.\n')
            return True
        else:
            sys.stderr.write('[-] Failed to create ElastiFlow objects - [{}]\n'.format(err))
        return False


class ConfigManager:
    """
    Provides an interface for interacting with the kibana.yml
    """
    tokens = {
        'server_host': ('server.host',),
        'server_port': ('server.port', ),
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

        with open(os.path.join(self.configuration_directory, 'kibana.yml'), 'r') as configyaml:
            self.config_data = load(configyaml, Loader=Loader)

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def _parse_environment_file(self):
        """
        Parses the /etc/dynamite/environment file and returns results for JAVA_HOME, KIBANA_PATH_CONF, KIBANA_HOME;
        KIBANA_LOGS

        stores the results in class variables of the same name
        """
        for line in open('/etc/dynamite/environment').readlines():
            if line.startswith('JAVA_HOME'):
                self.java_home = line.split('=')[1].strip()
            elif line.startswith('KIBANA_PATH_CONF'):
                self.kibana_path_conf = line.split('=')[1].strip()
            elif line.startswith('KIBANA_HOME'):
                self.kibana_home = line.split('=')[1].strip()
            elif line.startswith('KIBANA_LOGS'):
                self.kibana_logs = line.split('=')[1].strip()

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
        os.makedirs(backup_configurations, exist_ok=True)
        shutil.copy(os.path.join(self.configuration_directory, 'kibana.yml'), filebeat_config_backup)

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        with open(os.path.join(self.configuration_directory, 'kibana.yml'), 'w') as configyaml:
            dump(self.config_data, configyaml, default_flow_style=False)


def change_kibana_elasticsearch_password(configuration_directory, password='changeme', prompt_user=True, stdout=False):
    """
    Change the password used by Kibana to authenticate to Elasticsearch

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
    :param password: The new Elasticsearch password
    :param prompt_user: If True, warning prompt is displayed before proceeding
    :param stdout: Print status to stdout
    :return: True, if successful
    """

    from dynamite_nsm.services.kibana import process as kibana_process

    if prompt_user:
        resp = utilities.prompt_input(
            'Changing the Kibana password can cause Kibana to lose communication with ElasticSearch. '
            'Are you sure you wish to continue? [no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    kb_config = ConfigManager(configuration_directory)
    kb_config.elasticsearch_password = password
    kb_config.write_config()
    return kibana_process.ProcessManager().restart(stdout=True)
