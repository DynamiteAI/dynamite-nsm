import os
import pty
import sys

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from dynamite_nsm import utilities


class ConfigManager:
    """
    Wrapper for configuring dynamite-sdk-lite config.cfg
    """

    tokens = {
        'elasticsearch_url': 'AUTHENTICATION',
        'elasticsearch_user': 'AUTHENTICATION',
        'elasticsearch_password': 'AUTHENTICATION',
        'timeout': 'SEARCH',
        'max_results': 'SEARCH'
    }

    def __init__(self, configuration_directory):
        """
        :param configuration_directory: The directory that stores the JupyterHub and DynamiteSDK configurations
        """
        self.configuration_directory = configuration_directory
        self.elasticsearch_url = None
        self.elasticsearch_user = None
        self.elasticsearch_password = None
        self.timeout = None
        self.max_results = None
        self.config = self._parse_lab_config()

    def _parse_lab_config(self):
        """
        :return: A dictionary representing the configurations stored within node.cfg
        """
        config_parser = ConfigParser()
        config_parser.readfp(open(os.path.join(self.configuration_directory, 'config.cfg')))
        for section in config_parser.sections():
            for item in config_parser.items(section):
                key, value = item
                setattr(self, key, value)
        return config_parser

    def write_config(self):
        """
        Write the DynamiteSDK config file
        """
        for k, v in vars(self).items():
            if k not in self.tokens.keys():
                continue
            section = self.tokens[k]
            self.config.set(section, k, v)
        with open(os.path.join(self.configuration_directory, 'config.cfg'), 'w') as configfile:
            self.config.write(configfile)


def change_sdk_elasticsearch_password(password='changeme', prompt_user=True, stdout=False):
    """
    Change the DynamiteSDK to ElasticSearch password
    :param password: The password that the SDK will use to connect to ElasticSearch
    :param prompt_user: Whether or not to warn the user
    :param stdout: Print output to console
    :return: True if changed successfully
    """
    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('DYNAMITE_LAB_CONFIG')
    if prompt_user:
        resp = utilities.prompt_input(
            'Changing the SDK password can cause your notebooks to lose communication with ElasticSearch. '
            'Are you sure you wish to continue? [no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            return False
    dynamite_lab_config = ConfigManager(configuration_directory=configuration_directory)
    dynamite_lab_config.elasticsearch_password = password
    dynamite_lab_config.write_config()
    return True


def prompt_password_change_options():
    """
    Provide the user with a choice between changing the jupyter user password (logging into jupyterhub)
    or changing the password that the SDK uses to connect to ElasticSearch.

    :return: True, if successfully changed
    """
    resp = utilities.prompt_input(
        '1. Change the password the SDK uses to connect to Elasticsearch.\n'
        '2. Change the password for logging into Jupyterhub (jupyter user).\n\n'
        'Select an option [1, 2]: ')
    while str(resp) not in ['', '1', '2']:
        resp = utilities.prompt_input('Select an option [1, 2]: ')
    if str(resp) == '1':
        return change_sdk_elasticsearch_password(utilities.prompt_password('Enter the new Elasticsearch password: '),
                                                 prompt_user=False)
    else:
        pty.spawn(['passwd', 'jupyter'])
    return True
