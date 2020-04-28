import os
import pty
import sys

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from dynamite_nsm import utilities
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.lab import exceptions as lab_exceptions


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
        self.config = None
        self._parse_lab_config()

    def _parse_lab_config(self):
        config_parser = ConfigParser()
        sdk_config_file = os.path.join(self.configuration_directory, 'config.cfg')
        try:
            with open(sdk_config_file) as configfile:
                config_parser.readfp(configfile)
        except Exception as e:
            raise lab_exceptions.ReadLabConfigError(
                "General error occurred while reading SDK config at {}; {}".format(sdk_config_file, e))
        for section in config_parser.sections():
            for item in config_parser.items(section):
                key, value = item
                setattr(self, key, value)
        self.config = config_parser

    def write_config(self):
        """
        Write the DynamiteSDK config file
        """
        for k, v in vars(self).items():
            if k not in self.tokens.keys():
                continue
            section = self.tokens[k]
            self.config.set(section, k, v)
        try:
            with open(os.path.join(self.configuration_directory, 'config.cfg'), 'w') as configfile:
                self.config.write(configfile)
        except Exception as e:
            raise lab_exceptions.WriteLabConfigError(
                "General error occurred while writing SDK config to {}; {}".format(self.configuration_directory, e))


def change_sdk_elasticsearch_password(password='changeme', prompt_user=True, stdout=False):
    """
    Change the DynamiteSDK to ElasticSearch password
    :param password: The password that the SDK will use to connect to ElasticSearch
    :param prompt_user: Whether or not to warn the user
    :param stdout: Print output to console
    """

    environment_variables = utilities.get_environment_file_dict()
    configuration_directory = environment_variables.get('DYNAMITE_LAB_CONFIG')
    if prompt_user:
        resp = utilities.prompt_input(
            '\033[93m[-] Changing the SDK password can cause your notebooks to lose communication with ElasticSearch.\n'
            '[?] Are you sure you wish to continue? [no]|yes):\033[0m ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            return
    dynamite_lab_config = ConfigManager(configuration_directory=configuration_directory)
    try:
        dynamite_lab_config.elasticsearch_password = password
        dynamite_lab_config.write_config()
    except lab_exceptions.WriteLabConfigError:
        raise general_exceptions.ResetPasswordError("Could not write new password to DynamiteSDK config.cfg.")


def prompt_password_change_options():
    """
    Provide the user with a choice between changing the jupyter user password (logging into jupyterhub)
    or changing the password that the SDK uses to connect to ElasticSearch.
    """

    resp = utilities.prompt_input(
        '[+] 1. Change the password the SDK uses to connect to Elasticsearch.\n'
        '[+] 2. Change the password for logging into Jupyterhub (jupyter user).\n\n'
        '[?] Select an option [1, 2]: ')
    while str(resp) not in ['', '1', '2']:
        resp = utilities.prompt_input('Select an option [1, 2]: ')
    if str(resp) == '1':
        return change_sdk_elasticsearch_password(utilities.prompt_password('Enter the new Elasticsearch password: '),
                                                 prompt_user=False)
    else:
        pty.spawn(['passwd', 'jupyter'])
