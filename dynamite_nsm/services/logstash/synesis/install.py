import os
import sys
import logging
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.logstash.synesis import config as synesis_config
from dynamite_nsm.services.logstash.synesis import exceptions as synesis_exceptions


class InstallManager:

    def __init__(self, install_directory, stdout=True, verbose=False):
        """
        Install Synesis LogsStash configurations

        :param install_directory: Path to the install directory (E.G /etc/dynamite/logstash/synlite_suricata/)
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('SYNESIS', level=log_level, stdout=stdout)

        self.stdout = stdout
        self.verbose = verbose
        self.install_directory = install_directory

    def setup_logstash_synesis(self):
        """
        Create required environmental variables; copy configurations to various directories.
        """

        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info('Creating Synesis installation and configuration directories.')
        utilities.makedirs(self.install_directory, exist_ok=True)
        self.logger.info('Copying Synesis configurations.')
        utilities.copytree(os.path.join(const.DEFAULT_CONFIGS, 'logstash','suricata'), self.install_directory)
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        try:
            with open(env_file) as env_f:
                env_str = env_f.read()
                if 'SYNLITE_SURICATA_DICT_PATH' not in env_str:
                    dict_path = os.path.join(self.install_directory, 'dictionaries')
                    self.logger.info('Updating Synesis dictionary configuration path [{}]'.format(dict_path))
                    subprocess.call('echo SYNLITE_SURICATA_DICT_PATH="{}" >> {}'.format(dict_path, env_file),
                                    shell=True)
                if 'SYNLITE_SURICATA_TEMPLATE_PATH' not in env_str:
                    template_path = os.path.join(self.install_directory, 'templates')
                    self.logger.info('Updating Synesis template configuration path [{}]'.format(template_path))
                    subprocess.call('echo SYNLITE_SURICATA_TEMPLATE_PATH="{}" >> {}'.format(template_path, env_file),
                                    shell=True)
                if 'SYNLITE_SURICATA_GEOIP_DB_PATH' not in env_str:
                    geo_path = os.path.join(self.install_directory, 'geoipdbs')
                    self.logger.info('Updating Synesis GeoDBs configuration path [{}]'.format(geo_path))
                    subprocess.call('echo SYNLITE_SURICATA_GEOIP_DB_PATH="{}" >> {}'.format(geo_path, env_file),
                                    shell=True)
        except Exception as e:
            self.logger.error('Failed to read Synesis environment variables.')
            self.logger.debug("Failed to read Synesis environment variables; {}".format(e))
            raise synesis_exceptions.InstallSynesisError(
                "Failed to read Synesis environment variables; {} ".format(e))
        try:
            synesis_config.ConfigManager().write_environment_variables()
        except (synesis_exceptions.ReadSynesisConfigError, synesis_exceptions.WriteSynesisConfigError):
            self.logger.error('Failed to read/write Synesis environment variables.')
            raise synesis_exceptions.InstallSynesisError("Could not read/write Synesis environment variables.")
