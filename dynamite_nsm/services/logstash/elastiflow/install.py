import os
import logging
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.logstash.elastiflow import config as elastiflow_config
from dynamite_nsm.services.logstash.elastiflow import exceptions as elastiflow_exceptions


class InstallManager:

    def __init__(self, install_directory, stdout=True, verbose=False):
        """
        Install ElastiFlow LogsStash configurations

        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/elastiflow/)
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('ELASTIFLOW', level=log_level, stdout=stdout)

        self.stdout = stdout
        self.verbose = verbose
        self.install_directory = install_directory

    def setup_logstash_elastiflow(self):
        """
        Create required environmental variables; copy configurations to various directories.
        """

        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info('Creating ElastiFlow installation and configuration directories.')
        utilities.makedirs(self.install_directory, exist_ok=True)
        self.logger.info('Copying ElastiFlow configurations.')
        utilities.copytree(os.path.join(const.DEFAULT_CONFIGS, 'logstash', 'zeek'), self.install_directory)
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        try:
            with open(env_file) as env_f:
                env_str = env_f.read()
                if 'ELASTIFLOW_DICT_PATH' not in env_str:
                    dict_path = os.path.join(self.install_directory, 'dictionaries')
                    self.logger.info('Updating ElastiFlow dictionary configuration path [{}]'.format(dict_path))
                    subprocess.call('echo ELASTIFLOW_DICT_PATH="{}" >> {}'.format(dict_path, env_file), shell=True)
                if 'ELASTIFLOW_TEMPLATE_PATH' not in env_str:
                    template_path = os.path.join(self.install_directory, 'templates')

                    self.logger.info('Updating ElastiFlow template configuration path [{}]'.format(template_path))
                    subprocess.call('echo ELASTIFLOW_TEMPLATE_PATH="{}" >> {}'.format(template_path, env_file),
                                    shell=True)
                if 'ELASTIFLOW_GEOIP_DB_PATH' not in env_str:
                    geo_path = os.path.join(self.install_directory, 'geoipdbs')
                    self.logger.info('Updating ElastiFlow GeoDBs configuration path [{}]'.format(geo_path))
                    subprocess.call('echo ELASTIFLOW_GEOIP_DB_PATH="{}" >> {}'.format(geo_path, env_file), shell=True)
                if 'ELASTIFLOW_DEFINITION_PATH' not in env_str:
                    def_path = os.path.join(self.install_directory, 'definitions')
                    self.logger.info('Updating ElastiFlow definitions configuration path [{}]'.format(def_path))
                    subprocess.call('echo ELASTIFLOW_DEFINITION_PATH="{}" >> {}'.format(def_path, env_file), shell=True)
        except Exception as e:
            self.logger.error('Failed to read ElastiFlow environment variables.')
            self.logger.debug("Failed to read ElastiFlow environment variables; {}".format(e))
            raise elastiflow_exceptions.InstallElastiflowError(
                "Failed to read ElastiFlow environment variables; {}".format(e))
        try:
            elastiflow_config.ConfigManager().write_environment_variables()
        except (elastiflow_exceptions.ReadElastiflowConfigError, elastiflow_exceptions.WriteElastiflowConfigError):
            self.logger.error('Failed to read/write ElastiFlow environment variables.')
            raise elastiflow_exceptions.InstallElastiflowError("Could not read/write ElastiFlow environment variables.")
