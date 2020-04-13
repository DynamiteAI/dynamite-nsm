import os
import sys
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.logstash.elastiflow import config as elastiflow_config
from dynamite_nsm.services.logstash.elastiflow import exceptions as elastiflow_exceptions


class InstallManager:

    def __init__(self, install_directory):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/elastiflow/)
        """

        self.install_directory = install_directory

    def setup_logstash_elastiflow(self, stdout=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if stdout:
            sys.stdout.write('[+] Creating elastiflow install|configuration directories.\n')
        utilities.makedirs(self.install_directory, exist_ok=True)
        if stdout:
            sys.stdout.write('[+] Copying elastiflow configurations\n')
        utilities.copytree(os.path.join(const.DEFAULT_CONFIGS, 'logstash', 'zeek'),
                           self.install_directory)
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        try:
            with open(env_file) as env_f:
                env_str = env_f.read()
                if 'ELASTIFLOW_DICT_PATH' not in env_str:
                    dict_path = os.path.join(self.install_directory, 'dictionaries')
                    if stdout:
                        sys.stdout.write(
                            '[+] Updating Elastiflow dictionary configuration path [{}]\n'.format(dict_path))
                    subprocess.call('echo ELASTIFLOW_DICT_PATH="{}" >> {}'.format(dict_path, env_file), shell=True)
                if 'ELASTIFLOW_TEMPLATE_PATH' not in env_str:
                    template_path = os.path.join(self.install_directory, 'templates')
                    if stdout:
                        sys.stdout.write(
                            '[+] Updating Elastiflow template configuration path [{}]\n'.format(template_path))
                    subprocess.call('echo ELASTIFLOW_TEMPLATE_PATH="{}" >> {}'.format(template_path, env_file),
                                    shell=True)
                if 'ELASTIFLOW_GEOIP_DB_PATH' not in env_str:
                    geo_path = os.path.join(self.install_directory, 'geoipdbs')
                    if stdout:
                        sys.stdout.write('[+] Updating Elastiflow geodb configuration path [{}]\n'.format(geo_path))
                    subprocess.call('echo ELASTIFLOW_GEOIP_DB_PATH="{}" >> {}'.format(geo_path, env_file), shell=True)
                if 'ELASTIFLOW_DEFINITION_PATH' not in env_str:
                    def_path = os.path.join(self.install_directory, 'definitions')
                    if stdout:
                        sys.stdout.write(
                            '[+] Updating Elastiflow definitions configuration path [{}]\n'.format(def_path))
                    subprocess.call('echo ELASTIFLOW_DEFINITION_PATH="{}" >> {}'.format(def_path, env_file), shell=True)
        except Exception as e:
            raise elastiflow_exceptions.InstallElastiflowError(
                "Failed to read elastiflow environment variables; {} ".format(e))
        try:
            elastiflow_config.ConfigManager().write_environment_variables()
        except (elastiflow_exceptions.ReadElastiflowConfigError, elastiflow_exceptions.WriteElastiflowConfigError):
            raise elastiflow_exceptions.InstallElastiflowError("Could not read/write elastiflow environment variables.")
