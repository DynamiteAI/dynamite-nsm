import os
import sys
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.logstash.synesis import config as synesis_config
from dynamite_nsm.services.logstash.synesis import exceptions as synesis_exceptions


class InstallManager:

    def __init__(self, install_directory):
        """
        :param install_directory: Path to the install directory (E.G /etc/dynamite/logstash/synlite_suricata/)
        """
        self.install_directory = install_directory

    def setup_logstash_synesis(self, stdout=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if stdout:
            sys.stdout.write('[+] Creating synesis install|configuration directories.\n')
        utilities.makedirs(self.install_directory, exist_ok=True)
        if stdout:
            sys.stdout.write('[+] Copying synesis configurations\n')
        utilities.copytree(os.path.join(const.DEFAULT_CONFIGS, 'logstash',
                                        'suricata'),
                           self.install_directory)
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        try:
            with open(env_file) as env_f:
                env_str = env_f.read()
                if 'SYNLITE_SURICATA_DICT_PATH' not in env_str:
                    dict_path = os.path.join(self.install_directory, 'dictionaries')
                    if stdout:
                        sys.stdout.write('[+] Updating Synesis dictionary configuration path [{}]\n'.format(dict_path))
                    subprocess.call('echo SYNLITE_SURICATA_DICT_PATH="{}" >> {}'.format(dict_path, env_file),
                                    shell=True)
                if 'SYNLITE_SURICATA_TEMPLATE_PATH' not in env_str:
                    template_path = os.path.join(self.install_directory, 'templates')
                    if stdout:
                        sys.stdout.write(
                            '[+] Updating Synesis template configuration path [{}]\n'.format(template_path))
                    subprocess.call('echo SYNLITE_SURICATA_TEMPLATE_PATH="{}" >> {}'.format(template_path, env_file),
                                    shell=True)
                if 'SYNLITE_SURICATA_GEOIP_DB_PATH' not in env_str:
                    geo_path = os.path.join(self.install_directory, 'geoipdbs')
                    if stdout:
                        sys.stdout.write('[+] Updating Synesis geodb configuration path [{}]\n'.format(geo_path))
                    subprocess.call('echo SYNLITE_SURICATA_GEOIP_DB_PATH="{}" >> {}'.format(geo_path, env_file),
                                    shell=True)
        except Exception as e:
            raise synesis_exceptions.InstallSynesisError(
                "Failed to read synesis environment variables; {} ".format(e))
        try:
            synesis_config.ConfigManager().write_environment_variables()
        except synesis_exceptions.ReadSynesisConfigError, synesis_exceptions.WriteSynesisConfigError:
            raise synesis_exceptions.InstallSynesisError("Could not read/write synesis environment variables.")
