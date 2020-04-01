import os
import sys
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.logstash.synesis import config as synesis_config


class InstallManager:

    def __init__(self, install_directory):
        """
        :param install_directory: Path to the install directory (E.G /etc/dynamite/logstash/synlite_suricata/)
        """
        self.install_directory = install_directory

    @staticmethod
    def download_synesis(stdout=False):
        """
        Download SynesisLite (Suricata) archive

        :param stdout: Print output to console
        """
        for url in open(const.SYNESIS_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.SYNESIS_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_synesis(stdout=False):
        """
        Extract SynesisLite (Suricata) archive to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.SYNESIS_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.SYNESIS_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_logstash_synesis(self, stdout=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if stdout:
            sys.stdout.write('[+] Creating synesis install|configuration directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        if stdout:
            sys.stdout.write('[+] Copying synesis configurations\n')
        utilities.copytree(os.path.join(const.DEFAULT_CONFIGS, 'logstash',
                                        'suricata'),
                           self.install_directory)
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        if 'SYNLITE_SURICATA_DICT_PATH' not in open(env_file).read():
            dict_path = os.path.join(self.install_directory, 'dictionaries')
            if stdout:
                sys.stdout.write('[+] Updating Synesis dictionary configuration path [{}]\n'.format(dict_path))
            subprocess.call('echo SYNLITE_SURICATA_DICT_PATH="{}" >> {}'.format(dict_path, env_file), shell=True)
        if 'SYNLITE_SURICATA_TEMPLATE_PATH' not in open(env_file).read():
            template_path = os.path.join(self.install_directory, 'templates')
            if stdout:
                sys.stdout.write('[+] Updating Synesis template configuration path [{}]\n'.format(template_path))
            subprocess.call('echo SYNLITE_SURICATA_TEMPLATE_PATH="{}" >> {}'.format(template_path, env_file),
                            shell=True)
        if 'SYNLITE_SURICATA_GEOIP_DB_PATH' not in open(env_file).read():
            geo_path = os.path.join(self.install_directory, 'geoipdbs')
            if stdout:
                sys.stdout.write('[+] Updating Synesis geodb configuration path [{}]\n'.format(geo_path))
            subprocess.call('echo SYNLITE_SURICATA_GEOIP_DB_PATH="{}" >> {}'.format(geo_path, env_file), shell=True)
        synesis_config.ConfigManager().write_environment_variables()
