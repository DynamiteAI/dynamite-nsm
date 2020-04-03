import os
import sys
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.logstash.elastiflow import config as elastiflow_config


class InstallManager:

    def __init__(self, install_directory):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/elastiflow/)
        """

        self.install_directory = install_directory

    @staticmethod
    def download_elasticflow(stdout=False):
        """
        Download Elastiflow archive

        :param stdout: Print output to console
        """
        for url in open(const.ELASTIFLOW_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.ELASTIFLOW_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_elastiflow(stdout=False):
        """
        Extract ElastiFlow to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.ELASTIFLOW_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.ELASTIFLOW_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_logstash_elastiflow(self, stdout=False):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if stdout:
            sys.stdout.write('[+] Creating elastiflow install|configuration directories.\n')
        os.makedirs(self.install_directory, exist_ok=True)
        if stdout:
            sys.stdout.write('[+] Copying elastiflow configurations\n')
        utilities.copytree(os.path.join(const.DEFAULT_CONFIGS, 'logstash', 'zeek'),
                           self.install_directory)
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        if 'ELASTIFLOW_DICT_PATH' not in open(env_file).read():
            dict_path = os.path.join(self.install_directory, 'dictionaries')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow dictionary configuration path [{}]\n'.format(dict_path))
            subprocess.call('echo ELASTIFLOW_DICT_PATH="{}" >> {}'.format(dict_path, env_file), shell=True)
        if 'ELASTIFLOW_TEMPLATE_PATH' not in open(env_file).read():
            template_path = os.path.join(self.install_directory, 'templates')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow template configuration path [{}]\n'.format(template_path))
            subprocess.call('echo ELASTIFLOW_TEMPLATE_PATH="{}" >> {}'.format(template_path, env_file), shell=True)
        if 'ELASTIFLOW_GEOIP_DB_PATH' not in open(env_file).read():
            geo_path = os.path.join(self.install_directory, 'geoipdbs')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow geodb configuration path [{}]\n'.format(geo_path))
            subprocess.call('echo ELASTIFLOW_GEOIP_DB_PATH="{}" >> {}'.format(geo_path, env_file), shell=True)
        if 'ELASTIFLOW_DEFINITION_PATH' not in open(env_file).read():
            def_path = os.path.join(self.install_directory, 'definitions')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow definitions configuration path [{}]\n'.format(def_path))
            subprocess.call('echo ELASTIFLOW_DEFINITION_PATH="{}" >> {}'.format(def_path, env_file), shell=True)
        elastiflow_config.ConfigManager().write_environment_variables()
