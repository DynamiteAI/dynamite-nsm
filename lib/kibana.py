import os
import sys
import shutil
import tarfile
import traceback
import subprocess

from lib import const
from lib import utilities

INSTALL_DIRECTORY = '/opt/dynamite/kibana/'
CONFIGURATION_DIRECTORY = '/etc/dynamite/kibana/'
LOG_DIRECTORY = '/var/log/dynamite/kibana/'


class KibanaInstaller:

    def __init__(self, install_directory=INSTALL_DIRECTORY,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 log_directory=LOG_DIRECTORY):
        self.install_directory = install_directory
        self.configuration_directory = configuration_directory
        self.log_directory = log_directory

    @staticmethod
    def download_kibana(stdout=False):
        """
        Download Kibana archive

        :param stdout: Print output to console
        """
        for url in open(const.KIBANA_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.KIBANA_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_kibana(stdout=False):
        """
        Extract Kibana to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.KIBANA_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.KIBANA_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            if stdout:
                sys.stdout.write('[+] Complete!\n')
                sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_kibana(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating kibana install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.log_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(os.path.join(self.install_directory, 'data')), shell=True)
        config_paths = [
            'config/kibana.yml',
        ]
        install_paths = [
            'package.json',
            'bin/',
            'built_assets/'
            'node/',
            'node_modules/',
            'optimize/',
            'plugins/',
            'src/',
            'target/',
            'webpackShims/'
        ]
        for path in config_paths:
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                            self.configuration_directory)

            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))
        for path in install_paths:
            try:
                shutil.move(os.path.join(const.INSTALL_CACHE, '{}/{}'.format(const.KIBANA_DIRECTORY_NAME, path)),
                            self.install_directory)
            except shutil.Error as e:
                sys.stderr.write('[-] {} already exists at this path. [{}]\n'.format(path, e))


def install_kibana(install_jdk=True, create_dynamite_user=True, stdout=False):
    """
    Install Kibana/ElastiFlow Dashboards

    :param install_jdk: Install the latest OpenJDK that will be used by Logstash/ElasticSearch
    :param create_dynamite_user: Automatically create the 'dynamite' user, who has privs to run Logstash/ElasticSearch
    :param stdout: Print the output to console
    :return: True, if installation succeeded
    """
    if utilities.get_memory_available_bytes() < 3 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite Kibana requires at-least 3GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes()/(1024 ** 3)
        ))
        return False
    try:
        kb_installer = KibanaInstaller()
        if install_jdk:
            utilities.download_java(stdout=True)
            utilities.extract_java(stdout=True)
            utilities.setup_java()
        if create_dynamite_user:
            utilities.create_dynamite_user('password')
        kb_installer.download_kibana(stdout=True)
        kb_installer.extract_kibana(stdout=True)
        kb_installer.setup_kibana(stdout=True)
    except Exception:
        sys.stderr.write('[-] A fatal error occurred while attempting to install LogStash: ')
        traceback.print_exc(file=sys.stderr)
        return False
    if stdout:
        sys.stdout.write('[+] *** Kibana + Dashboards installed successfully. ***\n\n')
        sys.stdout.write('[+] Next, Start your collector: \'dynamite.py start kibana\'.\n')
        sys.stdout.flush()
    return True