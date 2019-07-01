import os
import sys
import tarfile
import subprocess

from installer import const
from installer import utilities


CONFIGURATION_DIRECTORY = '/etc/dynamite/logstash/elastiflow/conf.d/'
INSTALL_DIRECTORY = '/etc/dynamite/logstash/elastiflow/'


class ElastiFlowInstaller:

    def __init__(self,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 install_directory=INSTALL_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory
        (E.G /etc/dynamite/logstash/elastiflow/conf.d/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/elastiflow/)
        """

        self.configuration_directory = configuration_directory
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
        if stdout:
            sys.stdout.write('[+] Creating elastiflow install|configuration directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        if stdout:
            sys.stdout.write('[+] Copying elastiflow configurations\n')
        utilities.copytree(os.path.join(const.INSTALL_CACHE, 'elastiflow-3.5.0', 'logstash', 'elastiflow'),
                           self.install_directory)
        utilities.set_ownership_of_file(self.install_directory)
        utilities.set_ownership_of_file(self.configuration_directory)
        if 'ELASTIFLOW_DICT_PATH' not in open('/etc/environment').read():
            dict_path = os.path.join(self.install_directory, 'dictionaries')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow dictionary configuration path [{}]\n'.format(dict_path))
            subprocess.call('echo ELASTIFLOW_DICT_PATH="{}" >> /etc/environment'.format(dict_path), shell=True)
        if 'ELASTIFLOW_TEMPLATE_PATH' not in open('/etc/environment').read():
            template_path = os.path.join(self.install_directory, 'templates')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow template configuration path [{}]\n'.format(template_path))
            subprocess.call('echo ELASTIFLOW_TEMPLATE_PATH="{}" >> /etc/environment'.format(template_path), shell=True)
        if 'ELASTIFLOW_GEOIP_DB_PATH' not in open('/etc/environment').read():
            geo_path = os.path.join(self.install_directory, 'geoipdbs')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow geodb configuration path [{}]\n'.format(geo_path))
            subprocess.call('echo ELASTIFLOW_GEOIP_DB_PATH="{}" >> /etc/environment'.format(geo_path), shell=True)
        if 'ELASTIFLOW_DEFINITION_PATH' not in open('/etc/environment').read():
            def_path = os.path.join(self.install_directory, 'definitions')
            if stdout:
                sys.stdout.write('[+] Updating Elastiflow definitions configuration path [{}]\n'.format(def_path))
            subprocess.call('echo ELASTIFLOW_GEOIP_DB_PATH="{}" >> /etc/environment'.format(def_path), shell=True)