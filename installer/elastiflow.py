import os
import sys
import shutil
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

    def setup_logstash_elastiflow(self):
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'logstash', 'elastiflow-pipeline.yml'),
                    os.path.join(self.install_directory, 'pipelines.yml'))
        utilities.copytree(os.path.join(const.INSTALL_CACHE, 'elastiflow-3.5.0', 'logstash', 'elastiflow'),
                           self.install_directory)