import os
import sys
import shutil
import tarfile
import subprocess

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.filebeat import config as filebeat_configs


class InstallManager:

    def __init__(self, install_directory, monitor_paths,
                 download_filebeat_archive=True, stdout=True):
        """
        :param install_directory: The installation directory (E.G /opt/dynamite/filebeat/)
        :param monitor_paths: The tuple of log paths to monitor
        :param download_filebeat_archive: If True, download the Filebeat archive from a mirror
        :param stdout: Print the output to console
        """
        self.monitor_paths = list(monitor_paths)
        self.install_directory = install_directory
        self.stdout = stdout
        if download_filebeat_archive:
            self.download_filebeat(stdout=stdout)
            self.extract_filebeat(stdout=stdout)

    @staticmethod
    def download_filebeat(stdout=False):
        """
        Download Filebeat archive

        :param stdout: Print output to console
        """
        for url in open(const.FILE_BEAT_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.FILE_BEAT_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_filebeat(stdout=False):
        """
        Extract Filebeat to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.FILE_BEAT_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            if stdout:
                sys.stdout.write('[+] Complete!\n')
                sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    def setup_filebeat(self):
        """
        Creates necessary directory structure, and copies required files, generates a default configuration
        """
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if self.stdout:
            sys.stdout.write('[+] Creating Filebeat install directory.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        if self.stdout:
            sys.stdout.write('[+] Copying Filebeat to install directory.\n')
        utilities.copytree(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_DIRECTORY_NAME), self.install_directory)
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'filebeat', 'filebeat.yml'),
                    self.install_directory)
        if self.stdout:
            sys.stdout.write('[+] Building configurations and setting up permissions.\n')
        beats_config = filebeat_configs.ConfigManager(self.install_directory)
        beats_config.set_monitor_target_paths(self.monitor_paths)
        beats_config.write_config()
        utilities.set_permissions_of_file(os.path.join(self.install_directory, 'filebeat.yml'),
                                          unix_permissions_integer=501)
        if 'FILEBEAT_HOME' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating FileBeat default script path [{}]\n'.format(
                    self.install_directory)
                )
            subprocess.call('echo FILEBEAT_HOME="{}" >> {}'.format(self.install_directory, env_file),
                            shell=True)
