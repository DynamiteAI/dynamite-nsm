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
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.filebeat import config as filebeat_configs
from dynamite_nsm.services.filebeat import exceptions as filebeat_exceptions


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
            try:
                self.download_filebeat(stdout=stdout)
                self.extract_filebeat(stdout=stdout)
            except (general_exceptions.ArchiveExtractionError, general_exceptions.DownloadError):
                raise filebeat_exceptions.InstallFilebeatError("Failed to download/extract Filebeat archive.")

    @staticmethod
    def download_filebeat(stdout=False):
        """
        Download Filebeat archive

        :param stdout: Print output to console
        """
        url = None
        try:
            with open(const.FILE_BEAT_MIRRORS, 'r') as filebeat_archive:
                for url in filebeat_archive.readlines():
                    if utilities.download_file(url, const.FILE_BEAT_ARCHIVE_NAME, stdout=stdout):
                        break
        except Exception as e:
            raise general_exceptions.DownloadError(
                "General error while downloading elasticsearch from {}; {}".format(url, e))

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
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract filebeat archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract filebeat archive; {}".format(e))

    def setup_filebeat(self):
        """
        Creates necessary directory structure, and copies required files, generates a default configuration
        """
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if self.stdout:
            sys.stdout.write('[+] Creating Filebeat install directory.\n')
        utilities.makedirs(self.install_directory, exist_ok=True)
        if self.stdout:
            sys.stdout.write('[+] Copying Filebeat to install directory.\n')
        utilities.copytree(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_DIRECTORY_NAME), self.install_directory)
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'filebeat', 'filebeat.yml'),
                    self.install_directory)
        if self.stdout:
            sys.stdout.write('[+] Building configurations and setting up permissions.\n')
        try:
            beats_config = filebeat_configs.ConfigManager(self.install_directory)
        except filebeat_exceptions.ReadFilebeatConfigError:
            raise filebeat_exceptions.InstallFilebeatError("Failed to read filebeat configuration.")
        beats_config.set_monitor_target_paths(self.monitor_paths)
        try:
            beats_config.write_config()
        except filebeat_exceptions.WriteFilebeatConfigError:
            raise filebeat_exceptions.InstallFilebeatError("Failed to write filebeat configuration.")
        try:
            utilities.set_permissions_of_file(os.path.join(self.install_directory, 'filebeat.yml'),
                                              unix_permissions_integer=501)
        except Exception as e:
            filebeat_exceptions.InstallFilebeatError("Failed to set permissions of filebeat.yml file; {}".format(e))
        try:
            with open(env_file) as env_f:
                if 'FILEBEAT_HOME' not in env_f.read():
                    if self.stdout:
                        sys.stdout.write('[+] Updating FileBeat default script path [{}]\n'.format(
                            self.install_directory)
                        )
                    subprocess.call('echo FILEBEAT_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
        except Exception as e:
            raise filebeat_exceptions.InstallFilebeatError(
                "General error occurred while attempting to install filebeat; {}".format(e))
