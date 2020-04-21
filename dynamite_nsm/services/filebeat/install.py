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
from dynamite_nsm.services.filebeat import profile as filebeat_profile
from dynamite_nsm.services.filebeat import process as filebeat_process
from dynamite_nsm.services.filebeat import exceptions as filebeat_exceptions


class InstallManager:

    def __init__(self, install_directory, monitor_log_paths, logstash_targets, agent_tag=None,
                 download_filebeat_archive=True, stdout=True):
        """
        :param install_directory: The installation directory (E.G /opt/dynamite/filebeat/)
        :param monitor_log_paths: A tuple of log paths to monitor
        :param logstash_targets: A tuple of Logstash targets to forward events to (E.G ["192.168.0.9:5044", ...])
        :param agent_tag: A friendly name for the agent (defaults to the hostname with no spaces and _agt suffix)
        :param download_filebeat_archive: If True, download the Filebeat archive from a mirror
        :param stdout: Print the output to console
        """

        self.monitor_paths = list(monitor_log_paths)
        self.logstash_targets = list(logstash_targets)
        self.install_directory = install_directory
        self.stdout = stdout
        self.agent_tag = agent_tag
        if download_filebeat_archive:
            try:
                self.download_filebeat(stdout=stdout)
            except (general_exceptions.ArchiveExtractionError, general_exceptions.DownloadError):
                raise filebeat_exceptions.InstallFilebeatError("Failed to download Filebeat archive.")

        if not agent_tag:
            self.agent_tag = utilities.get_default_agent_tag()
        else:
            self.agent_tag = str(agent_tag)[0:29]
        try:
            self.extract_filebeat(stdout=stdout)
        except general_exceptions.ArchiveExtractionError:
            raise filebeat_exceptions.InstallFilebeatError("Failed to extract Filebeat archive.")

        if not self.validate_logstash_targets(logstash_targets):
            raise filebeat_exceptions.InstallFilebeatError(
                "Invalid Logstash Targets specified: {}.".format(logstash_targets))

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

    @staticmethod
    def validate_logstash_targets(logstash_targets):
        """
        Ensures that Logstash targets are entered in a valid format (E.G ["192.168.0.1:5044", "myhost2:5044"])

        :param logstash_targets: A list of IP/host port pair
        :return: True if valid
        """

        if isinstance(logstash_targets, list) or isinstance(logstash_targets, tuple):
            for i, target in enumerate(logstash_targets):
                target = str(target)
                try:
                    host, port = target.split(':')
                    if not str(port).isdigit():
                        sys.stderr.write(
                            '[-] Logstash Target Invalid: {} port must be numeric at position {}\n'.format(target, i))
                        return False
                except ValueError:
                    sys.stderr.write(
                        '[-] Logstash Target Invalid: {} expected host:port at position {}\n'.format(target, i))
                    return False
        else:
            sys.stderr.write(
                '[-] Logstash Target Invalid: {}; must be a enumerable (list, tuple)'.format(logstash_targets))
            return False
        return True

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
        beats_config.set_agent_tag(self.agent_tag)
        beats_config.set_logstash_targets(self.logstash_targets)
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


def install_filebeat(install_directory, monitor_log_paths, agent_tag, download_filebeat_archive=True, stdout=True):
    filebeat_profiler = filebeat_profile.ProcessProfiler()
    if filebeat_profiler.is_installed:
        raise filebeat_exceptions.AlreadyInstalledFilebeatError()
    filebeat_installer = InstallManager(install_directory, monitor_log_paths, agent_tag,
                                        download_filebeat_archive=download_filebeat_archive, stdout=stdout)
    filebeat_installer.setup_filebeat()


def uninstall_filebeat(stdout=False, prompt_user=True):
    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    filebeat_profiler = filebeat_profile.ProcessProfiler()
    if prompt_user:
        sys.stderr.write('[-] WARNING! Removing Filebeat Will Remove Critical Agent Functionality.\n')
        resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            exit(0)
    if filebeat_profiler.is_running:
        try:
            filebeat_process.ProcessManager().stop()
        except filebeat_exceptions.CallFilebeatProcessError:
            raise filebeat_exceptions.AlreadyInstalledFilebeatError()
    install_directory = environment_variables.get('FILEBEAT_HOME')
    try:
        with open(env_file) as env_fr:
            env_lines = ''
            for line in env_fr.readlines():
                if 'FILEBEAT_HOME' in line:
                    continue
                elif line.strip() == '':
                    continue
                env_lines += line.strip() + '\n'
        with open(env_file, 'w') as env_fw:
            env_fw.write(env_lines)
        if filebeat_profiler.is_installed:
            shutil.rmtree(install_directory, ignore_errors=True)
    except Exception as e:
        raise filebeat_exceptions.UninstallFilebeatError(
            "General error occurred while attempting to uninstall filebeat; {}".format(e))
