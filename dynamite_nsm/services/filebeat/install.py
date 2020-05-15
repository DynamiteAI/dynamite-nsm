import os
import re
import sys
import time
import shutil
import logging
import tarfile
import subprocess

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.filebeat import config as filebeat_configs
from dynamite_nsm.services.filebeat import profile as filebeat_profile
from dynamite_nsm.services.filebeat import process as filebeat_process
from dynamite_nsm.services.filebeat import exceptions as filebeat_exceptions


class InstallManager:

    def __init__(self, install_directory, monitor_log_paths, targets, kafka_topic=None, kafka_username=None,
                 kafka_password=None, agent_tag=None, download_filebeat_archive=True, stdout=True, verbose=False):
        """
        Install Filebeat

        :param install_directory: The installation directory (E.G /opt/dynamite/filebeat/)
        :param monitor_log_paths: A tuple of log paths to monitor
        :param targets: A tuple of Logstash/Kafka targets to forward events to (E.G ["192.168.0.9:5044", ...])
        :param kafka_topic: A string representing the name of the Kafka topic to write messages too
        :param kafka_username: The username for connecting to Kafka
        :param kafka_password: The password for connecting to Kafka
        :param agent_tag: A friendly name for the agent (defaults to the hostname with no spaces and _agt suffix)
        :param download_filebeat_archive: If True, download the Filebeat archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('FILEBEAT', level=log_level, stdout=stdout)

        self.monitor_paths = list(monitor_log_paths)
        self.targets = list(targets)
        self.kafka_topic = kafka_topic
        self.kafka_username = kafka_username
        self.kafka_password = kafka_password
        self.install_directory = install_directory
        self.stdout = stdout
        self.agent_tag = agent_tag
        if download_filebeat_archive:
            try:
                self.logger.info("Attempting to download Filebeat archive.")
                self.download_filebeat(stdout=stdout)
            except (general_exceptions.ArchiveExtractionError, general_exceptions.DownloadError):
                self.logger.error("Failed to download Zeek archive.")
                raise filebeat_exceptions.InstallFilebeatError("Failed to download Filebeat archive.")

        if not agent_tag:
            self.agent_tag = utilities.get_default_agent_tag()
            self.logger.info("Setting Agent Tag to {} as none was set.".format(self.agent_tag))
        else:
            if len(agent_tag) < 5:
                self.logger.warning("Agent tag too short. Must be more than 5 characters. Using default agent tag.")
            elif not bool(re.findall("^[a-zA-Z0-9_]*$", agent_tag)):
                self.logger.warning(
                    "Agent tag cannot contain alphanumeric and '_' characters. Using default agent tag.")
                agent_tag = utilities.get_default_agent_tag()
            self.agent_tag = str(agent_tag)[0:29]
            self.logger.info("Setting Agent Tag to {}.".format(self.agent_tag))
        try:
            self.logger.info("Attempting to extract FileBeat archive ({}).".format(const.FILE_BEAT_ARCHIVE_NAME))
            self.extract_filebeat()
            self.logger.info("Extraction completed.")
        except general_exceptions.ArchiveExtractionError as e:
            self.logger.error("Failed to extract FileBeat archive.")
            self.logger.debug("Failed to extract FileBeat archive, threw: {}.".format(e))
            raise filebeat_exceptions.InstallFilebeatError("Failed to extract Filebeat archive.")

        if not self.validate_targets(targets):
            self.logger.error("Invalid Targets specified: {}.".format(targets))
            raise filebeat_exceptions.InstallFilebeatError(
                "Invalid Targets specified: {}.".format(targets))

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
                "General error while downloading FileBeat from {}; {}".format(url, e))

    @staticmethod
    def extract_filebeat():
        """
        Extract Filebeat to local install_cache
        """

        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract FileBeat archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract FileBeat archive; {}".format(e))

    @staticmethod
    def validate_targets(targets, stdout=True, verbose=False):
        """
        Ensures that Logstash targets are entered in a valid format (E.G ["192.168.0.1:5044", "myhost2:5044"])

        :param targets: A list of IP/host port pair
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        :return: True if valid
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('FILEBEAT', level=log_level, stdout=stdout)

        if isinstance(targets, list) or isinstance(targets, tuple):
            for i, target in enumerate(targets):
                target = str(target)
                try:
                    host, port = target.split(':')
                    if not str(port).isdigit():
                        logger.warning(
                            'Target Invalid: {} port must be numeric at position {}'.format(target, i))
                        return False
                except ValueError:
                    logger.warning('Target Invalid: {} expected host:port at position {}'.format(target, i))
                    return False
        else:
            logger.warning('Target Invalid: {}; must be a enumerable (list, tuple)'.format(targets))
            return False
        return True

    def setup_filebeat(self):
        """
        Creates necessary directory structure, and copies required files, generates a default configuration
        """

        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info('Creating FileBeat install directory.')
        utilities.makedirs(self.install_directory, exist_ok=True)
        self.logger.info('Copying FileBeat to install directory.')
        try:
            utilities.copytree(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_DIRECTORY_NAME),
                               self.install_directory)
            shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'filebeat', 'filebeat.yml'),
                        self.install_directory)
        except Exception as e:
            self.logger.error("General error occurred while copying Filebeat configs.")
            self.logger.debug("General error occurred while copying Filebeat configs; {}".format(e))
            raise filebeat_exceptions.InstallFilebeatError(
                "General error occurred while copying Filebeat configs; {}".format(e))
        self.logger.info("Building configurations and setting up permissions.")
        try:
            beats_config = filebeat_configs.ConfigManager(self.install_directory)
        except filebeat_exceptions.ReadFilebeatConfigError:
            self.logger.error("Failed to read Filebeat configuration.")
            raise filebeat_exceptions.InstallFilebeatError("Failed to read Filebeat configuration.")
        beats_config.set_monitor_target_paths(self.monitor_paths)
        beats_config.set_agent_tag(self.agent_tag)
        if (self.kafka_password or self.kafka_username) and not self.kafka_topic:
            self.logger.error("You have specified Kafka config options without specifying a Kafka topic.")
            raise filebeat_exceptions.InstallFilebeatError(
                "You have specified Kafka config options without specifying a Kafka topic.")
        if self.kafka_topic:
            self.logger.warning(
                "You have enabled the Agent's Kafka output which does integrate natively with Dynamite "
                "Monitor/LogStash component. You will have to bring your own broker. Happy Hacking!")
            time.sleep(2)
            beats_config.set_kafka_targets(target_hosts=self.targets, topic=self.kafka_topic,
                                           username=self.kafka_username, password=self.kafka_password)
            # setup example upstream LogStash example, just in case you want to configure later
            beats_config.set_logstash_targets(target_hosts=['localhost:5601'])
            beats_config.enable_kafka_output()
        else:
            # setup example upstream Kafka example, just in case you want to configure later
            beats_config.set_kafka_targets(target_hosts=['localhost:9092'], topic='dynamite-nsm-events')
            beats_config.enable_logstash_output()
            beats_config.set_logstash_targets(self.targets)
        try:
            beats_config.write_config()
        except filebeat_exceptions.WriteFilebeatConfigError:
            self.logger.error("Failed to write filebeat configuration.")
            raise filebeat_exceptions.InstallFilebeatError("Failed to write filebeat configuration.")
        try:
            utilities.set_permissions_of_file(os.path.join(self.install_directory, 'filebeat.yml'),
                                              unix_permissions_integer=501)
        except Exception as e:
            self.logger.error("Failed to set permissions of filebeat.yml file.")
            self.logger.debug("Failed to set permissions of filebeat.yml file; {}".format(e))
            filebeat_exceptions.InstallFilebeatError("Failed to set permissions of filebeat.yml file; {}".format(e))
        try:
            with open(env_file) as env_f:
                if 'FILEBEAT_HOME' not in env_f.read():
                    self.logger.info('Updating FileBeat default script path [{}]'.format(self.install_directory))
                    subprocess.call('echo FILEBEAT_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
        except Exception as e:
            self.logger.error("General error occurred while attempting to install FileBeat.")
            self.logger.debug("General error occurred while attempting to install FileBeat; {}".format(e))
            raise filebeat_exceptions.InstallFilebeatError(
                "General error occurred while attempting to install FileBeat; {}".format(e))
        try:
            sysctl = systemctl.SystemCtl()
        except general_exceptions.CallProcessError:
            raise filebeat_exceptions.InstallFilebeatError("Could not find systemctl.")
        self.logger.info("Installing Filebeat systemd service.")
        if not sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'filebeat.service')):
            raise filebeat_exceptions.InstallFilebeatError("Failed to install Filebeat systemd service.")
        sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'dynamite-agent.target'))


def install_filebeat(install_directory, monitor_log_paths, targets, kafka_topic=None, kafka_username=None,
                     kafka_password=None, agent_tag=None, download_filebeat_archive=True,
                     stdout=True, verbose=False):
    """
    Install Filebeat

    :param install_directory: The installation directory (E.G /opt/dynamite/filebeat/)
    :param monitor_log_paths: A tuple of log paths to monitor
    :param targets: A tuple of Logstash/Kafka targets to forward events to (E.G ["192.168.0.9:5044", ...])
    :param kafka_topic: A string representing the name of the Kafka topic to write messages too
    :param kafka_username: The username for connecting to Kafka
    :param kafka_password: The password for connecting to Kafka
    :param agent_tag: A friendly name for the agent (defaults to the hostname with no spaces and _agt suffix)
    :param download_filebeat_archive: If True, download the Filebeat archive from a mirror
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('FILEBEAT', level=log_level, stdout=stdout)

    filebeat_profiler = filebeat_profile.ProcessProfiler()
    if filebeat_profiler.is_installed:
        logger.error('FileBeat is already installed.')
        raise filebeat_exceptions.AlreadyInstalledFilebeatError()
    filebeat_installer = InstallManager(install_directory, monitor_log_paths=monitor_log_paths,
                                        targets=targets, kafka_topic=kafka_topic, kafka_username=kafka_username,
                                        kafka_password=kafka_password, agent_tag=agent_tag,
                                        download_filebeat_archive=download_filebeat_archive, stdout=stdout,
                                        verbose=verbose)
    filebeat_installer.setup_filebeat()


def uninstall_filebeat(prompt_user=True, stdout=True, verbose=False):
    """
    Uninstall Filebeat

    :param prompt_user: Print a warning before continuing
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('FILEBEAT', level=log_level, stdout=stdout)
    logger.info("Uninstalling FileBeat.")
    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    filebeat_profiler = filebeat_profile.ProcessProfiler()
    if prompt_user:
        sys.stderr.write('\n[-] WARNING! Removing Filebeat Will Remove Critical Agent Functionality.\n')
        resp = utilities.prompt_input('[?] Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('[?] Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    if filebeat_profiler.is_running:
        try:
            filebeat_process.ProcessManager().stop()
        except filebeat_exceptions.CallFilebeatProcessError as e:
            logger.error("Could not kill Filebeat process. Cannot uninstall.")
            logger.debug("Could not kill Filebeat process. Cannot uninstall; {}".format(e))
            raise filebeat_exceptions.UninstallFilebeatError('Could not kill Filebeat process; {}'.format(e))
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
        logger.error("General error occurred while attempting to uninstall Filebeat.")
        logger.debug("General error occurred while attempting to uninstall Filebeat; {}".format(e))
        raise filebeat_exceptions.UninstallFilebeatError(
            "General error occurred while attempting to uninstall Filebeat; {}".format(e))
    try:
        sysctl = systemctl.SystemCtl()
    except general_exceptions.CallProcessError:
        raise filebeat_exceptions.UninstallFilebeatError("Could not find systemctl.")
    sysctl.uninstall_and_disable('filebeat')
    sysctl.uninstall_and_disable('dynamite-agent')
