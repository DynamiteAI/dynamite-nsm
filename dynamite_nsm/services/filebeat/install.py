import logging
import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.base import install
from dynamite_nsm.services.base import systemctl
from dynamite_nsm.services.filebeat import config as filebeat_configs
from dynamite_nsm.service_objects.filebeat import targets as filebeat_targets


class InstallManager(install.BaseInstallManager):

    def __init__(self, install_directory: str, monitor_log_paths: str, target_strings: List[str],
                 agent_tag: Optional[str] = None, download_filebeat_archive: Optional[bool] = True,
                 stdout: Optional[bool] = True, verbose: Optional[bool] = True):
        """
        Install Filebeat

        :param install_directory: The installation directory (E.G /opt/dynamite/filebeat/)
        :param monitor_log_paths: A tuple of log paths to monitor
        :param target_strings: A tuple of Logstash/Kafka target_strings to forward events to
               (E.G ["192.168.0.9:5044", ...])
        :param agent_tag: A friendly name for the agent (defaults to the hostname with no spaces and _agt suffix)
        :param download_filebeat_archive: If True, download the Filebeat archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """

        self.monitor_paths = list(monitor_log_paths)
        self.target_strings = list(target_strings)
        self.install_directory = install_directory
        self.stdout = stdout
        self.verbose = verbose
        self.agent_tag = agent_tag
        self.environ = utilities.get_environment_file_dict()
        install.BaseInstallManager.__init__(self, 'filebeat', verbose=self.verbose, stdout=stdout)
        if download_filebeat_archive:
            self.logger.info("Attempting to download Filebeat archive.")
            self.download_from_mirror(const.FILE_BEAT_MIRRORS, const.FILE_BEAT_ARCHIVE_NAME, stdout=stdout,
                                      verbose=verbose)

        if not agent_tag:
            self.agent_tag = utilities.get_default_agent_tag()
            self.logger.info(f'Setting Agent Tag to {self.agent_tag} as none was set.')
        else:
            if len(agent_tag) < 5:
                self.logger.warning("Agent tag too short. Must be more than 5 characters. Using default agent tag.")
            elif not bool(re.findall("^[a-zA-Z0-9_]*$", agent_tag)):
                self.logger.warning(
                    "Agent tag cannot contain alphanumeric and '_' characters. Using default agent tag.")
                agent_tag = utilities.get_default_agent_tag()
            self.agent_tag = str(agent_tag)[0:29]
            self.logger.info(f'Setting Agent Tag to {self.agent_tag}.')
        self.logger.info(f'Attempting to extract FileBeat archive ({const.FILE_BEAT_ARCHIVE_NAME}).')
        self.extract_archive(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_ARCHIVE_NAME))
        self.logger.info("Extraction completed.")

    @staticmethod
    def validate_targets(target_strings: List[str], stdout: Optional[bool] = True,
                         verbose: Optional[bool] = False) -> bool:
        """
        Ensures that target_strings are entered in a valid format (E.G ["192.168.0.1:5044", "myhost2:5044"])

        :param target_strings: A list of IP/host port pair
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        :return: True if valid
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('FILEBEAT', level=log_level, stdout=stdout)

        if isinstance(target_strings, list) or isinstance(target_strings, tuple):
            for i, target in enumerate(target_strings):
                target = str(target)
                try:
                    host, port = target.split(':')
                    if not str(port).isdigit():
                        logger.warning(f'Target Invalid: {target} port must be numeric at position {i}')
                        return False
                except ValueError:
                    logger.warning(f'Target Invalid: {target} expected host:port at position {i}')
                    return False
        else:
            logger.warning(f'Target Invalid: {target_strings}; must be a enumerable (list, tuple)')
            return False
        return True

    def setup_filebeat(self) -> None:
        """
        Creates necessary directory structure, and copies required files, generates a default configuration
        """

        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info('Creating FileBeat install directory.')
        utilities.makedirs(self.install_directory, exist_ok=True)
        self.logger.info('Copying FileBeat to install directory.')
        utilities.copytree(os.path.join(const.INSTALL_CACHE, const.FILE_BEAT_DIRECTORY_NAME),
                           self.install_directory)
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'filebeat', 'filebeat.yml'),
                    self.install_directory)
        self.logger.info("Building configurations and setting up permissions.")

        beats_config = filebeat_configs.ConfigManager(self.install_directory)
        beats_config.input_logs.monitor_log_paths = self.monitor_paths
        beats_config.field_processors.originating_agent_tag = self.agent_tag
        beats_config.logstash_targets = filebeat_targets.LogstashTargets(self.target_strings)
        beats_config.index_template_settings.index_name = beats_config.logstash_targets.index.split('-')[0]
        beats_config.index_template_settings.index_pattern = beats_config.index_template_settings.index_name + '-*'
        beats_config.index_template_settings.enabled = True

        beats_config.commit()
        utilities.set_permissions_of_file(os.path.join(self.install_directory, 'filebeat.yml'),
                                          unix_permissions_integer=501)

        with open(env_file) as env_f:
            if 'FILEBEAT_HOME' not in env_f.read():
                self.logger.info(f'Updating FileBeat default script path [{self.install_directory}]')
                subprocess.call(f'echo FILEBEAT_HOME="{self.install_directory}" >> {env_file}', shell=True)

        sysctl = systemctl.SystemCtl()
        self.logger.info("Installing Filebeat systemd service.")
        sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'filebeat.service'))
        zeek_logs = None
        zeek_home = self.environ.get('ZEEK_HOME')
        suricata_logs = os.path.join(const.LOG_PATH, 'suricata')
        if zeek_home:
            zeek_logs = os.path.join(zeek_home, 'logs', 'current')
        self.logger.info('Patching Zeek/Suricata modules.')
        beats_config.patch_modules(zeek_log_directory=zeek_logs, suricata_log_directory=suricata_logs)


def install_filebeat(install_directory: str, monitor_log_paths: str, target_strings: List[str],
                     agent_tag: Optional[str] = None, download_filebeat_archive: Optional[bool] = True,
                     stdout: Optional[bool] = True, verbose: Optional[bool] = False) -> None:
    """
    Install Filebeat

    :param install_directory: The installation directory (E.G /opt/dynamite/filebeat/)
    :param monitor_log_paths: A tuple of log paths to monitor
    :param target_strings: A tuple of Logstash/Kafka target_strings to forward events to (E.G ["192.168.0.9:5044", ...])
    :param agent_tag: A friendly name for the agent (defaults to the hostname with no spaces and _agt suffix)
    :param download_filebeat_archive: If True, download the Filebeat archive from a mirror
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    filebeat_installer = InstallManager(install_directory, monitor_log_paths=monitor_log_paths,
                                        target_strings=target_strings, agent_tag=agent_tag,
                                        download_filebeat_archive=download_filebeat_archive, stdout=stdout,
                                        verbose=verbose)
    filebeat_installer.setup_filebeat()


def uninstall_filebeat(prompt_user: Optional[bool] = True, stdout: Optional[bool] = True,
                       verbose: Optional[bool] = False) -> None:
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
    if prompt_user:
        sys.stderr.write('\n[-] WARNING! Removing Filebeat Will Remove Critical Agent Functionality.\n')
        resp = utilities.prompt_input('[?] Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('[?] Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    install_directory = environment_variables.get('FILEBEAT_HOME')
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
    shutil.rmtree(install_directory, ignore_errors=True)
    sysctl = systemctl.SystemCtl()
    sysctl.stop('filebeat')
    sysctl.uninstall_and_disable('filebeat')
