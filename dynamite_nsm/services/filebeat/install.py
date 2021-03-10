import os
from typing import List, Optional

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.filebeat import config
from dynamite_nsm.services.base import install, systemctl
from dynamite_nsm.service_objects.filebeat import misc as misc_filebeat_objs
from dynamite_nsm.service_objects.filebeat import targets as filebeat_targets


class InstallManager(install.BaseInstallManager):

    def __init__(self, install_directory: str, download_filebeat_archive: Optional[bool] = True,
                 stdout=True, verbose=False):
        """
        Install Filebeat

        :param install_directory: The installation directory (E.G /opt/dynamite/filebeat/)
        :param download_filebeat_archive: If True, download the Filebeat archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """

        self.install_directory = install_directory
        self.download_filebeat_archive = download_filebeat_archive
        self.stdout = stdout
        self.verbose = verbose

        super().__init__('filebeat', verbose, stdout)
        if download_filebeat_archive:
            self.logger.info('Attempting to download Filebeat OSS archive.')
            _, archive_name, self.local_mirror_root = self.download_from_mirror(const.FILE_BEAT_MIRRORS)
            self.logger.info(f'Attempting to extract Filebeat archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.local_mirror_root = self.get_mirror_info(const.FILE_BEAT_MIRRORS)

    def copy_filebeat_files_and_directories(self) -> None:
        filebeat_tarball_extracted = f'{const.INSTALL_CACHE}/{self.local_mirror_root}'

        install_paths = [
            'kibana/',
            'module/',
            'modules.d/',
            'fields.yml',
            'filebeat',
            'filebeat.yml'
        ]
        for inst in install_paths:
            self.copy_file_or_directory_to_destination(f'{filebeat_tarball_extracted}/{inst}',
                                                       self.install_directory)

    def create_update_filebeat_environment_variables(self) -> None:
        """
        Creates all the required Logstash environmental variables
        """
        self.create_update_env_variable('FILEBEAT_HOME', self.install_directory)

    def setup(self, monitor_log_paths: Optional[List[str]] = None, targets: Optional[List[str]] = None,
              agent_tag: Optional[str] = None) -> None:
        """
        :param monitor_log_paths: A tuple of log paths to monitor
        :param targets: A tuple of Logstash/Kafka targets to forward events to (E.G ["192.168.0.9:5044", ...])
        :param agent_tag: A friendly name for the agent (defaults to the hostname with no spaces and _agt suffix)
        """
        from dynamite_nsm.services.zeek import profile as zeek_profile
        from dynamite_nsm.services.suricata import profile as suricata_profile
        from dynamite_nsm.services.logstash import profile as logstash_profile

        sysctl = systemctl.SystemCtl()
        zeek_log_root, suricata_log_root = None, None
        # Directory setup
        self.logger.debug(f'Creating directory: {self.install_directory}')
        utilities.makedirs(self.install_directory)
        self.logger.info('Installing files and directories.')
        self.copy_filebeat_files_and_directories()
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/filebeat/filebeat.yml',
                                                   self.install_directory)

        # Overwrite with dynamite default configurations
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/filebeat/module/', self.install_directory)
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/filebeat/modules.d/',
                                                   self.install_directory)
        filebeat_config = config.ConfigManager(self.install_directory, verbose=self.verbose, stdout=self.stdout)
        filebeat_config.logstash_targets = filebeat_targets.LogstashTargets(
            target_strings=targets,
            enabled=True
        )
        filebeat_config.input_logs = misc_filebeat_objs.InputLogs(
            monitor_log_paths=[]
        )
        filebeat_config.field_processors.originating_agent_tag = agent_tag
        if not monitor_log_paths:
            environ = utilities.get_environment_file_dict()
            zeek_log_root = f'{environ["ZEEK_HOME"]}/logs/current/'
            suricata_log_root = environ["SURICATA_LOGS"]
            zeek_profiler = zeek_profile.ProcessProfiler()
            suricata_profiler = suricata_profile.ProcessProfiler()
            if zeek_profiler.is_installed():
                self.logger.info(f'Zeek installation found; monitoring: {zeek_log_root}*.log')
                filebeat_config.input_logs.monitor_log_paths.append(f'{zeek_log_root}*.log')
            if suricata_profiler.is_installed():
                self.logger.info(f'Suricata installation found; monitoring: {suricata_log_root}eve.json')
                filebeat_config.input_logs.monitor_log_paths.append(f'{suricata_log_root}eve.json')
        else:
            filebeat_config.input_logs = misc_filebeat_objs.InputLogs(
                monitor_log_paths=monitor_log_paths
            )
        self.logger.info(f'Monitoring Paths = {filebeat_config.input_logs.monitor_log_paths}')
        if not targets:
            logstash_profiler = logstash_profile.ProcessProfiler()
            if logstash_profiler.is_installed():
                filebeat_config.logstash_targets.target_strings = [f'{utilities.get_primary_ip_address()}:5601']
        if not agent_tag:
            filebeat_config.field_processors.originating_agent_tag = utilities.get_default_agent_tag()
        self.logger.info(f'Agent Tag = {filebeat_config.field_processors.originating_agent_tag}')
        self.logger.info('Enabling Logstash connector by default.')
        filebeat_config.switch_to_logstash_target()
        filebeat_config.commit()
        self.logger.info('Applying configuration.')
        # Fix Permissions

        self.logger.info('Setting up file permissions.')
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_permissions_of_file(os.path.join(self.install_directory, 'filebeat.yml'),
                                          unix_permissions_integer=501)
        self.logger.info('Installing modules.')
        filebeat_config.patch_modules(zeek_log_directory=zeek_log_root, suricata_log_directory=suricata_log_root)

        # Install and enable service
        self.logger.info(f'Installing service -> {const.DEFAULT_CONFIGS}/systemd/filebeat.service')
        sysctl.install_and_enable(f'{const.DEFAULT_CONFIGS}/systemd/filebeat.service')


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=f'{const.INSTALL_PATH}/filebeat',
        download_filebeat_archive=True,
        stdout=True,
        verbose=True
    )
    install_mngr.setup()
