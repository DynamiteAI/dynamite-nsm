from dynamite_nsm.logger import get_logger
import logging
import os
from typing import List, Optional

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.services.base import install, systemctl
from dynamite_nsm.services.base.config_objects.filebeat import misc as misc_filebeat_objs
from dynamite_nsm.services.filebeat import config


class InstallManager(install.BaseInstallManager):
    """
    Manage Filebeat installation process
    """

    def __init__(self, install_directory: str, download_filebeat_archive: Optional[bool] = True,
                 stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        """Install Filebeat
        Args:
            install_directory: The installation directory (E.G /opt/dynamite/filebeat/)
            download_filebeat_archive: If True, download the Filebeat archive from a mirror
            stdout: Print the output to console
            verbose: Include detailed debug messages
        """

        self.install_directory = install_directory
        self.download_filebeat_archive = download_filebeat_archive
        self.stdout = stdout
        self.verbose = verbose

        super().__init__('filebeat.install', verbose, stdout)
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

    @staticmethod
    def validate_targets(targets, stdout=True, verbose=False):
        """Ensures that targets are entered in a valid format (E.G ["192.168.0.1:5044", "myhost2:5044"])
        Args:
            targets: A list of IP/host port pair
            stdout: Print the output to console
            verbose: Include detailed debug messages
        Returns:
             True if valid
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('FILEBEAT', level=log_level, stdout=stdout)
        if isinstance(targets, list) or isinstance(targets, tuple):
            protocol_tokens = ['http://', 'https://', 'plain://', 'sasl://', 'redis://']
            for i, target in enumerate(targets):
                target = str(target).lower()
                for token in protocol_tokens:
                    target = target.replace(token, '')
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

    def create_update_filebeat_environment_variables(self) -> None:
        """Creates all the required Filebeat environmental variables
        Returns:
            None
        """
        self.create_update_env_variable('FILEBEAT_HOME', self.install_directory)

    def setup(self, targets: List[str], target_type: Optional[str] = 'elasticsearch',
              monitor_log_paths: Optional[List[str]] = None, agent_tag: Optional[str] = None) -> None:
        """Setup Filebeat
        Args:
            targets: A list of Elasticsearch/Kafka/Logstash targets to forward events to (E.G ["192.168.0.9 5044", ...])
            target_type: The target type; current supported: elasticsearch (default), logstash, kafka, redis
            monitor_log_paths: A tuple of log paths to monitor
            agent_tag: A friendly name for the agent (defaults to the hostname with no spaces and _agt suffix)

        Returns:
            None
        """
        from dynamite_nsm.services.zeek import profile as zeek_profile
        from dynamite_nsm.services.suricata import profile as suricata_profile

        sysctl = systemctl.SystemCtl()
        zeek_log_root, suricata_log_root = None, None
        # Directory setup
        self.logger.debug(f'Creating directory: {self.install_directory}')
        utilities.makedirs(self.install_directory)
        utilities.makedirs(f'{self.install_directory}/logs')
        self.logger.info('Installing files and directories.')
        self.copy_filebeat_files_and_directories()
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/filebeat/filebeat.yml',
                                                   self.install_directory)

        # Overwrite with dynamite default configurations
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/filebeat/module/', self.install_directory)
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/filebeat/modules.d/',
                                                   self.install_directory)
        filebeat_config = config.ConfigManager(self.install_directory, verbose=self.verbose, stdout=self.stdout)
        if target_type == 'elasticsearch':
            filebeat_config.switch_to_elasticsearch_target()
            filebeat_config.elasticsearch_targets.target_strings = targets
            self.logger.info(f'Enabling Elasticsearch connector: '
                             f'{filebeat_config.elasticsearch_targets.target_strings}')
        elif target_type == 'logstash':
            filebeat_config.switch_to_logstash_target()
            filebeat_config.logstash_targets.target_strings = targets
        elif target_type == 'kafka':
            filebeat_config.switch_to_kafka_target()
            filebeat_config.kafka_targets.target_strings = targets
        elif target_type == 'redis':
            filebeat_config.switch_to_redis_target()
            filebeat_config.redis_targets.target_strings = targets
        filebeat_config.input_logs = misc_filebeat_objs.InputLogs(
            monitor_log_paths=[]
        )
        filebeat_config.field_processors.originating_agent_tag = agent_tag
        if not monitor_log_paths:
            environ = utilities.get_environment_file_dict()
            zeek_log_root = f'{environ.get("ZEEK_HOME", "")}/logs/current/'
            suricata_log_root = environ.get('SURICATA_LOGS', '')
            zeek_profiler = zeek_profile.ProcessProfiler()
            suricata_profiler = suricata_profile.ProcessProfiler()
            if zeek_profiler.is_installed():
                self.logger.info(f'Zeek installation found; monitoring: {zeek_log_root}*.log')
                filebeat_config.input_logs.monitor_log_paths.append(f'{zeek_log_root}*.log')
            if suricata_profiler.is_installed():
                self.logger.info(f'Suricata installation found; monitoring: {suricata_log_root}/eve.json')
                filebeat_config.input_logs.monitor_log_paths.append(f'{suricata_log_root}/eve.json')
        else:
            filebeat_config.input_logs = misc_filebeat_objs.InputLogs(
                monitor_log_paths=monitor_log_paths
            )
        self.logger.info(f'Monitoring Paths = {filebeat_config.input_logs.monitor_log_paths}')

        if not agent_tag:
            filebeat_config.field_processors.originating_agent_tag = utilities.get_default_agent_tag()
        self.logger.info(f'Agent Tag = {filebeat_config.field_processors.originating_agent_tag}')
        self.logger.debug(filebeat_config.elasticsearch_targets.get_raw())
        filebeat_config.commit()
        self.logger.info('Applying configuration.')
        # Fix Permissions
        self.logger.info('Installing modules.')
        filebeat_config.patch_modules(zeek_log_directory=zeek_log_root, suricata_log_directory=suricata_log_root)

        # Setting up permissions
        self.logger.info('Setting up file permissions.')
        config_file = f'{self.install_directory}/filebeat.yml'
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_permissions_of_file(f'{self.install_directory}/modules.d/',
                                          unix_permissions_integer='go-w')
        utilities.set_permissions_of_file(f'{self.install_directory}/module/', unix_permissions_integer='go-w')
        utilities.set_ownership_of_file(config_file, user='dynamite', group='dynamite')
        utilities.set_permissions_of_file(config_file, unix_permissions_integer=660)
        filebeat_config.enable_ecs_normalization()

        # Install and enable service
        self.logger.info(f'Installing service -> {const.DEFAULT_CONFIGS}/systemd/filebeat.service')
        sysctl.install_and_enable(f'{const.DEFAULT_CONFIGS}/systemd/filebeat.service')

        # Update environment file
        self.create_update_filebeat_environment_variables()


class UninstallManager(install.BaseUninstallManager):
    """
    Manage Filebeat uninstall process
    """

    def __init__(self, stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        """Uninstall Filebeat
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
        """
        from dynamite_nsm.services.filebeat.process import ProcessManager

        env_vars = utilities.get_environment_file_dict()
        fb_directories = [env_vars.get('FILEBEAT_HOME'), ]
        super().__init__('filebeat.uninstall', directories=fb_directories,
                         process=ProcessManager(stdout=stdout, verbose=verbose), sysctl_service_name='filebeat.service',
                         environ_vars=['FILEBEAT_HOME'], stdout=stdout, verbose=verbose)


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=f'{const.INSTALL_PATH}/filebeat',
        download_filebeat_archive=True,
        stdout=True,
        verbose=True
    )
    install_mngr.setup(targets=[f'https://{utilities.get_primary_ip_address()}:9200'])
