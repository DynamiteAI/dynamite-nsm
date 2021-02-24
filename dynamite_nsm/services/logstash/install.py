import os
from typing import Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.services.logstash import config
from dynamite_nsm.services.base import install, systemctl


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory: str, install_directory: str, log_directory: str,
                 download_logstash_archive: Optional[bool] = True, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/logstash/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/logstash/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/logstash/)
        :param download_logstash_archive: If True, download the Logstash archive from a mirror
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.stdout = stdout
        self.verbose = verbose
        super().__init__('logstash', verbose, stdout)
        if download_logstash_archive:
            self.logger.info("Attempting to download Logstash (OSS) archive.")
            _, archive_name, self.directory_name = self.download_from_mirror(const.LOGSTASH_MIRRORS, stdout=stdout,
                                                                             verbose=verbose)
            self.logger.info(f'Attempting to extract Logstash archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.directory_name = self.get_mirror_info(const.LOGSTASH_MIRRORS)

    def copy_logstash_files_and_directories(self) -> None:
        """
        Copy the required Logstash files from the install cache to their respective directories
        """
        elasticsearch_tarball_extracted = f'{const.INSTALL_CACHE}/{self.directory_name}'
        config_paths = [
            'config/logstash.yml',
            'config/pipelines.yml',
            'config/jvm.options',
            'config/log4j2.properties'
        ]
        install_paths = [
            'Gemfile',
            'Gemfile.lock',
            'bin/',
            'data/',
            'lib/',
            'logstash-core/',
            'logstash-core-plugin-api/',
            'modules/',
            'tools/',
            'vendor/',
        ]
        for conf in config_paths:
            self.copy_file_or_directory_to_destination(f'{elasticsearch_tarball_extracted}/{conf}',
                                                       self.configuration_directory)
        for inst in install_paths:
            self.copy_file_or_directory_to_destination(f'{elasticsearch_tarball_extracted}/{inst}',
                                                       self.install_directory)

    def create_update_logstash_environment_variables(self) -> None:
        """
        Creates all the required Logstash environmental variables
        """
        self.create_update_env_variable('LS_PATH_CONF', self.configuration_directory)
        self.create_update_env_variable('LS_HOME', self.install_directory)
        self.create_update_env_variable('LS_LOGS', self.log_directory)

    def setup(self, node_name: Optional[str] = None, host: Optional[str] = None,
              elasticsearch_host: Optional[str] = None, elasticsearch_port: Optional[str] = None,
              pipeline_batch_size: Optional[int] = None, pipeline_batch_delay: Optional[int] = None,
              heap_size_gigs: Optional[int] = None):

        sysctl = systemctl.SystemCtl()

        # System patching and directory setup
        utilities.update_sysctl()
        utilities.update_user_file_handle_limits()
        utilities.makedirs(self.configuration_directory)
        utilities.makedirs(self.install_directory)
        utilities.makedirs(self.log_directory)

        self.copy_logstash_files_and_directories()
        self.create_update_logstash_environment_variables()

        # Overwrite with dynamite default configurations
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/logstash/logstash.yml',
                                                   self.configuration_directory)
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/logstash/jvm.options',
                                                   self.configuration_directory)

        # Optimize Configurations
        ls_main_config = config.ConfigManager(self.configuration_directory)
        ls_java_config = config.JavaHeapOptionsConfigManager(self.configuration_directory)
        ls_main_config.path_logs = self.log_directory
        if not node_name:
            node_name = utilities.get_default_es_node_name().replace('es_node', 'ls_node')
        if not host:
            host = utilities.get_primary_ip_address()
        if not elasticsearch_host:
            elasticsearch_host = utilities.get_primary_ip_address()
        if not elasticsearch_port:
            elasticsearch_port = 9200
        if not pipeline_batch_size:
            pipeline_batch_size = 125
        if not pipeline_batch_delay:
            pipeline_batch_delay = 50
        if not heap_size_gigs:
            heap_size_gigs = int((utilities.get_memory_available_bytes() / 10 ** 9) / 2)

        ls_main_config.node_name = node_name
        ls_main_config.host = host
        ls_main_config.pipeline_batch_size = pipeline_batch_size
        ls_main_config.pipeline_batch_delay = pipeline_batch_delay
        self.create_update_env_variable('LS_ES_HOST', elasticsearch_host)
        self.create_update_env_variable('LS_ES_PORT', elasticsearch_port)
        ls_java_config.initial_memory = f'{heap_size_gigs}g'
        ls_java_config.maximum_memory = f'{heap_size_gigs}g'
        ls_main_config.commit()
        ls_java_config.commit()

        # Fix Permissions
        utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')

        # Install and enable service
        sysctl.install_and_enable(f'{const.DEFAULT_CONFIGS}/systemd/logstash.service')


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=f'{const.INSTALL_PATH}/logstash',
        configuration_directory=f'{const.CONFIG_PATH}/logstash',
        log_directory=f'{const.LOG_PATH}/logstash',
        download_logstash_archive=True,
        stdout=True,
        verbose=True
    )
    install_mngr.setup()