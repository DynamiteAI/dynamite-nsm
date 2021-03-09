import os
from typing import List, Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.services.kibana import config
from dynamite_nsm.services.base import install, systemctl


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory: str, install_directory: str, log_directory: str,
                 download_kibana_archive: Optional[bool] = True, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/kibana/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/kibana/)
        :param download_kibana_archive: If True, download the Kibana archive from a mirror
        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        """
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.stdout = stdout
        self.verbose = verbose
        super().__init__('kibana', verbose, stdout)
        if download_kibana_archive:
            self.logger.info("Attempting to download Kibana (OpenDistro) archive.")
            _, archive_name, self.directory_name = self.download_from_mirror(const.KIBANA_MIRRORS, stdout=stdout,
                                                                             verbose=verbose)
            self.logger.info(f'Attempting to extract Kibana archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.directory_name = self.get_mirror_info(const.KIBANA_MIRRORS)

    def copy_kibana_files_and_directories(self) -> None:
        """
        Copy the required Kibana files from the install cache to their respective directories
        """
        kibana_tarball_extracted = f'{const.INSTALL_CACHE}/{self.directory_name}'
        config_paths = [
            'config/kibana.yml',
            'config/node.options'
        ]
        install_paths = [
            'bin/',
            'data/',
            'node/',
            'node_modules/',
            'plugins/',
            'src/',
            'package.json'
        ]
        for conf in config_paths:
            self.copy_file_or_directory_to_destination(f'{kibana_tarball_extracted}/{conf}',
                                                       self.configuration_directory)
        for inst in install_paths:
            self.copy_file_or_directory_to_destination(f'{kibana_tarball_extracted}/{inst}', self.install_directory)

    def create_update_kibana_environment_variables(self) -> None:
        """
        Creates all the required Kibana environmental variables
        """
        self.create_update_env_variable('KIBANA_PATH_CONF', self.configuration_directory)
        self.create_update_env_variable('KIBANA_HOME', self.install_directory)
        self.create_update_env_variable('KIBANA_LOGS', self.log_directory)

    def setup(self, host: Optional[str] = None, port: Optional[int] = None,
              elasticsearch_targets: Optional[List[str]] = None):

        sysctl = systemctl.SystemCtl()

        # Directory setup
        self.logger.debug(f'Creating directory: {self.configuration_directory}')
        utilities.makedirs(self.configuration_directory)
        self.logger.debug(f'Creating directory: {self.install_directory}')
        utilities.makedirs(self.install_directory)
        self.logger.debug(f'Creating directory: {self.log_directory}')
        utilities.makedirs(self.log_directory)
        self.copy_kibana_files_and_directories()
        self.create_update_kibana_environment_variables()
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/kibana/kibana.yml',
                                                   self.configuration_directory)

        # Optimize Configurations
        kb_main_config = config.ConfigManager(self.configuration_directory)
        if not host:
            host = utilities.get_primary_ip_address()
        if not port:
            port = 5601
        if not elasticsearch_targets:
            elasticsearch_targets = [f'https://{utilities.get_primary_ip_address()}:9200']
        self.logger.debug(f'Elasticsearch Targets = {elasticsearch_targets}')
        kb_main_config.host = host
        kb_main_config.port = port
        self.logger.debug(f'Kibana will listen on {kb_main_config.host}:{kb_main_config.port}')
        kb_main_config.elasticsearch_targets = elasticsearch_targets
        kb_main_config.commit()
        self.logger.info('Applying configuration.')

        # Fix Permissions
        utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')

        # Install and enable service
        self.logger.debug(f'Installing service -> {const.DEFAULT_CONFIGS}/systemd/kibana.service')
        sysctl.install_and_enable(f'{const.DEFAULT_CONFIGS}/systemd/kibana.service')


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=f'{const.INSTALL_PATH}/kibana',
        configuration_directory=f'{const.CONFIG_PATH}/kibana',
        log_directory=f'{const.LOG_PATH}/kibana',
        download_kibana_archive=True,
        stdout=True,
        verbose=True
    )
    install_mngr.setup()
