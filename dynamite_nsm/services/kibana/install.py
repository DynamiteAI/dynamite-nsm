import os
from typing import List, Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.services.base import install, systemctl
from dynamite_nsm.services.kibana import config
from dynamite_nsm.services.kibana.tasks import install_dynamite_base_views


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory: str, install_directory: str, log_directory: str,
                 download_kibana_archive: Optional[bool] = True, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """Install Kibana
        Args:
            configuration_directory: Path to the configuration directory (E.G /etc/dynamite/kibana/)
            install_directory: Path to the install directory (E.G /opt/dynamite/kibana/)
            log_directory: Path to the log directory (E.G /var/log/dynamite/kibana/)
            download_kibana_archive: If True, download the Kibana archive from a mirror
            stdout: Print output to console
            verbose: Include detailed debug messages
        """
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.stdout = stdout
        self.verbose = verbose
        super().__init__('kibana.install', verbose, stdout)
        if download_kibana_archive:
            self.logger.info("Attempting to download Kibana (OpenDistro) archive.")
            _, archive_name, self.local_mirror_root = self.download_from_mirror(const.KIBANA_MIRRORS)
            self.logger.info(f'Attempting to extract Kibana archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.local_mirror_root = self.get_mirror_info(const.KIBANA_MIRRORS)

    def copy_kibana_files_and_directories(self) -> None:
        """Copy the required Kibana files from the install cache to their respective directories

        Returns:
            None
        """
        kibana_tarball_extracted = f'{const.INSTALL_CACHE}/{self.local_mirror_root}'
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
        """Creates all the required Kibana environmental variables

        Returns:
            None
        """
        self.create_update_env_variable('KIBANA_PATH_CONF', self.configuration_directory)
        self.create_update_env_variable('KIBANA_HOME', self.install_directory)
        self.create_update_env_variable('KIBANA_LOGS', self.log_directory)

    def setup(self, host: Optional[str] = None, port: Optional[int] = None,
              elasticsearch_targets: Optional[List[str]] = None) -> None:
        """Setup Kibana
        Args:
            host: The IP or hostname to listen on
            port: The port to listen on
            elasticsearch_targets: A list of Elasticsearch urls
        Returns:
            None
        """

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
        self.logger.info('Applying configuration.')
        kb_main_config.commit()

        # Fix Permissions
        utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')

        # Install and enable service
        self.logger.info(f'Installing service -> {const.DEFAULT_CONFIGS}/systemd/kibana.service')
        sysctl.install_and_enable(f'{const.DEFAULT_CONFIGS}/systemd/kibana.service')

        self.logger.info('Installing "BaseViews" Kibana package')
        task = install_dynamite_base_views.InstallKibanaDynamiteBaseViewsPackage(username='admin',
                                                                                 password='admin',
                                                                                 target=f"http://{host}:{port}")
        task.download_and_install()


class UninstallManager(install.BaseUninstallManager):

    def __init__(self, purge_config: Optional[bool] = True, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """Uninstall Kibana
        Args:
            purge_config: If enabled, remove all the configuration files associated with this installation
            stdout: Print output to console
            verbose: Include detailed debug messages
        Returns:
            None
        """
        from dynamite_nsm.services.kibana.process import ProcessManager

        env_vars = utilities.get_environment_file_dict()
        kb_directories = [env_vars.get('KIBANA_HOME'), env_vars.get('KIBANA_LOGS')]
        if purge_config:
            kb_directories.append(env_vars.get('KIBANA_PATH_CONF'))
        super().__init__('kibana.uninstall', directories=kb_directories,
                         process=ProcessManager(stdout=stdout, verbose=verbose), sysctl_service_name='kibana.service',
                         environ_vars=['KIBANA_HOME', 'KIBANA_LOGS', 'KIBANA_PATH_CONF'],
                         stdout=stdout, verbose=verbose)


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
