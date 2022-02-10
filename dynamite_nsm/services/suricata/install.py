import os
import random
import time
import subprocess
from typing import List, Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.services.base.config_objects.suricata import misc
from dynamite_nsm.services.base import install, systemctl
from dynamite_nsm.services.suricata import config
from dynamite_nsm.services.suricata.tasks import set_caps

COMPILE_PROCESS_EXPECTED_LINE_COUNT = 935


def post_install_bootstrap_updater(suricata_install_directory: str, stdout: Optional[bool] = False,
                                   verbose: Optional[bool] = False) -> None:
    """Perform Suricata rule setup and updating with Oinkmaster
    Args:
        suricata_install_directory: The location of the suricata root install directory (E.G /opt/dynamite/suricata)
        stdout: Print the output to console
        verbose: Include detailed debug messages
    Returns:
        None
    """
    from dynamite_nsm.services.suricata import oinkmaster as suricata_rule_updater
    from dynamite_nsm.services.suricata.oinkmaster import install as suricata_rule_updater_install
    suricata_rule_updater_install.InstallManager(
        install_directory=f'{suricata_install_directory}/rule_updater',
        download_oinkmaster_archive=True,
        stdout=stdout,
        verbose=verbose
    ).setup()
    suricata_rule_updater.update_suricata_rules()


class InstallManager(install.BaseInstallManager):
    """
    Manage Suricata installation process
    """

    def __init__(self, configuration_directory: str, install_directory: str, log_directory: str,
                 download_suricata_archive: Optional[bool] = True, skip_interface_validation: Optional[bool] = False,
                 stdout: Optional[bool] = False, verbose: Optional[bool] = False):
        """Install Suricata
        Args:
            configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
            install_directory: Path to the install directory (E.G /opt/dynamite/suricata/)
            log_directory: Path to the log directory (E.G /var/log/dynamite/suricata/)
            download_suricata_archive: If True, download the Suricata archive from a mirror
            skip_interface_validation: If included we don't check if the interface is available on the system
            stdout: Print the output to console
            verbose: Include detailed debug messages
        """
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.download_suricata_archive = download_suricata_archive
        self.skip_interface_validation = skip_interface_validation
        self.stdout = stdout
        self.verbose = verbose
        install.BaseInstallManager.__init__(self, 'suricata.install', verbose=self.verbose, stdout=stdout)
        if download_suricata_archive:
            self.logger.info("Attempting to download Suricata archive.")
            _, archive_name, self.local_mirror_root = self.download_from_mirror(const.SURICATA_MIRRORS)
            self.logger.info(f'Attempting to extract Suricata archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.local_mirror_root = self.get_mirror_info(const.SURICATA_MIRRORS)

    def configure_compile_suricata(self, parallel_threads: Optional[int] = None) -> None:
        """Configure and build Suricata from source
        Args:
            parallel_threads: Number of parallel threads to use during the compiling process
        Returns:
            None
        """
        suricata_source_install_cache = os.path.join(const.INSTALL_CACHE, self.local_mirror_root)
        suricata_config_parent_directory = '/'.join(self.configuration_directory.split('/')[:-1])
        if self.configuration_directory.endswith('/'):
            suricata_config_parent_directory = '/'.join(self.configuration_directory.split('/')[:-2])

        configure_args = [f'--prefix={self.install_directory}',
                          f'--sysconfdir={suricata_config_parent_directory} ',
                          f'--localstatedir={const.STATE_PATH}/suricata']
        self.logger.debug(f'Configuring with: {configure_args}')
        self.configure_source_package(suricata_source_install_cache, configure_args=configure_args)
        time.sleep(1)
        self.compile_source_package(suricata_source_install_cache,
                                    parallel_threads=parallel_threads,
                                    expected_lines_printed=COMPILE_PROCESS_EXPECTED_LINE_COUNT)

    def create_update_suricata_environment_variables(self) -> None:
        """Creates all the required Suricata environmental variables

        Returns:
            None
        """
        self.create_update_env_variable('SURICATA_HOME', self.install_directory)
        self.create_update_env_variable('SURICATA_CONFIG', self.configuration_directory)
        self.create_update_env_variable('SURICATA_LOGS', self.log_directory)

    def install_suricata_dependencies(self) -> None:
        """Install Suricata dependencies

        Returns:
            None
        """
        apt_get_packages = ['automake', 'bison', 'cargo', 'cmake', 'flex', 'g++', 'gcc', 'libcap-ng-dev',
                            'libjansson-dev', 'libjemalloc-dev', 'liblz4-dev', 'libmagic-dev', 'libnspr4-dev',
                            'libnss3-dev', 'libpcap-dev', 'libpcre3-dev', 'libtool', 'libyaml-dev', 'make',
                            'pkg-config', 'rustc', 'tar', 'wget', 'zlib1g-dev']

        yum_packages = ['automake', 'bison', 'cargo', 'cmake', 'file-devel', 'flex', 'gcc', 'gcc-c++', 'jansson-devel',
                        'jemalloc-devel', 'libcap-ng-devel', 'libpcap-devel', 'libtool', 'libyaml-devel', 'lz4-devel',
                        'make', 'nspr-devel', 'nss-devel', 'pcre-devel', 'pkgconfig', 'rustc', 'tar',
                        'wget', 'zlib-devel']

        def install_powertools_rhel(pacman_type):
            """Install Zeek dependencies (And PowerTools repo if on redhat based distro)
            Args:

            Returns:
                None
            """
            if pacman_type != 'yum':
                self.logger.info('Skipping RHEL PowerTools install, as it is not needed on this distribution.')
                return
            self.install_dependencies(yum_packages=['dnf-plugins-core', 'epel-release'])
            enable_powertools_p = subprocess.Popen(['yum', 'config-manager', '--set-enabled', 'powertools'],
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            enable_powertools_p.communicate()
            if enable_powertools_p.returncode == 0:
                self.logger.info("Installed PowerTools.")

        super(InstallManager, self).install_dependencies(apt_get_packages=apt_get_packages, yum_packages=yum_packages,
                                                         pre_install_function=install_powertools_rhel)

    def copy_suricata_files_and_directories(self) -> None:
        """Copy the required Suricata files from the install cache to their respective directories
        Returns:
            None
        """
        suricata_tarball_extracted = f'{const.INSTALL_CACHE}/{self.local_mirror_root}'
        config_paths = [
            'reference.config',
            'threshold.config',
            'rules/'
        ]
        for conf in config_paths:
            self.copy_file_or_directory_to_destination(f'{suricata_tarball_extracted}/{conf}',
                                                       self.configuration_directory)

    def setup(self, inspect_interfaces: List[str]):
        """Install Suricata
        Args:
            inspect_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
        Returns:
            None
        """
        if not self.skip_interface_validation:
            if not self.validate_inspect_interfaces(inspect_interfaces):
                raise install.NetworkInterfaceNotFound(inspect_interfaces)
        sysctl = systemctl.SystemCtl()
        self.install_suricata_dependencies()
        self.create_update_suricata_environment_variables()
        self.logger.debug(f'Creating directory: {self.configuration_directory}')
        utilities.makedirs(self.configuration_directory)
        self.logger.debug(f'Creating directory: {self.install_directory}')
        utilities.makedirs(self.install_directory)
        self.logger.debug(f'Creating directory: {self.log_directory}')
        utilities.makedirs(self.log_directory)
        self.copy_suricata_files_and_directories()
        self.logger.info('Setting up Suricata from source. This can take a few minutes.')
        if self.stdout:
            utilities.print_coffee_art()
        self.configure_compile_suricata()

        self.copy_file_or_directory_to_destination(
            f'{const.DEFAULT_CONFIGS}/suricata/suricata.yaml',
            self.configuration_directory
        )

        suricata_config = config.ConfigManager(self.configuration_directory, stdout=self.stdout, verbose=self.verbose)
        suricata_config.default_log_directory = self.log_directory
        suricata_config.suricata_log_output_file = os.path.join(self.log_directory, 'suricata.log')
        suricata_config.default_rules_directory = os.path.join(self.configuration_directory, 'rules')
        suricata_config.reference_config_file = os.path.join(self.configuration_directory, 'reference.config')
        suricata_config.classification_file = os.path.join(self.configuration_directory, 'rules',
                                                           'classification.config')
        suricata_config.af_packet_interfaces = misc.AfPacketInterfaces()
        for interface in inspect_interfaces:
            suricata_config.af_packet_interfaces.add(
                misc.AfPacketInterface(
                    interface_name=interface, threads='auto', cluster_id=random.randint(1, 50000),
                    cluster_type='cluster_qm'
                )
            )

        suricata_config.threading = suricata_config.get_optimal_suricata_threading_config(
            tuple([i for i in range(0, utilities.get_cpu_core_count() - 1)]))

        suricata_config.commit()
        self.logger.info('Applying Suricata configuration.')
        self.logger.debug(suricata_config.af_packet_interfaces)
        suricata_config.commit()

        # Fix Permissions
        self.logger.info('Setting up file permissions.')
        utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')
        utilities.set_permissions_of_file(f'{self.configuration_directory}/suricata.yaml', 660)
        post_install_bootstrap_updater(self.install_directory, stdout=self.stdout, verbose=self.verbose)

        self.logger.info('Setting up Suricata capture rules for dynamite user.')
        set_caps.SetCapturePermissions(self.install_directory).invoke(shell=True)

        self.logger.info(f'Installing service -> {const.DEFAULT_CONFIGS}/systemd/suricata.service')
        sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'suricata.service'))


class UninstallManager(install.BaseUninstallManager):
    """
    Uninstall Suricata process manager
    """

    def __init__(self, purge_config: Optional[bool] = True, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """Uninstall Suricata
        Args:
            purge_config: If enabled, remove all the configuration files associated with this installation
            stdout: Print output to console
            verbose: Include detailed debug messages
        Returns:
            None
        """
        from dynamite_nsm.services.suricata.process import ProcessManager

        env_vars = utilities.get_environment_file_dict()
        suricata_directories = [env_vars.get('SURICATA_HOME'), env_vars.get('SURICATA_LOGS')]
        if purge_config:
            suricata_directories.append(env_vars.get('SURICATA_CONFIG'))
        super().__init__('suricata.uninstall', directories=suricata_directories, sysctl_service_name='suricata.service',
                         environ_vars=['SURICATA_HOME', 'SURICATA_CONFIG', 'SURICATA_LOGS', 'OINKMASTER_HOME'],
                         process=ProcessManager(stdout=stdout, verbose=verbose), stdout=stdout, verbose=verbose)


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=f'{const.INSTALL_PATH}/suricata',
        configuration_directory=f'{const.CONFIG_PATH}/suricata',
        log_directory=f'{const.INSTALL_PATH}/suricata/logs',
        download_suricata_archive=False,
        stdout=True,
        verbose=False
    )
    install_mngr.setup([utilities.get_network_interface_names()[0]])
