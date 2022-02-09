import os
import shutil
import subprocess
import time
from typing import List, Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.services.zeek import config
from dynamite_nsm.exceptions import InstallError
from dynamite_nsm.services.zeek import package, zkg
from dynamite_nsm.services.zeek.tasks import set_caps
from dynamite_nsm.services.zeek.zkg import install as zkg_install
from dynamite_nsm.services.base.config_objects.zeek import node
from dynamite_nsm.services.base import install, systemctl

COMPILE_PROCESS_EXPECTED_LINE_COUNT = 7392


class InstallManager(install.BaseInstallManager):
    """
    Manage Zeek installation process
    """

    def __init__(self, configuration_directory: str, install_directory: str,
                 download_zeek_archive: Optional[bool] = True, skip_interface_validation: Optional[bool] = False,
                 stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """Install Zeek
        Args:
            configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek/)
            install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
            download_zeek_archive: If True, download the Zeek archive from a mirror
            skip_interface_validation: If included we don't check if the interface is available on the system
            stdout: Print output to console
            verbose: Include detailed debug messages
        """
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.skip_interface_validation = skip_interface_validation
        self.stdout = stdout
        self.verbose = verbose

        super(InstallManager, self).__init__(name='zeek.install', verbose=verbose, stdout=stdout)

        if not shutil.which('python3-config'):
            raise InstallError(
                'Python3 development bindings must be installed for Zeek installation to fully succeed. '
                'Common Packages: "python3-dev" (Debian based) "python3-devel" (RHEL based)')

        if download_zeek_archive:
            self.logger.info("Attempting to download Zeek archive.")
            _, archive_name, self.local_mirror_root = self.download_from_mirror(const.ZEEK_MIRRORS)
            self.logger.info(f'Attempting to extract Zeek archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.local_mirror_root = self.get_mirror_info(const.ZEEK_MIRRORS)

    def configure_compile_zeek(self, parallel_threads: Optional[int] = None) -> None:
        """Configure and build Zeek from source
        Args:
            parallel_threads: Number of parallel threads to use during the compiling process
        Returns:
            None
        """
        zeek_source_install_cache = os.path.join(const.INSTALL_CACHE, self.local_mirror_root)
        configure_args = [f'--prefix={self.install_directory}', f'--scriptdir={self.configuration_directory}',
                          '--enable-jemalloc', '--with-python=/usr/bin/python3']
        self.configure_source_package(zeek_source_install_cache, configure_args=configure_args)
        time.sleep(1)
        self.compile_source_package(zeek_source_install_cache,
                                    parallel_threads=parallel_threads,
                                    expected_lines_printed=COMPILE_PROCESS_EXPECTED_LINE_COUNT)

    def create_update_zeek_environment_variables(self) -> None:
        """Creates all the required Zeek environmental variables
        Args:

        Returns:
            None
        """
        self.create_update_env_variable('ZEEK_HOME', self.install_directory)
        self.create_update_env_variable('ZEEK_SCRIPTS', self.configuration_directory)

    def install_zeek_dependencies(self) -> None:
        """Install Zeek dependencies (And PowerTools repo if on redhat based distro)
        Args:

        Returns:
            None
        """

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

        apt_get_packages = \
            ['bison', 'cmake', 'cmake3', 'flex', 'g++', 'gcc', 'libjemalloc-dev', 'libpcap-dev', 'libssl-dev',
             'linux-headers-$(uname -r)', 'linux-headers-generic', 'make', 'swig', 'tar', 'sqlite3', 'zlib1g-dev']

        yum_packages = \
            ['bison', 'cmake', 'cmake3', 'flex', 'gcc', 'gcc-c++', 'jemalloc-devel', 'kernel-devel', 'libpcap-devel',
             'make', 'openssl-devel', 'swig', 'tar', 'sqlite-devel', 'zlib-devel']

        self.install_dependencies(apt_get_packages=apt_get_packages, yum_packages=yum_packages,
                                  pre_install_function=install_powertools_rhel)

    def setup(self, inspect_interfaces: List[str]):
        """Setup Zeek
        Args:
            inspect_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
        Returns:
            None
        """
        if not self.skip_interface_validation:
            if not self.validate_inspect_interfaces(inspect_interfaces):
                raise install.NetworkInterfaceNotFound(inspect_interfaces)
        sysctl = systemctl.SystemCtl()
        self.install_zeek_dependencies()
        self.create_update_zeek_environment_variables()
        self.logger.debug(f'Creating directory: {self.configuration_directory}')
        utilities.makedirs(self.configuration_directory)
        self.logger.debug(f'Creating directory: {self.install_directory}')
        utilities.makedirs(self.install_directory)
        self.logger.info('Setting up Zeek from source. This can take up to 15 minutes.')
        if self.stdout:
            utilities.print_coffee_art()
        self.configure_compile_zeek()
        self.logger.info('Setting up Zeek package manager.')
        zkg_installer = zkg_install.InstallManager()
        zkg_installer.setup()
        try:
            package.InstallPackageManager(const.ZEEK_PACKAGES, stdout=self.stdout, verbose=self.verbose).setup()
        except zkg.InstallZeekPackageError as e:
            self.logger.error(f'An error occurred while installing one or more Zeek packages: {e}')

        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/zeek/broctl-nodes.cfg',
                                                   f'{self.install_directory}/etc/node.cfg')
        self.copy_file_or_directory_to_destination(f'{const.DEFAULT_CONFIGS}/zeek/local.zeek',
                                                   f'{self.configuration_directory}/site/local.zeek')

        # Optimize Configurations
        node_config = config.NodeConfigManager(self.install_directory, stdout=self.stdout, verbose=self.verbose)
        node_config.workers = node.Workers()
        for worker in node_config.get_optimal_zeek_worker_config(inspect_interfaces):
            node_config.workers.add_worker(
                worker=worker
            )
        self.logger.info('Applying node configuration.')
        node_config.commit()

        self.logger.info('Setting up BPF input configuration')
        with open(f'{self.configuration_directory}/bpf_map_file.input', 'w') as bpf_config_f:
            bpf_config_f.write('')

        # Fix Permissions
        self.logger.info('Setting up file permissions.')
        utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
        utilities.set_permissions_of_file(f'{self.configuration_directory}/site/local.zeek', 660)
        utilities.set_permissions_of_file(f'{self.configuration_directory}/site/bpf_map_file.input', 660)
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_permissions_of_file(f'{self.install_directory}/etc/node.cfg', 660)
        utilities.set_permissions_of_file(f'{self.install_directory}/etc/networks.cfg', 660)
        utilities.set_permissions_of_file(f'{self.install_directory}/etc/networks.cfg', 660)
        self.logger.info('Setting up Zeek capture rules for dynamite user.')
        set_caps.SetCapturePermissions(self.install_directory).invoke(shell=True)

        self.logger.info(f'Installing service -> {const.DEFAULT_CONFIGS}/systemd/zeek.service')
        sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'zeek.service'))


class UninstallManager(install.BaseUninstallManager):
    """
    Manage Zeek uninstallation process
    """

    def __init__(self, purge_config: Optional[bool] = True, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """Uninstall Zeek
        Args:
            purge_config: If enabled, remove all the configuration files associated with this installation
            stdout: Print output to console
            verbose: Include detailed debug messages
        """

        from dynamite_nsm.services.zeek.process import ProcessManager

        env_vars = utilities.get_environment_file_dict()
        zeek_directories = [env_vars.get('ZEEK_HOME')]
        if purge_config:
            zeek_directories.append(env_vars.get('ZEEK_SCRIPTS'))
        super().__init__('zeek.uninstall', directories=zeek_directories, sysctl_service_name='zeek.service',
                         environ_vars=['ZEEK_HOME', 'ZEEK_SCRIPTS'],
                         process=ProcessManager(stdout=stdout, verbose=verbose), stdout=stdout, verbose=verbose)


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=f'{const.INSTALL_PATH}/zeek',
        configuration_directory=f'{const.CONFIG_PATH}/zeek',
        download_zeek_archive=False,
        stdout=True,
        verbose=True
    )
    install_mngr.setup(utilities.get_network_interface_names())
