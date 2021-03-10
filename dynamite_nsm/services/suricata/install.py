import os
import time
import random
from typing import List, Optional

from dynamite_nsm import const, utilities
from dynamite_nsm.services.base import install, systemctl
from dynamite_nsm.services.suricata import config
from dynamite_nsm.service_objects.suricata import misc

COMPILE_PROCESS_EXPECTED_LINE_COUNT = 935


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory: str, install_directory: str, log_directory: str,
                 download_suricata_archive: Optional[bool] = True, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):
        """
        Install Suricata

        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/suricata/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/suricata/)
        :param download_suricata_archive: If True, download the Suricata archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """
        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.download_suricata_archive = download_suricata_archive
        self.stdout = stdout
        self.verbose = verbose
        install.BaseInstallManager.__init__(self, 'suricata', verbose=self.verbose, stdout=stdout)
        if download_suricata_archive:
            self.logger.info("Attempting to download Suricata archive.")
            _, archive_name, self.local_mirror_root = self.download_from_mirror(const.SURICATA_MIRRORS)
            self.logger.info(f'Attempting to extract Suricata archive ({archive_name}).')
            self.extract_archive(os.path.join(const.INSTALL_CACHE, archive_name))
            self.logger.info("Extraction completed.")
        else:
            _, _, self.local_mirror_root = self.get_mirror_info(const.SURICATA_MIRRORS)

    def configure_compile_suricata(self, parallel_threads: Optional[int] = None) -> None:
        """
        Configure and build Suricata from source

        :param parallel_threads: Number of parallel threads to use during the compiling process
        """
        suricata_source_install_cache = os.path.join(const.INSTALL_CACHE, self.local_mirror_root)
        suricata_config_parent_directory = '/'.join(self.configuration_directory.split('/')[:-1])
        if self.configuration_directory.endswith('/'):
            suricata_config_parent_directory = '/'.join(self.configuration_directory.split('/')[:-2])

        configure_args = [f'--prefix={self.install_directory}',
                          f'--sysconfdir={suricata_config_parent_directory} ',
                          f'--localstatedir={const.STATE_PATH}/suricata']
        self.configure_source_package(suricata_source_install_cache, configure_args=configure_args)
        time.sleep(1)
        self.compile_source_package(suricata_source_install_cache,
                                    parallel_threads=parallel_threads,
                                    expected_lines_printed=COMPILE_PROCESS_EXPECTED_LINE_COUNT)

    def create_update_suricata_environment_variables(self) -> None:
        """
        Creates all the required Suricata environmental variables
        """
        self.create_update_env_variable('SURICATA_HOME', self.install_directory)
        self.create_update_env_variable('SURICATA_CONFIG', self.configuration_directory)
        self.create_update_env_variable('SURICATA_LOGS', self.configuration_directory)

    def install_suricata_dependencies(self) -> None:
        """
        Install Suricata dependencies
        """
        apt_get_packages = ['automake', 'bison', 'cargo', 'cmake', 'flex', 'g++', 'gcc', 'libcap-ng-dev',
                            'libjansson-dev', 'libjemalloc-dev', 'liblz4-dev', 'libmagic-dev', 'libnspr4-dev',
                            'libnss3-dev', 'libpcap-dev', 'libpcre3-dev', 'libtool', 'libyaml-dev', 'make',
                            'pkg-config', 'python-pip', 'rustc', 'tar', 'wget', 'wireshark', 'zlib1g-dev']

        yum_packages = ['automake', 'bison', 'cargo', 'cmake', 'file-devel', 'flex', 'gcc', 'gcc-c++', 'jansson-devel',
                        'jemalloc-devel', 'libcap-ng-devel', 'libpcap-devel', 'libtool', 'libyaml-devel', 'lz4-devel',
                        'make', 'nspr-devel', 'nss-devel', 'pcre-devel', 'pkgconfig', 'python3-pip', 'rustc', 'tar',
                        'wget', 'wireshark', 'zlib-devel']

        super(InstallManager, self).install_dependencies(apt_get_packages=apt_get_packages, yum_packages=yum_packages)

    def setup(self, capture_network_interfaces: Optional[List[str]] = None):
        """
        Install Suricata

        :param capture_network_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
        """
        if not capture_network_interfaces:
            capture_network_interfaces = utilities.get_network_interface_names()
        if not self.validate_capture_network_interfaces(capture_network_interfaces):
            raise install.NetworkInterfaceNotFound(capture_network_interfaces)
        sysctl = systemctl.SystemCtl()
        self.install_suricata_dependencies()
        self.create_update_suricata_environment_variables()
        self.logger.debug(f'Creating directory: {self.configuration_directory}')
        utilities.makedirs(self.configuration_directory)
        self.logger.debug(f'Creating directory: {self.install_directory}')
        utilities.makedirs(self.install_directory)
        self.logger.debug(f'Creating directory: {self.log_directory}')
        utilities.makedirs(self.log_directory)
        self.logger.info('Setting up Suricata from source. This can a few minutes.')
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
        for interface in capture_network_interfaces:
            suricata_config.af_packet_interfaces.add(
                misc.AfPacketInterface(
                    interface_name=interface, threads='auto', cluster_id=random.randint(1, 50000),
                    cluster_type='cluster_flow'
                )
            )
        suricata_config.commit()
        self.logger.info('Applying Suricata configuration.')
        self.logger.debug(suricata_config.af_packet_interfaces)
        suricata_config.commit()

        # Fix Permissions
        self.logger.info('Setting up file permissions.')
        utilities.set_ownership_of_file(self.configuration_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.install_directory, user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(self.log_directory, user='dynamite', group='dynamite')

        self.logger.info(f'Installing service -> {const.DEFAULT_CONFIGS}/systemd/suricata.service')
        sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'suricata.service'))


if __name__ == '__main__':
    install_mngr = InstallManager(
        install_directory=f'{const.INSTALL_PATH}/suricata',
        configuration_directory=f'{const.CONFIG_PATH}/suricata',
        log_directory=f'{const.INSTALL_PATH}/suricata/logs',
        download_suricata_archive=True,
        stdout=True,
        verbose=False
    )
    install_mngr.setup()
