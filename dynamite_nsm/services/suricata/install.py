import logging
import os
import random
import shutil
import subprocess
import sys
import time
from typing import List, Optional

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.service_objects.suricata import misc as suricata_misc
from dynamite_nsm.services.base import install
from dynamite_nsm.services.base import systemctl
from dynamite_nsm.services.suricata import config as suricata_configs
from dynamite_nsm.services.suricata import exceptions as suricata_exceptions
from dynamite_nsm.services.suricata.oinkmaster import exceptions as oinkmaster_exceptions
from dynamite_nsm.services.suricata.oinkmaster import install as rules_install


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory: str, install_directory: str, log_directory: str,
                 capture_network_interfaces: List, download_suricata_archive: Optional[bool] = True,
                 stdout: Optional[bool] = True, verbose: Optional[bool] = False):
        """
        Install Suricata
        
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/suricata/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/suricata/)
        :param capture_network_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
        :param download_suricata_archive: If True, download the Suricata archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.capture_network_interfaces = capture_network_interfaces
        self.download_suricata_archive = download_suricata_archive
        self.stdout = stdout
        self.verbose = verbose
        install.BaseInstallManager.__init__(self, 'suricata', verbose=self.verbose, stdout=stdout)

        utilities.create_dynamite_environment_file()
        if download_suricata_archive:
            self.logger.info("Attempting to download Suricata archive.")
            self.download_from_mirror(const.SURICATA_MIRRORS, const.SURICATA_ARCHIVE_NAME, stdout=stdout,
                                      verbose=verbose)
        self.logger.info("Attempting to extract Suricata archive ({}).".format(const.SURICATA_ARCHIVE_NAME))
        self.extract_archive(os.path.join(const.INSTALL_CACHE, const.SURICATA_ARCHIVE_NAME))
        self.logger.info("Extraction completed.")
        self.install_suricata_dependencies()

    def _configure_and_compile_suricata(self) -> None:
        if self.configuration_directory.endswith('/'):
            suricata_config_parent = '/'.join(self.configuration_directory.split('/')[:-2])
        else:
            suricata_config_parent = '/'.join(self.configuration_directory.split('/')[:-1])
        self.logger.info('Compiling Suricata from source. This can take up to 5 to 10 minutes.')
        if self.stdout:
            utilities.print_coffee_art()
        time.sleep(1)
        self.logger.info('Configuring Suricata.')
        if self.verbose:
            suricata_config_p = subprocess.Popen(
                './configure --prefix={} --sysconfdir={} --localstatedir=/var/dynamite/suricata'.format(
                    self.install_directory, suricata_config_parent), shell=True,
                cwd=os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME))
        else:
            suricata_config_p = subprocess.Popen(
                './configure --prefix={} --sysconfdir={} --localstatedir=/var/dynamite/suricata'.format(
                    self.install_directory, suricata_config_parent),
                shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        suricata_config_p.communicate()
        time.sleep(1)
        self.logger.info("Compiling Suricata.")
        if utilities.get_cpu_core_count() > 1:
            parallel_threads = utilities.get_cpu_core_count() - 1
        else:
            parallel_threads = 1
        if self.verbose:
            compile_suricata_process = subprocess.Popen(
                'make -j {}; make install; make install-conf'.format(parallel_threads), shell=True,
                cwd=os.path.join(const.INSTALL_CACHE,
                                 const.SURICATA_DIRECTORY_NAME))
            compile_suricata_process.communicate()
        else:
            compile_suricata_process = subprocess.Popen(
                'make -j {}; make install; make install-conf'.format(parallel_threads), shell=True,
                cwd=os.path.join(const.INSTALL_CACHE,
                                 const.SURICATA_DIRECTORY_NAME),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            utilities.run_subprocess_with_status(compile_suricata_process, expected_lines=935)

    def _copy_suricata_files_and_directories(self) -> None:

        self.logger.info(f'Creating Suricata installation directory -> {self.install_directory}')
        utilities.makedirs(self.install_directory, exist_ok=True)
        self.logger.info(f'Creating Suricata configuration directory -> {self.configuration_directory}')
        utilities.makedirs(self.configuration_directory, exist_ok=True)
        self.logger.info(f'Creating Suricata log directory -> {self.log_directory}')
        utilities.makedirs(self.log_directory, exist_ok=True)

        utilities.makedirs(os.path.join(self.configuration_directory, 'rules'), exist_ok=True)
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'suricata', 'suricata.yaml'),
                    os.path.join(self.configuration_directory, 'suricata.yaml'))
        utilities.copytree(os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME, 'rules'),
                           os.path.join(self.configuration_directory, 'rules'))

    def install_suricata_dependencies(self) -> None:

        apt_get_packages = \
            ['cmake', 'make', 'gcc', 'g++', 'flex', 'bison', 'libtool', 'automake', 'pkg-config',
             'libpcre3-dev', 'libpcap-dev', 'libyaml-dev', 'libjansson-dev', 'rustc', 'cargo',
             'python-pip',
             'wireshark', 'zlib1g-dev', 'libcap-ng-dev', 'libnspr4-dev', 'libnss3-dev', 'libmagic-dev',
             'liblz4-dev', 'tar', 'wget', 'libjemalloc-dev']

        yum_packages = \
            ['cmake', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libtool', 'automake', 'pkgconfig',
             'pcre-devel', 'libpcap-devel', 'libyaml-devel', 'jansson-devel', 'rustc', 'cargo',
             'python3-pip', 'wireshark', 'zlib-devel', 'libcap-ng-devel', 'nspr-devel', 'nss-devel',
             'file-devel', 'lz4-devel', 'tar', 'wget', 'jemalloc-devel']
        super(InstallManager, self).install_dependencies(apt_get_packages=apt_get_packages, yum_packages=yum_packages)

    @staticmethod
    def validate_capture_network_interfaces(network_interfaces) -> bool:
        for interface in network_interfaces:
            if interface not in utilities.get_network_interface_names():
                return False
        return True

    def setup_suricata_rules(self) -> None:
        """
        Installs Oinkmaster, sets up rules, and disables unneeded rule sets.
        """
        self.logger.info("Installing Suricata Rules (via Oinkmaster).")
        oink_installer = rules_install.InstallManager(
            download_oinkmaster_archive=True,
            stdout=self.stdout,
            verbose=self.verbose,
            install_directory=os.path.join(self.install_directory, 'oinkmaster')
        )
        try:
            oink_installer.setup_oinkmaster()
        except oinkmaster_exceptions.InstallOinkmasterError as e:
            self.logger.error("Unable to install Oinkmaster dependency.")
            self.logger.debug("Unable to install Oinkmaster dependency; {}".format(e))
            raise suricata_exceptions.InstallSuricataError("Unable to install Oinkmaster dependency.")

        try:
            self.logger.info("Updating Suricata Rules (via Oinkmaster)")
            rules_install.update_suricata_rules()
        except oinkmaster_exceptions.UpdateSuricataRulesError as e:
            self.logger.error("Unable to update Suricata rule-sets.")
            self.logger.debug("Unable to update Suricata rule-sets; {}".format(e))
            raise suricata_exceptions.InstallSuricataError("Unable to update Suricata rule-sets.")
        try:
            config = suricata_configs.ConfigManager(self.configuration_directory)
        except suricata_exceptions.ReadsSuricataConfigError:
            self.logger.error("Failed to read Suricata configuration.")
            raise suricata_exceptions.InstallSuricataError("Failed to read Suricata configuration.")
        config.default_log_directory = self.log_directory
        config.suricata_log_output_file = os.path.join(self.log_directory, 'suricata.log')
        config.default_rules_directory = os.path.join(self.configuration_directory, 'rules')
        config.reference_config_file = os.path.join(self.configuration_directory, 'reference.config')
        config.classification_file = os.path.join(self.configuration_directory, 'rules', 'classification.config')

        self.logger.debug("Disabling Suricata Rule: 'http-events.rules'")
        config.rules['http-events.rules'].enabled = False

        self.logger.debug("Disabling Suricata Rule: 'smtp-events.rules'")
        config.rules['smtp-events.rules'].enabled = False

        self.logger.debug("Disabling Suricata Rule: 'dns-events.rules'")
        config.rules['dns-events.rules'].enabled = False

        self.logger.debug("Disabling Suricata Rule: 'tls-events.rules'")
        config.rules['tls-events.rules'].enabled = False

        self.logger.debug("Disabling Suricata Rule: 'drop.rules'")
        config.rules['drop.rules'].enabled = False

        self.logger.debug("Disabling Suricata Rule: 'emerging-p2p.rules'")
        config.rules['emerging-p2p.rules'].enabled = False

        self.logger.debug("Disabling Suricata Rule: 'emerging-pop3.rules'")
        config.rules['emerging-pop3.rules'].enabled = False

        self.logger.debug("Disabling Suricata Rule: 'emerging-telnet.rules'")
        config.rules['emerging-telnet.rules'].enabled = False

        self.logger.debug("Disabling Suricata Rule: 'http-events.rules'")
        config.rules['emerging-tftp.rules'].enabled = False

        self.logger.debug("Disabling Suricata Rule: 'emerging-voip.rules'")
        config.rules['emerging-voip.rules'].enabled = False

        config.commit()

    def setup_suricata(self) -> None:
        """
        Setup Suricata IDS with AF_PACKET support
        """
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self._copy_suricata_files_and_directories()
        self._configure_and_compile_suricata()
        with open(env_file) as env_f:
            if 'SURICATA_HOME' not in env_f.read():
                self.logger.info('Updating Suricata default home path [{}]'.format(self.install_directory))
                subprocess.call('echo SURICATA_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                shell=True)
            if 'SURICATA_CONFIG' not in env_f.read():
                self.logger.info('Updating Suricata default config path [{}]'.format(self.configuration_directory))
                subprocess.call('echo SURICATA_CONFIG="{}" >> {}'.format(
                    self.configuration_directory, env_file), shell=True)
            if 'SURICATA_LOGS' not in env_f.read():
                self.logger.info('Updating Suricata default logs path [{}]'.format(self.log_directory))
                subprocess.call('echo SURICATA_LOGS="{}" >> {}'.format(
                    self.log_directory, env_file), shell=True)
        config = suricata_configs.ConfigManager(self.configuration_directory)
        config.af_packet_interfaces = suricata_misc.AfPacketInterfaces()
        for interface in self.capture_network_interfaces:
            config.af_packet_interfaces.add(
                suricata_misc.AfPacketInterface(
                    interface_name=interface, threads='auto', cluster_id=random.randint(1, 50000),
                    cluster_type='cluster_flow'
                )
            )
        config.commit()
        sysctl = systemctl.SystemCtl()
        self.logger.info("Installing Suricata systemd Service.")
        sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'suricata.service'))


def install_suricata(configuration_directory, install_directory, log_directory, capture_network_interfaces,
                     download_suricata_archive=True, stdout=True, verbose=False):
    """
    Install Suricata

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
    :param install_directory: Path to the install directory (E.G /opt/dynamite/suricata/)
    :param log_directory: Path to the log directory (E.G /var/log/dynamite/suricata/)
    :param capture_network_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
    :param download_suricata_archive: If True, download the Suricata archive from a mirror
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """
    suricata_installer = InstallManager(configuration_directory, install_directory, log_directory,
                                        capture_network_interfaces=capture_network_interfaces,
                                        download_suricata_archive=download_suricata_archive, stdout=stdout,
                                        verbose=verbose)
    suricata_installer.setup_suricata()
    suricata_installer.setup_suricata_rules()


def uninstall_suricata(prompt_user: Optional[bool] = True, stdout: Optional[bool] = True,
                       verbose: Optional[bool] = False) -> None:
    """
    Uninstall Suricata

    :param prompt_user: Print a warning before continuing
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('SURICATA', level=log_level, stdout=stdout)
    logger.info("Uninstalling Suricata.")

    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    if prompt_user:
        sys.stderr.write(
            '\n\033[93m[-] WARNING! Removing Suricata Will Remove Critical Agent Functionality.\033[0m\n')
        resp = utilities.prompt_input('\n\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\n\033[93m[?] Are you sure you wish to continue? ([no]|yes):\033[0m ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)

    with open(env_file) as env_fr:
        env_lines = ''
        for line in env_fr.readlines():
            if 'SURICATA_HOME' in line:
                continue
            elif 'SURICATA_CONFIG' in line:
                continue
            elif 'SURICATA_LOGS' in line:
                continue
            elif 'OINKMASTER_HOME' in line:
                continue
            elif line.strip() == '':
                continue
            env_lines += line.strip() + '\n'
    with open(env_file, 'w') as env_fw:
        env_fw.write(env_lines)

    shutil.rmtree(environment_variables.get('SURICATA_HOME'), ignore_errors=True)
    shutil.rmtree(environment_variables.get('SURICATA_CONFIG'), ignore_errors=True)
    shutil.rmtree(environment_variables.get('OINKMASTER_HOME'), ignore_errors=True)

    sysctl = systemctl.SystemCtl()
    sysctl.stop('suricata')
    sysctl.uninstall_and_disable('suricata')
