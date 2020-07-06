import os
import sys
import time
import shutil
import logging
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.suricata import config as suricata_configs
from dynamite_nsm.services.suricata import process as suricata_process
from dynamite_nsm.services.suricata import profile as suricata_profile
from dynamite_nsm.services.suricata import exceptions as suricata_exceptions
from dynamite_nsm.services.suricata.oinkmaster import install as rules_install
from dynamite_nsm.services.suricata.oinkmaster import exceptions as oinkmaster_exceptions


class InstallManager:

    def __init__(self, configuration_directory, install_directory, log_directory, capture_network_interfaces,
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

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('SURICATA', level=log_level, stdout=stdout)

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.capture_network_interfaces = capture_network_interfaces
        self.download_suricata_archive = download_suricata_archive
        self.stdout = stdout
        self.verbose = verbose
        utilities.create_dynamite_environment_file()
        if download_suricata_archive:
            try:
                self.logger.info("Attempting to download Suricata archive.")
                self.download_suricata(stdout=stdout)
            except general_exceptions.DownloadError as e:
                self.logger.error("Failed to download Suricata archive.")
                self.logger.debug("Failed to download Suricata archive, threw: {}.".format(e))
                raise suricata_exceptions.InstallSuricataError("Failed to download Suricata archive.")
        try:
            self.logger.info("Attempting to extract Suricata archive ({}).".format(const.SURICATA_ARCHIVE_NAME))
            self.extract_suricata()
            self.logger.info("Extraction completed.")
        except general_exceptions.ArchiveExtractionError as e:
            self.logger.error("Failed to extract Suricata archive.")
            self.logger.debug("Failed to extract Suricata archive, threw: {}.".format(e))
            raise suricata_exceptions.InstallSuricataError("Failed to extract Suricata archive")
        try:
            self.install_dependencies(stdout=stdout, verbose=verbose)
        except (general_exceptions.InvalidOsPackageManagerDetectedError,
                general_exceptions.OsPackageManagerRefreshError):
            raise suricata_exceptions.InstallSuricataError("One or more OS dependencies failed to install.")
        if not self.validate_capture_network_interfaces(self.capture_network_interfaces):
            self.logger.error(
                "One or more defined network interfaces is invalid: {}".format(capture_network_interfaces))
            raise suricata_exceptions.InstallSuricataError(
                "One or more defined network interfaces is invalid: {}".format(capture_network_interfaces))

    def _configure_and_compile_suricata(self):
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
        try:
            suricata_config_p.communicate()
        except Exception as e:
            self.logger.error("General error occurred while configuring Suricata.")
            self.logger.debug("General error occurred while configuring Suricata; {}".format(e))
            raise suricata_exceptions.InstallSuricataError(
                "General error occurred while configuring Suricata; {}".format(e))
        if suricata_config_p.returncode != 0:
            self.logger.error(
                "Zeek configuration process returned non-zero; exit-code: {}".format(suricata_config_p.returncode))
            raise suricata_exceptions.InstallSuricataError(
                "Suricata configuration process returned non-zero; exit-code: {}".format(suricata_config_p.returncode))
        time.sleep(1)
        self.logger.info("Compiling Suricata.")
        if utilities.get_cpu_core_count() > 1:
            parallel_threads = utilities.get_cpu_core_count() - 1
        else:
            parallel_threads = 1
        if self.verbose:
            compile_suricata_process = subprocess.Popen(
                'make -g {}; make install; make install-conf'.format(parallel_threads), shell=True,
                cwd=os.path.join(const.INSTALL_CACHE,
                                 const.SURICATA_DIRECTORY_NAME))
            try:
                compile_suricata_process.communicate()
            except Exception as e:
                self.logger.error("General error occurred while compiling Suricata.")
                self.logger.debug("General error occurred while compiling Suricata; {}".format(e))
                raise suricata_exceptions.InstallSuricataError(
                    "General error occurred while compiling Suricata; {}".format(e))
            compile_suricata_return_code = compile_suricata_process.returncode
        else:
            compile_suricata_process = subprocess.Popen(
                'make -g {}; make install; make install-conf'.format(parallel_threads), shell=True,
                cwd=os.path.join(const.INSTALL_CACHE,
                                 const.SURICATA_DIRECTORY_NAME),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                compile_suricata_return_code = utilities.run_subprocess_with_status(compile_suricata_process,
                                                                                    expected_lines=935)
            except Exception as e:
                self.logger.error("General error occurred while compiling Suricata.")
                self.logger.debug("General error occurred while compiling Suricata; {}".format(e))
                raise suricata_exceptions.InstallSuricataError(
                    "General error occurred while compiling Suricata; {}".format(e))
        if compile_suricata_return_code != 0:
            self.logger.error(
                "Failed to compile Suricata from source; error code: {}; run with --verbose flag for more info.".format(
                    compile_suricata_return_code))
            raise suricata_exceptions.InstallSuricataError(
                "Suricata compilation process returned non-zero; exit-code: {}".format(compile_suricata_return_code))

    def _copy_suricata_files_and_directories(self):
        self.logger.info('Creating Suricata installation, configuration, and logging directories.')
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
            utilities.makedirs(self.log_directory, exist_ok=True)
        except Exception as e:
            self.logger.error('Failed to create required directory structure.')
            self.logger.debug("Failed to create required directory structure; {}".format(e))
            raise suricata_exceptions.InstallSuricataError(
                "Failed to create required directory structure; {}".format(e))
        try:
            utilities.makedirs(os.path.join(self.configuration_directory, 'rules'), exist_ok=True)
        except Exception as e:
            self.logger.error('Unable to re-create Suricata rules directory.')
            self.logger.debug('Unable to re-create Suricata rules directory: {}'.format(e))
        try:
            shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'suricata', 'suricata.yaml'),
                        os.path.join(self.configuration_directory, 'suricata.yaml'))
        except Exception as e:
            self.logger.error("General error while attempting to copy {} to {}.".format(
                os.path.join(const.DEFAULT_CONFIGS, 'suricata', 'suricata.yaml'), self.configuration_directory))

            self.logger.debug("General error while attempting to copy {} to {}; {}".format(
                os.path.join(const.DEFAULT_CONFIGS, 'suricata', 'suricata.yaml'), self.configuration_directory, e))

            raise suricata_exceptions.InstallSuricataError(
                "General error while attempting to copy {} to {}; {}".format(
                    os.path.join(const.DEFAULT_CONFIGS, 'suricata', 'suricata.yaml'), self.configuration_directory, e))
        try:
            utilities.copytree(os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME, 'rules'),
                               os.path.join(self.configuration_directory, 'rules'))
        except Exception as e:
            self.logger.error("General error while attempting to copy {} to {}.".format(
                os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME, 'rules'),
                os.path.join(self.configuration_directory, 'rules')))

            self.logger.debug("General error while attempting to copy {} to {}; {}".format(
                os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME, 'rules'),
                os.path.join(self.configuration_directory, 'rules'), e))

            raise suricata_exceptions.InstallSuricataError(
                "General error while attempting to copy {} to {}; {}".format(
                    os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME, 'rules'),
                    os.path.join(self.configuration_directory, 'rules'), e))

    @staticmethod
    def download_suricata(stdout=False):
        """
        Download Suricata archive

        :param stdout: Print output to console
        """
        url = None
        try:
            with open(const.SURICATA_MIRRORS, 'r') as suricata_archive:
                for url in suricata_archive.readlines():
                    if utilities.download_file(url, const.SURICATA_ARCHIVE_NAME, stdout=stdout):
                        break
        except Exception as e:
            raise general_exceptions.DownloadError(
                "General error while downloading Suricata from {}; {}".format(url, e))

    @staticmethod
    def extract_suricata():
        """
        Extract Suricata to local install_cache
        """

        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.SURICATA_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract Suricata archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract Suricata archive; {}".format(e))

    @staticmethod
    def install_dependencies(stdout=False, verbose=False):
        """
        Install the required dependencies required by Suricata

        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('SURICATA', level=log_level, stdout=stdout)
        logger.info('Installing Dependencies.')

        pkt_mng = package_manager.OSPackageManager(stdout=stdout, verbose=verbose)

        packages = None
        if pkt_mng.package_manager == 'apt-get':
            packages = ['cmake', 'make', 'gcc', 'g++', 'flex', 'bison', 'libtool', 'automake', 'pkg-config',
                        'libpcre3-dev', 'libpcap-dev', 'libyaml-dev', 'libjansson-dev', 'rustc', 'cargo', 'python-pip',
                        'wireshark', 'zlib1g-dev', 'libcap-ng-dev', 'libnspr4-dev', 'libnss3-dev', 'libmagic-dev',
                        'liblz4-dev', 'tar', 'wget']
        elif pkt_mng.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libtool', 'automake', 'pkgconfig',
                        'pcre-devel', 'libpcap-devel', 'libyaml-devel', 'jansson-devel', 'rustc', 'cargo', 'python-pip',
                        'wireshark', 'zlib-devel', 'libcap-ng-devel', 'nspr-devel', 'nss-devel', 'file-devel',
                        'lz4-devel', 'tar', 'wget']
        logger.info('Refreshing Package Index.')
        try:
            pkt_mng.refresh_package_indexes()
        except general_exceptions.OsPackageManagerRefreshError as e:
            logger.warning("Failed to refresh packages.")
            logger.debug("Failed to refresh packages threw: {}".format(e))
            raise general_exceptions.OsPackageManagerRefreshError('Failed to refresh packages.')
        logger.info('Installing the following packages: {}.'.format(packages))
        try:
            pkt_mng.install_packages(packages)
        except general_exceptions.OsPackageManagerInstallError as e:
            logger.warning("Failed to install one or more packages: {}".format(e))

    @staticmethod
    def validate_capture_network_interfaces(network_interfaces):
        for interface in network_interfaces:
            if interface not in utilities.get_network_interface_names():
                return False
        return True

    def setup_suricata_rules(self):
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
        config.default_rules_directory = os.path.join(self.configuration_directory, 'rules')
        config.reference_config_file = os.path.join(self.configuration_directory, 'reference.config')
        config.classification_file = os.path.join(self.configuration_directory, 'rules', 'classification.config')

        # Disable Unneeded Suricata rules
        try:
            self.logger.debug("Disabling Suricata Rule: 'http-events.rules'")
            config.disable_rule('http-events.rules')

            self.logger.debug("Disabling Suricata Rule: 'smtp-events.rules'")
            config.disable_rule('smtp-events.rules')

            self.logger.debug("Disabling Suricata Rule: 'dns-events.rules'")
            config.disable_rule('dns-events.rules')

            self.logger.debug("Disabling Suricata Rule: 'tls-events.rules'")
            config.disable_rule('tls-events.rules')

            self.logger.debug("Disabling Suricata Rule: 'drop.rules'")
            config.disable_rule('drop.rules')

            self.logger.debug("Disabling Suricata Rule: 'emerging-p2p.rules'")
            config.disable_rule('emerging-p2p.rules')

            self.logger.debug("Disabling Suricata Rule: 'emerging-pop3.rules'")
            config.disable_rule('emerging-pop3.rules')

            self.logger.debug("Disabling Suricata Rule: 'emerging-telnet.rules'")
            config.disable_rule('emerging-telnet.rules')

            self.logger.debug("Disabling Suricata Rule: 'http-events.rules'")
            config.disable_rule('emerging-tftp.rules')

            self.logger.debug("Disabling Suricata Rule: 'emerging-voip.rules'")
            config.disable_rule('emerging-voip.rules')

        except suricata_exceptions.SuricataRuleNotFoundError:
            self.logger.error('Could not disable one or more Suricata rules.')
            raise suricata_exceptions.InstallSuricataError("Could not disable one or more Suricata rules.")
        try:
            config.write_config()
        except suricata_exceptions.WriteSuricataConfigError:
            self.logger.error('Could not write Suricata configurations.')
            suricata_exceptions.InstallSuricataError("Could not write Suricata configurations.")

    def setup_suricata(self):
        """
        Setup Suricata IDS with PF_RING support
        """
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self._copy_suricata_files_and_directories()
        self._configure_and_compile_suricata()
        try:
            with open(env_file) as env_f:
                if 'SURICATA_HOME' not in env_f.read():
                    self.logger.info('Updating Suricata default home path [{}]'.format(self.install_directory))
                    subprocess.call('echo SURICATA_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
                if 'SURICATA_CONFIG' not in env_f.read():
                    self.logger.info('Updating Suricata default config path [{}]'.format(self.configuration_directory))
                    subprocess.call('echo SURICATA_CONFIG="{}" >> {}'.format(
                        self.configuration_directory, env_file), shell=True)
        except IOError:
            self.logger.error("Failed to open {} for reading.".format(env_file))
            raise suricata_exceptions.InstallSuricataError(
                "Failed to open {} for reading.".format(env_file))
        except Exception as e:
            self.logger.error("General error while creating environment variables in {}.".format(env_file))
            self.logger.debug("General error while creating environment variables in {}; {}".format(env_file, e))
            raise suricata_exceptions.InstallSuricataError(
                "General error while creating environment variables in {}; {}".format(env_file, e))
        try:
            config = suricata_configs.ConfigManager(self.configuration_directory)
        except suricata_exceptions.ReadsSuricataConfigError:
            self.logger.error("Failed to read Suricata configuration.")
            raise suricata_exceptions.InstallSuricataError("Failed to read Suricata configuration.")
        config.af_packet_interfaces = []
        for interface in self.capture_network_interfaces:
            config.add_afpacket_interface(interface, threads='auto', cluster_id=99)
        try:
            config.write_config()
        except suricata_exceptions.WriteSuricataConfigError:
            self.logger.error("Failed to write Suricata configuration.")
            suricata_exceptions.InstallSuricataError("Could not write Suricata configurations.")
        try:
            sysctl = systemctl.SystemCtl()
        except general_exceptions.CallProcessError:
            raise suricata_exceptions.InstallSuricataError("Could not find systemctl.")
        self.logger.info("Installing Suricata systemd Service.")
        if not sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'suricata.service')):
            raise suricata_exceptions.InstallSuricataError("Failed to install Suricata systemd service.")


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
    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('SURICATA', level=log_level, stdout=stdout)
    suricata_profiler = suricata_profile.ProcessProfiler()
    if suricata_profiler.is_installed:
        logger.error("Suricata is already installed.")
        raise suricata_exceptions.AlreadyInstalledSuricataError()
    suricata_installer = InstallManager(configuration_directory, install_directory, log_directory,
                                        capture_network_interfaces=capture_network_interfaces,
                                        download_suricata_archive=download_suricata_archive, stdout=stdout,
                                        verbose=verbose)
    suricata_installer.setup_suricata()
    suricata_installer.setup_suricata_rules()


def uninstall_suricata(prompt_user=True, stdout=True, verbose=False):
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
    suricata_profiler = suricata_profile.ProcessProfiler()
    if not suricata_profiler.is_installed:
        logger.error("Suricata is not installed. Cannot uninstall.")
        raise suricata_exceptions.UninstallSuricataError("Suricata is not installed.")
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
    if suricata_profiler.is_running:
        try:
            suricata_process.stop()
        except suricata_exceptions.CallSuricataProcessError as e:
            logger.error("Could not kill Suricata process. Cannot uninstall.")
            logger.debug("Could not kill Suricata process. Cannot uninstall; {}".format(e))
            raise suricata_exceptions.UninstallSuricataError("Could not kill Suricata process.")
    try:
        with open(env_file) as env_fr:
            env_lines = ''
            for line in env_fr.readlines():
                if 'SURICATA_HOME' in line:
                    continue
                elif 'SURICATA_CONFIG' in line:
                    continue
                elif 'OINKMASTER_HOME' in line:
                    continue
                elif line.strip() == '':
                    continue
                env_lines += line.strip() + '\n'
        with open(env_file, 'w') as env_fw:
            env_fw.write(env_lines)
        if suricata_profiler.is_installed:
            shutil.rmtree(environment_variables.get('SURICATA_HOME'), ignore_errors=True)
            shutil.rmtree(environment_variables.get('SURICATA_CONFIG'), ignore_errors=True)
            shutil.rmtree(environment_variables.get('OINKMASTER_HOME'), ignore_errors=True)
    except Exception as e:
        logger.error("General error occurred while attempting to uninstall Suricata.")
        logger.debug("General error occurred while attempting to uninstall Suricata; {}".format(e))
        raise suricata_exceptions.UninstallSuricataError(
            "General error occurred while attempting to uninstall Suricata; {}".format(e))
    try:
        sysctl = systemctl.SystemCtl()
    except general_exceptions.CallProcessError:
        raise suricata_exceptions.UninstallSuricataError("Could not find systemctl.")
    sysctl.uninstall_and_disable('suricata')
