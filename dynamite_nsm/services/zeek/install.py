import os
import sys
import time
import shutil
import logging
import subprocess
from typing import List, Optional

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.base import install
from dynamite_nsm.services.base import systemctl
from dynamite_nsm.service_objects.zeek import node
from dynamite_nsm.services.zeek import config as zeek_configs


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory: str, install_directory: str, capture_network_interfaces: List[str],
                 download_zeek_archive: Optional[bool] = True, stdout: Optional[bool] = True,
                 verbose: Optional[bool] = False):
        """
        Install Zeek

        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        :param capture_network_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
        :param download_zeek_archive: If True, download the Zeek archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('ZEEK', level=log_level, stdout=stdout)

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.capture_network_interfaces = capture_network_interfaces
        self.stdout = stdout
        self.verbose = verbose
        install.BaseInstallManager.__init__(self, 'zeek', verbose=self.verbose, stdout=stdout)
        utilities.create_dynamite_environment_file()
        if download_zeek_archive:
            self.download_from_mirror(const.ZEEK_MIRRORS, const.ZEEK_ARCHIVE_NAME, stdout=stdout, verbose=verbose)
        self.logger.info(f'Attempting to extract Zeek archive ({const.ZEEK_ARCHIVE_NAME}).')
        self.extract_archive(f'{const.INSTALL_CACHE}/{const.ZEEK_ARCHIVE_NAME}')
        self.install_dependencies(stdout=stdout, verbose=verbose)

    @staticmethod
    def install_dependencies(stdout: Optional[bool] = True, verbose: Optional[bool] = False) -> None:
        """
        Install the required dependencies required by Zeek

        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('ZEEK', level=log_level, stdout=stdout)
        logger.info('Installing Dependencies.')
        pkt_mng = package_manager.OSPackageManager(stdout=stdout, verbose=verbose)
        packages = None
        if pkt_mng.package_manager == 'apt-get':
            packages = ['cmake', 'cmake3', 'make', 'gcc', 'g++', 'flex', 'bison', 'libpcap-dev', 'libssl-dev',
                        'python-dev', 'swig', 'zlib1g-dev', 'linux-headers-$(uname -r)', 'linux-headers-generic', 'tar',
                        'libjemalloc-dev']
        elif pkt_mng.package_manager == 'yum':

            packages = ['cmake', 'cmake3', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libpcap-devel',
                        'openssl-devel', 'python3-devel', 'python2-devel', 'swig', 'zlib-devel',
                        'kernel-devel', 'tar', 'jemalloc-devel']

            pkt_mng.install_packages(['dnf-plugins-core'])
            enable_powertools_p = subprocess.Popen(['yum', 'config-manager', '--set-enabled', 'PowerTools'],
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            enable_powertools_p.communicate()

            if enable_powertools_p.returncode == 0:
                logger.info("Installed PowerTools.")
        logger.info('Refreshing Package Index.')
        pkt_mng.refresh_package_indexes()
        logger.info('Installing the following packages: {}.'.format(packages))

    @staticmethod
    def validate_capture_network_interfaces(network_interfaces: List[str]) -> bool:
        for interface in network_interfaces:
            if interface not in utilities.get_network_interface_names():
                return False
        return True

    def setup_zeek_af_packet_plugin(self) -> None:
        """
        Configure and compile AF_PACKET plugin
        """

        bro_af_packet_plugin_path = f'{const.DEFAULT_CONFIGS}/zeek/uncompiled_scripts/zeek-af_packet-plugin'
        self.logger.info('Configuring Zeek_AF_Packet plugin.')
        if self.verbose:
            config_zeek_af_packet_process = subprocess.Popen(
                './configure --zeek-dist={} --install-root={} --with-latest-kernel'.format(
                    os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), self.configuration_directory),
                shell=True, cwd=bro_af_packet_plugin_path
            )
        else:
            config_zeek_af_packet_process = subprocess.Popen(
                './configure --zeek-dist={} --install-root={} --with-latest-kernel'.format(
                    os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), self.configuration_directory),
                shell=True, cwd=bro_af_packet_plugin_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

        config_zeek_af_packet_process.communicate()
        self.logger.info('Compiling Zeek Zeek_AF_Packet plugin.')
        if utilities.get_cpu_core_count() > 1:
            parallel_threads = utilities.get_cpu_core_count() - 1
        else:
            parallel_threads = 1
        if self.verbose:
            compile_zeek_af_packet_process = subprocess.Popen('make -j {}; make install'.format(parallel_threads),
                                                              shell=True,
                                                              cwd=bro_af_packet_plugin_path)
        else:
            compile_zeek_af_packet_process = subprocess.Popen('make -j {}; make install'.format(parallel_threads),
                                                              shell=True,
                                                              cwd=bro_af_packet_plugin_path,
                                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        compile_zeek_af_packet_process.communicate()

        shutil.copytree(f'{self.configuration_directory}/Zeek_AF_Packet',
                        f'{self.install_directory}/lib/zeek/plugins/Zeek_AF_Packet')

    def setup_zeek_community_id_plugin(self) -> None:
        """
        Configure and compile Dynamite patched community_id plugin.
        """
        bro_commmunity_id_plugin_path = f'{const.DEFAULT_CONFIGS}/zeek/uncompiled_scripts/zeek-community-id'
        self.logger.info('Configuring Zeek Corelight_CommunityID plugin.')
        if self.verbose:
            config_zeek_community_id_script_process = subprocess.Popen(
                './configure --zeek-dist={} --install-root={}'.format(
                    os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), self.configuration_directory),
                shell=True, cwd=bro_commmunity_id_plugin_path
            )
        else:
            config_zeek_community_id_script_process = subprocess.Popen(
                './configure --zeek-dist={} --install-root={}'.format(
                    os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), self.configuration_directory),
                shell=True, cwd=bro_commmunity_id_plugin_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        config_zeek_community_id_script_process.communicate()
        self.logger.info('Compiling Zeek Corelight_CommunityID [PATCHED] plugin.')
        if utilities.get_cpu_core_count() > 1:
            parallel_threads = utilities.get_cpu_core_count() - 1
        else:
            parallel_threads = 1
        if self.verbose:
            compile_zeek_community_id_script_process = subprocess.Popen(
                'make -j {}; make install'.format(parallel_threads), shell=True,
                cwd=bro_commmunity_id_plugin_path)
        else:
            compile_zeek_community_id_script_process = subprocess.Popen(
                'make -j {}; make install'.format(parallel_threads), shell=True,
                cwd=bro_commmunity_id_plugin_path,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        compile_zeek_community_id_script_process.communicate()
        shutil.copytree(f'{self.configuration_directory}/Corelight_CommunityID',
                        f'{self.install_directory}/lib/zeek/plugins/Corelight_CommunityID')

    def setup_dynamite_zeek_scripts(self) -> None:
        """
        Installs and enables extra dynamite Zeek scripts
        """

        scripts = ''
        redefs = ''
        self.logger.info('Setting up Zeek scripts.')
        install_cache_extra_scripts_path = f'{const.DEFAULT_CONFIGS}/zeek/dynamite_extra_scripts'
        destination_extra_scripts_path = f'{self.configuration_directory}/dynamite_extra_scripts'
        utilities.makedirs(destination_extra_scripts_path, exist_ok=True)
        self.logger.info(
            f'Copying configurations from {install_cache_extra_scripts_path} to {destination_extra_scripts_path}')
        utilities.copytree(install_cache_extra_scripts_path, destination_extra_scripts_path)

        destination_zeek_site_local_path = f'{self.configuration_directory}/site/local.zeek'

        with open(destination_zeek_site_local_path, 'r') as rf:
            for line in rf.readlines():
                if '@load' in line:
                    scripts += line.strip() + '\n'
                elif 'redef' in line:
                    redefs += line.strip() + '\n'

        with open(destination_zeek_site_local_path, 'w') as wf:
            wf.write(scripts)
            for script_dir in os.listdir(destination_extra_scripts_path):
                wf.write('@load {}\n'.format(os.path.join(destination_extra_scripts_path, script_dir)))
            wf.write(redefs)

        self.setup_zeek_af_packet_plugin()
        self.setup_zeek_community_id_plugin()
        self.logger.info('Disabling unneeded Zeek scripts.')

        # Disable Unneeded Zeek scripts
        script_config = zeek_configs.SiteLocalConfigManager(self.configuration_directory)
        self.logger.debug('Disabling Zeek Script: protocols/ftp/detect')
        script_config.scripts['protocols/ftp/detect'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ftp/software')
        script_config.scripts['protocols/ftp/software'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ftp/detect-bruteforcing')
        script_config.scripts['protocols/ftp/detect-bruteforcing'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/dns/detect-external-names')
        script_config.scripts['protocols/dns/detect-external-names'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/http/detect-sqli')
        script_config.scripts['protocols/http/detect-sqli'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/http/detect-webapps')
        script_config.scripts['protocols/http/detect-webapps'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/krb/ticket-logging')
        script_config.scripts['protocols/krb/ticket-logging'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/rdp/indicate_ssl')
        script_config.scripts['protocols/rdp/indicate_ssl'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/smb/log-cmds')
        script_config.scripts['protocols/smb/log-cmds'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/smtp/blocklists')
        script_config.scripts['protocols/smtp/blocklists'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/smtp/detect-suspicious-orig')
        script_config.scripts['protocols/smtp/detect-suspicious-orig'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/smtp/entities-excerpt')
        script_config.scripts['protocols/smtp/entities-excerpt'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/smtp/blocklists')
        script_config.scripts['protocols/smtp/blocklists'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/smtp/software')
        script_config.scripts['protocols/smtp/software'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssh/detect-bruteforcing')
        script_config.scripts['protocols/ssh/detect-bruteforcing'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssh/geo-data')
        script_config.scripts['protocols/ssh/geo-data'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssh/interesting-hostnames')
        script_config.scripts['protocols/ssh/interesting-hostnames'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssh/software')
        script_config.scripts['protocols/ssh/software'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssl/expiring-certs')
        script_config.scripts['protocols/ssl/expiring-certs'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssl/extract-certs-pem')
        script_config.scripts['protocols/ssl/extract-certs-pem'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssl/heartbleed')
        script_config.scripts['protocols/ssl/heartbleed'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssl/known-certs')
        script_config.scripts['protocols/ssl/known-certs'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssl/notary')
        script_config.scripts['protocols/ssl/notary'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssl/validate-ocsp')
        script_config.scripts['protocols/ssl/validate-ocsp'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssl/validate-sct')
        script_config.scripts['protocols/ssl/validate-sct'].enabled = False
        self.logger.debug('Disabling Zeek Script: protocols/ssl/weak-keys')
        script_config.scripts['protocols/ssl/weak-keys'].enabled = False
        self.logger.debug('Disabling Zeek Script: frameworks/dpd/detect-protocols')
        script_config.scripts['frameworks/dpd/detect-protocols'].enabled = False
        self.logger.debug('Disabling Zeek Script: frameworks/dpd/packet-segment-logging')
        script_config.scripts['frameworks/dpd/packet-segment-logging'].enabled = False
        self.logger.debug('Disabling Zeek Script: frameworks/files/detect-MHR')
        script_config.scripts['frameworks/files/detect-MHR'].enabled = False
        self.logger.debug('Disabling Zeek Script: frameworks/files/entropy-test-all-files')
        script_config.scripts['frameworks/files/entropy-test-all-files'].enabled = False
        self.logger.debug('Disabling Zeek Script: frameworks/files/extract-all-files')
        script_config.scripts['frameworks/files/extract-all-files'].enabled = False
        self.logger.debug('Disabling Zeek Script: frameworks/files/hash-all-files')
        script_config.scripts['frameworks/files/hash-all-files'].enabled = False
        self.logger.debug('Disabling Zeek Script: policy/frameworks/notice/extend-email/hostnames')
        script_config.scripts['policy/frameworks/notice/extend-email/hostnames'].enabled = False
        script_config.commit()

    def setup_zeek(self) -> None:
        """
        Setup Zeek NSM with AF_PACKET support
        """

        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info('Creating Zeek installation, configuration and logging directories.')
        utilities.makedirs(self.install_directory, exist_ok=True)
        utilities.makedirs(self.configuration_directory, exist_ok=True)
        self.logger.info('Compiling Zeek from source. This can take up to 30 minutes.')
        if self.stdout:
            utilities.print_coffee_art()
        time.sleep(1)
        self.logger.info('Configuring Zeek.')
        if self.verbose:
            zeek_config_p = subprocess.Popen('./configure --prefix={} --scriptdir={} --enable-jemalloc'.format(
                self.install_directory, self.configuration_directory),
                shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME))
        else:
            zeek_config_p = subprocess.Popen('./configure --prefix={} --scriptdir={} --enable-jemalloc'.format(
                self.install_directory, self.configuration_directory),
                shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

        zeek_config_p.communicate()
        time.sleep(1)
        self.logger.info("Compiling Zeek.")
        if utilities.get_cpu_core_count() > 1:
            parallel_threads = utilities.get_cpu_core_count() - 1
        else:
            parallel_threads = 1
        if self.verbose:
            compile_zeek_process = subprocess.Popen('make -j {}; make install'.format(parallel_threads), shell=True,
                                                    cwd=f'{const.INSTALL_CACHE}/{const.ZEEK_DIRECTORY_NAME}')
            compile_zeek_process.communicate()
        else:
            compile_zeek_process = subprocess.Popen('make -j {}; make install'.format(parallel_threads), shell=True,
                                                    cwd=f'{const.INSTALL_CACHE}/{const.ZEEK_DIRECTORY_NAME}',
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            utilities.run_subprocess_with_status(compile_zeek_process, expected_lines=6779)
        with open(env_file) as env_f:
            if 'ZEEK_HOME' not in env_f.read():
                self.logger.info(f'Updating Zeek default home path [{self.install_directory}]')
                subprocess.call(f'echo ZEEK_HOME="{self.install_directory}" >> {env_file}', shell=True)
            if 'ZEEK_SCRIPTS' not in env_f.read():
                self.logger.info(f'Updating Zeek default script path [{self.configuration_directory}]')
                subprocess.call(f'echo ZEEK_SCRIPTS="{self.configuration_directory}" >> {env_file}',
                                shell=True)

        self.logger.info("Overwriting Zeek node.cfg file with our changes.")

        default_node_config_path = f'{const.DEFAULT_CONFIGS}/zeek/broctl-nodes.cfg'
        destination_node_config_path = f'{self.install_directory}/etc/node.cfg'

        default_local_site_config_path = f'{const.DEFAULT_CONFIGS}/zeek/local.zeek'
        destination_local_site_config_path = f'{self.configuration_directory}/site/local.zeek'

        shutil.copy(default_node_config_path, destination_node_config_path)
        shutil.copy(default_local_site_config_path, destination_local_site_config_path)

        node_config = zeek_configs.NodeConfigManager(self.install_directory)
        node_config.workers = node.Workers()

        # Calculate new workers.
        for worker in node_config.get_optimal_zeek_worker_config(self.capture_network_interfaces):
            node_config.workers.add_worker(
                worker=worker
            )
        node_config.commit()
        sysctl = systemctl.SystemCtl()
        sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'zeek.service'))


def install_zeek(configuration_directory: str, install_directory: str, capture_network_interfaces: List[str],
                 download_zeek_archive: Optional[bool] = True, stdout: Optional[bool] = True,
                 verbose: Optional[bool] = False) -> None:
    """
    Install Zeek

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
    :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
    :param capture_network_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
    :param download_zeek_archive: If True, download the Zeek archive from a mirror
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """
    zeek_installer = InstallManager(configuration_directory, install_directory,
                                    capture_network_interfaces=capture_network_interfaces,
                                    download_zeek_archive=download_zeek_archive, stdout=stdout, verbose=verbose)

    zeek_installer.setup_zeek()
    zeek_installer.setup_dynamite_zeek_scripts()


def uninstall_zeek(prompt_user: Optional[bool] = True, stdout: Optional[bool] = True,
                   verbose: Optional[bool] = False) -> None:
    """
    Uninstall Zeek

    :param prompt_user: Print a warning before continuing
    :param stdout: Print the output to console
    :param verbose: Include detailed debug messages
    """

    log_level = logging.INFO
    if verbose:
        log_level = logging.DEBUG
    logger = get_logger('ZEEK', level=log_level, stdout=stdout)
    logger.info("Uninstalling Zeek.")
    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    if prompt_user:
        sys.stderr.write('\n\033[93m[-] WARNING! Removing Zeek Will Remove Critical Agent Functionality.\033[0m\n')
        resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    install_directory = environment_variables.get('ZEEK_HOME')
    config_directory = environment_variables.get('ZEEK_SCRIPTS')
    with open(env_file) as env_fr:
        env_lines = ''
        for line in env_fr.readlines():
            if 'ZEEK_HOME' in line:
                continue
            elif 'ZEEK_SCRIPTS' in line:
                continue
            elif line.strip() == '':
                continue
            env_lines += line.strip() + '\n'
    with open(env_file, 'w') as env_fw:
        env_fw.write(env_lines)

    shutil.rmtree(install_directory, ignore_errors=True)
    shutil.rmtree(config_directory, ignore_errors=True)
    sysctl = systemctl.SystemCtl()
    sysctl.stop('zeek')
    sysctl.uninstall_and_disable('zeek')
