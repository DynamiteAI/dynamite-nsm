import os
import sys
import time
import shutil
import logging
import subprocess

try:
    # Python 3
    from itertools import zip_longest
except ImportError:
    # Python 2
    from itertools import izip_longest as zip_longest

from dynamite_nsm import const
from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.base import install
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.zeek import config as zeek_configs
from dynamite_nsm.services.zeek import profile as zeek_profile
from dynamite_nsm.services.zeek import process as zeek_process
from dynamite_nsm.services.zeek import exceptions as zeek_exceptions


class InstallManager(install.BaseInstallManager):

    def __init__(self, configuration_directory, install_directory, capture_network_interfaces,
                 download_zeek_archive=True, stdout=True, verbose=False):
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
            try:
                self.logger.info("Attempting to download Zeek archive.")
                self.download_from_mirror(const.ZEEK_MIRRORS, const.ZEEK_ARCHIVE_NAME, stdout=stdout, verbose=verbose)
            except general_exceptions.DownloadError as e:
                self.logger.error("Failed to download Zeek archive.")
                self.logger.debug("Failed to download Zeek archive, threw: {}.".format(e))
                raise zeek_exceptions.InstallZeekError("Failed to download Zeek archive.")
        try:
            self.logger.info("Attempting to extract Zeek archive ({}).".format(const.ZEEK_ARCHIVE_NAME))
            self.extract_archive(os.path.join(const.INSTALL_CACHE, const.ZEEK_ARCHIVE_NAME))
            self.logger.info("Extraction completed.")
        except general_exceptions.ArchiveExtractionError as e:
            self.logger.error("Failed to extract Zeek archive.")
            self.logger.debug("Failed to extract Zeek archive, threw: {}.".format(e))
            raise zeek_exceptions.InstallZeekError("Failed to extract Zeek archive.")
        try:
            self.install_dependencies(stdout=stdout, verbose=verbose)
        except (general_exceptions.InvalidOsPackageManagerDetectedError,
                general_exceptions.OsPackageManagerRefreshError):
            raise zeek_exceptions.InstallZeekError("One or more OS dependencies failed to install.")
        if not self.validate_capture_network_interfaces(self.capture_network_interfaces):
            self.logger.error(
                "One or more defined network interfaces is invalid: {}".format(capture_network_interfaces))
            raise zeek_exceptions.InstallZeekError(
                "One or more defined network interfaces is invalid: {}".format(capture_network_interfaces))

    @staticmethod
    def install_dependencies(stdout=False, verbose=False):
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

            # Work around for missing dependencies in RHEL/Centos8
            try:
                pkt_mng.install_packages(['dnf-plugins-core'])
            except general_exceptions.OsPackageManagerInstallError as e:
                logger.warning("Failed to install one or more packages: {}".format(e))
            enable_powertools_p = subprocess.Popen(['yum', 'config-manager', '--set-enabled', 'PowerTools'],
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            enable_powertools_p.communicate()

            if enable_powertools_p.returncode == 0:
                logger.info("Installed PowerTools.")
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
            logger.warning("Failed to install packages one or more packages: {}".format(e))

    @staticmethod
    def validate_capture_network_interfaces(network_interfaces):
        for interface in network_interfaces:
            if interface not in utilities.get_network_interface_names():
                return False
        return True

    def setup_zeek_af_packet_plugin(self):
        bro_af_packet_plugin_path = \
            os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'uncompiled_scripts', 'zeek-af_packet-plugin')
        self.logger.info('Configuring Zeek Zeek_AF_Packet plugin.')
        if self.verbose:
            print('./configure --zeek-dist={} --install-root={} --with-latest-kernel'.format(
                os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), self.configuration_directory))
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

        try:
            config_zeek_af_packet_process.communicate()
        except Exception as e:
            self.logger.error('General error occurred while starting Zeek_AF_Packet configuration.')
            self.logger.debug('General error occurred while starting Zeek_AF_Packet configuration; {}'.format(e))
        if config_zeek_af_packet_process.returncode != 0:
            self.logger.debug("Zeek_AF_Packet configuration returned non-zero; exit-code: {}".format(
                config_zeek_af_packet_process.returncode))
            raise zeek_exceptions.InstallZeekError(
                "Zeek_AF_Packet configuration returned non-zero; exit-code: {}".format(
                    config_zeek_af_packet_process.returncode))
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
        try:
            compile_zeek_af_packet_process.communicate()
        except Exception as e:
            self.logger.error('General error occurred while compiling Zeek_AF_Packet.')
            self.logger.debug("General error occurred while compiling Zeek_AF_Packet; {}".format(e))
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while compiling Zeek_AF_Packet; {}".format(e))
        if compile_zeek_af_packet_process.returncode != 0:
            self.logger.error("General error occurred while compiling Zeek_AF_Packet; {}".format(
                compile_zeek_af_packet_process.returncode))
            raise zeek_exceptions.InstallZeekError(
                "Zeek_AF_Packet compilation process returned non-zero; exit-code: {}".format(
                    compile_zeek_af_packet_process.returncode))
        try:
            shutil.copytree(os.path.join(self.configuration_directory, 'Zeek_AF_Packet'),
                            os.path.join(self.install_directory, 'lib', 'zeek', 'plugins', 'Zeek_AF_Packet'))
        except Exception as e:
            if 'FileExist' not in str(e):
                self.logger.error("General error occurred while installing Zeek_AF_Packet plugin.")
                self.logger.debug("General error occurred while installing Zeek_AF_Packet plugin; "
                                  "{}".format(e))
                raise zeek_exceptions.InstallZeekError(
                    "General error occurred while installing Zeek_AF_Packet plugin; {}".format(
                        e))

    def setup_zeek_community_id_plugin(self):
        bro_commmunity_id_plugin_path = \
            os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'uncompiled_scripts', 'zeek-community-id')
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
        try:
            config_zeek_community_id_script_process.communicate()
        except Exception as e:
            self.logger.error('General error occurred while starting Corelight_CommunityID configuration.')
            self.logger.debug('General error occurred while starting Corelight_CommunityID configuration; {}'.format(e))
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while starting Corelight_CommunityID configuration; {}".format(e))
        if config_zeek_community_id_script_process.returncode != 0:
            self.logger.debug("Corelight_CommunityID configuration returned non-zero; exit-code: {}".format(
                config_zeek_community_id_script_process.returncode))
            raise zeek_exceptions.InstallZeekError(
                "Corelight_CommunityID configuration returned non-zero; exit-code: {}".format(
                    config_zeek_community_id_script_process.returncode))
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
        try:
            compile_zeek_community_id_script_process.communicate()
        except Exception as e:
            self.logger.error('General error occurred while compiling Corelight_CommunityID [PATCHED].')
            self.logger.debug("General error occurred while compiling Corelight_CommunityID [PATCHED]; {}".format(e))
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while compiling Corelight_CommunityID [PATCHED]; {}".format(e))
        if compile_zeek_community_id_script_process.returncode != 0:
            self.logger.error("General error occurred while compiling Corelight_CommunityID [PATCHED]; {}".format(
                compile_zeek_community_id_script_process.returncode))
            raise zeek_exceptions.InstallZeekError(
                "Corelight_CommunityID [PATCHED] compilation process returned non-zero; exit-code: {}".format(
                    compile_zeek_community_id_script_process.returncode))
        try:
            shutil.copytree(os.path.join(self.configuration_directory, 'Corelight_CommunityID'),
                            os.path.join(self.install_directory, 'lib', 'zeek', 'plugins', 'Corelight_CommunityID'))
        except Exception as e:
            if 'FileExist' not in str(e):
                self.logger.error("General error occurred while installing Corelight_CommunityID [PATCHED] plugin.")
                self.logger.debug("General error occurred while installing Corelight_CommunityID [PATCHED] plugin; "
                                  "{}".format(e))
                raise zeek_exceptions.InstallZeekError(
                    "General error occurred while installing Corelight_CommunityID [PATCHED] plugin; {}".format(
                        e))

    def setup_dynamite_zeek_scripts(self):
        """
        Installs and enables extra dynamite Zeek scripts
        """

        scripts = ''
        redefs = ''
        self.logger.info('Setting up Zeek scripts.')
        install_cache_extra_scripts_path = \
            os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'dynamite_extra_scripts')
        if not os.path.exists(install_cache_extra_scripts_path):
            self.logger.error('dynamite_extra_scripts not found in install_cache.')
            raise zeek_exceptions.InstallZeekError(
                "Third party scripts could not be installed; could not locate {}".format(
                    install_cache_extra_scripts_path))
        try:
            utilities.makedirs(os.path.join(self.configuration_directory, 'dynamite_extra_scripts'), exist_ok=True)
        except Exception as e:
            self.logger.error('General error occurred while creating dynamite_extra_scripts directory.')
            self.logger.debug("General error occurred while creating dynamite_extra_scripts directory; {}".format(e))
            zeek_exceptions.InstallZeekError(
                "General error occurred while creating dynamite_extra_scripts directory; {}".format(e))
        self.logger.info("Installing third-party Zeek scripts.")
        extra_scripts_path = os.path.join(self.configuration_directory, 'dynamite_extra_scripts')
        try:
            utilities.copytree(install_cache_extra_scripts_path, extra_scripts_path)
        except Exception as e:
            self.logger.error("General error occurred while copying files to dynamite_extra_scripts directory.")
            self.logger.debug(
                "General error occurred while copying files to dynamite_extra_scripts directory; {}".format(e))
            zeek_exceptions.InstallZeekError(
                "General error occurred while copying files to dynamite_extra_scripts directory; {}".format(e))
        zeek_site_local_path = os.path.join(self.configuration_directory, 'site', 'local.zeek')
        try:
            with open(zeek_site_local_path, 'r') as rf:
                for line in rf.readlines():
                    if '@load' in line:
                        scripts += line.strip() + '\n'
                    elif 'redef' in line:
                        redefs += line.strip() + '\n'
        except Exception as e:
            self.logger.error("General error occurred while reading {}.".format(e))
            self.logger.debug("General error occurred while reading {}; {}".format(zeek_site_local_path, e))
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while reading {}; {}".format(zeek_site_local_path, e))
        try:
            with open(zeek_site_local_path, 'w') as wf:
                extra_script_install_path = os.path.join(self.configuration_directory, 'dynamite_extra_scripts')
                wf.write(scripts)
                for script_dir in os.listdir(extra_script_install_path):
                    wf.write('@load {}\n'.format(os.path.join(extra_script_install_path, script_dir)))
                wf.write(redefs)
        except Exception as e:
            self.logger.error("General error occurred while writing {}.".format(e))
            self.logger.debug("General error occurred while writing {}; {}".format(zeek_site_local_path, e))
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while writing {}; {}".format(zeek_site_local_path, e)
            )
        self.setup_zeek_af_packet_plugin()
        self.setup_zeek_community_id_plugin()
        self.logger.info('Disabling unneeded Zeek scripts.')

        # Disable Unneeded Zeek scripts
        try:
            script_config = zeek_configs.ScriptConfigManager(self.configuration_directory)
        except zeek_exceptions.ReadsZeekConfigError:
            self.logger.error('Could not read Zeek script configuration.')
            raise zeek_exceptions.InstallZeekError("Could not read Zeek script configuration.")
        try:
            self.logger.debug('Disabling Zeek Script: protocols/ftp/detect')
            script_config.disable_script('protocols/ftp/detect')

            self.logger.debug('Disabling Zeek Script: protocols/ftp/software')
            script_config.disable_script('protocols/ftp/software')

            self.logger.debug('Disabling Zeek Script: protocols/ftp/detect-bruteforcing')
            script_config.disable_script('protocols/ftp/detect-bruteforcing')

            self.logger.debug('Disabling Zeek Script: protocols/dns/detect-external-names')
            script_config.disable_script('protocols/dns/detect-external-names')

            self.logger.debug('Disabling Zeek Script: protocols/http/detect-sqli')
            script_config.disable_script('protocols/http/detect-sqli')

            self.logger.debug('Disabling Zeek Script: protocols/http/detect-webapps')
            script_config.disable_script('protocols/http/detect-webapps')

            self.logger.debug('Disabling Zeek Script: protocols/krb/ticket-logging')
            script_config.disable_script('protocols/krb/ticket-logging')

            self.logger.debug('Disabling Zeek Script: protocols/rdp/indicate_ssl')
            script_config.disable_script('protocols/rdp/indicate_ssl')

            self.logger.debug('Disabling Zeek Script: protocols/smb/log-cmds')
            script_config.disable_script('protocols/smb/log-cmds')

            self.logger.debug('Disabling Zeek Script: protocols/smtp/blocklists')
            script_config.disable_script('protocols/smtp/blocklists')

            self.logger.debug('Disabling Zeek Script: protocols/smtp/detect-suspicious-orig')
            script_config.disable_script('protocols/smtp/detect-suspicious-orig')

            self.logger.debug('Disabling Zeek Script: protocols/smtp/entities-excerpt')
            script_config.disable_script('protocols/smtp/entities-excerpt')

            self.logger.debug('Disabling Zeek Script: protocols/smtp/blocklists')
            script_config.disable_script('protocols/smtp/blocklists')

            self.logger.debug('Disabling Zeek Script: protocols/smtp/software')
            script_config.disable_script('protocols/smtp/software')

            self.logger.debug('Disabling Zeek Script: protocols/ssh/detect-bruteforcing')
            script_config.disable_script('protocols/ssh/detect-bruteforcing')

            self.logger.debug('Disabling Zeek Script: protocols/ssh/geo-data')
            script_config.disable_script('protocols/ssh/geo-data')

            self.logger.debug('Disabling Zeek Script: protocols/ssh/interesting-hostnames')
            script_config.disable_script('protocols/ssh/interesting-hostnames')

            self.logger.debug('Disabling Zeek Script: protocols/ssh/software')
            script_config.disable_script('protocols/ssh/software')

            self.logger.debug('Disabling Zeek Script: protocols/ssl/expiring-certs')
            script_config.disable_script('protocols/ssl/expiring-certs')

            self.logger.debug('Disabling Zeek Script: protocols/ssl/extract-certs-pem')
            script_config.disable_script('protocols/ssl/extract-certs-pem')

            self.logger.debug('Disabling Zeek Script: protocols/ssl/heartbleed')
            script_config.disable_script('protocols/ssl/heartbleed')

            self.logger.debug('Disabling Zeek Script: protocols/ssl/known-certs')
            script_config.disable_script('protocols/ssl/known-certs')

            self.logger.debug('Disabling Zeek Script: protocols/ssl/notary')
            script_config.disable_script('protocols/ssl/notary')

            self.logger.debug('Disabling Zeek Script: protocols/ssl/validate-ocsp')
            script_config.disable_script('protocols/ssl/validate-ocsp')

            self.logger.debug('Disabling Zeek Script: protocols/ssl/validate-sct')
            script_config.disable_script('protocols/ssl/validate-sct')

            self.logger.debug('Disabling Zeek Script: protocols/ssl/weak-keys')
            script_config.disable_script('protocols/ssl/weak-keys')

            self.logger.debug('Disabling Zeek Script: frameworks/dpd/detect-protocols')
            script_config.disable_script('frameworks/dpd/detect-protocols')

            self.logger.debug('Disabling Zeek Script: frameworks/dpd/packet-segment-logging')
            script_config.disable_script('frameworks/dpd/packet-segment-logging')

            self.logger.debug('Disabling Zeek Script: frameworks/files/detect-MHR')
            script_config.disable_script('frameworks/files/detect-MHR')

            self.logger.debug('Disabling Zeek Script: frameworks/files/entropy-test-all-files')
            script_config.disable_script('frameworks/files/entropy-test-all-files')

            self.logger.debug('Disabling Zeek Script: frameworks/files/extract-all-files')
            script_config.disable_script('frameworks/files/extract-all-files')

            self.logger.debug('Disabling Zeek Script: frameworks/files/hash-all-files')
            script_config.disable_script('frameworks/files/hash-all-files')

            self.logger.debug('Disabling Zeek Script: policy/frameworks/notice/extend-email/hostnames')
            script_config.disable_script('policy/frameworks/notice/extend-email/hostnames')

        except zeek_exceptions.ZeekScriptNotFoundError:
            self.logger.error('Could not disable one or more Zeek scripts.')
            raise zeek_exceptions.InstallZeekError("Could not disable one or more Zeek scripts.")
        try:
            script_config.write_config()
        except zeek_exceptions.WriteZeekConfigError:
            self.logger.error('Could not write Zeek script configuration.')
            raise zeek_exceptions.InstallZeekError("Could not write Zeek script configuration.")

    def setup_zeek(self):
        """
        Setup Zeek NSM with PF_RING support
        """

        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        self.logger.info('Creating Zeek installation, configuration and logging directories.')
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
        except Exception as e:
            self.logger.error('General error occurred while attempting to create root directories.')
            self.logger.debug("General error occurred while attempting to create root directories; {}".format(e))
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while attempting to create root directories; {}".format(e))

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
        try:
            zeek_config_p.communicate()
        except Exception as e:
            self.logger.error("General error occurred while configuring Zeek.")
            self.logger.debug("General error occurred while configuring Zeek; {}".format(e))
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while configuring Zeek; {}".format(e))
        if zeek_config_p.returncode != 0:
            self.logger.error(
                "Zeek configuration process returned non-zero; exit-code: {}".format(zeek_config_p.returncode))
            raise zeek_exceptions.InstallZeekError(
                "Zeek configuration process returned non-zero; exit-code: {}".format(zeek_config_p.returncode))
        time.sleep(1)
        self.logger.info("Compiling Zeek.")
        if utilities.get_cpu_core_count() > 1:
            parallel_threads = utilities.get_cpu_core_count() - 1
        else:
            parallel_threads = 1
        if self.verbose:
            compile_zeek_process = subprocess.Popen('make -j {}; make install'.format(parallel_threads), shell=True,
                                                    cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME))
            try:
                compile_zeek_process.communicate()
            except Exception as e:
                self.logger.error("General error occurred while compiling Zeek.")
                self.logger.debug("General error occurred while compiling Zeek; {}".format(e))
                raise zeek_exceptions.InstallZeekError(
                    "General error occurred while compiling Zeek; {}".format(e))
            compile_zeek_return_code = compile_zeek_process.returncode
        else:
            compile_zeek_process = subprocess.Popen('make -j {}; make install'.format(parallel_threads), shell=True,
                                                    cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME),
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                compile_zeek_return_code = utilities.run_subprocess_with_status(compile_zeek_process,
                                                                                expected_lines=6779)
            except Exception as e:
                self.logger.error("General error occurred while compiling Zeek.")
                self.logger.debug("General error occurred while compiling Zeek; {}".format(e))
                raise zeek_exceptions.InstallZeekError(
                    "General error occurred while compiling Zeek; {}".format(e))
        if compile_zeek_return_code != 0:
            self.logger.error(
                "Failed to compile Zeek from source; error code: {}; run with --verbose flag for more info.".format(
                    compile_zeek_return_code))
            raise zeek_exceptions.InstallZeekError(
                "Zeek compilation process returned non-zero; exit-code: {}".format(compile_zeek_return_code))
        try:
            with open(env_file) as env_f:
                if 'ZEEK_HOME' not in env_f.read():
                    self.logger.info('Updating Zeek default home path [{}]'.format(self.install_directory))
                    subprocess.call('echo ZEEK_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
                if 'ZEEK_SCRIPTS' not in env_f.read():
                    self.logger.info('Updating Zeek default script path [{}]'.format(self.configuration_directory))
                    subprocess.call('echo ZEEK_SCRIPTS="{}" >> {}'.format(self.configuration_directory, env_file),
                                    shell=True)
        except IOError as e:
            self.logger.error("Failed to open {} for reading.".format(env_file))
            self.logger.debug("Failed to open {} for reading; {}".format(env_file, e))
            raise zeek_exceptions.InstallZeekError(
                "Failed to open {} for reading; {}".format(env_file, e))
        except Exception as e:
            self.logger.error("General error while creating environment variables in {}.".format(env_file))
            self.logger.debug("General error while creating environment variables in {}; {}".format(env_file, e))
            raise zeek_exceptions.InstallZeekError(
                "General error while creating environment variables in {}; {}".format(env_file, e))
        self.logger.info("Overwriting Zeek node.cfg file with our changes.")
        try:
            shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'broctl-nodes.cfg'),
                        os.path.join(self.install_directory, 'etc', 'node.cfg'))
            shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'local.zeek'),
                        os.path.join(self.configuration_directory, 'site', 'local.zeek'))
        except Exception as e:
            self.logger.error("General error occurred while copying default Zeek configurations.")
            self.logger.debug("General error occurred while copying default Zeek configurations; {}".format(e))
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while copying default Zeek configurations; {}".format(e))
        try:
            node_config = zeek_configs.NodeConfigManager(self.install_directory)
        except zeek_exceptions.ReadsZeekConfigError:
            self.logger.error("An error occurred while reading Zeek configurations.")
            raise zeek_exceptions.InstallZeekError("An error occurred while reading Zeek configurations.")

        # Clear out pre-set workers.
        for key in list(node_config.node_config):
            if node_config.node_config[key]['type'] == 'worker':
                del node_config.node_config[key]

        # Calculate new workers.
        for worker in node_config.get_optimal_zeek_worker_config(self.capture_network_interfaces, stdout=self.stdout,
                                                                 verbose=self.verbose):
            node_config.add_worker(name=worker['name'],
                                   host=worker['host'],
                                   interface=worker['interface'],
                                   lb_procs=worker['lb_procs'],
                                   pin_cpus=worker['pinned_cpus']
                                   )
        try:
            node_config.write_config()
        except zeek_exceptions.WriteZeekConfigError:
            self.logger.error("An error occurred while writing Zeek configurations.")
            raise zeek_exceptions.InstallZeekError("An error occurred while writing Zeek configurations.")
        try:
            sysctl = systemctl.SystemCtl()
        except general_exceptions.CallProcessError:
            raise zeek_exceptions.InstallZeekError("Could not find systemctl.")
        self.logger.info("Installing Zeek systemd service.")
        if not sysctl.install_and_enable(os.path.join(const.DEFAULT_CONFIGS, 'systemd', 'zeek.service')):
            raise zeek_exceptions.InstallZeekError("Failed to install Zeek systemd service.")


def install_zeek(configuration_directory, install_directory, capture_network_interfaces, download_zeek_archive=True,
                 stdout=True, verbose=False):
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
    logger = get_logger('ZEEK', level=log_level, stdout=stdout)
    zeek_profiler = zeek_profile.ProcessProfiler()
    if zeek_profiler.is_installed():
        logger.error("Zeek is already installed.")
        raise zeek_exceptions.AlreadyInstalledZeekError()
    zeek_installer = InstallManager(configuration_directory, install_directory,
                                    capture_network_interfaces=capture_network_interfaces,
                                    download_zeek_archive=download_zeek_archive, stdout=stdout, verbose=verbose)

    zeek_installer.setup_zeek()
    zeek_installer.setup_dynamite_zeek_scripts()


def uninstall_zeek(prompt_user=True, stdout=True, verbose=False):
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
    zeek_profiler = zeek_profile.ProcessProfiler()
    if not zeek_profiler.is_installed():
        logger.error("Zeek is not installed. Cannot uninstall.")
        raise zeek_exceptions.UninstallZeekError("Zeek is not installed.")
    if prompt_user:
        sys.stderr.write('\n\033[93m[-] WARNING! Removing Zeek Will Remove Critical Agent Functionality.\033[0m\n')
        resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('\033[93m[?] Are you sure you wish to continue? ([no]|yes): \033[0m')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('\n[+] Exiting\n')
            exit(0)
    if zeek_profiler.is_running():
        try:
            zeek_process.ProcessManager().stop()
        except zeek_exceptions.CallZeekProcessError as e:
            logger.error("Could not kill Zeek process. Cannot uninstall.")
            logger.debug("Could not kill Zeek process. Cannot uninstall; {}".format(e))
            raise zeek_exceptions.UninstallZeekError("Could not kill Zeek process; {}".format(e))
    install_directory = environment_variables.get('ZEEK_HOME')
    config_directory = environment_variables.get('ZEEK_SCRIPTS')
    try:
        with open(env_file) as env_fr:
            env_lines = ''
            for line in env_fr.readlines():
                if 'ZEEK_HOME' in line:
                    continue
                elif 'ZEEK_SCRIPTS' in line:
                    continue
                elif 'PF_RING_HOME' in line:
                    continue
                elif line.strip() == '':
                    continue
                env_lines += line.strip() + '\n'
        with open(env_file, 'w') as env_fw:
            env_fw.write(env_lines)
        if zeek_profiler.is_installed():
            shutil.rmtree(install_directory, ignore_errors=True)
            shutil.rmtree(config_directory, ignore_errors=True)
    except Exception as e:
        logger.error("General error occurred while attempting to uninstall Zeek.")
        logger.debug("General error occurred while attempting to uninstall Zeek; {}".format(e))
        raise zeek_exceptions.UninstallZeekError(
            "General error occurred while attempting to uninstall Zeek; {}".format(e))
    try:
        sysctl = systemctl.SystemCtl()
    except general_exceptions.CallProcessError:
        raise zeek_exceptions.UninstallZeekError("Could not find systemctl.")
    sysctl.uninstall_and_disable('zeek')
