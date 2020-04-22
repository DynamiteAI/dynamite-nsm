import os
import sys
import time
import logging
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.zeek.pf_ring import exceptions as pf_ring_exceptions


class InstallManager:
    """
    An interface for installing PF_RING kernel module and UserLand requirements
    """

    def __init__(self, install_directory, download_pf_ring_archive=True, stdout=True, verbose=False):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/pf_ring/)
        :param verbose: Include output from system utilities
        """

        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('PF_RING', level=log_level, stdout=stdout)

        self.install_directory = install_directory
        self.stdout = stdout
        self.verbose = verbose

        if download_pf_ring_archive:
            try:
                self.logger.info("Attempting to download PF_RING archive.")
                self.download_pf_ring(stdout=stdout)
            except general_exceptions.DownloadError as e:
                self.logger.error("Failed to download PF_RING archive.")
                self.logger.debug("Failed to download PF_RING archive, threw: {}.".format(e))
                raise pf_ring_exceptions.InstallPfringError("Failed to download PF_RING archive; {}".format(e))
        try:
            self.logger.info("Attempting to extract PF_RING archive ({}).".format(const.PF_RING_ARCHIVE_NAME))
            self.extract_pf_ring()
            self.logger.info("Extraction completed.")
        except general_exceptions.ArchiveExtractionError as e:
            self.logger.error("Failed to extract PF_RING archive.")
            self.logger.debug("Failed to extract PF_RING archive, threw: {}.".format(e))
            raise pf_ring_exceptions.InstallPfringError("Failed to extract PF_RING archive.")
        try:
            self.install_dependencies(stdout=stdout, verbose=verbose)
        except (general_exceptions.InvalidOsPackageManagerDetectedError,
                general_exceptions.OsPackageManagerInstallError, general_exceptions.OsPackageManagerRefreshError):
            raise pf_ring_exceptions.InstallPfringError("One or more OS dependencies failed to install.")

    def _compile_pf_ring_modules(self):
        self.logger.info('Compiling PF_RING from source [Userland].')
        if self.verbose:
            config_userland_p = subprocess.Popen(
                './configure --prefix={} && make install'.format(self.install_directory),
                cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'userland', 'lib'),
                shell=True)
        else:
            config_userland_p = subprocess.Popen(
                './configure --prefix={} && make install'.format(self.install_directory),
                cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'userland', 'lib'),
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            config_userland_p.communicate()
        except Exception as e:
            self.logger.error('General error occurred while starting PF_RING Userland configuration.')
            self.logger.debug("General error occurred while starting PF_RING Userland configuration; {}.".format(e))
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while starting PF_RING Userland configuration; {}".format(e))
        if config_userland_p.returncode != 0:
            self.logger.error("An error occurred while compiling Userland with PF_RING, exit-code: {}".format(
                config_userland_p.returncode))
            raise pf_ring_exceptions.InstallPfringError(
                "PF_RING Userland configuration returned non-zero; exit-code: {}".format(config_userland_p.returncode))

        self.logger.info('Compiling PF_RING from source [libpcap].')
        time.sleep(1)
        if self.verbose:
            config_libpcap_p = subprocess.Popen(
                './configure --prefix={} && make install'.format(self.install_directory),
                cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'userland', 'libpcap'),
                shell=True)
        else:
            config_libpcap_p = subprocess.Popen(
                './configure --prefix={} && make install'.format(self.install_directory),
                cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'userland', 'libpcap'),
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            config_libpcap_p.communicate()
        except Exception as e:
            self.logger.error('General error occurred while starting PF_RING LIBPCAP configuration.')
            self.logger.debug("General error occurred while starting PF_RING LIBPCAP configuration; {}.".format(e))
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while starting PF_RING LIBPCAP configuration; {}".format(e))
        if config_libpcap_p.returncode != 0:
            self.logger.error("An error occurred while compiling LIBPCAP with PF_RING, exit-code: {}".format(
                config_libpcap_p.returncode))
            raise pf_ring_exceptions.InstallPfringError(
                "PF_RING LIBPCAP configuration returned non-zero; exit-code: {}".format(config_libpcap_p.returncode))
        self.logger.info('Compiling PF_RING from source [tcpdump]')
        time.sleep(1)
        if self.verbose:
            config_tcpdump_p = subprocess.Popen(
                './configure --prefix={} && make install'.format(self.install_directory),
                cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'userland', 'tcpdump'),
                shell=True)
        else:
            config_tcpdump_p = subprocess.Popen(
                './configure --prefix={} && make install'.format(self.install_directory),
                cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'userland', 'tcpdump'),
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            config_tcpdump_p.communicate()
        except Exception as e:
            self.logger.error('General error occurred while starting PF_RING TCPDUMP configuration.')
            self.logger.debug("General error occurred while starting PF_RING TCPDUMP configuration; {}".format(e))
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while starting PF_RING TCPDUMP configuration; {}".format(e))
        if config_tcpdump_p.returncode != 0:
            self.logger.error(
                "PF_RING TCPDUMP configuration returned non-zero; exit-code: {}".format(config_tcpdump_p.returncode))
            raise pf_ring_exceptions.InstallPfringError(
                "PF_RING TCPDUMP configuration returned non-zero; exit-code: {}".format(config_tcpdump_p.returncode))
        self.logger.info('Compiling PF_RING from source [KERNEL]')
        time.sleep(2)
        if self.verbose:
            compile_p = subprocess.Popen('make && make install', shell=True,
                                         cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'kernel'))
        else:
            compile_p = subprocess.Popen('make && make install', shell=True,
                                         cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'kernel'),
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            compile_p.communicate()
        except Exception as e:
            self.logger.error('General error occurred while compiling PF_RING.')
            self.logger.debug("General error occurred while compiling PF_RING; {}".format(e))
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while compiling PF_RING; {}".format(e))
        if compile_p.returncode != 0:
            self.logger.error('PF_RING compile process returned non-zero; exit-code: {}'.format(compile_p.returncode))
            raise pf_ring_exceptions.InstallPfringError(
                "PF_RING compile process returned non-zero; exit-code: {}".format(compile_p.returncode))

        self.logger.info("Enabling PF_RING Kernel Module.")
        self.logger.debug('modprobe pf_ring min_num_slots=32768 enable_tx_capture=0')
        mod_probe_p = subprocess.Popen('modprobe pf_ring min_num_slots=32768 enable_tx_capture=0', shell=True,
                                       cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'kernel'))
        try:
            mod_probe_p.communicate()
        except Exception as e:
            self.logger.error("General error occurred while enabling PF_RING kernel modules.")
            self.logger.debug("General error occurred while enabling PF_RING kernel modules; {}".format(e))
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while enabling PF_RING kernel modules; {}".format(e))

    def _create_pf_ring_environment_variables(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        try:
            with open(env_file) as env_f:
                if 'PF_RING_HOME' not in env_f.read():
                    self.logger.info('Updating PF_RING default home path [{}]'.format(
                        self.install_directory))
                    subprocess.call('echo PF_RING_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
        except IOError:
            self.logger.error("Failed to open {} for reading.".format(env_file))
            raise pf_ring_exceptions.InstallPfringError(
                "Failed to open {} for reading.".format(env_file))
        except Exception as e:
            self.logger.error('General error while creating environment variables in {}.'.format(env_file))
            self.logger.debug("General error while creating environment variables in {}; {}".format(env_file, e))
            raise pf_ring_exceptions.InstallPfringError(
                "General error while creating environment variables in {}; {}".format(env_file, e))

    @staticmethod
    def _setup_pf_ring_kernel_modules(stdout=False, verbose=False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('PF_RING', level=log_level, stdout=stdout)
        try:
            with open('/etc/modules') as modules_f:
                if 'pf_ring' not in modules_f.read():
                    logger.info('Method 1: Setting PF_RING kernel module to load at boot.')
                    logger.debug('echo pf_ring min_num_slots=32768 enable_tx_capture=0 >> /etc/modules')
                    subprocess.call('echo pf_ring min_num_slots=32768 enable_tx_capture=0 >> /etc/modules', shell=True)
        except IOError:
            if os.path.exists('/etc/modules-load.d'):
                pf_ring_module_found = False
                for mod_conf in os.listdir('/etc/modules-load.d/'):
                    mod_conf_path = os.path.join('/etc/modules-load.d', mod_conf)
                    with open(mod_conf_path) as mod_conf_f:
                        if 'pf_ring' in mod_conf_f.read():
                            pf_ring_module_found = True
                            break
                if not pf_ring_module_found:
                    logger.info('Method 2: Setting PF_RING kernel module to load at boot.')
                    logger.debug(
                        'echo pf_ring min_num_slots=32768 enable_tx_capture=0 >> /etc/modules-load.d/pf_ring.conf')
                    subprocess.call(
                        'echo pf_ring min_num_slots=32768 enable_tx_capture=0 >> /etc/modules-load.d/pf_ring.conf',
                        shell=True)
            elif os.path.exists('/etc/modprobe.d'):
                pf_ring_mod_opts_found = False
                for mod_opt in os.listdir('/etc/modprobe.d'):
                    mod_opt_path = os.path.join('/etc/modprobe.d', mod_opt)
                    with open(mod_opt_path) as mod_opt_f:
                        if 'options pf_ring' in mod_opt_f.read():
                            pf_ring_mod_opts_found = True
                            break
                if not pf_ring_mod_opts_found:
                    logger.info('Method 3: Setting PF_RING kernel module to load at boot.')
                    logger.debug(
                        'echo "options pf_ring min_num_slots=32768 enable_tx_capture=0" >> '
                        '/etc/modprobe.d/pf_ring.conf')
                    subprocess.call(
                        'echo "options pf_ring min_num_slots=32768 enable_tx_capture=0" >> '
                        '/etc/modprobe.d/pf_ring.conf',
                        shell=True)
            else:
                logger.error(
                    'Could not determine a method to enable pf_ring KERNEL module. '
                    'You must enable manually using a tool such as \'modprobe\'')
                raise pf_ring_exceptions.InstallPfringError(
                    "Could not determine a method to enable pf_ring KERNEL module.")

    @staticmethod
    def download_pf_ring(stdout=False):
        """
        Download PF_RING archive

        :param stdout: Print output to console
        """
        url = None
        try:
            with open(const.PF_RING_MIRRORS, 'r') as pfring_archive_f:
                for url in pfring_archive_f.readlines():
                    if utilities.download_file(url, const.PF_RING_ARCHIVE_NAME, stdout=stdout):
                        break
        except Exception as e:
            raise general_exceptions.DownloadError(
                "General error while downloading PF_RING from {}; {}".format(url, e))

    @staticmethod
    def extract_pf_ring():
        """
        Extract PF_RING to local install_cache
        """
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.PF_RING_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
        except IOError as e:
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract PF_RING archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract PF_RING archive; {}".format(e))

    @staticmethod
    def install_dependencies(stdout=False, verbose=False):
        """
        Install required PF_RING dependencies

        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('PF_RING', level=log_level, stdout=stdout)
        pkt_mng = package_manager.OSPackageManager(verbose=verbose)

        packages = None
        logger.info('Installing Dependencies.')
        if pkt_mng.package_manager == 'apt-get':
            packages = ['make', 'gcc', 'linux-headers-generic']
        elif pkt_mng.package_manager == 'yum':
            packages = ['make', 'gcc', 'kernel-devel-$(uname -r)']
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
            logger.warning("Failed to install packages.")
            logger.debug("Failed to install packages threw: {}".format(e))
            raise general_exceptions.OsPackageManagerInstallError('Failed to install packages.')

    def setup_pf_ring(self):
        """
        Compile and setup required binaries and kernel modules
        """
        self.logger.info("Beginning setup process of PF_RING and its dependencies.")
        self._compile_pf_ring_modules()
        self._setup_pf_ring_kernel_modules(stdout=self.stdout, verbose=self.verbose)
        self._create_pf_ring_environment_variables()
