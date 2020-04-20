import os
import sys
import time
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager

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
        self.install_directory = install_directory
        self.stdout = stdout
        self.verbose = verbose

        if download_pf_ring_archive:
            try:
                self.download_pf_ring(stdout=stdout)
            except general_exceptions.DownloadError as e:
                raise pf_ring_exceptions.InstallPfringError("Failed to download PF_RING archive; {}".format(e))
        try:
            self.extract_pf_ring(stdout=stdout)
        except general_exceptions.ArchiveExtractionError:
            raise pf_ring_exceptions.InstallPfringError("Failed to extract PF_RING archive.")

        try:
            self.install_dependencies(verbose=verbose)
        except (general_exceptions.InvalidOsPackageManagerDetectedError,
                general_exceptions.OsPackageManagerInstallError, general_exceptions.OsPackageManagerRefreshError):
            raise pf_ring_exceptions.InstallPfringError("One or more OS dependencies failed to install.")

    def _compile_pf_ring_modules(self):
        if self.stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [USERLAND].\n')
            sys.stdout.flush()
            time.sleep(1)
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
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while starting PF_RING USERLAND configuration; {}".format(e))
        if config_userland_p.returncode != 0:
            raise pf_ring_exceptions.InstallPfringError(
                "PF_RING USERLAND configuration returned non-zero; exit-code: {}".format(config_userland_p.returncode))

        if self.stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [libpcap].\n')
            sys.stdout.flush()
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
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while starting PF_RING LIBPCAP configuration; {}".format(e))
        if config_libpcap_p.returncode != 0:
            raise pf_ring_exceptions.InstallPfringError(
                "PF_RING LIBPCAP configuration returned non-zero; exit-code: {}".format(config_userland_p.returncode))
        if self.stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [tcpdump].\n')
            sys.stdout.flush()
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
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while starting PF_RING TCPDUMP configuration; {}".format(e))

        if config_tcpdump_p.returncode != 0:
            raise pf_ring_exceptions.InstallPfringError(
                "PF_RING TCPDUMP configuration returned non-zero; exit-code: {}".format(config_userland_p.returncode))
        if self.stdout:
            sys.stdout.write('[+] Compiling PF_RING from source [KERNEL].\n')
            sys.stdout.flush()
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
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while compiling PF_RING; {}".format(e))
        if compile_p.returncode != 0:
            raise pf_ring_exceptions.InstallPfringError(
                "PF_RING compile process returned non-zero; exit-code: {}".format(config_userland_p.returncode))

        mod_probe_p = subprocess.Popen('modprobe pf_ring min_num_slots=32768 enable_tx_capture=0', shell=True,
                                       cwd=os.path.join(const.INSTALL_CACHE, const.PF_RING_DIRECTORY_NAME, 'kernel'))
        try:
            mod_probe_p.communicate()
        except Exception as e:
            raise pf_ring_exceptions.InstallPfringError(
                "General error occurred while enabling PF_RING kernel modules; {}".format(e))

    def _create_pf_ring_environment_variables(self):
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        try:
            with open(env_file) as env_f:
                if 'PF_RING_HOME' not in env_f.read():
                    if self.stdout:
                        sys.stdout.write('[+] Updating PF_RING default home path [{}]\n'.format(
                            self.install_directory))
                    subprocess.call('echo PF_RING_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
        except IOError:
            raise pf_ring_exceptions.InstallPfringError(
                "Failed to open {} for reading.".format(env_file))
        except Exception as e:
            raise pf_ring_exceptions.InstallPfringError(
                "General error while creating environment variables in {}; {}".format(env_file, e))

    @staticmethod
    def _setup_pf_ring_kernel_modules(stdout=False):
        try:
            with open('/etc/modules') as modules_f:
                if 'pf_ring' not in modules_f.read():
                    if stdout:
                        sys.stdout.write('[+] Setting PF_RING kernel module to load at boot.\n')
                    subprocess.call('echo pf_ring min_num_slots=32768 >> /etc/modules', shell=True)
        except IOError:
            if os.path.exists('/etc/modules-load.d') and os.path.exists('/etc/modprobe.d'):
                pf_ring_module_found = False
                pf_ring_mod_opts_found = False
                for mod_conf in os.listdir('/etc/modules-load.d/'):
                    mod_conf_path = os.path.join('/etc/modules-load.d', mod_conf)
                    with open(mod_conf_path) as mod_conf_f:
                        if 'pf_ring' in mod_conf_f.read():
                            pf_ring_module_found = True
                            break
                for mod_opt in os.listdir('/etc/modprobe.d'):
                    mod_opt_path = os.path.join('/etc/modprobe.d', mod_opt)
                    with open(mod_opt_path) as mod_opt_f:
                        if 'options pf_ring' in mod_opt_f.read():
                            pf_ring_mod_opts_found = True
                            break
                if not pf_ring_module_found:
                    subprocess.call('echo "pf_ring" >> /etc/modules-load.d/pf_ring.conf', shell=True)
                if not pf_ring_mod_opts_found:
                    subprocess.call(
                        'echo "options pf_ring min_num_slots=32768 enable_tx_capture=0" >> '
                        '/etc/modprobe.d/pf_ring.conf',
                        shell=True)
            else:
                sys.stderr.write('[-] Could not determine a method to enable pf_ring KERNEL module. '
                                 'You must enable manually using a tool such as \'modprobe\'.\n')
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
    def extract_pf_ring(stdout=False):
        """
        Extract PF_RING to local install_cache

        :param stdout: Print output to console
        """

        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.PF_RING_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.PF_RING_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))
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

        pkt_mng = package_manager.OSPackageManager(verbose=verbose)

        packages = None
        if stdout:
            sys.stdout.write('[+] Installing dependencies.\n')
            sys.stdout.flush()
        if pkt_mng.package_manager == 'apt-get':
            packages = ['make', 'gcc', 'linux-headers-generic']
        elif pkt_mng.package_manager == 'yum':
            packages = ['make', 'gcc', 'kernel-devel-$(uname -r)']
        if stdout:
            sys.stdout.write('[+] Updating Package Indexes.\n')
            sys.stdout.flush()
        pkt_mng.refresh_package_indexes()
        if stdout:
            sys.stdout.write('[+] Installing the following packages: {}.\n'.format(packages))
            sys.stdout.flush()
        pkt_mng.install_packages(packages)

    def setup_pf_ring(self):
        """
        Compile and setup required binaries and kernel modules
        """

        self._compile_pf_ring_modules()
        self._setup_pf_ring_kernel_modules(stdout=self.stdout)
        self._create_pf_ring_environment_variables()
