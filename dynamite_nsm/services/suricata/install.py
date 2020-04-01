import os
import sys
import time
import shutil
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.services.suricata import config as suricata_configs
from dynamite_nsm.services.suricata.oinkmaster import install as rules_install


class InstallManager:

    def __init__(self, configuration_directory, install_directory, log_directory, download_suricata_archive=True,
                 stdout=True, verbose=False):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/suricata/)
        :param log_directory: Path to the log directory (E.G /var/log/dynamite/suricata/)
        :param download_suricata_archive: If True, download the Suricata archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory
        self.download_suricata_archive = download_suricata_archive
        self.stdout = stdout
        self.verbose = verbose
        if download_suricata_archive:
            self.download_suricata(stdout=stdout)
            self.extract_suricata(stdout=stdout)
        if not self.install_dependencies(verbose=verbose):
            raise Exception('Could not install Suricata dependencies.')

    def _configure_and_compile_suricata(self):
        if self.configuration_directory.endswith('/'):
            suricata_config_parent = '/'.join(self.configuration_directory.split('/')[:-2])
        else:
            suricata_config_parent = '/'.join(self.configuration_directory.split('/')[:-1])
        if self.stdout:
            sys.stdout.write('[+] Compiling Suricata from source. This can take up to 5 to 10 minutes. '
                             'Have a cup of coffee.\n')
            sys.stdout.flush()
            utilities.print_coffee_art()
        time.sleep(1)
        sys.stdout.write('[+] Configuring...\n')
        sys.stdout.flush()
        if self.verbose:
            configure_result = subprocess.call(
                './configure --prefix={} --sysconfdir={} --localstatedir=/var/dynamite/suricata'.format(
                    self.install_directory, suricata_config_parent), shell=True,
                cwd=os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME))
        else:
            configure_result = subprocess.call(
                './configure --prefix={} --sysconfdir={} --localstatedir=/var/dynamite/suricata'.format(
                    self.install_directory, suricata_config_parent),
                shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if configure_result != 0:
            sys.stderr.write('[-] Unable to configure Suricata installation files: {}\n')
            return False
        sys.stdout.write('[+] Compiling...\n')
        sys.stdout.flush()
        if self.verbose:
            compile_suricata_process = subprocess.Popen('make; make install; make install-conf', shell=True,
                                                        cwd=os.path.join(const.INSTALL_CACHE,
                                                                         const.SURICATA_DIRECTORY_NAME))
            compile_suricata_process.communicate()
            compile_suricata_return_code = compile_suricata_process.returncode
        else:
            compile_suricata_process = subprocess.Popen('make; make install; make install-conf', shell=True,
                                                        cwd=os.path.join(const.INSTALL_CACHE,
                                                                         const.SURICATA_DIRECTORY_NAME),
                                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            compile_suricata_return_code = utilities.run_subprocess_with_status(compile_suricata_process,
                                                                                expected_lines=935)
        if compile_suricata_return_code != 0:
            sys.stderr.write('[-] Unable to compile Suricata installation package; error code {};'
                             'run with --debug flag for more info.\n'.format(compile_suricata_process.returncode))
            return False
        return True

    def _copy_suricata_files_and_directories(self):
        if self.stdout:
            sys.stdout.write('[+] Creating suricata install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.log_directory), shell=True)
        try:
            os.mkdir(os.path.join(self.configuration_directory, 'rules'))
            shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'suricata', 'suricata.yaml'),
                        os.path.join(self.configuration_directory, 'suricata.yaml'))
            utilities.copytree(os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME, 'rules'),
                               os.path.join(self.configuration_directory, 'rules'))
        except Exception as e:
            sys.stderr.write('[-] Unable to re-create Suricata rules directory: {}\n'.format(e))
            return False
        return True

    def _setup_suricata_rules(self):
        if self.stdout:
            sys.stdout.write('[+] Installing Rules.\n')
        oink_installer = rules_install.InstallManager(
            download_oinkmaster_archive=True,
            stdout=self.stdout,
            verbose=self.verbose,
            install_directory=os.path.join(self.install_directory, 'oinkmaster')
        )
        try:
            oink_installer.download_oinkmaster(stdout=self.stdout)
        except Exception as e:
            sys.stderr.write('[-] Unable to download Oinkmaster: {}\n'.format(e))
            return False
        try:
            oink_installer.extract_oinkmaster(stdout=self.stdout)
        except Exception as e:
            sys.stderr.write('[-] Unable to extract Oinkmaster: {}'.format(e))
            return False
        try:
            oink_install_res = oink_installer.setup_oinkmaster()
        except Exception as e:
            sys.stderr.write('[-] Unable to setup Oinkmaster: {}'.format(e))
            return False

        rules_install.update_suricata_rules()
        return oink_install_res

    @staticmethod
    def download_suricata(stdout=False):
        """
        Download Suricata archive

        :param stdout: Print output to console
        """
        for url in open(const.SURICATA_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.SURICATA_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_suricata(stdout=False):
        """
        Extract Suricata to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.SURICATA_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.SURICATA_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    @staticmethod
    def install_dependencies(verbose=False):
        """
        Install the required dependencies required by Suricata

        :return: True, if all packages installed successfully
        """
        pacman = package_manager.OSPackageManager(verbose=verbose)
        if not pacman.refresh_package_indexes():
            return False
        packages = None
        if pacman.package_manager == 'apt-get':
            packages = ['cmake', 'make', 'gcc', 'g++', 'flex', 'bison', 'libtool', 'automake', 'pkg-config',
                        'libpcre3-dev', 'libpcap-dev', 'libyaml-dev', 'libjansson-dev', 'rustc', 'cargo', 'python-pip',
                        'wireshark', 'zlib1g-dev', 'libcap-ng-dev', 'libnspr4-dev', 'libnss3-dev', 'libmagic-dev',
                        'liblz4-dev']
        elif pacman.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libtool', 'automake', 'pkgconfig',
                        'pcre-devel', 'libpcap-devel', 'libyaml-devel', 'jansson-devel', 'rustc', 'cargo', 'python-pip',
                        'wireshark', 'zlib-devel', 'libcap-ng-devel', 'nspr-devel', 'nss-devel', 'file-devel',
                        'lz4-devel']
        if packages:
            return pacman.install_packages(packages)
        return False

    def setup_suricata(self, network_interface=None):
        """
        Setup Suricata IDS with PF_RING support

        :param network_interface: The interface to listen on
        """
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if not network_interface:
            network_interface = utilities.get_network_interface_names()[0]
        if network_interface not in utilities.get_network_interface_names():
            sys.stderr.write(
                '[-] The network interface that your defined: \'{}\' is invalid. Valid network interfaces: {}\n'.format(
                    network_interface, utilities.get_network_interface_names()))
            raise Exception('Invalid network interface {}'.format(network_interface))
        self._copy_suricata_files_and_directories()
        suricata_compiled = self._configure_and_compile_suricata()
        if not suricata_compiled:
            return False
        if 'SURICATA_HOME' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating Suricata default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo SURICATA_HOME="{}" >> {}'.format(self.install_directory, env_file),
                            shell=True)
        if 'SURICATA_CONFIG' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating Suricata default config path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo SURICATA_CONFIG="{}" >> {}'.format(
                self.configuration_directory, env_file), shell=True)
        self._setup_suricata_rules()
        config = suricata_configs.ConfigManager(self.configuration_directory)
        config.af_packet_interfaces = []
        config.add_afpacket_interface(network_interface, threads='auto', cluster_id=99)
        config.default_log_directory = self.log_directory
        config.default_rules_directory = os.path.join(self.configuration_directory, 'rules')
        config.reference_config_file = os.path.join(self.configuration_directory, 'reference.config')
        config.classification_file = os.path.join(self.configuration_directory, 'rules', 'classification.config')

        # Disable Unneeded Suricata rules
        config.disable_rule('http-events.rules')
        config.disable_rule('smtp-events.rules')
        config.disable_rule('dns-events.rules')
        config.disable_rule('tls-events.rules')
        config.disable_rule('drop.rules')
        config.disable_rule('emerging-p2p.rules')
        config.disable_rule('emerging-pop3.rules')
        config.disable_rule('emerging-telnet.rules')
        config.disable_rule('emerging-tftp.rules')
        config.disable_rule('emerging-voip.rules')
        config.write_config()
