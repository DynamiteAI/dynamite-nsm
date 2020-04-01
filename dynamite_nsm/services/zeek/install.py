import os
import sys
import time
import shutil
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.services.zeek import config as zeek_configs
from dynamite_nsm.services.zeek.pf_ring import install as pfring_install
from dynamite_nsm.services.zeek.pf_ring import profile as pfring_profile


class InstallManager:

    def __init__(self,
                 configuration_directory, install_directory, download_zeek_archive=True, stdout=True, verbose=False):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        :param download_zeek_archive: If True, download the Zeek archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.stdout = stdout
        self.verbose = verbose
        if download_zeek_archive:
            self.download_zeek(stdout=stdout)
            self.extract_zeek(stdout=stdout)
        if not self.install_dependencies(verbose=verbose):
            raise Exception('Could not install Zeek dependencies.')

    @staticmethod
    def download_zeek(stdout=False):
        """
        Download Zeek archive

        :param stdout: Print output to console
        """
        for url in open(const.ZEEK_MIRRORS, 'r').readlines():
            if utilities.download_file(url, const.ZEEK_ARCHIVE_NAME, stdout=stdout):
                break

    @staticmethod
    def extract_zeek(stdout=False):
        """
        Extract Zeek to local install_cache

        :param stdout: Print output to console
        """
        if stdout:
            sys.stdout.write('[+] Extracting: {} \n'.format(const.ZEEK_ARCHIVE_NAME))
        try:
            tf = tarfile.open(os.path.join(const.INSTALL_CACHE, const.ZEEK_ARCHIVE_NAME))
            tf.extractall(path=const.INSTALL_CACHE)
            sys.stdout.write('[+] Complete!\n')
            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))

    @staticmethod
    def install_dependencies(verbose=False):
        """
        Install the required dependencies required by Zeek

        :return: True, if all packages installed successfully
        """
        pacman = package_manager.OSPackageManager(verbose=verbose)
        if not pacman.refresh_package_indexes():
            return False
        packages = None
        if pacman.package_manager == 'apt-get':
            packages = ['cmake', 'make', 'gcc', 'g++', 'flex', 'bison', 'libpcap-dev', 'libssl-dev',
                        'python-dev', 'swig', 'zlib1g-dev']
        elif pacman.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libpcap-devel', 'openssl-devel',
                        'python-devel', 'swig', 'zlib-devel']
        if packages:
            return pacman.install_packages(packages)
        return False

    def setup_zeek_community_id_script(self):
        bro_commmunity_id_script_path = \
            os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'uncompiled_scripts', 'bro-community-id')
        if self.stdout:
            sys.stdout.write('[+] Compiling Zeek Corelight_CommunityID plugin\n')
        if self.verbose:
            config_zeek_community_id_script_process = subprocess.Popen(
                './configure --bro-dist={} --install-root={}'.format(
                    os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), self.configuration_directory),
                shell=True, cwd=bro_commmunity_id_script_path
            )
        else:
            config_zeek_community_id_script_process = subprocess.Popen(
                './configure --bro-dist={} --install-root={}'.format(
                    os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), self.configuration_directory),
                shell=True, cwd=bro_commmunity_id_script_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        config_zeek_community_id_script_process.communicate()
        if config_zeek_community_id_script_process.returncode != 0:
            sys.stderr.write('[-] An error occurred while configuring Corelight_CommunityID plugin; exited {}\n'.format(
                config_zeek_community_id_script_process.returncode))
            return False
        if self.verbose:
            compile_zeek_community_id_script_process = subprocess.Popen('make; make install', shell=True,
                                                                        cwd=bro_commmunity_id_script_path)
        else:
            compile_zeek_community_id_script_process = subprocess.Popen('make; make install', shell=True,
                                                                        cwd=bro_commmunity_id_script_path,
                                                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        compile_zeek_community_id_script_process.communicate()
        if compile_zeek_community_id_script_process.returncode != 0:
            sys.stderr.write('[-] An error occurred while compiling community_id script: exited {}\n'.format(
                compile_zeek_community_id_script_process.returncode))
            return False
        try:
            shutil.copytree(os.path.join(self.configuration_directory, 'Corelight_CommunityID'),
                            os.path.join(self.install_directory, 'lib', 'bro', 'plugins', 'Corelight_CommunityID'))
        except Exception as e:
            if 'FileExist' not in str(e):
                sys.stderr.write('[-] An error occurred while installing Corelight_CommunityID plugin; error: {}\n'
                                 ''.format(e))
                return False
        return True

    def setup_dynamite_zeek_scripts(self):
        """
        Installs and enables extra dynamite Zeek scripts

        :return: True if zeek scripts were successfully installed
        """
        scripts = ''
        redefs = ''
        if self.stdout:
            sys.stdout.write('[+] Setting up Zeek scripts.\n')
        install_cache_extra_scripts_path = \
            os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'dynamite_extra_scripts')
        if not os.path.exists(install_cache_extra_scripts_path):
            sys.stderr.write('[-] dynamite_extra_scripts not found in install_cache.\n')
            sys.stderr.flush()
            return False
        try:
            os.mkdir(os.path.join(self.configuration_directory, 'dynamite_extra_scripts'))
        except OSError:
            pass
        if self.stdout:
            sys.stdout.write('[+] Installing third-party Zeek scripts.\n')
        extra_scripts_path = os.path.join(self.configuration_directory, 'dynamite_extra_scripts')
        utilities.copytree(install_cache_extra_scripts_path, extra_scripts_path)
        with open(os.path.join(self.configuration_directory, 'site', 'local.bro'), 'r') as rf:
            for line in rf.readlines():
                if '@load' in line:
                    scripts += line.strip() + '\n'
                elif 'redef' in line:
                    redefs += line.strip() + '\n'
        with open(os.path.join(self.configuration_directory, 'site', 'local.bro'), 'w') as wf:
            extra_script_install_path = os.path.join(self.configuration_directory, 'dynamite_extra_scripts')
            wf.write(scripts)
            for script_dir in os.listdir(extra_script_install_path):
                wf.write('@load {}\n'.format(os.path.join(extra_script_install_path, script_dir)))
            wf.write(redefs)

        if self.stdout:
            sys.stdout.write('[+] Installing Corelight_CommunityID plugin.\n')
            res = self.setup_zeek_community_id_script()
            if not res:
                return False
        if self.stdout:
            sys.stdout.write('[+] Disabling unneeded Zeek scripts.\n')
        # Disable Unneeded Zeek scripts
        script_config = zeek_configs.ScriptConfigManager(self.configuration_directory)
        script_config.disable_script('protocols/ftp/detect')
        script_config.disable_script('protocols/ftp/software')
        script_config.disable_script('protocols/ftp/detect-bruteforcing')
        script_config.disable_script('protocols/dns/detect-external-names')
        script_config.disable_script('protocols/http/detect-sqli')
        script_config.disable_script('protocols/http/detect-webapps')
        script_config.disable_script('protocols/krb/ticket-logging')
        script_config.disable_script('protocols/rdp/indicate_ssl')
        script_config.disable_script('protocols/smb/log-cmds')
        script_config.disable_script('protocols/smtp/blocklists')
        script_config.disable_script('protocols/smtp/detect-suspicious-orig')
        script_config.disable_script('protocols/smtp/entities-excerpt')
        script_config.disable_script('protocols/smtp/blocklists')
        script_config.disable_script('protocols/smtp/software')
        script_config.disable_script('protocols/ssh/detect-bruteforcing')
        script_config.disable_script('protocols/ssh/geo-data')
        script_config.disable_script('protocols/ssh/interesting-hostnames')
        script_config.disable_script('protocols/ssh/software')
        script_config.disable_script('protocols/ssl/expiring-certs')
        script_config.disable_script('protocols/ssl/extract-certs-pem')
        script_config.disable_script('protocols/ssl/heartbleed')
        script_config.disable_script('protocols/ssl/known-certs')
        script_config.disable_script('protocols/ssl/notary')
        script_config.disable_script('protocols/ssl/validate-ocsp')
        script_config.disable_script('protocols/ssl/validate-sct')
        script_config.disable_script('protocols/ssl/weak-keys')
        script_config.disable_script('frameworks/dpd/detect-protocols')
        script_config.disable_script('frameworks/dpd/packet-segment-logging')
        script_config.disable_script('frameworks/files/detect-MHR')
        script_config.disable_script('frameworks/files/entropy-test-all-files')
        script_config.disable_script('frameworks/files/extract-all-files')
        script_config.disable_script('frameworks/files/hash-all-files')
        script_config.disable_script('policy/frameworks/notice/extend-email/hostnames')
        script_config.write_config()
        return True

    def setup_zeek(self, network_interface=None):
        """
        Setup Zeek NSM with PF_RING support

        :param network_interface: The interface to listen on
        :return: True, if setup successful
        """
        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if not network_interface:
            network_interface = utilities.get_network_interface_names()[0]
        if network_interface not in utilities.get_network_interface_names():
            sys.stderr.write(
                '[-] The network interface that your defined: \'{}\' is invalid. Valid network interfaces: {}\n'.format(
                    network_interface, utilities.get_network_interface_names()))
            raise Exception('Invalid network interface {}'.format(network_interface))
        if self.stdout:
            sys.stdout.write('[+] Creating zeek install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        pf_ring_profiler = pfring_profile.ModuleProfile()
        pf_ring_install = pfring_install.InstallManager(self.install_directory,
                                                        downlaod_pf_ring_archive=not pf_ring_profiler.is_downloaded,
                                                        stdout=self.stdout, verbose=self.verbose)
        if not pf_ring_profiler.is_installed:
            if self.stdout:
                sys.stdout.write('[+] Installing PF_RING kernel modules and dependencies.\n')
                sys.stdout.flush()
                time.sleep(1)
        if self.stdout:
            sys.stdout.write('[+] Compiling Zeek from source. This can take up to 30 minutes. '
                             'Have another cup of coffee.\n')
            sys.stdout.flush()
            utilities.print_coffee_art()
            time.sleep(1)
        sys.stdout.write('[+] Configuring...\n')
        sys.stdout.flush()
        if self.verbose:
            subprocess.call('./configure --prefix={} --scriptdir={} --with-pcap={}'.format(
                self.install_directory, self.configuration_directory, pf_ring_install.install_directory),
                shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME))
        else:
            subprocess.call('./configure --prefix={} --scriptdir={} --with-pcap={}'.format(
                self.install_directory, self.configuration_directory, pf_ring_install.install_directory),
                shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        sys.stdout.write('[+] Compiling...\n')
        sys.stdout.flush()
        time.sleep(1)
        if self.verbose:
            compile_zeek_process = subprocess.Popen('make; make install', shell=True,
                                                    cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME))
            compile_zeek_process.communicate()
            compile_return_code = compile_zeek_process.returncode
        else:
            compile_zeek_process = subprocess.Popen('make; make install', shell=True,
                                                    cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME),
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            compile_return_code = utilities.run_subprocess_with_status(compile_zeek_process, expected_lines=6596)
        if compile_return_code != 0:
            sys.stderr.write('[-] Failed to compile Zeek from source; error code: {}; ; run with '
                             '--debug flag for more info.\n'.format(compile_zeek_process.returncode))
            return False

        if 'ZEEK_HOME' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating Zeek default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo ZEEK_HOME="{}" >> {}'.format(self.install_directory, env_file),
                            shell=True)
        if 'ZEEK_SCRIPTS' not in open(env_file).read():
            if self.stdout:
                sys.stdout.write('[+] Updating Zeek default script path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo ZEEK_SCRIPTS="{}" >> {}'.format(self.configuration_directory, env_file),
                            shell=True)
        if self.stdout:
            sys.stdout.write('[+] Overwriting default Script | Node configurations.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'broctl-nodes.cfg'),
                    os.path.join(self.install_directory, 'etc', 'node.cfg'))
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'local.bro'),
                    os.path.join(self.configuration_directory, 'site', 'local.bro'))

        node_config = zeek_configs.NodeConfigManager(self.install_directory)

        cpu_count = utilities.get_cpu_core_count()
        cpus = [c for c in range(0, cpu_count)]
        if cpu_count > 1:
            pinned_cpus = cpus[:-1]
            lb_procs = len(pinned_cpus)
        else:
            pinned_cpus = cpus
            lb_procs = 1
        node_config.add_worker(name='dynamite-worker-1',
                               host='localhost',
                               interface=network_interface,
                               lb_procs=lb_procs,
                               pin_cpus=pinned_cpus
                               )
        node_config.write_config()
