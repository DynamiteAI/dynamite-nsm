import os
import sys
import time
import math
import shutil
import tarfile
import itertools
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.zeek import config as zeek_configs
from dynamite_nsm.services.zeek import profile as zeek_profile
from dynamite_nsm.services.zeek import process as zeek_process
from dynamite_nsm.services.zeek import exceptions as zeek_exceptions
from dynamite_nsm.services.zeek.pf_ring import install as pfring_install
from dynamite_nsm.services.zeek.pf_ring import profile as pfring_profile
from dynamite_nsm.services.zeek.pf_ring import exceptions as pf_ring_exceptions


class InstallManager:

    def __init__(self, configuration_directory, install_directory, capture_network_interfaces,
                 download_zeek_archive=True, stdout=True, verbose=False):
        """
        Install Zeek

        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        :param capture_network_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
        :param download_zeek_archive: If True, download the Zeek archive from a mirror
        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.capture_network_interfaces = capture_network_interfaces
        self.stdout = stdout
        self.verbose = verbose
        utilities.create_dynamite_environment_file()
        if download_zeek_archive:
            try:
                self.download_zeek(stdout=stdout)
            except general_exceptions.DownloadError:
                raise zeek_exceptions.InstallZeekError("Failed to download Zeek archive.")
        try:
            self.extract_zeek(stdout=stdout)
        except general_exceptions.ArchiveExtractionError:
            raise zeek_exceptions.InstallZeekError("Failed to extract Zeek archive.")
        try:
            self.install_dependencies(verbose=verbose)
        except (general_exceptions.InvalidOsPackageManagerDetectedError,
                general_exceptions.OsPackageManagerInstallError, general_exceptions.OsPackageManagerRefreshError):
            raise zeek_exceptions.InstallZeekError("One or more OS dependencies failed to install.")
        if not self.validate_capture_network_interfaces(self.capture_network_interfaces):
            raise zeek_exceptions.InstallZeekError(
                "One or more defined network interfaces is invalid: {}".format(capture_network_interfaces))

    @staticmethod
    def get_pf_ring_workers(network_capture_interfaces, strategy="aggressive"):
        cpus = [c for c in range(0, utilities.get_cpu_core_count())]

        # Reserve 0 for KERNEL/Userland opts
        available_cpus = cpus[1:]

        def grouper(n, iterable):
            args = [iter(iterable)] * n
            return itertools.izip_longest(*args)

        def create_workers(net_interfaces, available_cpus):
            idx = 0
            zeek_worker_configs = []
            for net_interface in net_interfaces:
                if idx >= len(available_cpus):
                    idx = 0
                if isinstance(available_cpus[idx], int):
                    available_cpus[idx] = [available_cpus[idx]]
                zeek_worker_configs.append(
                    dict(
                        name='dynamite-worker-' + net_interface,
                        host='localhost',
                        interface=net_interface,
                        lb_procs=len(available_cpus[idx]),
                        pinned_cpus=available_cpus[idx]
                    )
                )
                idx += 1
            return zeek_worker_configs

        if len(available_cpus) <= len(network_capture_interfaces):
            # Wrap the number of CPUs around the number of network interfaces;
            # Since there are more network interfaces than CPUs; CPUs will be assigned more than once
            # lb_procs will always be 1

            zeek_workers = create_workers(network_capture_interfaces, available_cpus)

        else:
            # In this scenario we choose from one of two strategies
            #  1. Aggressive:
            #     - Take the ratio of network_interfaces to available CPUS; ** ROUND UP **.
            #     - Group the available CPUs by this integer
            #       (if the ratio == 2 create as many groupings of 2 CPUs as possible)
            #     - Apply the same wrapping logic used above, but with the CPU groups instead of single CPU instances
            #  2. Conservative:
            #     - Take the ratio of network_interfaces to available CPUS; ** ROUND DOWN **.
            #     - Group the available CPUs by this integer
            #       (if the ratio == 2 create as many groupings of 2 CPUs as possible)
            #     - Apply the same wrapping logic used above, but with the CPU groups instead of single CPU instances
            aggressive_ratio = int(math.ceil(len(available_cpus) / float(len(network_capture_interfaces))))
            conservative_ratio = int(math.floor(len(available_cpus) / len(network_capture_interfaces)))
            if strategy == 'aggressive':
                cpu_groups = grouper(aggressive_ratio, available_cpus)
            else:
                cpu_groups = grouper(conservative_ratio, available_cpus)

            temp_cpu_groups = []
            for cpu_group in cpu_groups:
                cpu_group = [c for c in cpu_group if c]
                temp_cpu_groups.append(cpu_group)
            cpu_groups = temp_cpu_groups

            zeek_workers = create_workers(network_capture_interfaces, cpu_groups)
            return zeek_workers


    @staticmethod
    def download_zeek(stdout=False):
        """
        Download Zeek archive

        :param stdout: Print output to console
        """

        url = None
        try:
            with open(const.ZEEK_MIRRORS, 'r') as zeek_archive:
                for url in zeek_archive.readlines():
                    if utilities.download_file(url, const.ZEEK_ARCHIVE_NAME, stdout=stdout):
                        break
        except Exception as e:
            raise general_exceptions.DownloadError(
                "General error while downloading Zeek from {}; {}".format(url, e))

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
            raise general_exceptions.ArchiveExtractionError(
                "Could not extract Zeek archive to {}; {}".format(const.INSTALL_CACHE, e))
        except Exception as e:
            raise general_exceptions.ArchiveExtractionError(
                "General error while attempting to extract Zeek archive; {}".format(e))

    @staticmethod
    def install_dependencies(stdout=False, verbose=False):
        """
        Install the required dependencies required by Zeek

        :param stdout: Print the output to console
        :param verbose: Include output from system utilities
        """

        pkt_mng = package_manager.OSPackageManager(verbose=verbose)
        packages = None
        if pkt_mng.package_manager == 'apt-get':
            packages = ['cmake', 'make', 'gcc', 'g++', 'flex', 'bison', 'libpcap-dev', 'libssl-dev',
                        'python-dev', 'swig', 'zlib1g-dev']
        elif pkt_mng.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libpcap-devel', 'openssl-devel',
                        'python-devel', 'swig', 'zlib-devel']
        if stdout:
            sys.stdout.write('[+] Updating Package Indexes.\n')
            sys.stdout.flush()
        pkt_mng.refresh_package_indexes()
        if stdout:
            sys.stdout.write('[+] Installing the following packages: {}.\n'.format(packages))
            sys.stdout.flush()
        pkt_mng.install_packages(packages)

    @staticmethod
    def validate_capture_network_interfaces(network_interfaces):
        for interface in network_interfaces:
            if interface not in utilities.get_network_interface_names():
                sys.stderr.write(
                    '[-] The network interface that your defined: \'{}\' is invalid. Valid network interfaces: {}\n'
                    ''.format(interface, utilities.get_network_interface_names()))
                return False
        return True

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

        try:
            config_zeek_community_id_script_process.communicate()
        except Exception as e:
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while starting Corelight_CommunityID configuration; {}".format(e))
        if config_zeek_community_id_script_process.returncode != 0:
            raise zeek_exceptions.InstallZeekError(
                "Corelight_CommunityID configuration returned non-zero; exit-code: {}".format(
                    config_zeek_community_id_script_process.returncode))
        if self.verbose:
            compile_zeek_community_id_script_process = subprocess.Popen('make; make install', shell=True,
                                                                        cwd=bro_commmunity_id_script_path)
        else:
            compile_zeek_community_id_script_process = subprocess.Popen('make; make install', shell=True,
                                                                        cwd=bro_commmunity_id_script_path,
                                                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            compile_zeek_community_id_script_process.communicate()
        except Exception as e:
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while compiling Corelight_CommunityID; {}".format(e))
        if compile_zeek_community_id_script_process.returncode != 0:
            raise zeek_exceptions.InstallZeekError(
                "Corelight_CommunityID compilation process returned non-zero; exit-code: {}".format(
                    config_zeek_community_id_script_process.returncode))
        try:
            shutil.copytree(os.path.join(self.configuration_directory, 'Corelight_CommunityID'),
                            os.path.join(self.install_directory, 'lib', 'bro', 'plugins', 'Corelight_CommunityID'))
        except Exception as e:
            if 'FileExist' not in str(e):
                sys.stderr.write('[-] An error occurred while installing Corelight_CommunityID plugin; error: {}\n'
                                 ''.format(e))
                raise zeek_exceptions.InstallZeekError(
                    "General error occurred while installing Corelight_CommunityID plugin; error: {}".format(e))

    def setup_dynamite_zeek_scripts(self):
        """
        Installs and enables extra dynamite Zeek scripts
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
            raise zeek_exceptions.InstallZeekError(
                "Third party scripts could not be installed; could not locate {}".format(
                    install_cache_extra_scripts_path))
        try:
            utilities.makedirs(os.path.join(self.configuration_directory, 'dynamite_extra_scripts'), exist_ok=True)
        except Exception as e:
            zeek_exceptions.InstallZeekError(
                "General error occurred while creating dynamite_extra_scripts directory; {}".format(e))
        if self.stdout:
            sys.stdout.write('[+] Installing third-party Zeek scripts.\n')
        extra_scripts_path = os.path.join(self.configuration_directory, 'dynamite_extra_scripts')
        try:
            utilities.copytree(install_cache_extra_scripts_path, extra_scripts_path)
        except Exception as e:
            zeek_exceptions.InstallZeekError(
                "General error occurred while copying files to dynamite_extra_scripts directory; {}".format(e))
        zeek_site_local_path = os.path.join(self.configuration_directory, 'site', 'local.bro')
        try:
            with open(zeek_site_local_path, 'r') as rf:
                for line in rf.readlines():
                    if '@load' in line:
                        scripts += line.strip() + '\n'
                    elif 'redef' in line:
                        redefs += line.strip() + '\n'
        except Exception as e:
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
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while writing {}; {}".format(zeek_site_local_path, e)
            )

        if self.stdout:
            sys.stdout.write('[+] Installing Corelight_CommunityID plugin.\n')
            self.setup_zeek_community_id_script()
        if self.stdout:
            sys.stdout.write('[+] Disabling unneeded Zeek scripts.\n')

        # Disable Unneeded Zeek scripts
        try:
            script_config = zeek_configs.ScriptConfigManager(self.configuration_directory)
        except zeek_exceptions.ReadsZeekConfigError:
            raise zeek_exceptions.InstallZeekError("Could not read Zeek script configuration.")
        try:
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
        except zeek_exceptions.ZeekScriptNotFoundError:
            raise zeek_exceptions.InstallZeekError("Could not disable one or more Zeek scripts.")
        try:
            script_config.write_config()
        except zeek_exceptions.WriteZeekConfigError:
            raise zeek_exceptions.InstallZeekError("Could not write Zeek script configuration.")

    def setup_zeek(self):
        """
        Setup Zeek NSM with PF_RING support
        """

        env_file = os.path.join(const.CONFIG_PATH, 'environment')
        if self.stdout:
            sys.stdout.write('[+] Creating zeek install|configuration|logging directories.\n')
        try:
            utilities.makedirs(self.install_directory, exist_ok=True)
            utilities.makedirs(self.configuration_directory, exist_ok=True)
        except Exception as e:
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while attempting to create root directories; {}".format(e))
        pf_ring_profiler = pfring_profile.ModuleProfile()
        try:
            pf_ring_install = pfring_install.InstallManager(self.install_directory,
                                                            download_pf_ring_archive=True,
                                                            stdout=self.stdout, verbose=self.verbose)
            if not pf_ring_profiler.is_installed:
                if self.stdout:
                    sys.stdout.write('[+] Installing PF_RING kernel modules and dependencies.\n')
                    sys.stdout.flush()
                    time.sleep(1)
                pf_ring_install.setup_pf_ring()
        except pf_ring_exceptions.InstallPfringError as e:
            raise zeek_exceptions.InstallZeekError("PF_RING could not be installed/configured properly; {}.".format(e))
        if self.stdout:
            sys.stdout.write('[+] Compiling Zeek from source. This can take up to 30 minutes. '
                             'Have a cup of coffee.\n')
            sys.stdout.flush()
            utilities.print_coffee_art()
            time.sleep(1)
        sys.stdout.write('[+] Configuring...\n')
        sys.stdout.flush()
        if self.verbose:
            zeek_config_p = subprocess.Popen('./configure --prefix={} --scriptdir={} --with-pcap={}'.format(
                self.install_directory, self.configuration_directory, pf_ring_install.install_directory),
                shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME))
        else:
            zeek_config_p = subprocess.Popen('./configure --prefix={} --scriptdir={} --with-pcap={}'.format(
                self.install_directory, self.configuration_directory, pf_ring_install.install_directory),
                shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        try:
            zeek_config_p.communicate()
        except Exception as e:
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while configuring Zeek; {}".format(e))
        if zeek_config_p.returncode != 0:
            raise zeek_exceptions.InstallZeekError(
                "Zeek configuration process returned non-zero; exit-code: {}".format(zeek_config_p.returncode))
        time.sleep(1)
        sys.stdout.write('[+] Compiling...\n')
        sys.stdout.flush()

        if self.verbose:
            compile_zeek_process = subprocess.Popen('make; make install', shell=True,
                                                    cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME))
            try:
                compile_zeek_process.communicate()
            except Exception as e:
                raise zeek_exceptions.InstallZeekError(
                    "General error occurred while compiling Zeek; {}".format(e))
            compile_zeek_return_code = compile_zeek_process.returncode
        else:
            compile_zeek_process = subprocess.Popen('make; make install', shell=True,
                                                    cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME),
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                compile_zeek_return_code = utilities.run_subprocess_with_status(compile_zeek_process,
                                                                                expected_lines=6596)
            except Exception as e:
                raise zeek_exceptions.InstallZeekError(
                    "General error occurred while compiling Zeek; {}".format(e))
        if compile_zeek_return_code != 0:
            sys.stderr.write('[-] Failed to compile Zeek from source; error code: {}; ; run with '
                             '--debug flag for more info.\n'.format(compile_zeek_process.returncode))
            raise zeek_exceptions.InstallZeekError(
                "Zeek compilation process returned non-zero; exit-code: {}".format(compile_zeek_return_code))
        try:
            with open(env_file) as env_f:
                if 'ZEEK_HOME' not in env_f.read():
                    if self.stdout:
                        sys.stdout.write('[+] Updating Zeek default home path [{}]\n'.format(
                            self.install_directory))
                    subprocess.call('echo ZEEK_HOME="{}" >> {}'.format(self.install_directory, env_file),
                                    shell=True)
                if 'ZEEK_SCRIPTS' not in env_f.read():
                    if self.stdout:
                        sys.stdout.write('[+] Updating Zeek default script path [{}]\n'.format(
                            self.configuration_directory))
                    subprocess.call('echo ZEEK_SCRIPTS="{}" >> {}'.format(self.configuration_directory, env_file),
                                    shell=True)
        except IOError:
            raise zeek_exceptions.InstallZeekError(
                "Failed to open {} for reading.".format(env_file))
        except Exception as e:
            raise zeek_exceptions.InstallZeekError(
                "General error while creating environment variables in {}; {}".format(env_file, e))
        if self.stdout:
            sys.stdout.write('[+] Overwriting default Script | Node configurations.\n')
        try:
            shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'broctl-nodes.cfg'),
                        os.path.join(self.install_directory, 'etc', 'node.cfg'))
            shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'local.bro'),
                        os.path.join(self.configuration_directory, 'site', 'local.bro'))
        except Exception as e:
            raise zeek_exceptions.InstallZeekError(
                "General error occurred while copying default zeek configurations; {}".format(e))
        try:
            node_config = zeek_configs.NodeConfigManager(self.install_directory)
        except zeek_exceptions.ReadsZeekConfigError:
            raise zeek_exceptions.InstallZeekError("An error occurred while reading Zeek configurations.")

        for worker in self.get_pf_ring_workers(self.capture_network_interfaces):
            node_config.add_worker(name=worker['name'],
                                   host=worker['host'],
                                   interface=worker['interface'],
                                   lb_procs=worker['lb_procs'],
                                   pin_cpus=worker['pinned_cpus']
                                   )
        try:
            node_config.write_config()
        except zeek_exceptions.WriteZeekConfigError:
            raise zeek_exceptions.InstallZeekError("An error occurred while writing Zeek configurations.")


def install_zeek(configuration_directory, install_directory, capture_network_interfaces, download_zeek_archive=True,
                 stdout=True, verbose=False):
    """
    Install Zeek

    :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
    :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
    :param capture_network_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
    :param download_zeek_archive: If True, download the Zeek archive from a mirror
    :param stdout: Print the output to console
    :param verbose: Include output from system utilities
    """

    zeek_profiler = zeek_profile.ProcessProfiler()
    if zeek_profiler.is_installed:
        raise zeek_exceptions.AlreadyInstalledZeekError()
    zeek_installer = InstallManager(configuration_directory, install_directory,
                                    capture_network_interfaces=capture_network_interfaces,
                                    download_zeek_archive=download_zeek_archive, stdout=stdout, verbose=verbose)

    zeek_installer.setup_zeek()
    zeek_installer.setup_dynamite_zeek_scripts()


def uninstall_zeek(stdout=False, prompt_user=True):
    """
    Uninstall Zeek

    :param stdout: Print the output to console
    :param prompt_user: Print a warning before continuing
    """

    env_file = os.path.join(const.CONFIG_PATH, 'environment')
    environment_variables = utilities.get_environment_file_dict()
    zeek_profiler = zeek_profile.ProcessProfiler()
    pf_ring_profiler = pfring_profile.ModuleProfile()
    if not zeek_profiler.is_installed:
        raise zeek_exceptions.UninstallZeekError("Zeek is not installed.")
    if prompt_user:
        sys.stderr.write('[-] WARNING! Removing Zeek Will Remove Critical Agent Functionality.\n')
        resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = utilities.prompt_input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            if stdout:
                sys.stdout.write('[+] Exiting\n')
            exit(0)
    if zeek_profiler.is_running:
        try:
            zeek_process.ProcessManager().stop()
        except zeek_exceptions.CallZeekProcessError:
            raise zeek_exceptions.UninstallZeekError("Could not kill Zeek process.")

    if pf_ring_profiler.is_installed:
        shutil.rmtree(environment_variables.get('PF_RING_HOME'))
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
        if zeek_profiler.is_installed:
            shutil.rmtree(install_directory, ignore_errors=True)
            shutil.rmtree(config_directory, ignore_errors=True)
    except Exception as e:
        raise zeek_exceptions.UninstallZeekError(
            "General error occurred while attempting to uninstall zeek; {}".format(e))
