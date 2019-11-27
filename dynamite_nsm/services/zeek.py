import os
import re
import sys
import time
import shutil
import tarfile
import subprocess

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.services.helpers import pf_ring


CONFIGURATION_DIRECTORY = '/etc/dynamite/zeek/'
INSTALL_DIRECTORY = '/opt/dynamite/zeek/'


class ZeekScriptConfigurator:
    """
    Wrapper for configuring broctl sites/local.bro
    """
    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
        """
        self.configuration_directory = configuration_directory
        self.zeek_scripts = {}
        self.zeek_sigs = {}
        self.zeek_redefs = {}

        self._parse_zeek_scripts()

    def _parse_zeek_scripts(self):
        """
        Parse the local.bro configuration file, and determine which scripts are enabled/disabled
        """
        for line in open(os.path.join(self.configuration_directory, 'site', 'local.bro')).readlines():
            line = line.replace(' ', '').strip()
            if '@load-sigs' in line:
                if line.startswith('#'):
                    enabled = False
                    line = line[1:]
                else:
                    enabled = True
                sigs = line.split('@load-sigs')[1]
                self.zeek_sigs[sigs] = enabled
            elif '@load' in line:
                if line.startswith('#'):
                    enabled = False
                    line = line[1:]
                else:
                    enabled = True
                script = line.split('@load')[1]
                self.zeek_scripts[script] = enabled
            elif line.startswith('redef'):
                definition, value = line.split('redef')[1].split('=')
                self.zeek_redefs[definition] = value

    def disable_script(self, name):
        """
        :param name: The name of the script (E.G protocols/http/software)
        :return: True, if the script was successfully disabled
        """
        try:
            self.zeek_scripts[name] = False
            return True
        except KeyError:
            return False

    def enable_script(self, name):
        """
        :param name: The name of the script (E.G protocols/http/software)
        :return: True, if the script was successfully enabled
        """
        try:
            self.zeek_scripts[name] = True
            return True
        except KeyError:
            return False

    def list_disabled_scripts(self):
        """
        :return: A list of disabled Zeek scripts
        """
        return [script for script in self.zeek_scripts.keys() if not self.zeek_scripts[script]]

    def list_enabled_scripts(self):
        """
        :return: A list of enabled Zeek scripts
        """
        return [script for script in self.zeek_scripts.keys() if self.zeek_scripts[script]]

    def list_enabled_sigs(self):
        """
        :return: A list of enabled Zeek signatures
        """
        return [sig for sig in self.zeek_sigs.keys() if self.zeek_sigs[sig]]

    def list_disabled_sigs(self):
        """
        :return: A list of disabled Zeek signatures
        """
        return [sig for sig in self.zeek_sigs.keys() if not self.zeek_sigs[sig]]

    def list_redefinitions(self):
        return [(redef, val) for redef, val in self.zeek_redefs.items()]

    def write_config(self):
        """
        Overwrite the existing local.bro config with changed values
        """
        timestamp = int(time.time())
        output_str = ''
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        zeek_config_backup = os.path.join(backup_configurations, 'local.bro.backup.{}'.format(timestamp))

        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        for e_script in self.list_enabled_scripts():
            output_str += '@load {}\n'.format(e_script)
        for d_script in self.list_disabled_scripts():
            output_str += '#@load {}\n'.format(d_script)
        for e_sig in self.list_enabled_sigs():
            output_str += '@load-sigs {}\n'.format(e_sig)
        for d_sig in self.list_disabled_sigs():
            output_str += '@load-sigs {}\n'.format(d_sig)
        for rdef, val in self.list_redefinitions():
            output_str += 'redef {} = {}\n'.format(rdef, val)
        shutil.move(os.path.join(self.configuration_directory, 'site', 'local.bro'), zeek_config_backup)
        with open(os.path.join(self.configuration_directory, 'site', 'local.bro'), 'w') as f:
            f.write(output_str)


class ZeekNodeConfigurator:
    """
    Wrapper for configuring broctl node.cfg
    """
    def __init__(self, install_directory=INSTALL_DIRECTORY):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        """
        self.install_directory = install_directory
        self.node_config = self._parse_node_config()

    def _parse_node_config(self):
        """
        :return: A dictionary representing the configurations storred within node.cfg
        """
        node_config = {}
        config_parser = ConfigParser()
        config_parser.readfp(open(os.path.join(self.install_directory, 'etc', 'node.cfg')))
        for section in config_parser.sections():
            node_config[section] = {}
            for item in config_parser.items(section):
                key, value = item
                node_config[section][key] = value
        return node_config

    def add_logger(self, name, host):
        """
        :param name: The name of the logger
        :param host: The host on which the logger is running
        :return: True, if added successfully
        """
        self.node_config[name] = {
            'type': 'logger',
            'host': host
        }
        return True

    def add_manager(self, name, host):
        """
        :param name: The name of the manager
        :param host: The host on which the manager is running
        :return: True, if added successfully
        """
        self.node_config[name] = {
            'type': 'manager',
            'host': host
        }
        return True

    def add_proxy(self, name, host):
        """
        :param name: The name of the proxy
        :param host: The host on which the proxy is running
        :return: True, if added successfully
        """
        self.node_config[name] = {
            'type': 'proxy',
            'host': host
        }
        return True

    def add_worker(self, name, interface, host, lb_procs=10, pin_cpus=(0, 1)):
        """
        :param name: The name of the worker
        :param interface: The interface that the worker should be monitoring
        :param host: The host on which the worker is running
        :param lb_procs: The number of Zeek processes associated with a given worker
        :param pin_cpus: Core affinity for the processes (iterable)
        :return: True, if added successfully
        """
        if max(pin_cpus) < utilities.get_cpu_core_count() and min(pin_cpus) >= 0:
            pin_cpus = [str(cpu_n) for cpu_n in pin_cpus]
            self.node_config[name] = {
                'type': 'worker',
                'interface': interface,
                'lb_method': 'pf_ring',
                'lb_procs': lb_procs,
                'pin_cpus': ','.join(pin_cpus),
                'host': host
            }
            return True
        return False

    def remove_logger(self, name):
        """
        :param name: The name of the logger
        :return: True, if successfully removed
        """
        try:
            if self.node_config[name]['type'] == 'logger':
                del self.node_config[name]
            else:
                return False
        except KeyError:
            return False

    def remove_manager(self, name):
        """
        :param name: The name of the manager
        :return: True, if successfully removed
        """
        try:
            if self.node_config[name]['type'] == 'manager':
                del self.node_config[name]
            else:
                return False
        except KeyError:
            return False

    def remove_proxy(self, name):
        """
        :param name: The name of the proxy
        :return: True, if successfully removed
        """
        try:
            if self.node_config[name]['type'] == 'proxy':
                del self.node_config[name]
            else:
                return False
        except KeyError:
            return False

    def remove_worker(self, name):
        """
        :param name: The name of the worker
        :return: True, if successfully removed
        """
        try:
            if self.node_config[name]['type'] == 'worker':
                del self.node_config[name]
            else:
                return False
        except KeyError:
            return False
        return True

    def list_workers(self):
        """
        :return: A list of worker names
        """
        workers = []
        for component, values in self.node_config.items():
            if values['type'] == 'worker':
                workers.append(component)
        return workers

    def list_proxies(self):
        """
        :return: A list of proxy names
        """
        proxies = []
        for component, values in self.node_config.items():
            if values['type'] == 'proxy':
                proxies.append(component)
        return proxies

    def list_loggers(self):
        """
        :return: A list of logger names
        """
        loggers = []
        for component, values in self.node_config.items():
            if values['type'] == 'logger':
                loggers.append(component)
        return loggers

    def get_manager(self):
        """
        :return: The name of the manager
        """
        for component, values in self.node_config.items():
            if values['type'] == 'manager':
                return component
        return None

    def write_config(self):
        """
        Overwrite the existing node.cfg with changed values
        """
        config = ConfigParser()
        for section in self.node_config.keys():
            for k, v in self.node_config[section].items():
                try:
                    config.add_section(section)
                except Exception: # Duplicate section
                    pass
                config.set(section, k, str(v))
                with open(os.path.join(self.install_directory, 'etc', 'node.cfg'), 'w') as configfile:
                    config.write(configfile)


class ZeekInstaller:

    def __init__(self,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 install_directory=INSTALL_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        """

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory

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
    def install_dependencies():
        """
        Install the required dependencies required by Zeek

        :return: True, if all packages installed successfully
        """
        pacman = package_manager.OSPackageManager()
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

    def setup_dynamite_zeek_scripts(self):
        """
        Installs and enables extra dynamite Zeek scripts

        :return: True if zeek scripts were successfully installed
        """
        scripts = ''
        redefs = ''
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
        return True

    def setup_zeek(self, network_interface=None, stdout=False):
        """
        Setup Zeek NSM with PF_RING support

        :param stdout: Print output to console
        :param network_interface: The interface to listen on
        :return: True, if setup successful
        """
        if not network_interface:
            network_interface = utilities.get_network_interface_names()[0]
        if network_interface not in utilities.get_network_interface_names():
            sys.stderr.write(
                '[-] The network interface that your defined: \'{}\' is invalid. Valid network interfaces: {}\n'.format(
                    network_interface, utilities.get_network_interface_names()))
            return False
        if stdout:
            sys.stdout.write('[+] Creating zeek install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        pf_ring_install = pf_ring.PFRingInstaller()
        if not pf_ring.PFRingProfiler().is_installed:
            if stdout:
                sys.stdout.write('[+] Installing PF_RING kernel modules and dependencies.\n')
                sys.stdout.flush()
                time.sleep(1)
            pf_ring_install.download_pf_ring(stdout=True)
            pf_ring_install.extract_pf_ring(stdout=True)
            pf_ring_install.setup_pf_ring(stdout=True)
        if stdout:
            sys.stdout.write('\n\n[+] Compiling Zeek from source. This can take up to 30 minutes. Have a cup of coffee.'
                             '\n\n')
            sys.stdout.flush()
            time.sleep(5)
        subprocess.call('./configure --prefix={} --scriptdir={} --with-pcap={}'.format(
            self.install_directory, self.configuration_directory, pf_ring_install.install_directory),
            shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME))
        subprocess.call('make; make install', shell=True, cwd=os.path.join(const.INSTALL_CACHE,
                                                                           const.ZEEK_DIRECTORY_NAME))

        if 'ZEEK_HOME' not in open('/etc/dynamite/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Zeek default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo ZEEK_HOME="{}" >> /etc/dynamite/environment'.format(self.install_directory),
                            shell=True)
        if 'ZEEK_SCRIPTS' not in open('/etc/dynamite/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Zeek default script path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo ZEEK_SCRIPTS="{}" >> /etc/dynamite/environment'.format(self.configuration_directory),
                            shell=True)
        if stdout:
            sys.stdout.write('[+] Overwriting default Script | Node configurations.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'broctl-nodes.cfg'),
                    os.path.join(self.install_directory, 'etc', 'node.cfg'))
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'local.bro'),
                    os.path.join(self.configuration_directory, 'site', 'local.bro'))

        # Disable Unneeded Zeek scripts
        script_config = ZeekScriptConfigurator()
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

        node_config = ZeekNodeConfigurator(self.install_directory)

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


class ZeekProfiler:
    """
    An interface for profiling Zeek NSM
    """
    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_running = self._is_running()

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.ZEEK_ARCHIVE_NAME)):
            if stderr:
                sys.stderr.write('[-] Zeek installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        zeek_home = env_dict.get('ZEEK_HOME')
        zeek_scripts = env_dict.get('ZEEK_SCRIPTS')
        if not zeek_home:
            if stderr:
                sys.stderr.write('[-] ZEEK_HOME installation directory could not be located in /etc/dynamite/environment.\n')
            return False
        if not zeek_scripts:
            if stderr:
                sys.stderr.write('[-] ZEEK_SCRIPTS directory could not be located in /etc/dynamite/environment.\n')
            return False
        if not os.path.exists(zeek_home):
            if stderr:
                sys.stderr.write('[-] ZEEK_HOME installation directory could not be located on disk at: {}.\n'.format(
                    zeek_home))
            return False
        if not os.path.exists(zeek_scripts):
            if stderr:
                sys.stderr.write('[-] ZEEK_SCRIPTS directory could not be located on disk at: {}.\n'.format(
                    zeek_scripts))
            return False
        zeek_home_directories = os.listdir(zeek_home)
        zeek_scripts_directories = os.listdir(zeek_scripts)
        if 'bin' not in zeek_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate ZEEK_HOME {}/bin directory.\n'.format(zeek_home))
            return False
        elif 'lib' not in zeek_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate ZEEK_HOME {}/lib directory.\n'.format(zeek_home))
            return False
        elif 'etc' not in zeek_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate ZEEK_HOME {}/etc directory.\n'.format(zeek_home))
            return False
        if 'site' not in zeek_scripts_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate ZEEK_SCRIPTS {}/site directory.\n'.format(zeek_scripts))
            return False
        return True

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }

    @staticmethod
    def _is_running():
        env_dict = utilities.get_environment_file_dict()
        zeek_home = env_dict.get('ZEEK_HOME')
        if zeek_home:
            return ZeekProcess().status()['RUNNING']
        return False


class ZeekProcess:

    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('ZEEK_HOME')

    def start(self, stdout=False):
        """
        Start Zeek cluster via broctl

        :param stdout: Print output to console
        :return: True, if started successfully
        """
        if stdout:
            sys.stdout.write('[+] Attempting to start Zeek cluster.\n')
        p = subprocess.Popen('{} deploy'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True)
        p.communicate()
        return p.returncode == 0

    def stop(self, stdout=False):
        """
        Stop Zeek cluster via broctl

        :param stdout: Print output to console
        :return: True, if stopped successfully
        """
        if stdout:
            sys.stdout.write('[+] Attempting to stop Zeek cluster.\n')
        p = subprocess.Popen('{} stop'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True)
        p.communicate()
        return p.returncode == 0

    def status(self):
        """
        Check the status of all workers, proxies, and manager in Zeek cluster

        :return: A string containing the results outputted from 'broctl status'
        """
        p = subprocess.Popen('{} status'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True,
                             stdout=subprocess.PIPE)
        out, err = p.communicate()
        raw_output = out.decode('utf-8')

        zeek_status = {
            'RUNNING': False,
            'SUBPROCESSES': []
        }
        zeek_subprocesses = []
        for line in raw_output.split('\n')[1:]:
            tokenized_line = re.findall(r'\S+', line)
            if len(tokenized_line) == 8:
                name, _type, host, status, pid, _, _, _ = tokenized_line
                zeek_status['RUNNING'] = True
            elif len(tokenized_line) == 4:
                name, _type, host, status = tokenized_line
                pid = None
            else:
                continue
            zeek_subprocesses.append(
                {
                    'process_name': name,
                    'process_type': _type,
                    'host': host,
                    'status': status,
                    'pid': pid
                }
            )
        zeek_status['SUBPROCESSES'] = zeek_subprocesses
        return zeek_status

    def restart(self, stdout=False):
        """
        Restart the Zeek process via broctl

        :param stdout: Print output to console
        :return: True if restarted successfully
        """
        if stdout:
            sys.stdout.write('[+] Attempting to restart Zeek cluster.\n')
        p = subprocess.Popen('{} restart'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True)
        p.communicate()
        return p.returncode == 0