import os
import sys
import time
import shutil
import tarfile
import subprocess

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from lib import const
from lib import pf_ring
from lib import utilities
from lib import package_manager


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
        self.zeek_scripts = None
        self.zeek_sigs = None
        self._parse_zeek_scripts()

    def _parse_zeek_scripts(self):
        """
        Parse the local.bro configuration file, and determine which scripts are enabled/disabled
        """
        self.zeek_scripts = {}
        self.zeek_sigs = {}
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

    def get_disabled_scripts(self):
        """
        :return: A list of disabled Zeek scripts
        """
        return [script for script in self.zeek_scripts.keys() if not self.zeek_scripts[script]]

    def get_enabled_scripts(self):
        """
        :return: A list of enabled Zeek scripts
        """
        return [script for script in self.zeek_scripts.keys() if self.zeek_scripts[script]]

    def get_enabled_sigs(self):
        """
        :return: A list of enabled Zeek signatures
        """
        return [sig for sig in self.zeek_sigs.keys() if self.zeek_sigs[sig]]

    def get_disabled_sigs(self):
        """
        :return: A list of disabled Zeek signatures
        """
        return [sig for sig in self.zeek_sigs.keys() if not self.zeek_sigs[sig]]

    def write_config(self):
        """
        Overwrite the existing local.bro config with changed values
        """
        timestamp = int(time.time())
        output_str = ''
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        zeek_config_backup = os.path.join(backup_configurations, 'local.bro.backup.{}'.format(timestamp))

        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        for e_script in self.get_enabled_scripts():
            output_str += '@load {}\n'.format(e_script)
        for d_script in self.get_disabled_scripts():
            output_str += '#@load {}\n'.format(d_script)
        for e_sig in self.get_enabled_sigs():
            output_str += '@load-sigs {}\n'.format(e_sig)
        for d_sig in self.get_disabled_sigs():
            output_str += '@load-sigs {}\n'.format(d_sig)
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
            if self.node_config[name]['type'] == 'worker':
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
        pkt_mng = package_manager.OSPackageManager()
        if not pkt_mng.refresh_package_indexes():
            return False
        packages = None
        if pkt_mng.package_manager == 'apt-get':
            packages = ['cmake', 'make', 'gcc', 'g++', 'flex', 'bison', 'libpcap-dev', 'libssl-dev',
                        'python-dev', 'swig', 'zlib1g-dev']
        elif pkt_mng.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libpcap-devel', 'openssl-devel',
                        'python-devel', 'swig', 'zlib-devel']
        if packages:
            return pkt_mng.install_packages(packages)
        return False

    def setup_zeek(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Creating zeek install|configuration|logging directories.\n')
        subprocess.call('mkdir -p {}'.format(self.install_directory), shell=True)
        subprocess.call('mkdir -p {}'.format(self.configuration_directory), shell=True)
        if stdout:
            sys.stdout.write('[+] Installing PF_RING kernel modules and dependencies.\n')
            sys.stdout.flush()
            time.sleep(1)
        pf_ring_install = pf_ring.PFRingInstaller()
        pf_ring_install.download_pf_ring(stdout=True)
        pf_ring_install.extract_pf_ring(stdout=True)
        pf_ring_install.setup_pf_ring(stdout=True)
        if stdout:
            sys.stdout.write('[+] Compiling Zeek from source. This can take up to 30 minutes. Have a cup of coffee.')
            sys.stdout.flush()
            time.sleep(5)
        subprocess.call('./configure --prefix={} --scriptdir={} --with-pcap={}'.format(
            self.install_directory, self.configuration_directory, pf_ring_install.install_directory),
            shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.ZEEK_DIRECTORY_NAME))
        subprocess.call('make; make install', shell=True, cwd=os.path.join(const.INSTALL_CACHE,
                                                                           const.ZEEK_DIRECTORY_NAME))

        if 'ZEEK_HOME' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Zeek default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo ZEEK_HOME="{}" >> /etc/environment'.format(self.install_directory),
                            shell=True)
        if 'ZEEK_SCRIPTS' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Zeek default script path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo ZEEK_SCRIPTS="{}" >> /etc/environment'.format(self.configuration_directory),
                            shell=True)
        if stdout:
            sys.stdout.write('[+] Overwriting default Script | Node configurations.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'broctl-nodes.cfg'),
                    os.path.join(self.install_directory, 'etc', 'node.cfg'))
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'local.bro'),
                    os.path.join(self.configuration_directory, 'site', 'local.bro'))
        ZeekScriptConfigurator().write_config()

        node_config = ZeekNodeConfigurator(self.install_directory)

        available_cpus = utilities.get_cpu_core_count()
        workers_cpu_grps = [range(0, available_cpus)[n:n + 2] for n in range(0, len(range(0, available_cpus)), 2)]

        for i, cpu_group in enumerate(workers_cpu_grps):
            node_config.add_worker(name='dynamite-worker-{}'.format(i + 1),
                                   host='localhost',
                                   interface=utilities.get_network_interface_names()[0],
                                   lb_procs=10,
                                   pin_cpus=cpu_group
                                   )
            node_config.write_config()


class ZeekProcess:

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        """
        self.install_directory = install_directory

    def start(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Attempting to start Zeek cluster.\n')
        p = subprocess.Popen('{} deploy'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True)
        p.communicate()
        return p.returncode == 0

    def stop(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Attempting to stop Zeek cluster.\n')
        p = subprocess.Popen('{} stop'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True)
        p.communicate()
        return p.returncode == 0

    def status(self):
        p = subprocess.Popen('{} status'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True,
                             stdout=subprocess.PIPE)
        return p.communicate()

    def restart(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Attempting to restart Zeek cluster.\n')
        p = subprocess.Popen('{} restart'.format(os.path.join(self.install_directory, 'bin', 'broctl')), shell=True)
        p.communicate()
        return p.returncode == 0
