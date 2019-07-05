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

from installer import const
from installer import pf_ring
from installer import utilities
from installer import package_manager


CONFIGURATION_DIRECTORY = '/etc/dynamite/zeek/'
INSTALL_DIRECTORY = '/opt/dynamite/zeek/'


class ZeekScriptConfigurator:

    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        self.configuration_directory = configuration_directory
        self.zeek_scripts = None
        self.zeek_sigs = None
        self._parse_zeek_scripts()

    def _parse_zeek_scripts(self):
        self.zeek_scripts = {}
        self.zeek_sigs = {}
        for line in open(os.path.join(self.configuration_directory, 'site','local.bro')).readlines():
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

    def get_enabled_scripts(self):
        return [script for script in self.zeek_scripts.keys() if self.zeek_scripts[script]]

    def get_disabled_scripts(self):
        return [script for script in self.zeek_scripts.keys() if not self.zeek_scripts[script]]

    def get_enabled_sigs(self):
        return [sig for sig in self.zeek_sigs.keys() if self.zeek_sigs[sig]]

    def get_disabled_sigs(self):
        return [sig for sig in self.zeek_sigs.keys() if not self.zeek_sigs[sig]]

    def write_config(self):
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

    def __init__(self, install_directory=INSTALL_DIRECTORY):
        self.install_directory = install_directory
        self.node_config = self._parse_node_config()

    def _parse_node_config(self):
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
        self.node_config[name] = {
            'type': 'logger',
            'host': host
        }

    def add_manager(self, name, host):
        self.node_config[name] = {
            'type': 'manager',
            'host': host
        }

    def add_proxy(self, name, host):
        self.node_config[name] = {
            'type': 'proxy',
            'host': host
        }

    def add_worker(self, name, interface, host, lb_procs=10, pin_cpus=(0, 1)):
        pin_cpus = [str(cpu_n) for cpu_n in pin_cpus]
        self.node_config[name] = {
            'type': 'worker',
            'interface': interface,
            'lb_method': 'pf_ring',
            'lb_procs': lb_procs,
            'pin_cpus': ','.join(pin_cpus),
            'host': host
        }

    def remove_logger(self, name):
        if self.node_config[name]['type'] == 'worker':
            self.node_config[name].pop()

    def remove_manager(self, name):
        if self.node_config[name]['type'] == 'manager':
            self.node_config[name].pop()

    def remove_proxy(self, name):
        if self.node_config[name]['type'] == 'proxy':
            self.node_config[name].pop()

    def remove_worker(self, name):
        if self.node_config[name]['type'] == 'worker':
            self.node_config[name].pop()

    def write_config(self):
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
        """
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
            shell=True, cwd=os.path.join(const.INSTALL_CACHE, 'bro-2.6.2'))
        subprocess.call('make; make install', shell=True, cwd=os.path.join(const.INSTALL_CACHE, 'bro-2.6.2'))
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
        """
        if stdout:
            sys.stdout.write('[+] Overwriting default Script | Node configurations.\n')
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'broctl-nodes.cfg'),
                    os.path.join(self.install_directory, 'etc', 'node.cfg'))
        shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'local.bro'),
                    os.path.join(self.configuration_directory, 'site', 'local.bro'))
        ZeekScriptConfigurator().write_config()
        node_config = ZeekNodeConfigurator(self.install_directory)
        available_cpus = utilities.get_cpu_core_count() -1
        workers_cpu_grps = [range(0, available_cpus)[n:n + 2] for n in range(0, len(range(0, available_cpus)), 2)]

        for i, cpu_group in enumerate(workers_cpu_grps):
            node_config.add_worker(name='dynamite-worker-{}'.format(i + 1),
                                   host='localhost',
                                   interface=utilities.get_network_interface_names()[0],
                                   lb_procs=10,
                                   pin_cpus=cpu_group
                                   )
            node_config.write_config()