import os
import sys
import time
import shutil
import signal
import tarfile
import subprocess

from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.services.helpers import pf_ring
from dynamite_nsm.services.helpers import oinkmaster


INSTALL_DIRECTORY = '/opt/dynamite/suricata/'
CONFIGURATION_DIRECTORY = '/etc/dynamite/suricata/'
LOG_DIRECTORY = '/var/log/dynamite/suricata/'


class SuricataConfigurator:
    """
    Wrapper for configuring suricata.yml
    """
    default_suricata_rules = [
        'botcc.rules','botcc.portgrouped.rules','ciarmy.rules',
        'compromised.rules','drop.rules','dshield.rules',
        'emerging-attack_response.rules','emerging-chat.rules',
        'emerging-current_events.rules','emerging-dns.rules',
        'emerging-dos.rules','emerging-exploit.rules',
        'emerging-ftp.rules','emerging-imap.rules',
        'emerging-malware.rules','emerging-misc.rules',
        'emerging-mobile_malware.rules','emerging-netbios.rules',
        'emerging-p2p.rules','emerging-policy.rules',
        'emerging-pop3.rules','emerging-rpc.rules',
        'emerging-smtp.rules','emerging-snmp.rules',
        'emerging-sql.rules','emerging-telnet.rules',
        'emerging-tftp.rules','emerging-trojan.rules',
        'emerging-user_agents.rules','emerging-voip.rules',
        'emerging-web_client.rules','emerging-web_server.rules',
        'emerging-worm.rules','tor.rules',
        'http-events.rules','smtp-events.rules',
        'dns-events.rules','tls-events.rules',
    ]
    tokens = {
        'home_net': ('vars', 'address-groups', 'HOME_NET'),
        'external_net': ('vars', 'address-groups', 'EXTERNAL_NET'),
        'http_net': ('vars', 'address-groups', 'HTTP_SERVERS'),
        'sql_servers': ('vars', 'address-groups', 'SQL_SERVERS'),
        'dns_servers': ('vars', 'address-groups', 'DNS_SERVERS'),
        'telnet_servers': ('vars', 'address-groups', 'TELNET_SERVERS'),
        'aim_servers': ('vars', 'address-groups', 'AIM_SERVERS'),
        'dc_servers': ('vars', 'address-groups', 'DC_SERVERS'),
        'dnp3_servers': ('vars', 'address-groups', 'DNP3_SERVERS'),
        'modbus_client': ('vars', 'address-groups', 'MODBUS_CLIENT'),
        'modbus_server': ('vars', 'address-groups', 'MODBUS_SERVER'),
        'enip_client': ('vars', 'address-groups', 'ENIP_CLIENT'),
        'enip_server': ('vars', 'address-groups', 'ENIP_SERVER'),
        'http_ports': ('vars', 'port-groups', 'HTTP_PORTS'),
        'shellcode_ports': ('vars', 'port-groups', 'SHELLCODE_PORTS'),
        'oracle_ports': ('vars', 'port-groups', 'ORACLE_PORTS'),
        'ssh_ports': ('vars', 'port-groups', 'SSH_PORTS'),
        'dnp3_ports': ('vars', 'port-groups', 'DNP3_PORTS'),
        'modbus_ports': ('vars', 'port-groups', 'MODBUS_PORTS'),
        'file_data_ports': ('vars', 'port-groups', 'FILE_DATA_PORTS'),
        'ftp_ports': ('vars', 'port-groups', 'FTP_PORTS'),
        'default_log_directory': ('default-log-dir',),
        'default_rules_directory': ('default-rule-path',),
        'classification_file': ('classification-file',),
        'reference_config_file': ('reference-config-file',),
        'af_packet_interfaces': ('af-packet',),
        'pcap_interfaces': ('pcap',),
        'pfring_interfaces': ('pfring',),
        'rule_files': ('rule-files',)
    }

    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
        """
        self.configuration_directory = configuration_directory
        self.config_data = None

        self.home_net = None
        self.external_net = None
        self.http_net = None
        self.sql_servers = None
        self.dns_servers = None
        self.telnet_servers = None
        self.aim_servers = None
        self.dc_servers = None
        self.modbus_client = None
        self.modbus_server = None
        self.enip_client = None
        self.enip_server = None
        self.http_ports = None
        self.shellcode_ports = None
        self.oracle_ports = None
        self.ssh_ports = None
        self.dnp3_ports = None
        self.modbus_ports = None
        self.default_log_directory = None
        self.default_rules_directory = None
        self.classification_file = None
        self.reference_config_file = None
        self.af_packet_interfaces = None
        self.pcap_interfaces = None
        self.pfring_interfaces = None
        self.rule_files = None
        self._parse_suricatayaml()

    def _parse_suricatayaml(self):

        def set_instance_var_from_token(variable_name, data):
            """
            :param variable_name: The name of the instance variable to update
            :param data: The parsed yaml object
            :return: True if successfully located
            """
            if variable_name not in self.tokens.keys():
                return False
            key_path = self.tokens[variable_name]
            value = data
            for k in key_path:
                value = value[k]
            setattr(self, var_name, value)
            return True

        with open(os.path.join(self.configuration_directory, 'suricata.yaml'), 'r') as configyaml:
            self.config_data = load(configyaml, Loader=Loader)

        for var_name in vars(self).keys():
            set_instance_var_from_token(variable_name=var_name, data=self.config_data)

    def add_afpacket_interface(self, interface, threads=None, cluster_id=None, cluster_type='cluster_flow',
                                bpf_filter=None):
        """
        Add a new AF_PACKET interface to monitor

        :param interface: The name of the interface to monitor (eth0, mon0)
        :param threads: "auto" or the number of threads
        :param cluster_id: The AF_PACKET cluster id; AF_PACKET will load balance packets based on flow
        :param cluster_type: Recommended modes are cluster_flow on most boxes and cluster_cpu or cluster_qm on system
        :param bpf_filter: bpf filter for this interface (E.G tcp)
        :return: None
        """
        interface_config = {
            'interface': interface
        }
        if threads:
            interface_config['threads'] = threads
        if cluster_id:
            interface_config['cluster-id'] = cluster_id
        if cluster_type:
            interface_config['cluster-type'] = cluster_type
        if bpf_filter:
            interface_config['bpf-filter'] = bpf_filter

        self.af_packet_interfaces.append(interface_config)

    def add_pfring_interface(self, interface, threads=None, cluster_id=None, cluster_type='cluster_flow',
                             bpf_filter=None):
        """
        Add a new PF_RING interface to monitor

        :param interface: The name of the interface to monitor (eth0, mon0)
        :param threads: "auto" or the number of threads
        :param cluster_id: The PF_RING cluster id; PF_RING will load balance packets based on flow
        :param cluster_type: Recommended modes are cluster_flow on most boxes and cluster_cpu or cluster_qm on system
        :param bpf_filter: bpf filter for this interface (E.G tcp)
        :return: None
        """
        interface_config = {
                'interface': interface
        }
        if threads:
            interface_config['threads'] = threads
        if cluster_id:
            interface_config['cluster-id'] = cluster_id
        if cluster_type:
            interface_config['cluster-type'] = cluster_type
        if bpf_filter:
            interface_config['bpf-filter'] = bpf_filter

        self.pfring_interfaces.append(interface_config)

    def remove_afpacket_interface(self, interface):
        """
        Remove an existing AF_PACKET interface

        :param interface: The name of the interface to remove (eth0, mon0)
        :return: None
        """
        new_interface_config = []
        for interface_config in self.af_packet_interfaces:
            if interface_config['interface'] == interface:
                continue
            else:
                new_interface_config.append(interface_config)
        self.af_packet_interfaces = new_interface_config

    def remove_pfring_interface(self, interface):
        """
        Remove an existing PF_RING interface

        :param interface: The name of the interface to remove (eth0, mon0)
        :return: None
        """
        new_interface_config = []
        for interface_config in self.pfring_interfaces:
            if interface_config['interface'] == interface:
                continue
            else:
                new_interface_config.append(interface_config)
        self.pfring_interfaces = new_interface_config

    def list_enabled_rules(self):
        """
        List enabled rules

        :return: A list of enabled rule files
        """
        return [rule for rule in self.default_suricata_rules if rule in self.rule_files]

    def list_disabled_rules(self):
        """
        List disabled rules

        :return: A list of disabled rule files
        """
        return [rule for rule in self.default_suricata_rules if rule not in self.rule_files]

    def enable_rule(self, rule_file):
        """
        Enable a rule

        :param rule_file: The name of the rule to enable
        :return: None
        """
        if rule_file not in self.list_enabled_rules():
            self.rule_files.append(rule_file)

    def disable_rule(self, rule_file):
        """
        Disable a rule

        :param rule_file: The name of the rule to disable
        :return: None
        """
        if rule_file in self.list_enabled_rules():
            self.rule_files.remove(rule_file)

    def write_config(self):
        """
        Overwrite the existing suricata.yaml config with changed values
        """

        def update_dict_from_path(path, value):
            """
            :param path: A tuple representing each level of a nested path in the yaml document
                        ('vars', 'address-groups', 'HOME_NET') = /vars/address-groups/HOME_NET
            :param value: The new value
            :return: None
            """
            partial_config_data = self.config_data
            for i in range(0, len(path) - 1):
                partial_config_data = partial_config_data[path[i]]
            partial_config_data.update({path[-1]: value})

        timestamp = int(time.time())
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        suricata_config_backup = os.path.join(backup_configurations, 'suricata.yaml.backup.{}'.format(timestamp))
        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        shutil.copy(os.path.join(self.configuration_directory, 'suricata.yaml'), suricata_config_backup)

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        with open(os.path.join(self.configuration_directory, 'suricata.yaml'), 'w') as configyaml:
            configyaml.write('%YAML 1.1\n---\n\n')
            dump(self.config_data, configyaml, default_flow_style=False)


class SuricataInstaller:

    def __init__(self,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 install_directory=INSTALL_DIRECTORY,
                 log_directory=LOG_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/suricata/)
        """

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory
        self.log_directory = log_directory

    def _configure_and_compile_suricata(self, pf_ring_installer, stdout=False):
        if self.configuration_directory.endswith('/'):
            suricata_config_parent = '/'.join(self.configuration_directory.split('/')[:-2])
        else:
            suricata_config_parent = '/'.join(self.configuration_directory.split('/')[:-1])
        if stdout:
            sys.stdout.write('\n\n[+] Compiling Suricata from source. This can take up to 5 minutes.\n\n')
            sys.stdout.flush()
        configure_result = subprocess.call('./configure --prefix={} --sysconfdir={} '
                                           '--localstatedir=/var/dynamite/suricata --enable-pfring '
                                           '--with-libpfring-includes={} -with-libpfring-libraries={}'.format(
                                                self.install_directory,
                                                suricata_config_parent,
                                                os.path.join(pf_ring_installer.install_directory, 'include'),
                                                os.path.join(pf_ring_installer.install_directory, 'lib')),
            shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME))
        if configure_result != 0:
            sys.stderr.write('[-] Unable to configure Suricata installation files: {}\n')
            return False
        compile_result = subprocess.call('make; make install; make install-conf', shell=True, cwd=os.path.join(
            const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME)
        )
        if compile_result != 0:
            sys.stderr.write('[-] Unable to compile Suricata installation package: {}\n')
            return False
        return True

    def _copy_suricata_files_and_directories(self, stdout=False):
        if stdout:
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

    def _setup_suricata_rules(self, stdout=False):
        if stdout:
            sys.stdout.write('[+] Installing Oinkmaster.\n')
        oink_installer = oinkmaster.OinkmasterInstaller(
            install_directory=os.path.join(self.install_directory, 'oinkmaster')
        )
        try:
            oink_installer.download_oinkmaster(stdout=stdout)
        except Exception as e:
            sys.stderr.write('[-] Unable to download Oinkmaster: {}\n'.format(e))
            return False
        try:
            oink_installer.extract_oinkmaster(stdout=stdout)
        except Exception as e:
            sys.stderr.write('[-] Unable to extract Oinkmaster: {}'.format(e))
            return False
        try:
            oink_install_res = oink_installer.setup_oinkmaster(stdout=stdout)
        except Exception as e:
            sys.stderr.write('[-] Unable to setup Oinkmaster: {}'.format(e))
            return False

        oinkmaster.update_suricata_rules()
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
    def install_dependencies():
        """
        Install the required dependencies required by Suricata

        :return: True, if all packages installed successfully
        """
        pacman = package_manager.OSPackageManager()
        if not pacman.refresh_package_indexes():
            return False
        packages = None
        if pacman.package_manager == 'apt-get':
            packages = ['cmake', 'make', 'gcc', 'g++', 'flex', 'bison', 'libtool', 'automake', 'pkg-config',
                        'libpcre3-dev', 'libpcap-dev', 'libyaml-dev', 'libjansson-dev', 'rustc', 'cargo', 'python-pip',
                        'wireshark', 'zlib1g-dev', 'libcap-ng-dev', 'libnspr4-dev', 'libnss3-dev', 'libmagic-dev'
                        'liblz4-dev']
        elif pacman.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libtool', 'automake', 'pkgconfig',
                        'pcre-devel', 'libpcap-devel', 'libyaml-devel', 'jansson-devel', 'rustc', 'cargo', 'python-pip',
                        'wireshark', 'zlib-devel', 'libcap-ng-devel', 'nspr-devel', 'nss-devel', 'file-devel'
                        'lz4-devel']
        if packages:
            return pacman.install_packages(packages)
        return False

    def setup_suricata(self, network_interface=None, stdout=False):
        """
        Setup Suricata IDS with PF_RING support

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
        self._copy_suricata_files_and_directories(stdout=stdout)
        pf_ring_install = pf_ring.PFRingInstaller()
        if not pf_ring.PFRingProfiler().is_installed:
            if stdout:
                sys.stdout.write('[+] Installing PF_RING kernel modules and dependencies.\n')
                sys.stdout.flush()
                time.sleep(1)
            pf_ring_install.download_pf_ring(stdout=True)
            pf_ring_install.extract_pf_ring(stdout=True)
            pf_ring_install.setup_pf_ring(stdout=True)
        try:
            os.symlink(os.path.join(pf_ring_install.install_directory, 'lib', 'libpcap.so.1'), '/lib/libpcap.so.1')
        except Exception as e:
            sys.stderr.write('[-] Failed to re-link libpcap.so.1 -> /lib/libpcap.so.1: {}\n'.format(e))
            if 'exists' not in str(e).lower():
                return False
        try:
            os.symlink(os.path.join(pf_ring_install.install_directory, 'lib', 'libpfring.so'), '/lib/libpfring.so.1')
        except Exception as e:
            sys.stderr.write('[-] Failed to re-link libpfring.so -> /lib/libpfring.so.1: {}\n'.format(e))
            if 'exists' not in str(e).lower():
                return False
        # CentOS linker libraries
        try:
            os.symlink(os.path.join(pf_ring_install.install_directory, 'lib', 'libpcap.so.1'),
                       '/usr/local/lib/libpcap.so.1')
        except Exception as e:
            sys.stderr.write('[-] Failed to re-link libpcap.so.1 -> /usr/local/lib/libpcap.so.1: {}\n'.format(e))
            if 'exists' not in str(e).lower():
                return False
        try:
            os.symlink(os.path.join(pf_ring_install.install_directory, 'lib', 'libpfring.so'),
                       '/usr/local/lib/libpfring.so.1')
        except Exception as e:
            sys.stderr.write('[-] Failed to re-link libpfring.so -> /usr/local/lib/libpfring.so.1: {}\n'.format(e))
            if 'exists' not in str(e).lower():
                return False
        time.sleep(5)
        suricata_compiled = self._configure_and_compile_suricata(pf_ring_installer=pf_ring_install, stdout=stdout)
        if not suricata_compiled:
            return False
        if 'SURICATA_HOME' not in open('/etc/dynamite/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Suricata default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo SURICATA_HOME="{}" >> /etc/dynamite/environment'.format(self.install_directory),
                            shell=True)
        if 'SURICATA_CONFIG' not in open('/etc/dynamite/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Suricata default config path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo SURICATA_CONFIG="{}" >> /etc/dynamite/environment'.format(self.configuration_directory),
                            shell=True)
        suricata_rules_installed = self._setup_suricata_rules(stdout=stdout)
        if not suricata_rules_installed:
            return False
        config = SuricataConfigurator(self.configuration_directory)
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

        return True


class SuricataProfiler:
    """
    An interface for profiling Suricata IDS
    """
    def __init__(self, stderr=False):
        self.is_downloaded = self._is_downloaded(stderr=stderr)
        self.is_installed = self._is_installed(stderr=stderr)
        self.is_running = self._is_running()

    @staticmethod
    def _is_downloaded(stderr=False):
        if not os.path.exists(os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME)):
            if stderr:
                sys.stderr.write('[-] Zeek installation archive could not be found.\n')
            return False
        return True

    @staticmethod
    def _is_installed(stderr=False):
        env_dict = utilities.get_environment_file_dict()
        suricata_home = env_dict.get('SURICATA_HOME')
        suricata_config = env_dict.get('SURICATA_CONFIG')
        if not suricata_home:
            if stderr:
                sys.stderr.write('[-] SURICATA_HOME installation directory could not be located in '
                                 '/etc/dynamite/environment.\n')
            return False
        if not suricata_config:
            if stderr:
                sys.stderr.write('[-] SURICATA_CONFIG directory could not be located in /etc/dynamite/environment.\n')
            return False
        if not os.path.exists(suricata_home):
            if stderr:
                sys.stderr.write('[-] SURICATA_HOME installation directory could not be located on disk at: '
                                 '{}.\n'.format(suricata_home))
            return False
        if not os.path.exists(suricata_config):
            if stderr:
                sys.stderr.write('[-] SURICATA_CONFIG directory could not be located on disk at: {}.\n'.format(
                    suricata_config))
            return False
        suricata_home_directories = os.listdir(suricata_home)
        suricata_config_directories = os.listdir(suricata_config)
        if 'bin' not in suricata_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate SURICATA_HOME {}/bin directory.\n'.format(suricata_home))
            return False
        elif 'lib' not in suricata_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate SURICATA_HOME {}/lib directory.\n'.format(suricata_home))
            return False
        elif 'include' not in suricata_home_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate SURICATA_HOME {}/include directory.\n'.format(suricata_home))
            return False
        if 'rules' not in suricata_config_directories:
            if stderr:
                sys.stderr.write('[-] Could not locate SURICATA_CONFIG {}/rules directory.\n'.format(suricata_config))
            return False
        return True

    @staticmethod
    def _is_running():
        try:
            return SuricataProcess().status()['RUNNING']
        except Exception:
            return False

    def get_profile(self):
        return {
            'DOWNLOADED': self.is_downloaded,
            'INSTALLED': self.is_installed,
            'RUNNING': self.is_running,
        }


class SuricataProcess:
    """
    An interface for start|stop|status|restart of the Suricata process
    """

    def __init__(self):
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('SURICATA_HOME')
        self.configuration_directory = self.environment_variables.get('SURICATA_CONFIG')
        self.config = SuricataConfigurator(self.configuration_directory)

        try:
            self.pid = int(open('/var/run/dynamite/suricata/suricata.pid').read())
        except (IOError, ValueError):
            self.pid = -1

    def start(self, stdout=False):
        """
        Start Suricata IDS process in daemon mode

        :param stdout: Print output to console
        :return: True, if started successfully
        """
        if not os.path.exists('/var/run/dynamite/suricata/'):
            subprocess.call('mkdir -p {}'.format('/var/run/dynamite/suricata/'), shell=True)
        p = subprocess.Popen('bin/suricata -i {} '
                             '-D '
                             '--pidfile /var/run/dynamite/suricata/suricata.pid '
                             '-c {}'.format(
                                            self.config.af_packet_interfaces[0]['interface'],
                                            os.path.join(self.configuration_directory, 'suricata.yaml')
        ), shell=True, cwd=self.install_directory)
        p.communicate()
        retry = 0
        while retry < 6:
            start_message = '[+] [Attempt: {}] Starting Suricata on PID [{}]\n'.format(retry + 1, self.pid)
            try:
                with open('/var/run/dynamite/suricata/suricata.pid') as f:
                    self.pid = int(f.read())
                start_message = '[+] [Attempt: {}] Starting Suricata on PID [{}]\n'.format(retry + 1, self.pid)
                if stdout:
                    sys.stdout.write(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(5)
                else:
                    return True
            except IOError:
                if stdout:
                    sys.stdout.write(start_message)
                retry += 1
                time.sleep(3)
        return False

    def stop(self, stdout=False):
        """
        Stop the Suricata process

        :param stdout: Print output to console
        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                if stdout:
                    sys.stdout.write('[+] Attempting to stop Suricata [{}]\n'.format(self.pid))
                if attempts > 3:
                    sig_command = signal.SIGKILL
                else:
                    # Kill the zombie after the third attempt of asking it to kill itself
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)
                alive = utilities.check_pid(self.pid)
            except Exception as e:
                sys.stderr.write('[-] An error occurred while attempting to stop Suricata: {}\n'.format(e))
                return False
        return True

    def restart(self, stdout=False):
        """
        Restart the Suricata process

        :param stdout: Print output to console
        :return: True if restarted successfully
        """
        if stdout:
            sys.stdout.write('[+] Attempting to restart Suricata IDS.\n')
        self.stop(stdout=stdout)
        return self.start(stdout=stdout)

    def status(self):
        """
        Check the status of the Suricata process

        :return: A dictionary containing the run status and relevant configuration options
        """
        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'LOG': os.path.join(self.config.default_log_directory, 'suricata.log')
        }
