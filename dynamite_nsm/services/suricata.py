import os
import sys
import time
import json
import shutil
import signal
import tarfile
import subprocess

from dynamite_nsm import const
from dynamite_nsm import utilities
from dynamite_nsm import package_manager
from dynamite_nsm.services import pf_ring
from dynamite_nsm.services import oinkmaster


INSTALL_DIRECTORY = '/opt/dynamite/suricata/'
CONFIGURATION_DIRECTORY = '/etc/dynamite/suricata'


class SuricataConfigurator:
    """
    Wrapper for configuring suricata.yml
    """
    def __init__(self, configuration_directory=CONFIGURATION_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
        """
        self.configuration_directory = configuration_directory
        self.suricata_config = self._parse_suricatayaml()

    def _parse_suricatayaml(self):
        suricata_config = {}
        parsable_tokens = [
            # address groups
            'HOME_NET', 'EXTERNAL_NET', 'HTTP_SERVERS', 'SMTP_SERVERS', 'SQL_SERVERS', 'DNS_SERVERS',
            'TELNET_SERVERS', 'AIM_SERVERS', 'DC_SERVERS', 'DNP3_SERVER', 'DNP3_CLIENT', 'MODBUS_CLIENT',
            'MODBUS_SERVER', 'ENIP_CLIENT', 'ENIP_SERVER',

            # port groups
            'HTTP_PORTS', 'SHELLCODE_PORTS', 'ORACLE_PORTS', 'SSH_PORTS', 'DNP3_PORTS', 'MODBUS_PORTS',
            'FILE_DATA_PORTS', 'FTP_PORTS',

            # logging
            'default-log-dir',

            # rule-path
            'default-rule-path',

            # rule classifications
            'classification-file',
            'reference-config-file',

            '- interface'

        ]
        for line in open(os.path.join(self.configuration_directory, 'suricata.yaml')).readlines():
            token = line.split(':')[0].strip()
            if token in parsable_tokens:
                value = line.split(':')[1].strip()
                if token == '- interface' and value == 'default':
                    continue
                suricata_config[token] = value

        return suricata_config

    def get_monitor_interface(self):
        """
        Get the network interface being monitored

        :return: The name of the network interface (E.G eth0, mon1)
        """
        return self.suricata_config['- interface']

    def get_log_directory(self):
        """
        Get the location that logs are being written

        :return: Path to logs directory
        """
        return self.suricata_config['default-log-dir']

    def get_rules_directory(self):
        """
        Get the location that rules are being written

        :return: Path to rules directory
        """
        return self.suricata_config['default-rule-path']

    def get_classification_file(self):
        """
        Get the file used for alert classifications

        :return: Path to the classification file
        """
        return self.suricata_config['classification-file']

    def get_reference_config_file(self):
        """
        Get the file used for rule references

        :return: Path to the rule-reference-config file
        """
        return self.suricata_config['reference-config-file']

    def get_aim_servers_group(self):
        """
        Get the group of hosts/IPs associated with AIM (Instant Messaging) servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['AIM_SERVERS']

    def get_dnp3_clients_group(self):
        """
        Get the group of hosts/IPs associated with DNP3 clients

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['DNP3_CLIENT']

    def get_dnp3_servers_group(self):
        """
        Get the group of hosts/IPs associated with DNP3 servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['DNP3_SERVER']

    def get_dnp3_port_group(self):
        """
        Get the group of ports associated with the DNP3 protocol

        :return: port list, string or variable string/expression
        """
        return self.suricata_config['DNP3_PORTS']

    def get_dns_servers_group(self):
        """
        Get the group of hosts/IPs associated with DNS servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['DNS_SERVERS']

    def get_domain_controller_servers_group(self):
        """
        Get the group of hosts/IPs associated with Domain Controller servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['DC_SERVERS']

    def get_enip_clients_group(self):
        """
        Get the group of hosts/IPs associated with ENIP clients

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['ENIP_CLIENT']

    def get_enip_servers_group(self):
        """
        Get the group of hosts/IPs associated with ENIP servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['ENIP_SERVER']

    def get_external_net_group(self):
        """
        Get the group of hosts/IPs associated with External (WAN) devices

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['EXTERNAL_NET']

    def get_filedata_port_group(self):
        """
        Get the group of ports associated with file-serving protocols

        :return: port list, string or variable string/expression
        """
        return self.suricata_config['FILE_DATA_PORTS']

    def get_ftp_port_group(self):
        """
        Get the group of ports associated with FTP protocols

        :return: port list, string or variable string/expression
        """
        return self.suricata_config['FTP_PORTS']

    def get_home_net_group(self):
        """
        Get the group of hosts/IPs associated with Internal (LAN) devices

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['HOME_NET']

    def get_http_servers_group(self):
        """
        Get the group of hosts/IPs associated with HTTP servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['HTTP_SERVERS']

    def get_http_port_group(self):
        """
        Get the group of ports associated with HTTP protocols

        :return: port list, string or variable string/expression
        """
        return self.suricata_config['HTTP_PORTS']

    def get_modbus_clients_group(self):
        """
        Get the group of hosts/IPs associated with Modbus clients

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['MODBUS_CLIENT']

    def get_modbus_servers_group(self):
        """
        Get the group of hosts/IPs associated with Modbus servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['MODBUS_SERVER']

    def get_modbus_ports_group(self):
        """
        Get the group of ports associated with Modbus ports

        :return: port list, string or variable string/expression
        """
        return self.suricata_config['MODBUS_PORTS']

    def get_oracle_port_group(self):
        """
        Get the group of ports associated with Oracle ports

        :return: port list, string or variable string/expression
        """
        return self.suricata_config['ORACLE_PORTS']

    def get_smtp_servers_group(self):
        """
        Get the group of hosts/IPs associated with SMTP servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['SMTP_SERVERS']

    def get_shellcode_port_group(self):
        """
        Get the group of ports associated from shellcode payloads are commonly sent

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['SHELLCODE_PORTS']

    def get_ssh_port_group(self):
        """
        Get the group of ports associated with SSH ports

        :return: port list, string or variable string/expression
        """
        return self.suricata_config['SSH_PORTS']

    def get_sql_servers_group(self):
        """
        Get the group of hosts/IPs associated with SQL servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['SQL_SERVERS']

    def get_telnet_servers_group(self):
        """
        Get the group of hosts/IPs associated with Telnet servers

        :return: host/IPs list or variable string/expression
        """
        return self.suricata_config['TELNET_SERVERS']

    def set_monitor_interface(self, interface):
        """
        Set the interface to monitor

        :param interface: The interface to monitor (E.G eth0, mon1)
        :return: None
        """
        self.suricata_config['- interface'] = interface

    def set_log_directory(self, log_directory):
        """
        Set the path to the log directory

        :param log_directory: The full path to the log directory
        :return: None
        """
        log_directory = log_directory.replace('"', '').replace("'", '')
        self.suricata_config['default-log-dir'] = '"{}"'.format(log_directory)

    def set_rules_directory(self, rules_directory):
        """
        Set the path to the rules directory

        :param rules_directory: The path to the rules directory
        :return: None
        """
        rules_directory = rules_directory.replace('"', '').replace("'", '')
        self.suricata_config['default-rule-path'] = '"{}"'.format(rules_directory)

    def set_classification_file(self, classification_file):
        """
        Set the path to the alert classification file

        :param classification_file: The full path to the alert classification configuration
        :return: None
        """
        classification_file = classification_file.replace('"', '').replace("'", '')
        self.suricata_config['classification-file'] = '"{}"'.format(classification_file)

    def set_reference_config_file(self, reference_file):
        """
        Set the path to the rules reference file

        :param reference_file: The full path to the rules reference configuration
        :return: None
        """
        reference_file = reference_file.replace('"', '').replace("'", '')
        self.suricata_config['reference-config-file'] = '"{}"'.format(reference_file)

    def set_aim_servers_group(self, var_or_ips='EXTERNAL_NET'):
        """
        Set the group associated with AIM (Instant Messaging) servers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['AIM_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['AIM_SERVERS'] = var_or_ips

    def set_dnp3_clients_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with DNP3 clients

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['DNP3_CLIENT'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['DNP3_CLIENT'] = var_or_ips

    def set_dnp3_servers_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with DNP3 servers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['DNP3_SERVER'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['DNP3_SERVER'] = var_or_ips

    def set_dnp3_port_group(self, var_or_ports="20000"):
        """
        Set the group associated with DNP3 servers

        :param var_or_ports: A variable representing a group of ports or a list of ports representing the group
        :return: None
        """
        if isinstance(var_or_ports, tuple):
            self.suricata_config['DNP3_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['DNP3_PORTS'] = var_or_ports

    def set_dns_servers_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with DNS servers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['DNS_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['DNS_SERVERS'] = var_or_ips

    def set_domain_controller_servers_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with Windows Domain Controllers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['DC_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['DC_SERVERS'] = var_or_ips

    def set_enip_clients_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with ENIP clients

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['ENIP_CLIENT'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['ENIP_CLIENT'] = var_or_ips

    def set_enip_servers_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with ENIP servers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['ENIP_SERVER'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['ENIP_SERVER'] = var_or_ips

    def set_external_net_group(self, var_or_ips='!$HOME_NET'):
        """
        Set the group associated with WAN (Internet) devices

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['EXTERNAL_NET'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['EXTERNAL_NET'] = var_or_ips

    def set_filedata_port_group(self, var_or_ports=("$HTTP_PORTS", 110, 143)):
        """
        Set the group associated with common file-transfer ports

        :param var_or_ports: A variable representing a group of ports or a list of ports representing the group
        :return: None
        """
        if isinstance(var_or_ports, tuple):
            self.suricata_config['FILE_DATA_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['FILE_DATA_PORTS'] = var_or_ports

    def set_ftp_port_group(self, var_or_ports="21"):
        """
        Set the group associated with FTP ports

        :param var_or_ports: A variable representing a group of ports or a list of ports representing the group
        :return: None
        """
        if isinstance(var_or_ports, tuple):
            self.suricata_config['FTP_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['FTP_PORTS'] = var_or_ports

    def set_home_net_group(self, var_or_ips=('192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12')):
        """
        Set the group associated with LAN (local) devices

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        self.suricata_config['HOME_NET'] = json.dumps(list(var_or_ips))

    def set_http_servers_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with HTTP servers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['HTTP_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['HTTP_SERVERS'] = var_or_ips

    def set_http_port_group(self, var_or_ports="80"):
        """
        Set the group associated with HTTP ports

        :param var_or_ports: A variable representing a group of ports or a list of ports representing the group
        :return: None
        """
        if isinstance(var_or_ports, tuple):
            self.suricata_config['HTTP_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['HTTP_PORTS'] = var_or_ports

    def set_modbus_clients_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with Modbus clients

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['MODBUS_CLIENT'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['MODBUS_CLIENT'] = var_or_ips

    def set_modbus_port_group(self, var_or_ports="502"):
        """
        Set the group associated with Modbus ports

        :param var_or_ports: A variable representing a group of ports or a list of ports representing the group
        :return: None
        """
        if isinstance(var_or_ports, tuple):
            self.suricata_config['MODBUS_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['MODBUS_PORTS'] = var_or_ports

    def set_modbus_servers_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with Modbus servers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['MODBUS_SERVER'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['MODBUS_SERVER'] = var_or_ips

    def set_oracle_port_group(self, var_or_ports="1521"):
        """
        Set the group associated with Oracle ports

        :param var_or_ports: A variable representing a group of ports or a list of ports representing the group
        :return: None
        """
        if isinstance(var_or_ports, tuple):
            self.suricata_config['ORACLE_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['ORACLE_PORTS'] = var_or_ports

    def set_smtp_servers_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with SMTP servers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['SMTP_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['SMTP_SERVERS'] = var_or_ips

    def set_shellcode_port_group(self, var_or_ports="!80"):
        """
        Set the group from which shellcode payloads are commonly sent

        :param var_or_ports: A variable representing a group of ports or a list of ports representing the group
        :return: None
        """
        if isinstance(var_or_ports, tuple):
            self.suricata_config['SHELLCODE_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['SHELLCODE_PORTS'] = var_or_ports

    def set_ssh_port_group(self, var_or_ports="22"):
        """
        Set the group associated with SSH ports

        :param var_or_ports: A variable representing a group of ports or a list of ports representing the group
        :return: None
        """
        if isinstance(var_or_ports, tuple):
            self.suricata_config['SSH_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['SSH_PORTS'] = var_or_ports

    def set_sql_servers_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with SQL servers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['SQL_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['SQL_SERVERS'] = var_or_ips

    def set_telnet_servers_group(self, var_or_ips='$HOME_NET'):
        """
        Set the group associated with Telnet servers

        :param var_or_ips: A variable representing a group of IPs or a list of IPs representing the group
        :return: None
        """
        if isinstance(var_or_ips, tuple):
            self.suricata_config['TELNET_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['TELNET_SERVERS'] = var_or_ips

    def write_config(self):
        """
        Overwrite the existing suricata.yaml config with changed values
        """
        timestamp = int(time.time())
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        suricata_config_backup = os.path.join(backup_configurations, 'suricata.yaml.backup.{}'.format(timestamp))
        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        shutil.copy(os.path.join(self.configuration_directory, 'suricata.yaml'), suricata_config_backup)
        suricata_config_content = open(os.path.join(self.configuration_directory, 'suricata.yaml')).readlines()
        output_str = ''
        for line in suricata_config_content:
            padding = ' ' * (len(line) - len(line.lstrip()))
            token = line.split(':')[0].strip()
            if token in self.suricata_config.keys():
                line = '{}{}: {}'.format(padding, token, self.suricata_config[token]) + '\n'
            output_str += line

        with open(os.path.join(self.configuration_directory, 'suricata.yaml'), 'w') as f:
            f.write(output_str)


class SuricataInstaller:

    def __init__(self,
                 configuration_directory=CONFIGURATION_DIRECTORY,
                 install_directory=INSTALL_DIRECTORY):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
        :param install_directory: Path to the install directory (E.G /opt/dynamite/suricata/)
        """

        self.configuration_directory = configuration_directory
        self.install_directory = install_directory

    def _configure_and_compile_suricata(self, pf_ring_installer, stdout=False):
        if stdout:
            sys.stdout.write('\n\n[+] Compiling Suricata from source. This can take up to 5 minutes.\n\n')
            sys.stdout.flush()
        configure_result = subprocess.call('./configure --prefix={} --sysconfdir={} '
                                           '--localstatedir=/var/dynamite/suricata --enable-pfring '
                                           '--with-libpfring-includes={} -with-libpfring-libraries={}'.format(
                                                self.install_directory,
                                                '/'.join(self.configuration_directory.split('/')[:-1]),
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
                        'libpcre3-dev', 'libpcap-dev','libyaml-dev','libjansson-dev', 'rustc', 'cargo', 'python-pip',
                        'wireshark', 'zlib1g-dev']
        elif pacman.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'flex', 'bison', 'libtool', 'automake', 'pkgconfig',
                        'pcre-devel', 'libpcap-devel', 'libyaml-devel', 'jansson-devel', 'rustc', 'cargo', 'python-pip',
                        'wireshark', 'zlib-devel']
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
        if 'SURICATA_HOME' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Suricata default home path [{}]\n'.format(
                    self.install_directory))
            subprocess.call('echo SURICATA_HOME="{}" >> /etc/environment'.format(self.install_directory),
                            shell=True)
        if 'SURICATA_CONFIG' not in open('/etc/environment').read():
            if stdout:
                sys.stdout.write('[+] Updating Suricata default config path [{}]\n'.format(
                    self.configuration_directory))
            subprocess.call('echo SURICATA_CONFIG="{}" >> /etc/environment'.format(self.configuration_directory),
                            shell=True)
        suricata_rules_installed = self._setup_suricata_rules(stdout=stdout)
        if not suricata_rules_installed:
            return False
        config = SuricataConfigurator(self.configuration_directory)
        config.set_monitor_interface(network_interface)
        config.set_rules_directory(os.path.join(self.configuration_directory, 'rules'))
        config.set_reference_config_file(os.path.join(self.configuration_directory, 'reference.config'))
        config.set_classification_file(os.path.join(self.configuration_directory, 'rules', 'classification.config'))
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
                sys.stderr.write('[-] SURICATA_HOME installation directory could not be located in /etc/environment.\n')
            return False
        if not suricata_config:
            if stderr:
                sys.stderr.write('[-] SURICATA_CONFIG directory could not be located in /etc/environment.\n')
            return False
        if not os.path.exists(suricata_home):
            if stderr:
                sys.stderr.write('[-] SURICATA_HOME installation directory could not be located on disk at: {}.\n'.format(
                    suricata_home))
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
                             '--pfring-int={} --pfring-cluster-type=cluster_flow -D '
                             '--pidfile /var/run/dynamite/suricata/suricata.pid '
                             '-c {}'.format(
                                            self.config.get_monitor_interface(),
                                            self.config.get_monitor_interface(),
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
                    sig_command = signal.SIGTERM
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(1)
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
            'LOG': os.path.join(self.config.get_log_directory(), 'suricata.log')
        }