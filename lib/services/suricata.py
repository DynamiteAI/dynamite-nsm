import os
import sys
import time
import json
import shutil
import tarfile
import subprocess

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from lib import const
from lib import utilities
from lib import package_manager
from lib.services import pf_ring
from lib.services import oinkmaster


INSTALL_DIRECTORY = '/opt/dynamite/suricata/'
CONFIGURATION_DIRECTORY = '/etc/dynamite/suricata'


class SuricataConfigurator:

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
            'reference-config-file'

        ]
        for line in open(os.path.join(self.configuration_directory, 'suricata.yaml')).readlines():
            token = line.split(':')[0].strip()
            if token in parsable_tokens:
                value = line.split(':')[1].strip()
                suricata_config[token] = value
        return suricata_config

    def get_log_directory(self):
        return self.suricata_config['default-log-dir']

    def get_rules_directory(self):
        return self.suricata_config['default-rule-path']

    def get_classification_file(self):
        return self.suricata_config['classification-file']

    def get_reference_config_file(self):
        return self.suricata_config['reference-config-file']

    def get_aim_servers_group(self):
        return self.suricata_config['AIM_SERVERS']

    def get_dnp3_clients_group(self):
        return self.suricata_config['DNP3_CLIENT']

    def get_dnp3_servers_group(self):
        return self.suricata_config['DNP3_SERVER']

    def get_dnp3_port_group(self):
        return self.suricata_config['DNP3_PORTS']

    def get_dns_servers_group(self):
        return self.suricata_config['DNP3_PORTS']

    def get_domain_controller_servers_group(self):
        return self.suricata_config['DC_SERVERS']

    def get_enip_clients_group(self):
        return self.suricata_config['ENIP_CLIENT']

    def get_enip_servers_group(self):
        return self.suricata_config['ENIP_SERVER']

    def get_external_net_group(self):
        return self.suricata_config['EXTERNAL_NET']

    def get_filedata_port_group(self):
        return self.suricata_config['FILE_DATA_PORTS']

    def get_ftp_port_group(self):
        return self.suricata_config['FTP_PORTS']

    def get_home_net_group(self):
        return self.suricata_config['HOME_NET']

    def get_http_servers_group(self):
        return self.suricata_config['HTTP_SERVERS']

    def get_http_port_group(self):
        return self.suricata_config['HTTP_PORTS']

    def get_modbus_clients_group(self):
        return self.suricata_config['MODBUS_CLIENT']

    def get_modbus_servers_group(self):
        return self.suricata_config['MODBUS_SERVER']

    def get_modbus_ports_group(self):
        return self.suricata_config['MODBUS_PORTS']

    def get_oracle_port_group(self):
        return self.suricata_config['ORACLE_PORTS']

    def get_smtp_servers_group(self):
        return self.suricata_config['SMTP_SERVERS']

    def get_shellcode_port_group(self):
        return self.suricata_config['SHELLCODE_PORTS']

    def get_ssh_port_group(self):
        return self.suricata_config['SSH_PORTS']

    def get_sql_servers_group(self):
        return self.suricata_config['SQL_SERVERS']

    def get_telnet_servers_group(self):
        return self.suricata_config['TELNET_SERVERS']

    def set_log_directory(self, log_directory):
        log_directory = log_directory.replace('"', '').replace("'", '')
        self.suricata_config['default-log-dir'] = '"{}"'.format(log_directory)

    def set_rules_directory(self, rules_directory):
        rules_directory = rules_directory.replace('"', '').replace("'", '')
        self.suricata_config['default-rule-path'] = '"{}"'.format(rules_directory)

    def set_classification_file(self, classification_file):
        classification_file = classification_file.replace('"', '').replace("'", '')
        self.suricata_config['classification-file'] = '"{}"'.format(classification_file)

    def set_reference_config_file(self, reference_file):
        reference_file = reference_file.replace('"', '').replace("'", '')
        self.suricata_config['reference-config-file'] = '"{}"'.format(reference_file)

    def set_aim_servers_group(self, var_or_ips='EXTERNAL_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['AIM_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['AIM_SERVERS'] = var_or_ips

    def set_dnp3_clients_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['DNP3_CLIENT'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['DNP3_CLIENT'] = var_or_ips

    def set_dnp3_servers_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['DNP3_SERVER'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['DNP3_SERVER'] = var_or_ips

    def set_dnp3_port_group(self, var_or_ports="20000"):
        if isinstance(var_or_ports, tuple):
            self.suricata_config['DNP3_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['DNP3_PORTS'] = var_or_ports

    def set_dns_servers_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['DNS_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['DNS_SERVERS'] = var_or_ips

    def set_domain_controller_servers_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['DC_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['DC_SERVERS'] = var_or_ips

    def set_enip_clients_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['ENIP_CLIENT'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['ENIP_CLIENT'] = var_or_ips

    def set_enip_servers_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['ENIP_SERVER'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['ENIP_SERVER'] = var_or_ips

    def set_external_net_group(self, var_or_ips='!$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['EXTERNAL_NET'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['EXTERNAL_NET'] = var_or_ips

    def set_filedata_port_group(self, var_or_ports=("$HTTP_PORTS", 110, 143)):
        if isinstance(var_or_ports, tuple):
            self.suricata_config['FILE_DATA_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['FILE_DATA_PORTS'] = var_or_ports

    def set_ftp_port_group(self, var_or_ports="21"):
        if isinstance(var_or_ports, tuple):
            self.suricata_config['FTP_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['FTP_PORTS'] = var_or_ports

    def set_home_net_group(self, ips=('192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12')):
        self.suricata_config['HOME_NET'] = json.dumps(list(ips))

    def set_http_servers_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['HTTP_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['HTTP_SERVERS'] = var_or_ips

    def set_http_port_group(self, var_or_ports="80"):
        if isinstance(var_or_ports, tuple):
            self.suricata_config['HTTP_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['HTTP_PORTS'] = var_or_ports

    def set_modbus_clients_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['MODBUS_CLIENT'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['MODBUS_CLIENT'] = var_or_ips

    def set_modbus_port_group(self, var_or_ports="502"):
        if isinstance(var_or_ports, tuple):
            self.suricata_config['MODBUS_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['MODBUS_PORTS'] = var_or_ports

    def set_modbus_servers_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['MODBUS_SERVER'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['MODBUS_SERVER'] = var_or_ips

    def set_oracle_port_group(self, var_or_ports="1521"):
        if isinstance(var_or_ports, tuple):
            self.suricata_config['ORACLE_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['ORACLE_PORTS'] = var_or_ports

    def set_smtp_servers_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['SMTP_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['SMTP_SERVERS'] = var_or_ips

    def set_shellcode_port_group(self, var_or_ports="!80"):
        if isinstance(var_or_ports, tuple):
            self.suricata_config['SHELLCODE_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['SHELLCODE_PORTS'] = var_or_ports

    def set_ssh_port_group(self, var_or_ports="22"):
        if isinstance(var_or_ports, tuple):
            self.suricata_config['SSH_PORTS'] = json.dumps(list(var_or_ports))
        else:
            self.suricata_config['SSH_PORTS'] = var_or_ports

    def set_sql_servers_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['SQL_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['SQL_SERVERS'] = var_or_ips

    def set_telnet_servers_group(self, var_or_ips='$HOME_NET'):
        if isinstance(var_or_ips, tuple):
            self.suricata_config['TELNET_SERVERS'] = json.dumps(list(var_or_ips))
        else:
            self.suricata_config['TELNET_SERVERS'] = var_or_ips

    def write_config(self):
        """
        Overwrite the existing suricata.yaml config with changed values
        """
        """
        timestamp = int(time.time())
        backup_configurations = os.path.join(self.configuration_directory, 'config_backups/')
        suricata_config_backup = os.path.join(backup_configurations, 'suricata.yaml.backup.{}'.format(timestamp))
        subprocess.call('mkdir -p {}'.format(backup_configurations), shell=True)
        shutil.copy(os.path.join(self.configuration_directory, 'site', 'local.bro'), suricata_config_backup)
        """
        suricata_config_content = open(os.path.join(self.configuration_directory, 'suricata.yaml')).readlines()
        output_str = ''
        for line in suricata_config_content:
            line = line.strip()
            token = line.split(':')[0].strip()
            if token in self.suricata_config.keys():
                line = '{}: {}'.format(token, self.suricata_config[token])
            output_str += line + '\n'

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
            packages = ['cmake', 'make', 'gcc', 'g++', 'libtool', 'automake', 'pkg-config', 'libpcre3-dev',
                        'libyaml-dev','libjansson-dev', 'rustc', 'cargo', 'python-pip']
        elif pacman.package_manager == 'yum':
            packages = ['cmake', 'make', 'gcc', 'gcc-c++', 'libtool', 'automake', 'pkgconfig', 'pcre-devel',
                        'libyaml-devel', 'jansson-devel', 'rustc', 'cargo', 'python-pip']
        if packages:
            return pacman.install_packages(packages)
        return False

    def setup_suricata(self, network_interface=None, stdout=False):
        if not network_interface:
            network_interface = utilities.get_network_interface_names()[0]
        if network_interface not in utilities.get_network_interface_names():
            sys.stderr.write(
                '[-] The network interface that your defined: \'{}\' is invalid. Valid network interfaces: {}\n'.format(
                    network_interface, utilities.get_network_interface_names()))
            return False
        if stdout:
            sys.stdout.write('[+] Creating suricata install|configuration|logging directories.\n')
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
        if stdout:
            sys.stdout.write('\n\n[+] Compiling Suricata from source. This can take up to 5 minutes.\n\n')
            sys.stdout.flush()
            time.sleep(5)
        subprocess.call('./configure --prefix={} --sysconfdir={} --localstatedir=/var/dynamite/suricata '
                        '--enable-pfring --with-libpfring-includes={} -with-libpfring-libraries={}'.format(
            self.install_directory, '/'.join(self.configuration_directory.split('/')[:-1]),
            os.path.join(pf_ring_install.install_directory, 'include'),
            os.path.join(pf_ring_install.install_directory, 'lib')
        ), shell=True, cwd=os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME))

        subprocess.call('make; make install; make install-conf', shell=True, cwd=os.path.join(
            const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME)
        )
        if stdout:
            sys.stdout.write('[+] Installing Oinkmaster.\n')
        try:
            os.mkdir(os.path.join(self.configuration_directory, 'rules'))
            shutil.copy(os.path.join(const.DEFAULT_CONFIGS, 'suricata', 'suricata.yaml'),
                        os.path.join(self.configuration_directory, 'suricata.yaml'))
            utilities.copytree(os.path.join(const.INSTALL_CACHE, const.SURICATA_DIRECTORY_NAME, 'rules'),
                               os.path.join(self.configuration_directory, 'rules'))
        except Exception as e:
            sys.stderr.write('[-] Unable to re-create Suricata rules directory: {}\n'.format(e))
            return False
        oink_installer = oinkmaster.OinkmasterInstaller(
            install_directory=os.path.join(self.install_directory, 'oinkmaster')
        )
        oink_install_res = False
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

        oinkmaster.update_suricata_rules(self.configuration_directory,
                                         os.path.join(self.install_directory, 'oinkmaster'))
        return oink_install_res


config  = SuricataConfigurator('/Users/jaminbecker/PycharmProjects/dynamite-nsm/default_configs/suricata')
config._parse_suricatayaml()

config.set_aim_servers_group('192.168.0.1')
config.write_config()


