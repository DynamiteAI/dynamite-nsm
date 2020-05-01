import os
import time
import shutil

from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import utilities
from dynamite_nsm.services.suricata import exceptions as suricata_exceptions


class ConfigManager:
    """
    Wrapper for configuring suricata.yaml
    """
    default_suricata_rules = [
        'botcc.rules', 'botcc.portgrouped.rules', 'ciarmy.rules',
        'compromised.rules', 'drop.rules', 'dshield.rules',
        'emerging-attack_response.rules', 'emerging-chat.rules',
        'emerging-current_events.rules', 'emerging-dns.rules',
        'emerging-dos.rules', 'emerging-exploit.rules',
        'emerging-ftp.rules', 'emerging-imap.rules',
        'emerging-malware.rules', 'emerging-misc.rules',
        'emerging-mobile_malware.rules', 'emerging-netbios.rules',
        'emerging-p2p.rules', 'emerging-policy.rules',
        'emerging-pop3.rules', 'emerging-rpc.rules',
        'emerging-smtp.rules', 'emerging-snmp.rules',
        'emerging-sql.rules', 'emerging-telnet.rules',
        'emerging-tftp.rules', 'emerging-trojan.rules',
        'emerging-user_agents.rules', 'emerging-voip.rules',
        'emerging-web_client.rules', 'emerging-web_server.rules',
        'emerging-worm.rules', 'tor.rules',
        'http-events.rules', 'smtp-events.rules',
        'dns-events.rules', 'tls-events.rules',
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

    def __init__(self, configuration_directory):
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

        suricatayaml_path = os.path.join(self.configuration_directory, 'suricata.yaml')
        try:
            with open(suricatayaml_path, 'r') as configyaml:
                self.config_data = load(configyaml, Loader=Loader)
        except IOError:
            raise suricata_exceptions.ReadsSuricataConfigError(
                "Could not locate config at {}".format(suricatayaml_path))
        except Exception as e:
            raise suricata_exceptions.ReadsSuricataConfigError(
                "General exception when opening/parsing config at {}; {}".format(suricatayaml_path, e))

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

    def remove_afpacket_interface(self, interface):
        """
        Remove an existing AF_PACKET interface

        :param interface: The name of the interface to remove (eth0, mon0)
        """
        new_interface_config = []
        for interface_config in self.af_packet_interfaces:
            if interface_config['interface'] == interface:
                continue
            else:
                new_interface_config.append(interface_config)
        if not new_interface_config:
            raise suricata_exceptions.SuricataInterfaceNotFoundError(interface)
        self.af_packet_interfaces = new_interface_config

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
        """
        if rule_file not in self.list_enabled_rules():
            self.rule_files.append(rule_file)

    def disable_rule(self, rule_file):
        """
        Disable a rule

        :param rule_file: The name of the rule to disable
        """
        if rule_file in self.list_enabled_rules():
            self.rule_files.remove(rule_file)
        else:
            raise suricata_exceptions.SuricataRuleNotFoundError(rule_file)

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
        try:
            utilities.makedirs(backup_configurations, exist_ok=True)
        except Exception as e:
            raise suricata_exceptions.WriteSuricataConfigError(
                "General error while attempting to create backup directory at {}; {}".format(backup_configurations, e))
        try:
            shutil.copy(os.path.join(self.configuration_directory, 'suricata.yaml'), suricata_config_backup)
        except Exception as e:
            raise suricata_exceptions.WriteSuricataConfigError(
                "General error while attempting to copy old suricata.yaml file to {}; {}".format(
                    backup_configurations, e))

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        try:
            with open(os.path.join(self.configuration_directory, 'suricata.yaml'), 'w') as configyaml:
                configyaml.write('%YAML 1.1\n---\n\n')
                dump(self.config_data, configyaml, default_flow_style=False)
        except IOError:
            raise suricata_exceptions.WriteSuricataConfigError("Could not locate {}".format(self.configuration_directory))
        except Exception as e:
            raise suricata_exceptions.WriteSuricataConfigError(
                "General error while attempting to write new suricata.yaml file to {}; {}".format(
                    self.configuration_directory, e))
