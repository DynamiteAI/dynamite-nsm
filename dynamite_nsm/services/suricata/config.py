import os
import random

from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import utilities
from dynamite_nsm import exceptions as general_exceptions
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
        'http_servers': ('vars', 'address-groups', 'HTTP_SERVERS'),
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
        'suricata_log_output_file': ('logging', 'outputs', 'file', 'filename'),
        'default_rules_directory': ('default-rule-path',),
        'classification_file': ('classification-file',),
        'reference_config_file': ('reference-config-file',),
        'af_packet_interfaces': ('af-packet',),
        'pcap_interfaces': ('pcap',),
        'pfring_interfaces': ('pfring',),
        'rule_files': ('rule-files',)
    }

    def __init__(self, configuration_directory, backup_configuration_directory=None):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/suricata)
        """
        self.configuration_directory = configuration_directory
        self.backup_configuration_directory = backup_configuration_directory
        self.config_data = None

        self.home_net = None
        self.external_net = None
        self.http_servers = None
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
        self.ftp_ports = None
        self.file_data_ports = None
        self.default_log_directory = None
        self.suricata_log_output_file = None
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
                if isinstance(value, dict):
                    value = value[k]
                elif isinstance(value, list):
                    for list_entry in value:
                        if isinstance(list_entry, dict):
                            if k in list_entry.keys():
                                value = list_entry[k]
                else:
                    break
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

    @classmethod
    def from_raw_text(cls, raw_text, configuration_directory=None, backup_configuration_directory=None):
        """
        Alternative method for creating configuration file from raw text

        :param raw_text: The string representing the configuration file
        :param configuration_directory: The configuration directory for Suricata
        :param backup_configuration_directory: The backup configuration directory

        :return: An instance of SuricataConfigManager
        """
        tmp_dir = '/tmp/dynamite/temp_configs/'
        tmp_config = os.path.join(tmp_dir, 'suricata.yaml')
        utilities.makedirs(os.path.join(tmp_dir))
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(configuration_directory=tmp_dir, backup_configuration_directory=backup_configuration_directory)
        if configuration_directory:
            c.configuration_directory = configuration_directory
        if backup_configuration_directory:
            c.backup_configuration_directory = backup_configuration_directory
        return c

    @staticmethod
    def get_optimal_suricata_interface_config(network_capture_interfaces):

        def create_suricata_interfaces(net_interfaces):
            suricata_interface_configs = []
            for net_interface in net_interfaces:
                suricata_interface_configs.append(
                    {
                        'interface': net_interface,
                        'cluster-id': random.randint(32769, 65535),
                        'cluster-type': 'cluster_flow',
                        'threads': 'auto',
                    }
                )
            return suricata_interface_configs

        return create_suricata_interfaces(network_capture_interfaces)

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
        if interface not in self.list_af_packet_interfaces():
            raise suricata_exceptions.SuricataInterfaceNotFoundError(interface)
        new_interface_config = []
        for interface_config in self.af_packet_interfaces:
            if interface_config['interface'] == interface:
                continue
            else:
                new_interface_config.append(interface_config)
        self.af_packet_interfaces = new_interface_config

    def list_af_packet_interfaces(self):
        return [interface['interface'] for interface in self.af_packet_interfaces]

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

    def list_backup_configs(self):
        """
        List configuration backups in our config store

        :return: A list of dictionaries with the following keys: ["filename", "filepath", "time"]
        """
        return utilities.list_backup_configurations(
            os.path.join(self.backup_configuration_directory, 'suricata.yaml.d'))

    def restore_backup_config(self, name):
        """
        Restore a configuration from our config store

        :param name: The name of the configuration file or the keyword "recent" which will restore the most recent
        backup.
        :return: True, if successful
        """
        dest_config_file = os.path.join(self.configuration_directory, 'suricata.yaml')
        if name == "recent":
            configs = self.list_backup_configs()
            if configs:
                return utilities.restore_backup_configuration(
                    configs[0]['filepath'],
                    dest_config_file)
        return utilities.restore_backup_configuration(
            os.path.join(self.backup_configuration_directory, 'suricata.yaml.d', name), dest_config_file)

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
                k = path[i]
                if isinstance(partial_config_data, dict):
                    partial_config_data = partial_config_data[k]
                elif isinstance(partial_config_data, list):
                    for list_entry in partial_config_data:
                        if isinstance(list_entry, dict):
                            if k in list_entry.keys():
                                partial_config_data = list_entry[k]
                else:
                    break
            partial_config_data.update({path[-1]: value})

        # Backup old configuration first
        source_configuration_file_path = os.path.join(self.configuration_directory, 'suricata.yaml')
        if self.backup_configuration_directory:
            destination_configuration_path = os.path.join(self.backup_configuration_directory, 'suricata.yaml.d')
            try:
                utilities.backup_configuration_file(source_configuration_file_path, destination_configuration_path,
                                                    destination_file_prefix='suricata.yaml.backup')
            except general_exceptions.WriteConfigError:
                raise suricata_exceptions.WriteSuricataConfigError(
                    'Suricata configuration failed to write [suricata.yaml].')
            except general_exceptions.ReadConfigError:
                raise suricata_exceptions.ReadsSuricataConfigError(
                    'Suricata configuration failed to read [suricata.yaml].')

        for k, v in vars(self).items():
            if k not in self.tokens:
                continue
            token_path = self.tokens[k]
            update_dict_from_path(token_path, v)
        try:
            with open(source_configuration_file_path, 'w') as configyaml:
                configyaml.write('%YAML 1.1\n---\n\n')
                dump(self.config_data, configyaml, default_flow_style=False)
        except IOError:
            raise suricata_exceptions.WriteSuricataConfigError(
                "Could not locate {}".format(self.configuration_directory))
        except Exception as e:
            raise suricata_exceptions.WriteSuricataConfigError(
                "General error while attempting to write new suricata.yaml file to {}; {}".format(
                    self.configuration_directory, e))
