from __future__ import annotations
import os
from typing import Optional

from yaml import Loader
from yaml import load

from dynamite_nsm import utilities
from dynamite_nsm.service_objects.suricata import misc, rules
from dynamite_nsm.services.base.config import YamlConfigManager


class ConfigManager(YamlConfigManager):

    def __init__(self, configuration_directory: str):
        """
        Configuration Manager for suricata.yaml file

        :param configuration_directory: The path to the Suricata configuration directory
        """

        extract_tokens = {
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
            '_af_packet_interfaces_raw': ('af-packet',),
            '_pcap_interfaces_raw': ('pcap',),
            '_rule_files_raw': ('rule-files',)
        }
        self.configuration_directory = configuration_directory
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
        self._af_packet_interfaces_raw = []
        self._pcap_interfaces_raw = []
        self._rule_files_raw = []
        self.suricata_config_file = os.path.join(self.configuration_directory, 'suricata.yaml')
        with open(self.suricata_config_file, 'r') as configyaml:
            self.config_data_raw = load(configyaml, Loader=Loader)

        super().__init__(self.config_data_raw, **extract_tokens)

        self.parse_yaml_file()

        self.rules = rules.Rules()

        for rule_name in rules.list_available_rule_names():
            if rule_name in self._rule_files_raw:
                self.rules.add(rules.Rule(rule_name, enabled=True))
            else:
                self.rules.add(rules.Rule(rule_name, enabled=False))

        self.af_packet_interfaces = misc.AfPacketInterfaces(
            [misc.AfPacketInterface(
                cluster_id=af_packet_interface_raw.get('cluster-id'),
                cluster_type=af_packet_interface_raw.get('cluster-type'),
                interface_name=af_packet_interface_raw.get('interface'),
                bpf_filter=af_packet_interface_raw.get('bpf-filter'),
                threads=af_packet_interface_raw.get('threads')
            ) for af_packet_interface_raw in self._af_packet_interfaces_raw]
        )

        self.pcap_interfaces = misc.PcapInterfaces(
            interface_names=[interface_raw for interface_raw in self._pcap_interfaces_raw]
        )

    @classmethod
    def from_raw_text(cls, raw_text: str, configuration_directory: Optional[str] = None) -> ConfigManager:
        """
        Alternative method for creating configuration file from raw text

        :param raw_text: The string representing the configuration file
        :param configuration_directory: The configuration directory for Suricata

        :return: An instance of ConfigManager
        """
        tmp_dir = '/tmp/dynamite/temp_configs/'
        tmp_config = f'{tmp_dir}/suricata.yaml'
        utilities.makedirs(tmp_dir)
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(configuration_directory=tmp_dir)
        if configuration_directory:
            c.configuration_directory = configuration_directory
        return c

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        """
        Write out an updated configuration file, and optionally backup the old one.

        :param out_file_path: The path to the output file; if none given overwrites existing
        :param backup_directory: The path to the backup directory
        """
        if not out_file_path:
            out_file_path = f'{self.configuration_directory}/suricata.yaml'
        self._rule_files_raw = self.rules.get_raw()
        self._pcap_interfaces_raw = self.pcap_interfaces.get_raw()
        self._af_packet_interfaces_raw = self.af_packet_interfaces.get_raw()
        super(ConfigManager, self).write_config(out_file_path, backup_directory, top_text='%YAML 1.1\n---')