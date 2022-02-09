from __future__ import annotations

import os
import json
import random
from typing import Dict, List, Optional, Tuple

from yaml import Loader
from yaml import load

from dynamite_nsm import exceptions as general_exceptions

from dynamite_nsm import const, utilities
from dynamite_nsm.services.base import install
from dynamite_nsm.services.base.config import YamlConfigManager
from dynamite_nsm.services.base.config_objects.suricata import misc, rules


def lookup_rule_definition(rule_id: str) -> Dict:
    """Return the definition, categories, and friendly_name of a given script
    Args:
        rule_id: A unique identifier representing a Suricata rule.
    Returns:
         A dictionary of the format {"friendly_name" <str>, "description" <str>, "categories" <list>}
    """
    try:
        suricata_rule_defs = os.path.join(const.DEFAULT_CONFIGS, 'suricata', 'suricata_rule_definitions.json')
        with open(suricata_rule_defs) as f:
            suricata_defs = json.load(f)
    except FileNotFoundError:
        suricata_defs = {}
    definition = suricata_defs.get(str(rule_id))
    return definition


class ConfigManager(YamlConfigManager):
    """
    Manage Suricata.yaml configuration
    """

    def __init__(self, configuration_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):

        """Configuration Manager for suricata.yaml file

        Args:
            configuration_directory: The path to the Suricata configuration directory (E.G /etc/dynamite/suricata)
        ___

        # Instance Variables:

        ## Directories and Files:
        - `suricata_log_output_file` - Directory where logs are written
        - `default_rules_directory` - Directory where rules live
        - `classification_file` - The file (path) that maps severity to various [class]types (classification.config)
        - `reference_config_file` - The file (path) to the reference.config file

        ## Network Interface Setup:
        - `af_packet_interfaces` - A `list` of `misc.AfPacketInterfaces` representing suricata monitored interfaces
        - `pcap_interfaces` - A `list` of `misc.PcapInterfaces` (libpcap support if af_packet isn't possible)

        ## Rules:
        - `rule_files` - A `list` of suricata `rules.Rules` (rulesets)

        ## Address Groups:

        > <sup>[See syntax.](https://suricata.readthedocs.io/en/suricata-6.0.0/configuration/suricata-yaml.html#rule-vars)</sup>

        - `home_net`
        - `external_net`
        - `http_servers`
        - `sql_servers`
        - `dns_servers`
        - `telnet_servers`
        - `aim_servers`
        - `dc_servers`
        - `dnp3_servers`
        - `modbus_servers`
        - `enip_server`

        ## Port Groups:

        > <sup>[See syntax.](https://suricata.readthedocs.io/en/suricata-6.0.0/configuration/suricata-yaml.html#rule-vars)</sup>

        - `http_ports`
        - `shellcode_ports`
        - `oracle_ports`
        - `ssh_ports`
        - `dnp3_ports`
        - `modbus_ports`
        - `file_data_ports`
        - `ftp_ports`
        """

        extract_tokens = {
            'runmode': ('runmode',),
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
            '_rule_files_raw': ('rule-files',),
            '_threading_raw': ('threading',)
        }
        self.configuration_directory = configuration_directory
        self.config_data = None

        self.runmode = None
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
        self._rule_files_raw = []
        self._threading_raw = {}
        self.suricata_config_file = os.path.join(self.configuration_directory, 'suricata.yaml')
        try:
            with open(self.suricata_config_file, 'r') as configyaml:
                self.config_data_raw = load(configyaml, Loader=Loader)
        except (IOError, ValueError):
            raise general_exceptions.ReadConfigError(f'Failed to read or parse {self.suricata_config_file}.')

        super().__init__(self.config_data_raw, name='suricata.config', verbose=verbose, stdout=stdout, **extract_tokens)

        self.parse_yaml_file()

        self.rules = rules.Rules()

        for rule_name in self.list_available_rule_names():
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
        thread_families = self._threading_raw.get('cpu-affinity', [])
        management_cpu_set, receive_cpu_set, worker_cpu_set = None, None, None
        for thread_family in thread_families:
            if 'management-cpu-set' in thread_family.keys():
                management_cpu_set = thread_family.get('management-cpu-set', {}).get('cpu', [])
            elif 'receive-cpu-set' in thread_family.keys():
                receive_cpu_set = thread_family.get('receive-cpu-set', {}).get('cpu', [])
            elif 'worker-cpu-set' in thread_family.keys():
                worker_cpu_set = thread_family.get('worker-cpu-set', {}).get('cpu', [])
        self.threading = misc.Threading(management_cpu_set, receive_cpu_set, worker_cpu_set)

    @classmethod
    def from_raw_text(cls, raw_text: str, configuration_directory: Optional[str] = None) -> ConfigManager:
        """Alternative method for creating configuration file from raw text
        Args:
            raw_text: The string representing the configuration file
            configuration_directory: The configuration directory for Suricata
        Returns:
             An instance of ConfigManager
        """
        tmp_dir = f'{const.CONFIG_PATH}/.tmp'
        tmp_config = f'{tmp_dir}/suricata.yaml'
        utilities.makedirs(tmp_dir)
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(configuration_directory=tmp_dir)
        if configuration_directory:
            c.configuration_directory = configuration_directory
        return c

    @staticmethod
    def get_optimal_suricata_threading_config(available_cpus: Optional[Tuple] = None) -> misc.Threading:
        management_cpu_set = set()
        receive_cpu_set = set()
        worker_cpu_set = set()
        management_cpu_set.add(0)
        for i, c in enumerate(available_cpus):
            if i % 8 == 0 and i != 0:
                management_cpu_set.add(c)
            else:
                receive_cpu_set.add(c)
                worker_cpu_set.add(c)
        return misc.Threading(management_cpu_set, receive_cpu_set, worker_cpu_set)

    def list_available_rule_names(self) -> List[str]:
        """List the names of all available Suricata rules.
        Returns:
            A list of Suricata rule names that can be enabled
        """
        return [rule for rule in os.listdir(f'{self.configuration_directory}/rules') if rule.endswith('.rules')]

    def reset(self, inspect_interfaces: List[str], out_file_path: Optional[str] = None,
              default_config_path: Optional[str] = None):
        """Reset a configuration file back to its default
        Args:
            inspect_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1"])
            out_file_path: The path to the output file
            default_config_path: The path to the default configuration
        Returns:
            None
        """
        if not install.BaseInstallManager.validate_inspect_interfaces(inspect_interfaces):
            raise install.NetworkInterfaceNotFound(inspect_interfaces)
        if not out_file_path:
            out_file_path = f'{self.configuration_directory}/suricata.yaml'
        if not default_config_path:
            default_config_path = f'{const.DEFAULT_CONFIGS}/suricata/suricata.yaml'
        super(ConfigManager, self).reset(out_file_path, default_config_path)
        self.af_packet_interfaces = misc.AfPacketInterfaces()
        for interface in inspect_interfaces:
            self.af_packet_interfaces.add(
                misc.AfPacketInterface(
                    interface_name=interface, threads='auto', cluster_id=random.randint(1, 50000),
                    cluster_type='cluster_qm'
                )
            )
        self.commit(out_file_path=out_file_path)

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None,
               top_text: Optional[str] = None) -> None:

        """Write out an updated configuration file, and optionally backup the old one.
        Args:
            out_file_path: The path to the output file; if none given overwrites existing
            backup_directory: The path to the backup directory
            top_text: If specified, the first line of the configuration file will be set to the value of your choosing.
        Returns:
            None
        """
        if not out_file_path:
            out_file_path = f'{self.configuration_directory}/suricata.yaml'
        if not top_text:
            top_text = '%YAML 1.1\n---'
        self._rule_files_raw = self.rules.get_raw()
        self._af_packet_interfaces_raw = self.af_packet_interfaces.get_raw()
        self._threading_raw = self.threading.get_raw()
        super(ConfigManager, self).commit(out_file_path, backup_directory, top_text=top_text)
