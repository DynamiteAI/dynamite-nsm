import os
import re
import math
from io import StringIO
from random import randint
from datetime import datetime
from itertools import zip_longest
from configparser import ConfigParser
from typing import List, Optional, Tuple

from dynamite_nsm import utilities
from dynamite_nsm.service_objects.zeek import node
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.base.config import GenericConfigManager
from dynamite_nsm.services.zeek import exceptions as zeek_exceptions


class BpfConfigManager:
    """
    Wrapper for configuring interface_bpf.zeek script
    """

    def __init__(self, configuration_directory):
        self.configuration_directory = configuration_directory
        self.interface_pattern_map = {}
        self._parse_bpf_map_file()

    def _parse_bpf_map_file(self):
        """
        Parse bpf_map_file.input configuration file, and determine what bpf filters to apply to each interface
        """

        bpf_interface_map_path = os.path.join(self.configuration_directory, 'bpf_map_file.input')
        try:
            with open(bpf_interface_map_path) as conf_f:
                for line in conf_f.readlines():
                    if line.startswith('#'):
                        continue
                    tokenized_line = line.split('\t')
                    net_interface, bpf_pattern = tokenized_line[0], ''.join(tokenized_line[1:]).strip()
                    if net_interface in utilities.get_network_interface_names():
                        self.interface_pattern_map[net_interface] = bpf_pattern
        except IOError:
            with open(bpf_interface_map_path, 'w') as bpf_input_f:
                bpf_input_f.write('')

    def add_bpf_pattern(self, interface_name, bpf_pattern):
        """
        Associate a BPF pattern with a valid network interface.

        :param interface_name: The name of the network interface to apply the filter to
        :param bpf_pattern: A valid BPF filter
        """
        if interface_name in utilities.get_network_interface_names():
            self.interface_pattern_map[interface_name] = bpf_pattern

    def remove_bpf_pattern(self, interface_name):
        """
        Dis-associate a BPF pattern and a network interface

        :param interface_name: The name of the network interface
        """
        try:
            del self.interface_pattern_map[interface_name]
        except KeyError:
            pass

    def get_bpf_pattern(self, interface_name):
        """
        Get the BPF pattern for a given interface, assuming there is one.

        :param interface_name: The name of the network interface
        """
        return self.interface_pattern_map.get(interface_name)

    def write_config(self):
        """
        Overwrite the existing bpf_map_file.input config with changed values
        """

        output_str = ''

        source_configuration_file_path = os.path.join(self.configuration_directory, 'bpf_map_file.input')
        for k, v in self.interface_pattern_map.items():
            output_str += '{}\t{}\n'.format(k, v)
        try:
            with open(source_configuration_file_path, 'w') as f:
                f.write(output_str)
        except IOError:
            raise zeek_exceptions.WriteZeekConfigError("Could not locate {}".format(self.configuration_directory))
        except Exception as e:
            raise zeek_exceptions.WriteZeekConfigError(
                "General error while attempting to write new bpf_map_file.input file to {}; {}".format(
                    self.configuration_directory, e))


class ScriptConfigManager:
    """
    Wrapper for configuring broctl sites/local.zeek
    """

    def __init__(self, configuration_directory, backup_configuration_directory=None):
        """
        :param configuration_directory: Path to the configuration directory (E.G /etc/dynamite/zeek)
        """
        self.configuration_directory = configuration_directory
        self.backup_configuration_directory = backup_configuration_directory
        self.zeek_scripts = {}
        self.zeek_sigs = {}
        self.zeek_redefs = {}

        self._parse_zeek_scripts()

    def _parse_zeek_scripts(self):
        """
        Parse the local.zeek configuration file, and determine which scripts are enabled/disabled
        """
        zeeklocalsite_path = os.path.join(self.configuration_directory, 'site', 'local.zeek')
        try:
            with open(zeeklocalsite_path) as config_f:
                for line in config_f.readlines():
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
        except IOError:
            raise zeek_exceptions.ReadsZeekConfigError("Could not locate config at {}".format(zeeklocalsite_path))
        except Exception as e:
            raise zeek_exceptions.ReadsZeekConfigError(
                "General exception when opening/parsing config at {}; {}".format(zeeklocalsite_path, e))

    @classmethod
    def from_raw_text(cls, raw_text, configuration_directory=None, backup_configuration_directory=None):
        """
        Alternative method for creating configuration file from raw text

        :param raw_text: The string representing the configuration file
        :param configuration_directory: The configuration directory for Zeek
        :param backup_configuration_directory: The backup configuration directory

        :return: An instance of NodeConfigManager
        """
        tmp_dir = '/tmp/dynamite/temp_configs/'
        tmp_config = os.path.join(tmp_dir, 'site', 'local.zeek')
        utilities.makedirs(os.path.join(tmp_dir, 'site'))
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(configuration_directory=tmp_dir, backup_configuration_directory=backup_configuration_directory)
        if configuration_directory:
            c.configuration_directory = configuration_directory
        if backup_configuration_directory:
            c.backup_configuration_directory = backup_configuration_directory
        return c

    def get_raw_config(self):
        """
        Get the raw text of the config file

        :return: Config file contents
        """
        zeeklocalsite_path = os.path.join(self.configuration_directory, 'site', 'local.zeek')
        try:
            with open(zeeklocalsite_path) as config_f:
                raw_text = config_f.read()
        except IOError:
            raise zeek_exceptions.ReadsZeekConfigError("Could not locate config at {}".format(zeeklocalsite_path))
        except Exception as e:
            raise zeek_exceptions.ReadsZeekConfigError(
                "General exception when opening/parsing config at {}; {}".format(zeeklocalsite_path, e))
        return raw_text

    def disable_script(self, name):
        """
        :param name: The name of the script (E.G protocols/http/software)
        """
        try:
            self.zeek_scripts[name] = False
        except KeyError:
            raise zeek_exceptions.ZeekScriptNotFoundError(name)

    def enable_script(self, name):
        """
        :param name: The name of the script (E.G protocols/http/software)
        """
        try:
            self.zeek_scripts[name] = True
        except KeyError:
            pass

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

    def list_backup_configs(self):
        """
        List configuration backups in our config store

        :return: A list of dictionaries with the following keys: ["filename", "filepath", "time"]
        """
        return utilities.list_backup_configurations(
            os.path.join(self.backup_configuration_directory, 'local.zeek.d'))

    def restore_backup_config(self, name):
        """
        Restore a configuration from our config store

        :param name: The name of the configuration file or the keyword "recent" which will restore the most recent
        backup.
        :return: True, if successful
        """
        dest_config_file = os.path.join(self.configuration_directory, 'site', 'local.zeek')
        if name == "recent":
            configs = self.list_backup_configs()
            if configs:
                return utilities.restore_backup_configuration(
                    configs[0]['filepath'],
                    dest_config_file)
        return utilities.restore_backup_configuration(
            os.path.join(self.backup_configuration_directory, 'local.zeek.d', name), dest_config_file)

    def write_config(self):
        """
        Overwrite the existing local.zeek config with changed values
        """
        output_str = ''

        # Backup old configuration first
        source_configuration_file_path = os.path.join(self.configuration_directory, 'site', 'local.zeek')
        if self.backup_configuration_directory:
            destination_configuration_path = os.path.join(self.backup_configuration_directory, 'local.zeek.d')
            try:
                utilities.backup_configuration_file(source_configuration_file_path, destination_configuration_path,
                                                    destination_file_prefix='local.zeek.backup')
            except general_exceptions.WriteConfigError:
                raise zeek_exceptions.WriteZeekConfigError('Zeek configuration failed to write [local.zeek].')
            except general_exceptions.ReadConfigError:
                raise zeek_exceptions.ReadsZeekConfigError('Zeek configuration failed to read [local.zeek].')
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
        try:
            with open(source_configuration_file_path, 'w') as f:
                f.write(output_str)
        except IOError:
            raise zeek_exceptions.WriteZeekConfigError("Could not locate {}".format(self.configuration_directory))
        except Exception as e:
            raise zeek_exceptions.WriteZeekConfigError(
                "General error while attempting to write new local.zeek file to {}; {}".format(
                    self.configuration_directory, e))


class NodeConfigManager(GenericConfigManager):

    def __init__(self, install_directory: str):
        """
        Configuration Manager for node.cfg file

        :param install_directory: The path to the Zeek installation directory
        """
        self.install_directory = install_directory
        self.manager = None
        self.loggers = node.Loggers()
        self.proxies = node.Proxies()
        self.workers = node.Workers()
        config_parser = ConfigParser()
        with open(f'{self.install_directory}/etc/node.cfg') as config_f:
            config_parser.read_file(config_f)
        config_data = {}
        for section in config_parser.sections():
            config_data[section] = {}
            for item in config_parser.items(section):
                key, value = item
                config_data[section][key] = value
        super().__init__(config_data)
        self.add_parser(
            parser=lambda data:
            [
                node.Manager(
                    manager_name=name,
                    host=values.get('host')
                )
                for name, values in data.items() if
                values.get('type') == 'manager'][0],
            attribute_name='manager'
        )
        self.add_parser(
            parser=lambda data: node.Loggers(
                [
                    node.Logger(
                        logger_name=name,
                        host=values.get('host')
                    )
                    for name, values in data.items() if
                    values.get('type') == 'logger']),
            attribute_name='loggers'
        )
        self.add_parser(
            parser=lambda data: node.Proxies(
                [
                    node.Proxy(
                        proxy_name=name,
                        host=values.get('host')
                    )
                    for name, values in data.items() if
                    values.get('type') == 'proxy']),
            attribute_name='proxies'
        )
        self.add_parser(
            parser=lambda data: node.Workers(
                [node.Worker(worker_name=name,
                             interface_name=values.get('interface'),
                             cluster_id=values.get('af_packet_fanout_id'),
                             cluster_type=values.get('af_packet_fanout_mode'),
                             load_balance_processes=int(
                                 values.get('lb_procs')),
                             pinned_cpus=tuple(
                                 [int(cpu) for cpu in
                                  values.get('pin_cpus', '').split(',')]),
                             host=values.get('host'))
                 for name, values in data.items() if
                 values.get('type') == 'worker']),
            attribute_name='workers'
        )

    @classmethod
    def from_raw_text(cls, raw_text: str, install_directory: Optional[str] = None):
        """
        Alternative method for creating configuration file from raw text

        :param raw_text: The string representing the configuration file
        :param install_directory: The install directory for Zeek

        :return: An instance of ConfigManager
        """
        tmp_dir = '/tmp/dynamite/temp_configs/'
        tmp_config = f'{tmp_dir}/node.cfg'
        utilities.makedirs(tmp_dir)
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(install_directory=tmp_dir)
        if install_directory:
            c.install_directory = install_directory
        return c

    @staticmethod
    def get_optimal_zeek_worker_config(interface_names: List[str], strategy: Optional[str] = "aggressive",
                                       cpus: Optional[Tuple[int]] = (0,)) -> node.Workers:
        """
        Algorithm for determining the assignment of CPUs for Zeek workers

        :param interface_names: A list of network interface names
        :param strategy: 'aggressive', results in more CPUs pinned per interface, sometimes overshoots resources
                         'conservative', results in less CPUs pinned per interface, but never overshoots resources
        :param cpus: If None, we'll derive this by looking at the cpu core count,
                     otherwise a list of cpu cores (E.G [0, 1, 2])
        :return: A dictionary containing Zeek worker configuration
        """
        if not cpus:
            cpus = [c for c in range(0, utilities.get_cpu_core_count())]

        # Reserve 0 for KERNEL/Userland opts
        available_cpus = cpus[1:]

        def grouper(n, iterable):
            args = [iter(iterable)] * n
            return zip_longest(*args)

        def create_workers(net_interfaces, avail_cpus):
            idx = 0
            zeek_worker_configs = node.Workers()
            for net_interface in net_interfaces:
                if idx >= len(avail_cpus):
                    idx = 0
                if isinstance(avail_cpus[idx], int):
                    avail_cpus[idx] = [avail_cpus[idx]]
                zeek_worker_configs.add_worker(
                    node.Worker(
                        worker_name='dynamite-worker-' + net_interface,
                        host='localhost',
                        interface_name=net_interface,
                        load_balance_processes=len(avail_cpus[idx]),
                        pinned_cpus=avail_cpus[idx],
                        cluster_id=randint(1, 32768),
                        cluster_type='AF_Packet::FANOUT_HASH'
                    )
                )
                idx += 1
            return zeek_worker_configs

        if len(available_cpus) <= len(interface_names):
            # Wrap the number of CPUs around the number of network interfaces;
            # Since there are more network interfaces than CPUs; CPUs will be assigned more than once
            # lb_procs will always be 1

            zeek_workers = create_workers(interface_names, available_cpus)

        else:
            # In this scenario we choose from one of two strategies
            #  1. Aggressive:
            #     - Take the ratio of network_interfaces to available CPUS; ** ROUND UP **.
            #     - Group the available CPUs by this integer
            #       (if the ratio == 2 create as many groupings of 2 CPUs as possible)
            #     - Apply the same wrapping logic used above, but with the CPU groups instead of single CPU instances
            #  2. Conservative:
            #     - Take the ratio of network_interfaces to available CPUS; ** ROUND DOWN **.
            #     - Group the available CPUs by this integer
            #       (if the ratio == 2 create as many groupings of 2 CPUs as possible)
            #     - Apply the same wrapping logic used above, but with the CPU groups instead of single CPU instances
            aggressive_ratio = int(math.ceil(len(available_cpus) / float(len(interface_names))))
            conservative_ratio = int(math.floor(len(available_cpus) / len(interface_names)))
            if strategy == 'aggressive':
                cpu_groups = grouper(aggressive_ratio, available_cpus)
            else:
                cpu_groups = grouper(conservative_ratio, available_cpus)

            temp_cpu_groups = []
            for cpu_group in cpu_groups:
                cpu_group = [c for c in cpu_group if c]
                temp_cpu_groups.append(cpu_group)
            cpu_groups = temp_cpu_groups
            zeek_workers = create_workers(interface_names, cpu_groups)
        return zeek_workers

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        config_p = ConfigParser()

        def build_raw_component(components: node.BaseComponents):
            for component in components:
                config_p.add_section(component.name)
                for k, v in component.get_raw()[1].items():
                    config_p.set(component.name, k, v)

        if not out_file_path:
            out_file_path = f'{self.install_directory}/etc/node.cfg'

        build_raw_component(self.loggers)
        build_raw_component(self.proxies)
        build_raw_component(self.workers)
        build_raw_component(node.BaseComponents([self.manager]))

        # A hack to maintain parody with the parent class
        self.formatted_data = StringIO()
        config_p.write(self.formatted_data)
        self.formatted_data.seek(0)
        self.formatted_data = self.formatted_data.read()

        super(NodeConfigManager, self).write_config(out_file_path, backup_directory)


class LocalNetworkConfigManager:
    """
    Wrapper for configuring zeek networks.cfg (local network space)
    """

    IPV4_AND_CIDR_PATTERN = r'(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))'
    IPV6_AND_CIDR_PATTERN = r'^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:' \
                            r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                            r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}' \
                            r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                            r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                            r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                            r'(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                            r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                            r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                            r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::' \
                            r'(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                            r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                            r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:' \
                            r'(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::' \
                            r'(?:[0-9A-Fa-f]{1,4}:)' \
                            r'{2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                            r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                            r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                            r'(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:' \
                            r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
                            r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                            r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                            r'(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::' \
                            r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:' \
                            r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' \
                            r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
                            r'(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|' \
                            r'(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::/\d{1,2}(?!\d|(?:\.\d)))'

    def __init__(self, install_directory, backup_configuration_directory=None):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        """
        self.install_directory = install_directory
        self.backup_configuration_directory = backup_configuration_directory
        self.network_config = self._parse_network_config()

    def _parse_network_config(self):
        """
        :return: A dictionary representing the configurations stored within networks.cfg
        """
        with open(os.path.join(self.install_directory, 'etc', 'networks.cfg')) as net_config:
            local_networks = {}
            for line in net_config.readlines():
                ip_and_cidr = None
                if not line.strip():
                    continue
                elif line.startswith('#'):
                    continue
                ipv4_match = re.findall(self.IPV4_AND_CIDR_PATTERN, line)
                ipv6_match = re.findall(self.IPV6_AND_CIDR_PATTERN, line)
                if ipv4_match:
                    ip_and_cidr = ipv4_match[0]
                elif ipv6_match:
                    ip_and_cidr = ipv6_match[0]
                if ip_and_cidr:
                    if len(ip_and_cidr) != len(line.strip()):
                        description = line.replace(ip_and_cidr, '').strip()
                local_networks[ip_and_cidr] = description
        return local_networks

    @classmethod
    def from_raw_text(cls, raw_text, install_directory=None, backup_configuration_directory=None):
        """
        Alternative method for creating configuration file from raw text

        :param raw_text: The string representing the configuration file
        :param install_directory: The installation directory for Zeek
        :param backup_configuration_directory: The backup configuration directory

        :return: An instance of LocalNetworkConfigManager
        """
        tmp_dir = '/tmp/dynamite/temp_configs/'
        tmp_config = os.path.join(tmp_dir, 'etc', 'networks.cfg')
        utilities.makedirs(os.path.join(tmp_dir, 'etc'))
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(install_directory=tmp_dir, backup_configuration_directory=backup_configuration_directory)
        if install_directory:
            c.install_directory = install_directory
        if backup_configuration_directory:
            c.backup_configuration_directory = backup_configuration_directory
        return c

    def get_raw_config(self):
        """
        Get the raw text of the config file

        :return: Config file contents
        """
        zeek_network_cfg = os.path.join(self.install_directory, 'etc', 'networks.cfg')
        try:
            with open(zeek_network_cfg) as config_f:
                raw_text = config_f.read()
        except IOError:
            raise zeek_exceptions.ReadsZeekConfigError("Could not locate config at {}".format(zeek_network_cfg))
        except Exception as e:
            raise zeek_exceptions.ReadsZeekConfigError(
                "General exception when opening/parsing config at {}; {}".format(zeek_network_cfg, e))
        return raw_text

    def add_local_network(self, ip_and_cidr, description=None):
        """
        Add a new local network definition

        :param ip_and_cidr: The IP and CIDR address for private (likely internal) network (IPv4/IPv6 notation accepted)
        :param description: An optional description of that site
        """
        if re.match(self.IPV4_AND_CIDR_PATTERN, ip_and_cidr) or re.match(self.IPV4_AND_CIDR_PATTERN, ip_and_cidr):
            if isinstance(description, str):
                self.network_config[ip_and_cidr] = description
            else:
                self.network_config[ip_and_cidr] = "Added {}.".format(datetime.utcnow())

    def remove_local_network(self, ip_and_cidr):
        """
        Remove a network definition

        :param ip_and_cidr: The IP and CIDR address for private (likely internal) network (IPv4/IPv6 notation accepted)
        """
        try:
            del self.network_config[ip_and_cidr]
        except KeyError:
            raise zeek_exceptions.ZeekLocalNetworkNotFoundError(ip_and_cidr)

    def list_backup_configs(self):
        """
        List configuration backups

        :return: A list of dictionaries with the following keys: ["name", "path", "timestamp"]
        """
        return utilities.list_backup_configurations(
            os.path.join(self.backup_configuration_directory, 'networks.cfg.d'))

    def restore_backup_config(self, name):
        """
        Restore a configuration from our config store

        :param name: The name of the configuration file or the keyword "recent" which will restore the most recent
        backup.
        :return: True, if successful
        """
        dest_config_file = os.path.join(self.install_directory, 'etc', 'networks.cfg')
        if name == "recent":
            configs = self.list_backup_configs()
            if configs:
                return utilities.restore_backup_configuration(
                    configs[0]['filepath'],
                    dest_config_file)
        return utilities.restore_backup_configuration(
            os.path.join(self.backup_configuration_directory, 'networks.cfg.d', name), dest_config_file)

    def write_config(self):
        source_configuration_file_path = os.path.join(self.install_directory, 'etc', 'networks.cfg')
        if self.backup_configuration_directory:
            destination_configuration_path = os.path.join(self.backup_configuration_directory, 'networks.cfg.d')
            try:
                utilities.backup_configuration_file(source_configuration_file_path, destination_configuration_path,
                                                    destination_file_prefix='networks.cfg.backup')
            except general_exceptions.WriteConfigError:
                raise zeek_exceptions.WriteZeekConfigError('Zeek configuration failed to write [networks.cfg].')
            except general_exceptions.ReadConfigError:
                raise zeek_exceptions.ReadsZeekConfigError('Zeek configuration failed to read [networks.cfg].')

        try:
            with open(source_configuration_file_path, 'w') as net_config:
                lines = []
                for k, v in self.network_config.items():
                    if v:
                        line = '{0: <64} {1}\n'.format(k, v)
                    else:
                        line = '{0: <64} {1}\n'.format(k, 'Undocumented network')
                    lines.append(line)
                net_config.writelines(lines)
        except IOError as e:
            raise zeek_exceptions.WriteZeekConfigError(
                "General error while attempting to write new networks.cfg file to {}; {}".format(
                    self.install_directory, e))