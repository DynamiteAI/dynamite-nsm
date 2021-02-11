import math
from io import StringIO
from re import findall
from random import randint
from itertools import zip_longest
from configparser import ConfigParser
from typing import Dict, List, Optional, Tuple

from dynamite_nsm import utilities
from dynamite_nsm.services.base.config import GenericConfigManager
from dynamite_nsm.service_objects.zeek import bpf_filter, local_network, local_site, node


class BpfConfigManager(GenericConfigManager):

    def __init__(self, configuration_directory):
        self.configuration_directory = configuration_directory
        self.bpf_filters = bpf_filter.BpfFilters()

        with open(f'{self.configuration_directory}/bpf_map_file.input') as config_f:
            config_data = dict(data=config_f.readlines())
        super().__init__(config_data)

        self.add_parser(
            parser=lambda data: bpf_filter.BpfFilters(
                [bpf_filter.BpfFilter(
                    interface_name=line.split('\t')[0],
                    pattern=line.split('\t')[1]
                )
                    for line in data['data']
                    if '\t' in line.strip().replace(' ', '')]
            ),
            attribute_name='bpf_filters'
        )

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        if not out_file_path:
            out_file_path = f'{self.configuration_directory}/bpf_map_file.input'
        self.formatted_data = '\n'.join(self.bpf_filters.get_raw())
        super(BpfConfigManager, self).write_config(out_file_path, backup_directory)


class SiteLocalConfigManager(GenericConfigManager):

    @staticmethod
    def _line_denotes_script(line: str):
        return '@load' in line.replace(' ', '') and '@load-' not in line

    @staticmethod
    def _line_denotes_signature(line):
        return '@load-sig' in line.replace(' ', '')

    @staticmethod
    def _line_denotes_definition(line):
        return 'redef' in line.replace(' ', '')

    def __init__(self, configuration_directory):
        self.configuration_directory = configuration_directory
        self.scripts = local_site.Scripts()
        self.signatures = local_site.Signatures()
        self.definitions = local_site.Definitions()

        with open(f'{self.configuration_directory}/site/local.zeek') as config_f:
            config_data = dict(data=config_f.readlines())
        super().__init__(config_data)

        self.add_parser(
            parser=lambda data: local_site.Scripts(
                [local_site.Script(
                    name=line.replace(' ', '').replace('#', '').strip()[5:],
                    enabled=line.replace(' ', '').strip()[0] != '#'
                )
                    for line in data['data']
                    if self._line_denotes_script(line)]
            ),
            attribute_name='scripts'
        )

        self.add_parser(
            parser=lambda data: local_site.Signatures(
                [local_site.Signature(
                    name=line.replace(' ', '').replace('#', '').strip()[10:],
                    enabled=line.replace(' ', '').strip()[0] != '#'
                )
                    for line in data['data']
                    if self._line_denotes_signature(line)]
            ),
            attribute_name='signatures'
        )

        self.add_parser(
            parser=lambda data: local_site.Definitions(
                [local_site.Definition(
                    name=line.replace(' ', '').replace('#', '').strip()[5:].split('=')[0],
                    value=line.replace(' ', '').replace('#', '').strip()[5:].split('=')[1],
                    enabled=line.replace(' ', '').strip()[0] != '#'
                )
                    for line in data['data']
                    if self._line_denotes_definition(line)]
            ),
            attribute_name='definitions'
        )

    @classmethod
    def from_raw_text(cls, raw_text: str, configuration_directory: Optional[str] = None):
        """
        Alternative method for creating configuration file from raw text

        :param raw_text: The string representing the configuration file
        :param configuration_directory: The configuration directory for Zeek

        :return: An instance of ConfigManager
        """
        tmp_dir = '/tmp/dynamite/temp_configs/'
        tmp_config = f'{tmp_dir}/local.zeek'
        utilities.makedirs(tmp_dir)
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(configuration_directory=tmp_dir)
        if configuration_directory:
            c.configuration_directory = configuration_directory
        return c

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        if not out_file_path:
            out_file_path = f'{self.configuration_directory}/site/local.zeek'
        self.formatted_data = '\n'.join(
            self.definitions.get_raw() + self.signatures.get_raw() + self.scripts.get_raw()
        )
        super(SiteLocalConfigManager, self).write_config(out_file_path, backup_directory)


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
                                       cpus: Optional[Tuple] = None) -> node.Workers:
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
            avail_cpus = list(avail_cpus)
            zeek_worker_configs = node.Workers()
            if not avail_cpus:
                return zeek_worker_configs
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


class LocalNetworksConfigManager(GenericConfigManager):

    @staticmethod
    def _parse_local_networks(data: Dict) -> local_network.LocalNetworks:
        local_networks = local_network.LocalNetworks()
        for line in data['data']:
            ip_and_cidr, description = None, None
            ipv4_match = findall(local_network.IPV4_AND_CIDR_PATTERN, line)
            ipv6_match = findall(local_network.IPV6_AND_CIDR_PATTERN, line)
            if ipv4_match:
                ip_and_cidr = ipv4_match[0]
            elif ipv6_match:
                ip_and_cidr = ipv6_match[0]
            if ip_and_cidr:
                if len(ip_and_cidr) != len(line.strip()):
                    description = line.replace(ip_and_cidr, '').strip()
            local_networks.add(
                local_network.LocalNetwork(
                    ip_and_cidr=ip_and_cidr,
                    description=description
                )
            )
        return local_networks

    def __init__(self, installation_directory):
        self.installation_directory = installation_directory
        self.local_networks = local_network.LocalNetworks()

        with open(f'{self.installation_directory}/etc/networks.cfg') as config_f:
            config_data = dict(data=config_f.readlines())
        super().__init__(config_data)

        self.add_parser(
            parser=self._parse_local_networks,
            attribute_name='local_networks'
        )

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        if not out_file_path:
            out_file_path = f'{self.installation_directory}/etc/networks.cfg'
        self.formatted_data = '\n'.join(self.local_networks.get_raw())
        super(LocalNetworksConfigManager, self).write_config(out_file_path, backup_directory)
