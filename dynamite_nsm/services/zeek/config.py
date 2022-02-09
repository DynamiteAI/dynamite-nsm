import os
import json
from io import StringIO
from re import findall
from random import randint
from configparser import ConfigParser
from typing import Dict, List, Optional, Tuple

from dynamite_nsm import const, utilities
from dynamite_nsm.services.base import install
from dynamite_nsm.services.base.config import GenericConfigManager
from dynamite_nsm.services.base.config_objects.zeek import local_network, local_site, node
from dynamite_nsm.services.base.config_objects.zeek import bpf_filter


def lookup_script_definition(script_id: str) -> Dict:
    """Return the definition, categories, and friendly_name of a given script
    Args:
        script_id: A unique identifier representing a Zeek script.
    Returns:
         A dictionary of the format {"friendly_name" <str>, "description" <str>, "categories" <list>}
    """
    try:
        zeek_script_defs = os.path.join(const.DEFAULT_CONFIGS, 'zeek', 'zeek_script_definitions.json')
        with open(zeek_script_defs) as f:
            zeek_defs = json.load(f)
    except FileNotFoundError:
        zeek_defs = {}
    definition = zeek_defs.get(str(script_id))
    return definition


class BpfConfigManager(GenericConfigManager):
    """
    Manage Berkley Packet Filters for Zeek
    """

    def __init__(self, configuration_directory, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """Configure Berkley Packet Filters for Zeek monitored interfaces.

        Args:
            configuration_directory: The path to the Zeek configuration directory (E.G /etc/dynamite/zeek)
            verbose: Include detailed debug messages
            stdout: Print output to console
        ___

        # Instance Variables:
        - `bpf_filters` - A `bpf_filter.BpfFilters` instance.
        """
        self.configuration_directory = configuration_directory
        self.bpf_filters = bpf_filter.BpfFilters()

        with open(f'{self.configuration_directory}/bpf_map_file.input') as config_f:
            config_data = dict(data=config_f.readlines())
        super().__init__(config_data, name='zeek.config.bpf', verbose=verbose, stdout=stdout)

        self.add_parser(
            parser=lambda data: bpf_filter.BpfFilters(
                [bpf_filter.BpfFilter(
                    interface_name=line.split('\t')[0].strip(),
                    pattern=line.split('\t')[1].strip()
                )
                    for line in data['data']
                    if '\t' in line.strip().replace(' ', '')]
            ),
            attribute_name='bpf_filters'
        )

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        """Write the changes out to configuration file
        Args:
            out_file_path: The path to the configuration file to write (or overwrite)
            backup_directory: The path to the backup directory

        Returns:
            None
        """
        if not out_file_path:
            out_file_path = f'{self.configuration_directory}/bpf_map_file.input'
        self.formatted_data = '\n'.join(self.bpf_filters.get_raw())
        super(BpfConfigManager, self).commit(out_file_path, backup_directory)


class SiteLocalPackageManager:

    def __init__(self, configuration_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """
        Configure Zeek packages installed through ZKG

        Args:
            configuration_directory: The path to the Zeek configuration directory (E.G /etc/dynamite/zeek)
            verbose: Include detailed debug messages
            stdout: Print output to console
        ___

        # Instance Variables:
        - `scripts` - A `local_site.Scripts` instance representing a set of enabled (and disabled) Zeek scripts.
        """
        self.configuration_directory = configuration_directory
        self.packages = []
        self._load_packages()

    def _load_packages(self):
        package_root = f'{self.configuration_directory}/site/packages/'
        for package in os.listdir(package_root):
            if os.path.isfile(f'{package_root}/{package}'):
                continue
            package_path = f'{package_root}/{package}/__load__.zeek'
            with open(package_path, 'r') as package_in:
                self.packages.append((package_path, SiteLocalConfigManager.from_raw_text(package_in.read())))


class SiteLocalConfigManager(GenericConfigManager):
    """
    Manage local/site.zeek file (contains scripts, definitions, and signatures to be loaded)
    """

    @staticmethod
    def _line_denotes_script(line: str):
        return '@load' in line.replace(' ', '') and '@load-' not in line

    @staticmethod
    def _line_denotes_signature(line):
        return '@load-sig' in line.replace(' ', '')

    @staticmethod
    def _line_denotes_definition(line):
        return 'redef' in line.replace(' ', '')

    def __init__(self, configuration_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """
        Configure Zeek scripts, signatures, and definitions

        Args:
            configuration_directory: The path to the Zeek configuration directory (E.G /etc/dynamite/zeek)
            verbose: Include detailed debug messages
            stdout: Print output to console
        ___

        # Instance Variables:
        - `scripts` - A `local_site.Scripts` instance representing a set of enabled (and disabled) Zeek scripts.
        - `signatures` A `local_site.Signatures` instance representing a set of signatures to load.
        - `definitions` - A `local_site.Definitions` instance representing a set of script variables `redefs`.
        """
        self.configuration_directory = configuration_directory
        self.scripts = local_site.Scripts()
        self.signatures = local_site.Signatures()
        self.definitions = local_site.Definitions()

        with open(f'{self.configuration_directory}/site/local.zeek') as config_f:
            config_data = dict(data=config_f.readlines())
        super().__init__(config_data, name='zeek.config.local', verbose=verbose, stdout=stdout)

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
        """Alternative method for creating configuration file from raw text
        Args:
            raw_text: The string representing the configuration file
            configuration_directory: The configuration directory for Zeek
        Returns:
             An instance of ConfigManager
        """
        tmp_root = f'{const.CONFIG_PATH}/.tmp'
        tmp_dir = f'{tmp_root}/site'
        tmp_config = f'{tmp_dir}/local.zeek'
        utilities.makedirs(tmp_dir)
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(configuration_directory=tmp_root)
        if configuration_directory:
            c.configuration_directory = configuration_directory
        return c

    def disable_all_definitions(self) -> None:
        """Disable all definitions
           Returns:
                None
        """
        for definition in self.definitions:
            definition.enabled = False

    def disable_all_signatures(self) -> None:
        """Disable all scripts
           Returns:
                None
        """
        for sig in self.signatures:
            sig.enabled = False

    def disable_all_scripts(self) -> None:
        """Disable all scripts
           Returns:
                None
        """
        for script in self.scripts:
            script.enabled = False

    def enable_all_definitions(self) -> None:
        """Enable all definitions
           Returns:
               None
        """
        for definition in self.definitions:
            definition.enabled = False

    def enable_all_signatures(self) -> None:
        """Enable all signatures
           Returns:
               None
        """
        for sig in self.signatures:
            sig.enabled = True

    def enable_all_scripts(self) -> None:
        """Enable all scripts
           Returns:
               None
        """
        for script in self.scripts:
            script.enabled = True

    def reset(self, out_file_path: Optional[str] = None, default_config_path: Optional[str] = None):
        """Reset a configuration file back to its default
        Args:
            out_file_path: The path to the output file
            default_config_path: The path to the default configuration
        Returns:
            None
        """
        if not out_file_path:
            out_file_path = f'{self.configuration_directory}/site/local.zeek'
        if not default_config_path:
            default_config_path = f'{const.DEFAULT_CONFIGS}/zeek/local.zeek'
        super(SiteLocalConfigManager, self).reset(out_file_path, default_config_path)
        self.commit(out_file_path=out_file_path)

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        """Write the changes out to configuration file
        Args:
            out_file_path: The path to the configuration file to write (or overwrite)
            backup_directory: The path to the backup directory

        Returns:
            None
        """
        if not out_file_path:
            out_file_path = f'{self.configuration_directory}/site/local.zeek'
        self.formatted_data = '\n'.join(
            self.signatures.get_raw() + self.scripts.get_raw() + self.definitions.get_raw()
        )
        super(SiteLocalConfigManager, self).commit(out_file_path, backup_directory)


class NodeConfigManager(GenericConfigManager):
    """
    Manage Zeek node.cfg used to determine which network interfaces to monitor
    """

    def __init__(self, install_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """Configuration Manager for node.cfg file

        Args:
            install_directory: The path to the Zeek installation directory
        ___

        # Instance Variables:
        - `manager` - A basic `node.Manager` instance representing a manager configuration (one per cluster)
        - `loggers` - A `node.Loggers` instance representing one or more loggers. Loggers alleviate manager load
        - `proxies` A `node.Proxies` instance representing one or more proxies. Offload workloads.
        - `workers` A `node.Workers` instance representing one or more workers. The worker is the Zeek process that
        sniffs network traffic and does protocol analysis on the reassembled traffic streams.
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
        super().__init__(config_data, name='zeek.config.node', verbose=verbose, stdout=stdout)
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
                             cluster_id=int(values.get('af_packet_fanout_id')),
                             cluster_type=values.get('af_packet_fanout_mode', 'FANOUT_HASH'),
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
        """Alternative method for creating configuration file from raw text
        Args:
            raw_text: The string representing the configuration file
            install_directory: The install directory for Zeek
        Returns:
             An instance of ConfigManager
        """
        tmp_dir = f'{const.CONFIG_PATH}/.tmp/etc'
        tmp_config = f'{tmp_dir}/node.cfg'
        utilities.makedirs(tmp_dir)
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(install_directory=f"{tmp_dir}/../")
        if install_directory:
            c.install_directory = install_directory
        return c

    @staticmethod
    def get_optimal_zeek_worker_config(interface_names: List[str],
                                       available_cpus: Optional[Tuple] = None) -> node.Workers:
        """Algorithm for determining the assignment of CPUs for Zeek workers
        Args:
            interface_names: A list of network interface names
            available_cpus: If None, we'll derive this by looking at the cpu core count, otherwise a list of cpu cores
        Returns:
             A node.Workers object
        """
        zeek_worker_configs = node.Workers()
        if not available_cpus:
            # Reserve CPU 0 for KERNEL operations
            available_cpus = [c for c in range(1, utilities.get_cpu_core_count())]

        for cpu_affinity_group in utilities.get_optimal_cpu_interface_config(interface_names=interface_names,
                                                                             available_cpus=available_cpus):
            net_interface = cpu_affinity_group['interface_name']
            pinned_cpus = cpu_affinity_group['pin_cpus']
            lb_processes = cpu_affinity_group['thread_count']
            zeek_worker_configs.add_worker(
                node.Worker(
                    worker_name='dynamite-worker-' + net_interface,
                    host='localhost',
                    interface_name=net_interface,
                    load_balance_processes=lb_processes,
                    pinned_cpus=pinned_cpus,
                    cluster_id=randint(1, 32768),
                    cluster_type='AF_Packet::FANOUT_QM'
                )
            )

        return zeek_worker_configs

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
            out_file_path = f'{self.install_directory}/etc/node.cfg'
        if not default_config_path:
            default_config_path = f'{const.DEFAULT_CONFIGS}/zeek/broctl-nodes.cfg'
        super(NodeConfigManager, self).reset(out_file_path, default_config_path)
        self.workers = node.Workers()
        for worker in self.get_optimal_zeek_worker_config(inspect_interfaces):
            self.workers.add_worker(
                worker=worker
            )
        self.commit(out_file_path=out_file_path)

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        """Write the changes out to configuration file
        Args:
            out_file_path: The path to the configuration file to write (or overwrite)
            backup_directory: The path to the backup directory

        Returns:
            None
        """
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

        super(NodeConfigManager, self).commit(out_file_path, backup_directory)


class LocalNetworksConfigManager(GenericConfigManager):
    """
    Manage the networks network.cfg for defining which networks Zeek will consider local
    """

    @staticmethod
    def _parse_local_networks(data: Dict) -> local_network.LocalNetworks:
        local_networks = local_network.LocalNetworks()
        for line in data['data']:
            if any([not line,
                    line.strip().startswith('#'),
                    len(line) == 0,
                    len(line.split(" ")) == 1]):
                continue
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

    def __init__(self, install_directory: str, verbose: Optional[bool] = False, stdout: Optional[bool] = True):
        """
        Configure the networks Zeek will consider local to the monitoring environment

        Args:
            install_directory: The path to the installation directory (E.G /opt/dynamite/zeek)
            verbose: Include detailed debug messages
            stdout: Print output to console
        ___

        # Instance Variables: 
        - `local_networks` - A `local_network.LocalNetworks` instance representing a list of networks considered local 
        by this cluster.
        """
        self.install_directory = install_directory
        self.local_networks = local_network.LocalNetworks()

        with open(f'{self.install_directory}/etc/networks.cfg') as config_f:
            config_data = dict(data=config_f.readlines())
        super().__init__(config_data, name='zeek.config.networks', verbose=verbose, stdout=stdout)

        self.add_parser(
            parser=self._parse_local_networks,
            attribute_name='local_networks'
        )

    def commit(self, out_file_path: Optional[str] = None, backup_directory: Optional[str] = None) -> None:
        """Write the changes out to configuration file
        Args:
            out_file_path: The path to the configuration file to write (or overwrite)
            backup_directory: The path to the backup directory

        Returns:
            None
        """
        if not out_file_path:
            out_file_path = f'{self.install_directory}/etc/networks.cfg'
        self.formatted_data = '\n'.join(self.local_networks.get_raw())
        super(LocalNetworksConfigManager, self).commit(out_file_path, backup_directory)

    @classmethod
    def from_raw_text(cls, raw_text: str, install_directory: Optional[str] = None):
        """Alternative method for creating configuration file from raw text
        Args:
            raw_text: The string representing the configuration file
            install_directory: The installation directory where the config file resides
        Returns:
             An instance of ConfigManager
        """

        tmp_dir = f'{const.CONFIG_PATH}/.tmp/etc'
        tmp_config = f'{tmp_dir}/networks.cfg'
        utilities.makedirs(tmp_dir)
        with open(tmp_config, 'w') as out_f:
            out_f.write(raw_text)
        c = cls(install_directory=f"{tmp_dir}/../")
        if install_directory:
            c.install_directory = install_directory
        return c