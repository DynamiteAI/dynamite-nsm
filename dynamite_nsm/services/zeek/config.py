import os
import re
import math
import random
import logging
from datetime import datetime

try:
    # Python 3
    from itertools import zip_longest
except ImportError:
    # Python 2
    from itertools import izip_longest as zip_longest

try:
    from ConfigParser import ConfigParser
except Exception:
    from configparser import ConfigParser

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.zeek import exceptions as zeek_exceptions


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
        destination_configuration_path = os.path.join(self.backup_configuration_directory, 'local.zeek.d')
        if self.backup_configuration_directory:
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


class NodeConfigManager:
    """
    Wrapper for configuring broctl node.cfg
    """

    def __init__(self, install_directory, backup_configuration_directory=None):
        """
        :param install_directory: Path to the install directory (E.G /opt/dynamite/zeek/)
        """
        self.install_directory = install_directory
        self.backup_configuration_directory = backup_configuration_directory
        self.node_config = self._parse_node_config()

    def _parse_node_config(self):
        """
        :return: A dictionary representing the configurations stored within node.cfg
        """
        node_config = {}
        config_parser = ConfigParser()
        config_parser.readfp(open(os.path.join(self.install_directory, 'etc', 'node.cfg')))
        for section in config_parser.sections():
            node_config[section] = {}
            for item in config_parser.items(section):
                key, value = item
                node_config[section][key] = value
        return node_config

    @staticmethod
    def get_optimal_zeek_worker_config(network_capture_interfaces, strategy="aggressive", cpus=None, stdout=True,
                                       verbose=False):
        """
        Algorithm for determining the assignment of CPUs for Zeek workers

        :param network_capture_interfaces: A list of network interface names
        :param strategy: 'aggressive', results in more CPUs pinned per interface, sometimes overshoots resources
                         'conservative', results in less CPUs pinned per interface, but never overshoots resources
        :param cpus: If None, we'll derive this by looking at the cpu core count,
                     otherwise a list of cpu cores (E.G [0, 1, 2])
        :param stdout: Print the output to console
        :param verbose: Include detailed debug messages
        :return: A dictionary containing Zeek worker configuration
        """
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        logger = get_logger('ZEEK', level=log_level, stdout=stdout)
        if not cpus:
            cpus = [c for c in range(0, utilities.get_cpu_core_count())]
        logger.info("Calculating optimal Zeek worker strategy [strategy: {}].".format(strategy))
        logger.debug("Detected CPU Cores: {}".format(cpus))

        # Reserve 0 for KERNEL/Userland opts
        available_cpus = cpus[1:]

        def grouper(n, iterable):
            args = [iter(iterable)] * n
            return zip_longest(*args)

        def create_workers(net_interfaces, avail_cpus):
            idx = 0
            zeek_worker_configs = []
            for net_interface in net_interfaces:
                if idx >= len(avail_cpus):
                    idx = 0
                if isinstance(avail_cpus[idx], int):
                    avail_cpus[idx] = [avail_cpus[idx]]
                zeek_worker_configs.append(
                    dict(
                        name='dynamite-worker-' + net_interface,
                        host='localhost',
                        interface=net_interface,
                        lb_procs=len(avail_cpus[idx]),
                        pinned_cpus=avail_cpus[idx],
                        af_packet_fanout_id=random.randint(1, 32768),
                        af_packet_fanout_mode='AF_Packet::FANOUT_HASH'
                    )
                )
                idx += 1
            return zeek_worker_configs

        if len(available_cpus) <= len(network_capture_interfaces):
            # Wrap the number of CPUs around the number of network interfaces;
            # Since there are more network interfaces than CPUs; CPUs will be assigned more than once
            # lb_procs will always be 1

            zeek_workers = create_workers(network_capture_interfaces, available_cpus)

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
            aggressive_ratio = int(math.ceil(len(available_cpus) / float(len(network_capture_interfaces))))
            conservative_ratio = int(math.floor(len(available_cpus) / len(network_capture_interfaces)))
            if strategy == 'aggressive':
                cpu_groups = grouper(aggressive_ratio, available_cpus)
            else:
                cpu_groups = grouper(conservative_ratio, available_cpus)

            temp_cpu_groups = []
            for cpu_group in cpu_groups:
                cpu_group = [c for c in cpu_group if c]
                temp_cpu_groups.append(cpu_group)
            cpu_groups = temp_cpu_groups
            zeek_workers = create_workers(network_capture_interfaces, cpu_groups)
        logger.info('Zeek Worker Count: {}'.format(len(zeek_workers)))
        logger.debug('Zeek Workers: {}'.format(zeek_workers))
        return zeek_workers

    def add_logger(self, name, host):
        """
        :param name: The name of the logger
        :param host: The host on which the logger is running
        """
        self.node_config[name] = {
            'type': 'logger',
            'host': host
        }

    def add_manager(self, name, host):
        """
        :param name: The name of the manager
        :param host: The host on which the manager is running
        """
        self.node_config[name] = {
            'type': 'manager',
            'host': host
        }

    def add_proxy(self, name, host):
        """
        :param name: The name of the proxy
        :param host: The host on which the proxy is running
        """
        self.node_config[name] = {
            'type': 'proxy',
            'host': host
        }

    def add_worker(self, name, interface, host, lb_procs=10, pin_cpus=(0, 1), af_packet_fanout_id=None,
                   af_packet_fanout_mode=None):
        """
        :param name: The name of the worker
        :param interface: The interface that the worker should be monitoring
        :param host: The host on which the worker is running
        :param lb_procs: The number of Zeek processes associated with a given worker
        :param pin_cpus: Core affinity for the processes (iterable),
        :param af_packet_fanout_id: To scale processing across threads, packet sockets can form a
                                    fanout group.  In this mode, each matching packet is enqueued
                                    onto only one socket in the group.  A socket joins a fanout
                                    group by calling setsockopt(2) with level SOL_PACKET and
                                    option PACKET_FANOUT.  Each network namespace can have up to
                                    65536 independent groups.
        :param af_packet_fanout_mode: The algorithm used to spread traffic between sockets.
        """
        valid_fanout_modes = [
            'FANOUT_HASH',  # The default mode, PACKET_FANOUT_HASH, sends packets from
            # the same flow to the same socket to maintain per-flow
            # ordering.  For each packet, it chooses a socket by taking
            # the packet flow hash modulo the number of sockets in the
            # group, where a flow hash is a hash over network-layer
            # address and optional transport-layer port fields.

            'FANOUT_CPU',  # selects the socket based on the CPU that the packet arrived on

            'FANOUT_QM'  # (available since Linux 3.14) selects the socket using the recorded
            # queue_mapping of the received skb.
        ]
        if not str(interface).startswith('af_packet::'):
            interface = 'af_packet::' + interface
        if not af_packet_fanout_id:
            af_packet_fanout_id = random.randint(1, 32768)
        if not af_packet_fanout_mode:
            af_packet_fanout_mode = 'AF_Packet::FANOUT_HASH'
        else:
            if str(af_packet_fanout_mode).upper() in valid_fanout_modes:
                af_packet_fanout_mode = 'AF_Packet::' + str(af_packet_fanout_mode).upper()
            else:
                af_packet_fanout_mode = 'AF_Packet::FANOUT_HASH'
        if max(pin_cpus) < utilities.get_cpu_core_count() and min(pin_cpus) >= 0:
            pin_cpus = [str(cpu_n) for cpu_n in pin_cpus]
            self.node_config[name] = {
                'type': 'worker',
                'interface': interface,
                'lb_method': 'custom',
                'lb_procs': lb_procs,
                'pin_cpus': ','.join(pin_cpus),
                'host': host,
                'af_packet_fanout_id': af_packet_fanout_id,
                'af_packet_fanout_mode': af_packet_fanout_mode
            }

    def remove_logger(self, name):
        """
        :param name: The name of the logger
        """
        try:
            if self.node_config[name]['type'] == 'logger':
                del self.node_config[name]
        except KeyError:
            raise zeek_exceptions.ZeekLoggerNotFoundError(name)

    def remove_manager(self, name):
        """
        :param name: The name of the manager
        """
        try:
            if self.node_config[name]['type'] == 'manager':
                del self.node_config[name]
        except KeyError:
            raise zeek_exceptions.ZeekManagerNotFoundError(name)

    def remove_proxy(self, name):
        """
        :param name: The name of the proxy
        """
        try:
            if self.node_config[name]['type'] == 'proxy':
                del self.node_config[name]
        except KeyError:
            raise zeek_exceptions.ZeekProxyNotFoundError(name)

    def remove_worker(self, name):
        """
        :param name: The name of the worker
        """
        try:
            if self.node_config[name]['type'] == 'worker':
                del self.node_config[name]
        except KeyError:
            raise zeek_exceptions.ZeekWorkerNotFoundError(name)

    def list_workers(self):
        """
        :return: A list of worker names
        """
        workers = []
        for component, values in self.node_config.items():
            if values['type'] == 'worker':
                workers.append(component)
        return workers

    def list_proxies(self):
        """
        :return: A list of proxy names
        """
        proxies = []
        for component, values in self.node_config.items():
            if values['type'] == 'proxy':
                proxies.append(component)
        return proxies

    def list_loggers(self):
        """
        :return: A list of logger names
        """
        loggers = []
        for component, values in self.node_config.items():
            if values['type'] == 'logger':
                loggers.append(component)
        return loggers

    def get_manager(self):
        """
        :return: The name of the manager
        """
        for component, values in self.node_config.items():
            if values['type'] == 'manager':
                return component
        return None

    def list_backup_configs(self):
        """
        List configuration backups

        :return: A list of dictionaries with the following keys: ["name", "path", "timestamp"]
        """
        return utilities.list_backup_configurations(
            os.path.join(self.backup_configuration_directory, 'node.cfg.d'))

    def restore_backup_config(self, name):
        """
        Restore a configuration from our config store

        :param name: The name of the configuration file or the keyword "recent" which will restore the most recent
        backup.
        :return: True, if successful
        """
        dest_config_file = os.path.join(self.install_directory, 'etc', 'node.cfg')
        if name == "recent":
            configs = self.list_backup_configs()
            if configs:
                return utilities.restore_backup_configuration(
                    configs[0]['filepath'],
                    dest_config_file)
        return utilities.restore_backup_configuration(
            os.path.join(self.backup_configuration_directory, 'node.cfg.d', name), dest_config_file)

    def write_config(self):
        """
        Overwrite the existing node.cfg with changed values
        """
        source_configuration_file_path = os.path.join(self.install_directory, 'etc', 'node.cfg')
        destination_configuration_path = os.path.join(self.backup_configuration_directory, 'node.cfg.d')
        if self.backup_configuration_directory:
            try:
                utilities.backup_configuration_file(source_configuration_file_path, destination_configuration_path,
                                                    destination_file_prefix='node.cfg.backup')
            except general_exceptions.WriteConfigError:
                raise zeek_exceptions.WriteZeekConfigError('Zeek configuration failed to write [node.cfg].')
            except general_exceptions.ReadConfigError:
                raise zeek_exceptions.ReadsZeekConfigError('Zeek configuration failed to read [node.cfg].')

        config = ConfigParser()
        for section in self.node_config.keys():
            for k, v in self.node_config[section].items():
                try:
                    config.add_section(section)
                except Exception:  # Duplicate section
                    pass
                config.set(section, k, str(v))
        try:
            with open(source_configuration_file_path, 'w') as configfile:
                config.write(configfile)
        except IOError:
            raise zeek_exceptions.WriteZeekConfigError("Could not locate {}".format(self.install_directory))
        except Exception as e:
            raise zeek_exceptions.WriteZeekConfigError(
                "General error while attempting to write new node.cfg file to {}; {}".format(
                    self.install_directory, e))


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
        destination_configuration_path = os.path.join(self.backup_configuration_directory, 'networks.cfg.d')
        if self.backup_configuration_directory:
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
