import math
import logging
from typing import List, Optional

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.zeek import config as zeek_config
from dynamite_nsm.services.zeek import profile as zeek_profile
from dynamite_nsm.services.suricata import config as suricata_config
from dynamite_nsm.services.suricata import profile as suricata_profile


class OptimizeThreadingManager:

    def __init__(self, suricata_configuration_directory: Optional[str] = None,
                 zeek_install_directory: Optional[str] = None, stdout: Optional[bool] = False,
                 verbose: Optional[bool] = False):

        """Manage how Zeek and Suricata split up CPU resources
        Args:
            suricata_configuration_directory: Path to the Suricata configuration directory (E.G /etc/dynamite/suricata)
            zeek_install_directory: Path to the Zeek installation directory (E.G /opt/dynamite/zeek)
            stdout: Print the output to console
            verbose: Include detailed debug messages
        """
        self.suricata_configuration_directory = suricata_configuration_directory
        self.zeek_install_directory = zeek_install_directory
        self.stdout = stdout
        self.verbose = verbose
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('agent.thread_optimize', level=log_level, stdout=stdout)

    def optimize(self, inspect_interfaces: List[str]) -> None:
        """Apply the best CPU-affinity related configurations to Zeek and Suricata
        Args:
            inspect_interfaces: A list of network interfaces to capture on (E.G ["mon0", "mon1", "mon2"])

        Returns:
            None
        """
        if not inspect_interfaces:
            self.logger.error('Please specify the \'inspect-interfaces\' you wish to capture on.')
            return None
        zeek_profiler = zeek_profile.ProcessProfiler()
        suricata_profiler = suricata_profile.ProcessProfiler()

        available_cpus = [c for c in range(0, utilities.get_cpu_core_count())]
        self.logger.info(f'{len(available_cpus)} CPU cores detected.')
        if zeek_profiler.is_installed() and suricata_profiler.is_installed():
            self.logger.info(
                'Both Zeek and Suricata are installed. Allocating 60% of resources to Zeek, '
                '30% to Suricata, and 10% to Kernel.')
            kern_alloc, zeek_alloc, suricata_alloc = .1, .6, .3
        elif zeek_profiler.is_installed():
            self.logger.info(
                'Only Zeek is installed. Allocating 90% of resources to it and 10% to Kernel.')
            kern_alloc, zeek_alloc, suricata_alloc = .1, .9, 0
        elif suricata_profiler.is_installed():
            self.logger.info(
                'Only Suricata is installed. Allocating 90% of resources to it and 10% to Kernel.')
            kern_alloc, zeek_alloc, suricata_alloc = .1, 0, .9
        else:
            self.logger.error(
                'Neither Zeek nor Suricata is installed. You must install at least one of these in order '
                'to run this command.')
            return None
        kern_cpu_count = math.ceil(kern_alloc * len(available_cpus))
        zeek_cpu_count = math.ceil(zeek_alloc * len(available_cpus))
        suricata_cpu_count = math.ceil(suricata_alloc * len(available_cpus))

        zeek_cpus = [c for c in available_cpus[kern_cpu_count: kern_cpu_count + zeek_cpu_count]]
        suricata_cpus = [
            c for c in
            available_cpus[kern_cpu_count + zeek_cpu_count: kern_cpu_count + zeek_cpu_count + suricata_cpu_count]]

        if zeek_profiler.is_installed():
            zeek_node_config_mng = zeek_config.NodeConfigManager(install_directory=self.zeek_install_directory,
                                                                 stdout=self.stdout, verbose=self.verbose)
            zeek_node_config_mng.workers = zeek_node_config_mng.get_optimal_zeek_worker_config(
                inspect_interfaces, available_cpus=tuple(zeek_cpus))
            zeek_node_config_mng.commit()
        if suricata_profiler.is_installed():
            suricata_config_mng = suricata_config.ConfigManager(
                configuration_directory=self.suricata_configuration_directory, stdout=self.stdout, verbose=self.verbose)
            suricata_config_mng.threading = suricata_config_mng.get_optimal_suricata_threading_config(
                available_cpus=tuple(suricata_cpus))
            suricata_config_mng.runmode = 'workers'
            for suricata_iface in suricata_config_mng.af_packet_interfaces:
                suricata_iface.threads = len(suricata_config_mng.threading.worker_cpu_set)
                suricata_iface.cluster_type = 'cluster_qm'
            suricata_config_mng.commit()
