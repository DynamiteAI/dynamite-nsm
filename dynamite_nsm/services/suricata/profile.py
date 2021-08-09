try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from typing import List

from dynamite_nsm import utilities
from dynamite_nsm.services.base import profile
from dynamite_nsm.services.suricata import config as suricata_config
from dynamite_nsm.services.suricata import process as suricata_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        """
        Get information about the Suricata service
        """
        self.env_dict = utilities.get_environment_file_dict()
        self.suricata_home = self.env_dict.get('SURICATA_HOME')
        self.suricata_config = self.env_dict.get('SURICATA_CONFIG')

        profile.BaseProcessProfiler.__init__(self,
                                             install_directory=self.suricata_home,
                                             config_directory=self.suricata_config,
                                             required_install_files=['bin', 'include', 'lib'],
                                             required_config_files=['rules'])

    def get_attached_interfaces(self) -> List[str]:
        conf_mng = suricata_config.ConfigManager(configuration_directory=self.config_directory, stdout=False,
                                                 verbose=False)
        if not conf_mng.af_packet_interfaces:
            return []
        return [iface.interface for iface in conf_mng.af_packet_interfaces if
                iface.interface in utilities.get_network_interface_names()]

    def is_running(self) -> bool:
        """
        Determine of Suricata is running
        Returns:
            True, if running
        """
        if self.suricata_home:
            try:
                return suricata_process.ProcessManager().status()['running']
            except KeyError:
                return suricata_process.ProcessManager().status()['RUNNING']
        return False

    def is_attached_to_network(self) -> bool:
        """Determine if Suricata is bound to one or more network interfaces
        Returns:
            True, if attached to one or more network interfaces

        """
        return any(self.get_attached_interfaces())
