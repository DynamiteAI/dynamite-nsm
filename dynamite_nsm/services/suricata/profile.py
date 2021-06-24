try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from dynamite_nsm import utilities
from dynamite_nsm.services.base import profile
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
