from typing import List

from dynamite_nsm import utilities
from dynamite_nsm.services.base import profile
from dynamite_nsm.services.zeek import config as zeek_config
from dynamite_nsm.services.zeek import process as zeek_process


class ProcessProfiler(profile.BaseProcessProfiler):
    def __init__(self):
        """
        Get information about the Zeek service
        """
        self.env_dict = utilities.get_environment_file_dict()
        self.zeek_home = self.env_dict.get('ZEEK_HOME')
        self.zeek_scripts = self.env_dict.get('ZEEK_SCRIPTS')

        profile.BaseProcessProfiler.__init__(self,
                                             install_directory=self.zeek_home,
                                             config_directory=self.zeek_scripts,
                                             required_install_files=['bin', 'etc'],
                                             required_config_files=['site'])

    def get_attached_interfaces(self) -> List[str]:
        conf_mng = zeek_config.NodeConfigManager(install_directory=self.install_directory, stdout=False,
                                                 verbose=False)
        if not conf_mng.workers:
            return []
        return [worker.interface for worker in conf_mng.workers if
                worker.interface in utilities.get_network_interface_names()]

    def is_running(self) -> bool:
        """
        Determine of Zeek is running
        Returns:
            True, if running
        """
        if self.zeek_home:
            try:
                return zeek_process.ProcessManager().status()['running']
            except KeyError:
                return zeek_process.ProcessManager().status()['RUNNING']
        return False

    def is_attached_to_network(self) -> bool:
        """Determine if Zeek is bound to one or more network interfaces
        Returns:
            True, if attached to one or more network interfaces

        """
        return any(self.get_attached_interfaces())
