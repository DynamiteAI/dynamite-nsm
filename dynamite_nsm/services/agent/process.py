import logging
from typing import Optional

from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.zeek import process as zeek_process
from dynamite_nsm.services.filebeat import process as filebeat_process
from dynamite_nsm.services.suricata import process as suricata_process

from dynamite_nsm.services.zeek import profile as zeek_profile
from dynamite_nsm.services.filebeat import profile as filebeat_profile
from dynamite_nsm.services.suricata import profile as suricata_profile


class ProcessManager:
    """
    FileBeat Process Manager
    """

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage Filebeat Process
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
            pretty_print_status: If enabled, status will be printed in a tabulated style
        Returns:
            None
        """
        self.stdout = stdout
        self.verbose = verbose
        self.pretty_print_status = pretty_print_status
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('agent.process', level=log_level, stdout=stdout)

    def start(self) -> bool:
        filebeat_res, suricata_res, zeek_res = True, True, True
        if not filebeat_profile.ProcessProfiler().is_installed():
            self.logger.error('You must install Filebeat to run this command.')
            return False
        filebeat_res = filebeat_process.ProcessManager().start()
        if suricata_profile.ProcessProfiler().is_installed():
            suricata_res = suricata_process.ProcessManager().start()
        if zeek_profile.ProcessProfiler().is_installed():
            zeek_res = zeek_process.ProcessManager().start()
        return filebeat_res and zeek_res and suricata_res

    def stop(self) -> bool:
        filebeat_res, suricata_res, zeek_res = True, True, True
        if not filebeat_profile.ProcessProfiler().is_installed():
            self.logger.error('You must install Filebeat to run this command.')
            return False
        filebeat_res = filebeat_process.ProcessManager().stop()
        if suricata_profile.ProcessProfiler().is_installed():
            suricata_res = suricata_process.ProcessManager().stop()
        if zeek_profile.ProcessProfiler().is_installed():
            zeek_res = zeek_process.ProcessManager().stop()
        return filebeat_res and zeek_res and suricata_res

    def restart(self) -> bool:
        return self.stop() and self.start()
