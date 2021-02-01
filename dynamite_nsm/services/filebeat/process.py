import os
from typing import Dict, Optional

from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.base import process
from dynamite_nsm.services.filebeat import exceptions as filebeat_exceptions
from dynamite_nsm.services.filebeat import profile as filebeat_profile

PID_DIRECTORY = '/var/run/dynamite/filebeat/'


class ProcessManager(process.BaseProcessManager):
    """
    FileBeat Process Manager
    """

    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        try:
            process.BaseProcessManager.__init__(self, 'filebeat.service', 'filebeat', log_path=None,
                                                pid_file=os.path.join(PID_DIRECTORY, 'filebeat.pid'), stdout=stdout,
                                                verbose=verbose, pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            self.logger.error("Could not find systemctl on this system.")
            raise filebeat_exceptions.CallFilebeatProcessError("Could not find systemctl.")
        if not filebeat_profile.ProcessProfiler().is_installed():
            self.logger.error("FileBeat is not installed. Install it with 'dynamite agent install -h'")
            raise filebeat_exceptions.CallFilebeatProcessError("FileBeat is not installed.")


def start(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
          pretty_print_status: Optional[bool] = False) -> bool:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).start()


def stop(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
         pretty_print_status: Optional[bool] = False) -> bool:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).stop()


def restart(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
            pretty_print_status: Optional[bool] = False) -> bool:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).restart()


def status(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
           pretty_print_status: Optional[bool] = False) -> Dict:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()
