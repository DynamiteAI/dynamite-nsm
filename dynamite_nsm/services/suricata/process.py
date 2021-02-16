import os
from typing import Dict, Optional, Union

from dynamite_nsm.services.base import process
from dynamite_nsm.services.suricata import profile
from dynamite_nsm import exceptions as general_exceptions

PID_DIRECTORY = '/var/run/dynamite/suricata/'


class ProcessManager(process.BaseProcessManager):
    """
    Suricata Process Manager
    """

    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        process.BaseProcessManager.__init__(self, 'suricata.service', 'suricata', log_path=None,
                                            pid_file=os.path.join(PID_DIRECTORY, 'suricata.pid'), stdout=stdout,
                                            verbose=verbose, pretty_print_status=pretty_print_status)
        if not profile.ProcessProfiler().is_installed():
            raise general_exceptions.CallProcessError("Suricata is not installed.")


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
           pretty_print_status: Optional[bool] = False) -> Union[Dict, str]:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()
