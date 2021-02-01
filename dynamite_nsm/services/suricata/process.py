import os
from typing import Dict, Optional

from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.suricata import profile as suricata_profile
from dynamite_nsm.services.suricata import exceptions as suricata_exceptions


PID_DIRECTORY = '/var/run/dynamite/suricata/'


class ProcessManager(process.BaseProcessManager):
    """
    Suricata Process Manager
    """

    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        try:
            process.BaseProcessManager.__init__(self, 'suricata.service', 'suricata', log_path=None,
                                                pid_file=os.path.join(PID_DIRECTORY, 'suricata.pid'), stdout=stdout,
                                                verbose=verbose, pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            raise suricata_exceptions.CallSuricataProcessError("Could not find systemctl.")
        if not suricata_profile.ProcessProfiler().is_installed():
            self.logger.error("Suricata is not installed. Install it with 'dynamite agent install -h'")
            raise suricata_exceptions.CallSuricataProcessError("Suricata is not installed.")


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

