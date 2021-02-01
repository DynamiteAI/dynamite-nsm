import os
from typing import Dict, Optional

from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.dynamited import exceptions as dynamited_exceptions

PID_DIRECTORY = '/var/run/dynamite/dynamited/'


class ProcessManager(process.BaseProcessManager):
    """
    dynamited Process Manager
    """
    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        environ = utilities.get_environment_file_dict()
        try:
            process.BaseProcessManager.__init__(self, 'dynamited.service', 'dynamited',
                                                log_path=environ.get('DYNAMITED_LOGS'),
                                                pid_file=os.path.join(PID_DIRECTORY, 'dynamited.pid'),
                                                stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            raise dynamited_exceptions.CallDynamiteDaemonProcessError("Could not find systemctl.")


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
