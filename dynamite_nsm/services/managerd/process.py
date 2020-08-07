import os

from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.managerd import exceptions as managerd_exceptions

PID_DIRECTORY = '/var/run/dynamite/managerd/'


class ProcessManager(process.BaseProcessManager):
    """
    Managerd Process Manager
    """
    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        environ = utilities.get_environment_file_dict()
        try:
            process.BaseProcessManager.__init__(self, 'managerd.service', 'managerd',
                                                log_path=environ.get('MANAGERD_LOGS'),
                                                pid_file=os.path.join(PID_DIRECTORY, 'managerd.pid'),
                                                stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            raise managerd_exceptions.CallManagerDaemonProcessError("Could not find systemctl.")


def start(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).start()


def stop(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).stop()


def restart(stdout=True, verbose=False, pretty_print_status=False):
    ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).restart()


def status(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()


