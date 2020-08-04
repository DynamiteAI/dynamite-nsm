import os

from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.zeek import exceptions as zeek_exceptions

PID_DIRECTORY = '/var/run/dynamite/filebeat/'


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        try:
            process.BaseProcessManager.__init__(self, 'filebeat.service', 'filebeat', log_path=None,
                                                pid_file=os.path.join(PID_DIRECTORY, 'filebeat.pid'), stdout=stdout,
                                                verbose=verbose, pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            raise zeek_exceptions.CallZeekProcessError("Could not find systemctl.")


def start(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).start()


def stop(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).stop()


def restart(stdout=True, verbose=False, pretty_print_status=False):
    ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).restart()


def status(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()
