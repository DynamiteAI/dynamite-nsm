import os

from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.zeek import exceptions as zeek_exceptions

PID_DIRECTORY = '/var/run/dynamite/filebeat/'


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout=True, verbose=False):
        try:
            process.BaseProcessManager.__init__(self, 'filebeat.service', log_path=None,
                                                pid_file=os.path.join(PID_DIRECTORY, 'filebeat.pid'), stdout=stdout,
                                                verbose=verbose)
        except general_exceptions.CallProcessError:
            raise zeek_exceptions.CallZeekProcessError("Could not find systemctl.")


def start(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
