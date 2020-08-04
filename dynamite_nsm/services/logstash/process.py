import os

from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.logstash import exceptions as logstash_exceptions


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout=True, verbose=False):
        try:
            process.BaseProcessManager.__init__(self, 'logstash.service', log_path=None,
                                                stdout=stdout, verbose=verbose)
        except general_exceptions.CallProcessError:
            raise logstash_exceptions.CallLogstashProcessError("Could not find systemctl.")


def start(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
