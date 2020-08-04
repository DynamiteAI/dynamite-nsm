import os
import time

from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.elasticsearch import exceptions as elasticsearch_exceptions


PID_DIRECTORY = '/var/run/dynamite/elasticsearch/'


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout=True, verbose=False):
        try:
            process.BaseProcessManager.__init__(self, 'elasticsearch.service', log_path=None,
                                                pid_file=os.path.join(PID_DIRECTORY, 'elasticsearch.pid'),
                                                stdout=stdout, verbose=verbose)
        except general_exceptions.CallProcessError:
            raise elasticsearch_exceptions.CallElasticProcessError("Could not find systemctl.")


def start(stdout=True, verbose=False):
    p = ProcessManager(stdout=stdout, verbose=verbose)
    p.start()

    # Let's block for a few seconds to allow elasticsearch time to create a PID
    i = 0
    while not p.pid:
        # If after 10 seconds we don't detect a PID we return status of potentially dead process
        if i > 10:
            break
        time.sleep(1)
        i += 1
    return p.status()


def stop(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
