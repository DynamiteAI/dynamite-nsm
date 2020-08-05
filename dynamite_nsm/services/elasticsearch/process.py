import os
import time

from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.elasticsearch import exceptions as elasticsearch_exceptions

PID_DIRECTORY = '/var/run/dynamite/elasticsearch/'


class ProcessManager(process.BaseProcessManager):
    """
    ElasticSearch Process Manager
    """
    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        environ = utilities.get_environment_file_dict()
        try:
            process.BaseProcessManager.__init__(self, 'elasticsearch.service', 'elasticsearch',
                                                log_path=environ.get('ES_LOGS'),
                                                pid_file=os.path.join(PID_DIRECTORY, 'elasticsearch.pid'),
                                                stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            raise elasticsearch_exceptions.CallElasticProcessError("Could not find systemctl.")


def start(stdout=True, verbose=False, pretty_print_status=False):
    p = ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)
    p.start()

    # Let's block for a few seconds to allow kibana time to create a PID
    i = 0
    while not p.pid:
        # If after 10 seconds we don't detect a PID we return status of potentially dead process
        if i > 10:
            break
        time.sleep(1)
        i += 1
    return p.status()


def stop(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).stop()


def restart(stdout=True, verbose=False, pretty_print_status=False):
    ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).restart()


def status(stdout=True, verbose=False, pretty_print_status=False):
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()
