import os
import time
from typing import Dict, Optional, Union

from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm.services.elasticsearch import exceptions as elasticsearch_exceptions
from dynamite_nsm.services.elasticsearch import profile as elasticsearch_profile


class ProcessManager(process.BaseProcessManager):
    """
    ElasticSearch Process Manager
    """

    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        environ = utilities.get_environment_file_dict()
        try:
            process.BaseProcessManager.__init__(self, 'elasticsearch.service', 'elasticsearch',
                                                log_path=environ.get('ES_LOGS'),
                                                create_pid_file=True,
                                                stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            self.logger.error("Could not find systemctl on this system.")
            raise elasticsearch_exceptions.CallElasticProcessError("Could not find systemctl.")
        if not elasticsearch_profile.ProcessProfiler().is_installed():
            self.logger.error("ElasticSearch is not installed. Install it with 'dynamite elasticsearch install -h'")
            raise elasticsearch_exceptions.CallElasticProcessError("ElasticSearch is not installed.")


def start(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
          pretty_print_status: Optional[bool] = False) -> Union[Dict, str]:
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


def stop(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
         pretty_print_status: Optional[bool] = False) -> bool:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).stop()


def restart(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
            pretty_print_status: Optional[bool] = False) -> bool:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).restart()


def status(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
           pretty_print_status: Optional[bool] = False) -> Dict:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()
