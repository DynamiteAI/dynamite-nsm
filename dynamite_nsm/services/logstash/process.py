from typing import Optional

from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.logstash import profile as logstash_profile
from dynamite_nsm.services.logstash import exceptions as logstash_exceptions


class ProcessManager(process.BaseProcessManager):
    """
    LogStash Process Manager
    """
    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        environ = utilities.get_environment_file_dict()
        try:
            process.BaseProcessManager.__init__(self, 'logstash.service', 'logstash', log_path=environ.get('LS_LOGS'),
                                                stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            self.logger.error("Could not find systemctl on this system.")
            raise logstash_exceptions.CallLogstashProcessError("Could not find systemctl.")
        if not logstash_profile.ProcessProfiler().is_installed():
            self.logger.error("LogStash is not installed. Install it with 'dynamite logstash install -h'")
            raise logstash_exceptions.CallLogstashProcessError("LogStash is not installed.")


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
           pretty_print_status: Optional[bool] = False) -> bool:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()

