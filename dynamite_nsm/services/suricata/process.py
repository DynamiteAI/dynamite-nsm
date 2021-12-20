from typing import Optional

from dynamite_nsm.services.base import process
from dynamite_nsm.services.suricata import profile
from dynamite_nsm import exceptions


class CallSuricataProcessError(exceptions.CallProcessError):
    def __init__(self, message):
        """Thrown when suricata process encounters an error state
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred while calling suricata process: {}".format(message)
        super(CallSuricataProcessError, self).__init__(msg)


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage Suricata processes and sub-processes
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
            pretty_print_status: If true, status will be printed in a tabular form
        """
        process.BaseProcessManager.__init__(self, 'suricata.service', 'suricata.process', log_path=None,
                                            stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)
        if not profile.ProcessProfiler().is_installed():
            raise exceptions.CallProcessError("Suricata is not installed.")
