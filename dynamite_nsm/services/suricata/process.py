import os
from typing import Dict, Optional, Union

from dynamite_nsm.services.base import process
from dynamite_nsm.services.suricata import profile
from dynamite_nsm import exceptions as general_exceptions

PID_DIRECTORY = '/var/run/dynamite/suricata/'


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
            raise general_exceptions.CallProcessError("Suricata is not installed.")
