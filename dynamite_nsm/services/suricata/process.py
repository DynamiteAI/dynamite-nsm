import os
from typing import Dict, Optional, Union

from dynamite_nsm.services.base import process
from dynamite_nsm.services.suricata import profile
from dynamite_nsm import exceptions as general_exceptions

PID_DIRECTORY = '/var/run/dynamite/suricata/'


class ProcessManager(process.BaseProcessManager):
    """
    Suricata Process Manager
    """

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage Suricata processes and sub-processes
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
            pretty_print_status: If true, status will be printed in a tabular form
        """
        process.BaseProcessManager.__init__(self, 'suricata.service', 'suricata', log_path=None,
                                            stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)
        if not profile.ProcessProfiler().is_installed():
            raise general_exceptions.CallProcessError("Suricata is not installed.")


def start(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
          pretty_print_status: Optional[bool] = False) -> bool:
    """
    Start Suricata process
    Args:
        stdout: Print output to console
        verbose: Include detailed debug messages
        pretty_print_status: If true, status will be printed in a tabular form

    Returns:
        True, if succeeded
    """
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).start()


def stop(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
         pretty_print_status: Optional[bool] = False) -> bool:
    """
    Stop Suricata process
    Args:
        stdout: Print output to console
        verbose: Include detailed debug messages
        pretty_print_status: If true, status will be printed in a tabular form

    Returns:
        True, if succeeded
    """
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).stop()


def restart(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
            pretty_print_status: Optional[bool] = False) -> bool:
    """
    Restart Suricata process
    Args:
        stdout: Print output to console
        verbose: Include detailed debug messages
        pretty_print_status: If true, status will be printed in a tabular form

    Returns:
        True, if succeeded
    """
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).restart()


def status(stdout: Optional[bool] = True, verbose: Optional[bool] = False,
           pretty_print_status: Optional[bool] = False) -> Union[Dict, str]:
    """
    Get status of Suricata processes
    Args:
        stdout: Print output to console
        verbose: Include detailed debug messages
        pretty_print_status: If true, status will be printed in a tabular form

    Returns:
        A dictionary or string depending on the value of pretty_print_status
    """
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()
