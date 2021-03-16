from typing import Dict, Optional, Union

from dynamite_nsm import exceptions
from dynamite_nsm.services.base import process
from dynamite_nsm.services.filebeat import profile as profile


class CallFilebeatProcessError(exceptions.CallProcessError):
    """
    Thrown when filebeat process encounters an error state
    """
    def __init__(self, message):
        """
        :param message: A more specific error message
        """
        msg = "An error occurred while calling filebeat process: {}".format(message)
        super(CallFilebeatProcessError, self).__init__(msg)


class ProcessManager(process.BaseProcessManager):
    """
    FileBeat Process Manager
    """

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """
        Manage Filebeat Process

        :param stdout: Print output to console
        :param verbose: Include detailed debug messages
        :param pretty_print_status: If enabled, status will be printed in a tabulated style
        """
        process.BaseProcessManager.__init__(self, 'filebeat.service', 'filebeat', log_path=None, stdout=stdout,
                                            verbose=verbose, pretty_print_status=pretty_print_status)

        if not profile.ProcessProfiler().is_installed():
            self.logger.error("Filebeat is not installed. Install it with 'dynamite filebeat install -h'")
            raise CallFilebeatProcessError('Filebeat is not installed.')


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
           pretty_print_status: Optional[bool] = False) -> Union[Dict, str]:
    return ProcessManager(stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status).status()
