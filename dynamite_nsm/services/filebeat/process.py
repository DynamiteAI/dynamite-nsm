from typing import Optional

from dynamite_nsm import exceptions
from dynamite_nsm.services.base import process
from dynamite_nsm.services.filebeat import profile as profile


class CallFilebeatProcessError(exceptions.CallProcessError):
    def __init__(self, message):
        """Thrown when filebeat process encounters an error state
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = "An error occurred while calling filebeat process: {}".format(message)
        super(CallFilebeatProcessError, self).__init__(msg)


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage Filebeat Process
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
            pretty_print_status: If enabled, status will be printed in a tabulated style
        Returns:
            None
        """
        process.BaseProcessManager.__init__(self, 'filebeat.service', 'filebeat.process', log_path=None, stdout=stdout,
                                            verbose=verbose, pretty_print_status=pretty_print_status)

        if not profile.ProcessProfiler().is_installed():
            self.logger.error("Filebeat is not installed. Install it with 'dynamite filebeat install -h'")
            raise CallFilebeatProcessError('Filebeat is not installed.')
