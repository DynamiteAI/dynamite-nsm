import os
import subprocess
import time
from typing import Dict, Optional

from dynamite_nsm import utilities
from dynamite_nsm import exceptions
from dynamite_nsm.services.base import process
from dynamite_nsm.services.kibana import profile as kibana_profile

PID_DIRECTORY = '/var/run/dynamite/kibana/'


class CallKibanaProcessError(exceptions.CallProcessError):

    def __init__(self, message):
        """Thrown when kibana process encounters an error state
        Args:
            message: A more specific error message
        Returns:
            None
        """
        msg = f'An error occurred while calling kibana process: {message}'
        super(CallKibanaProcessError, self).__init__(msg)


class ProcessManager(process.BaseProcessManager):

    def __init__(self, stdout: Optional[bool] = True, verbose: Optional[bool] = False,
                 pretty_print_status: Optional[bool] = False):
        """Manage Kibana Process
        Args:
            stdout: Print output to console
            verbose: Include detailed debug messages
            pretty_print_status: If enabled, status will be printed in a tabulated style
        Returns:
            None
        """
        environ = utilities.get_environment_file_dict()
        process.BaseProcessManager.__init__(self, 'kibana.service', 'kibana.process', log_path=environ.get('KIBANA_LOGS'),
                                            stdout=stdout, verbose=verbose, pretty_print_status=pretty_print_status)
        if not kibana_profile.ProcessProfiler().is_installed():
            self.logger.error("Kibana is not installed. Install it with 'dynamite kibana install -h'")
            raise CallKibanaProcessError("Kibana is not installed.")

    def optimize(self) -> None:
        """Runs Kibana webpack optimizer among other things.

        Returns:
            None
        """
        environ = utilities.get_environment_file_dict()
        if not os.path.exists(PID_DIRECTORY):
            utilities.makedirs(PID_DIRECTORY)
        utilities.set_ownership_of_file(PID_DIRECTORY, user='dynamite', group='dynamite')
        self.logger.info('Optimizing Kibana Libraries.')
        # Kibana initially has to be called as root due to a process forking issue when using runuser
        # builtin
        subprocess.call('{}/bin/kibana --optimize --allow-root'.format(
            environ['KIBANA_HOME'],
        ), shell=True, env=utilities.get_environment_file_dict(), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # Pass permissions back to dynamite user
        utilities.set_ownership_of_file(environ['KIBANA_LOGS'], user='dynamite', group='dynamite')
        utilities.set_ownership_of_file(environ['KIBANA_HOME'], user='dynamite', group='dynamite')
