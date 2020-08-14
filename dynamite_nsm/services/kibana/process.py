import os
import time
import subprocess

from dynamite_nsm import utilities
from dynamite_nsm.services.base import process
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.kibana import profile as kibana_profile
from dynamite_nsm.services.kibana import exceptions as kibana_exceptions


PID_DIRECTORY = '/var/run/dynamite/kibana/'


class ProcessManager(process.BaseProcessManager):
    """
    Kibana Process Manager
    """
    def __init__(self, stdout=True, verbose=False, pretty_print_status=False):
        environ = utilities.get_environment_file_dict()
        try:
            process.BaseProcessManager.__init__(self, 'kibana.service', 'kibana', log_path=environ.get('KIBANA_LOGS'),
                                                pid_file=os.path.join(PID_DIRECTORY, 'kibana.pid'), stdout=stdout,
                                                verbose=verbose, pretty_print_status=pretty_print_status)
        except general_exceptions.CallProcessError:
            self.logger.error("Could not find systemctl on this system.")
            raise kibana_exceptions.CallKibanaProcessError("Could not find systemctl.")
        if not kibana_profile.ProcessProfiler().is_installed():
            self.logger.error("Kibana is not installed. Install it with 'dynamite kibana install -h'")
            raise kibana_exceptions.CallKibanaProcessError("Kibana is not installed.")

    def optimize(self):
        """
        Runs Kibana webpack optimizer among other things.
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
