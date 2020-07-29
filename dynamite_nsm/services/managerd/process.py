import os
import logging

from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.managerd import exceptions as managerd_exceptions

PID_DIRECTORY = '/var/run/dynamite/managerd/'


class ProcessManager:
    """
    An interface for start|stop|status|restart of the managerd process
    """

    def __init__(self, stdout=True, verbose=False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('MANAGERD', level=log_level, stdout=stdout)

        self.stdout = stdout,
        self.verbose = verbose
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('MANAGERD_INSTALL')
        self.logging_directory = self.environment_variables.get('MANAGERD_LOGS')
        if not self.install_directory:
            self.logger.error("Could not resolve MANAGERD_INSTALL environment variable. Is managerd installed?")
            raise managerd_exceptions.CallManagerDaemonProcessError(
                "Could not resolve MANAGERD_INSTALL environment variable. Is managerd installed?")

        if not os.path.exists(PID_DIRECTORY):
            utilities.makedirs(PID_DIRECTORY, exist_ok=True)
        try:
            with open(os.path.join(PID_DIRECTORY, 'managerd.pid')) as pid_f:
                self.pid = int(pid_f.read())
        except (IOError, ValueError):
            self.pid = -1

        try:
            self.sysctl = systemctl.SystemCtl()
        except general_exceptions.CallProcessError:
            raise managerd_exceptions.CallManagerDaemonProcessError("Could not find systemctl.")

    def start(self):
        """
        Start the managerd daemon

        :return: True if started successfully
        """
        self.logger.info('Attempting to start managerd.')
        return self.sysctl.start('managerd')

    def status(self):
        """
        Check the status of the managerd process

        :return: A dictionary containing the run status and relevant configuration options
        """
        log_path = self.logging_directory

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'LOGS': log_path
        }

    def stop(self):
        """
        Stop the managerd process

        :return: True if stopped successfully
        """
        self.logger.info('Attempting to stop managerd [{}].'.format(self.pid))
        return self.sysctl.stop('managerd')

    def restart(self):
        """
        Restart the managerd process

        :return: True if started successfully
        """
        self.logger.info('Attempting to restart managerd [{}].'.format(self.pid))
        return self.sysctl.restart('managerd')


def start(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
