import os
import logging

from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.filebeat import config as filebeat_configs
from dynamite_nsm.services.filebeat import exceptions as filebeat_exceptions

PID_DIRECTORY = '/var/run/dynamite/filebeat/'


class ProcessManager:
    """
    An interface for start|stop|status|restart of the Filebeat process
    """

    def __init__(self, stdout=True, verbose=False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('FILEBEAT', level=log_level, stdout=stdout)

        self.stdout = stdout,
        self.verbose = verbose
        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('FILEBEAT_HOME')
        if not self.install_directory:
            self.logger.error("Could not resolve FILEBEAT_HOME environment variable. Is Filebeat installed?")
            raise filebeat_exceptions.CallFilebeatProcessError(
                "Could not resolve FILEBEAT_HOME environment variable. Is Filebeat installed?")
        self.config = filebeat_configs.ConfigManager(self.install_directory)

        if not os.path.exists(PID_DIRECTORY):
            utilities.makedirs(PID_DIRECTORY, exist_ok=True)
        try:
            with open(os.path.join(PID_DIRECTORY, 'filebeat.pid')) as pid_f:
                self.pid = int(pid_f.read())
        except (IOError, ValueError):
            self.pid = -1

        try:
            self.sysctl = systemctl.SystemCtl()
        except general_exceptions.CallProcessError:
            raise filebeat_exceptions.CallFilebeatProcessError("Could not find systemctl.")

    def start(self):
        """
        Start the Filebeat daemon

        :return: True if started successfully
        """
        self.logger.info('Attempting to start Filebeat.')
        return self.sysctl.start('filebeat')

    def status(self):
        """
        Check the status of the FileBeat process

        :return: A dictionary containing the run status and relevant configuration options
        """
        log_path = os.path.join(self.config.install_directory, 'logs', 'filebeat')

        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'LOGS': log_path
        }

    def stop(self):
        """
        Stop the FileBeat process

        :return: True if stopped successfully
        """
        self.logger.info('Attempting to stop Filebeat [{}].'.format(self.pid))
        return self.sysctl.stop('filebeat')

    def restart(self):
        """
        Restart the FileBeat process

        :return: True if started successfully
        """
        self.logger.info('Attempting to restart Filebeat [{}].'.format(self.pid))
        return self.sysctl.restart('filebeat')


def start(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
