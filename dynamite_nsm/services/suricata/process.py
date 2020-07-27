import os
import logging

from dynamite_nsm import systemctl
from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
from dynamite_nsm import exceptions as general_exceptions
from dynamite_nsm.services.suricata import config as suricata_configs
from dynamite_nsm.services.suricata import exceptions as suricata_exceptions


PID_DIRECTORY = '/var/run/dynamite/suricata/'


class ProcessManager:
    """
    An interface for start|stop|status|restart of the Suricata process
    """

    def __init__(self, stdout=True, verbose=False):
        log_level = logging.INFO
        if verbose:
            log_level = logging.DEBUG
        self.logger = get_logger('SURICATA', level=log_level, stdout=stdout)

        self.environment_variables = utilities.get_environment_file_dict()
        self.install_directory = self.environment_variables.get('SURICATA_HOME')
        self.configuration_directory = self.environment_variables.get('SURICATA_CONFIG')
        if not self.install_directory:
            self.logger.error("Could not resolve SURICATA_HOME environment_variable. Is Suricata installed?")
            raise suricata_exceptions.CallSuricataProcessError(
                "Could not resolve SURICATA_HOME environment_variable. Is Suricata installed?")
        elif not self.configuration_directory:
            self.logger.error("Could not resolve SURICATA_CONFIG environment_variable. Is Suricata installed?")
            raise suricata_exceptions.CallSuricataProcessError(
                "Could not resolve SURICATA_CONFIG environment_variable. Is Suricata installed?")
        self.config = suricata_configs.ConfigManager(self.configuration_directory)

        try:
            with open(os.path.join(PID_DIRECTORY, 'suricata.pid')) as pid_f:
                self.pid = int(pid_f.read())
        except (IOError, ValueError):
            self.pid = -1

        try:
            self.sysctl = systemctl.SystemCtl()
        except general_exceptions.CallProcessError:
            raise suricata_exceptions.CallSuricataProcessError("Could not find systemctl.")

    def start(self):
        """
        Start Suricata IDS process in daemon mode

        :return: True, if started successfully
        """
        self.logger.info('Attempting to start Suricata.')
        return self.sysctl.start("suricata")

    def stop(self):
        """
        Stop the Suricata process

        :return: True if stopped successfully
        """
        self.logger.info('Attempting to stop Suricata [{}]'.format(self.pid))
        return self.sysctl.stop("suricata")

    def restart(self):
        """
        Restart the Suricata process

        :return: True if restarted successfully
        """
        self.logger.info('Attempting to restart Suricata.')
        return self.sysctl.restart("suricata")

    def status(self):
        """
        Check the status of the Suricata process

        :return: A dictionary containing the run status and relevant configuration options
        """
        return {
            'PID': self.pid,
            'RUNNING': utilities.check_pid(self.pid),
            'LOG': os.path.join(self.config.default_log_directory, 'suricata.log')
        }


def start(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).start()


def stop(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).stop()


def restart(stdout=True, verbose=False):
    ProcessManager(stdout, verbose).restart()


def status(stdout=True, verbose=False):
    return ProcessManager(stdout, verbose).status()
