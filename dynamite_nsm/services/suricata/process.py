import os
import time
import signal
import logging
import subprocess

from dynamite_nsm import utilities
from dynamite_nsm.logger import get_logger
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

    def start(self):
        """
        Start Suricata IDS process in daemon mode

        :return: True, if started successfully
        """
        if not os.path.exists(PID_DIRECTORY):
            utilities.makedirs(PID_DIRECTORY, exist_ok=True)
        p = subprocess.Popen('bin/suricata -i {} -D --pidfile {} -c {}'.format(
            self.config.af_packet_interfaces[0]['interface'],
            os.path.join(PID_DIRECTORY, 'suricata.pid'),
            os.path.join(self.configuration_directory, 'suricata.yaml')), shell=True, cwd=self.install_directory)
        p.communicate()
        retry = 0
        while retry < 6:
            start_message = '[Attempt: {}] Starting Suricata on PID [{}]'.format(retry + 1, self.pid)
            try:
                with open(os.path.join(PID_DIRECTORY, 'suricata.pid')) as f:
                    self.pid = int(f.read())
                start_message = '[Attempt: {}] Starting Suricata on PID [{}]'.format(retry + 1, self.pid)
                self.logger.info(start_message)
                if not utilities.check_pid(self.pid):
                    retry += 1
                    time.sleep(5)
                else:
                    return True
            except IOError:
                self.logger.info(start_message)
                retry += 1
                time.sleep(3)
        self.logger.error("Failed to start Suricata after {} attempts.".format(retry))
        return False

    def stop(self):
        """
        Stop the Suricata process

        :return: True if stopped successfully
        """
        alive = True
        attempts = 0
        while alive:
            try:
                self.logger.info('Attempting to stop Suricata [{}]'.format(self.pid))
                if attempts > 3:
                    sig_command = signal.SIGKILL
                else:
                    # Kill the zombie after the third attempt of asking it to kill itself
                    sig_command = signal.SIGINT
                attempts += 1
                if self.pid != -1:
                    os.kill(self.pid, sig_command)
                time.sleep(10)
                alive = utilities.check_pid(self.pid)
            except Exception as e:
                self.logger.error('An error occurred while attempting to stop Suricata.')
                self.logger.debug('An error occurred while attempting to stop Suricata; {}'.format(e))
                return False
        self.logger.info("Deleting Suricata PID [{}].".format(self.pid))
        utilities.safely_remove_file(os.path.join(PID_DIRECTORY, 'suricata.pid'))
        return True

    def restart(self):
        """
        Restart the Suricata process

        :return: True if restarted successfully
        """
        self.logger.info('Attempting to restart Suricata.')
        self.stop()
        return self.start()

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
